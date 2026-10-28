package hfs

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

var (
	t0    = time.Date(2026, 10, 28, 9, 12, 44, 0, time.UTC)
	t1    = time.Date(2026, 10, 28, 10, 0, 0, 0, time.UTC)
	group = "acme"
	meta  = Meta{Product: "RuleHawk", Version: "0.1.2", Host: "fw-audit-01"}
)

func base() Source {
	return Source{
		ID:          "f_8c1e",
		Fingerprint: "3b9a0f1c",
		Check:       "rule.permissive",
		Title:       "Rule allows any source to RDP (3389)",
		Target:      "ftd-hq:ACP/rule 42",
		Severity:    "High",
		Status:      "open",
		Remediation: "Restrict the source to the management VLAN.\nPut RDP behind an MFA VPN.",
		FirstSeen:   t0,
		LastSeen:    t0,
	}
}

// goldenCases are the HFS v1 test vectors. Every product's encoder must
// reproduce these bytes exactly.
func goldenCases() map[string]Event {
	opened := base()
	opened.Evidence = map[string]any{"rule_index": 42, "port": 3389, "src_ip": "203.0.113.7"}

	resolved := base()
	r := t1
	resolved.ResolvedAt = &r
	resolved.LastSeen = t1

	secrets := base()
	secrets.Evidence = map[string]any{
		"username": "admin", "password": "hunter2", "API_Key": "abc",
		"nested": map[string]any{"session_id": "x", "line": "permit ip any any"},
	}

	none := base()
	none.Evidence = map[string]any{"src_ip": "198.51.100.9", "detail": "kept out"}

	snap := base()
	snap.GroupID = &group
	snap.Status = "acknowledged"

	return map[string]Event{
		"opened_with_ip":   New(KindOpened, meta, opened, t0, Options{}),
		"resolved":         New(KindResolved, meta, resolved, t1, Options{}),
		"evidence_secrets": New(KindOpened, meta, secrets, t0, Options{}),
		"evidence_none":    New(KindOpened, meta, none, t0, Options{Evidence: EvidenceNone}),
		"snapshot_group":   New(KindSnapshot, meta, snap, t1, Options{}),
		"minimal_no_evidence": New(KindOpened, Meta{Product: "certlight"}, Source{
			Fingerprint: "aa", Check: "tls.expiry", Title: "Certificate expires in 9 days",
			Target: "example.com:443", Severity: "medium",
		}, t0, Options{}),
	}
}

func TestGolden(t *testing.T) {
	for name, ev := range goldenCases() {
		got, err := Marshal(ev)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		path := filepath.Join("testdata", name+".json")
		if *update {
			if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test -update)", name, err)
		}
		if strings.TrimRight(string(want), "\n") != string(got) {
			t.Errorf("%s mismatch\nwant %s\n got %s", name, want, got)
		}
	}
}

func TestInvariants(t *testing.T) {
	for name, ev := range goldenCases() {
		if ev.Schema != SchemaV1 {
			t.Errorf("%s: schema %q", name, ev.Schema)
		}
		if ev.Product != strings.ToLower(ev.Product) {
			t.Errorf("%s: product not lower-case", name)
		}
		b, _ := Marshal(ev)
		if strings.ContainsAny(string(b), "\n\r") {
			t.Errorf("%s: raw newline in encoded event", name)
		}
		var back map[string]any
		if err := json.Unmarshal(b, &back); err != nil {
			t.Errorf("%s: not valid JSON: %v", name, err)
		}
	}
}

func TestResolvedForcesStatus(t *testing.T) {
	s := base()
	s.Status = "open"
	if got := New(KindResolved, meta, s, t1, Options{}).Finding.Status; got != "resolved" {
		t.Fatalf("status = %q", got)
	}
}

func TestSecretsNeverLeave(t *testing.T) {
	ev := goldenCases()["evidence_secrets"]
	b, _ := Marshal(ev)
	for _, leak := range []string{"hunter2", "password", "abc", "session_id", "API_Key"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("leaked %q in %s", leak, b)
		}
	}
	if !strings.Contains(string(b), "permit ip any any") {
		t.Errorf("non-secret nested evidence was dropped: %s", b)
	}
}

func TestEvidenceNoneStillCarriesSrcIP(t *testing.T) {
	ev := goldenCases()["evidence_none"]
	if ev.Finding.Evidence != nil {
		t.Fatalf("evidence exported with EvidenceNone: %v", ev.Finding.Evidence)
	}
	if ev.SrcIP != "198.51.100.9" {
		t.Fatalf("src_ip = %q", ev.SrcIP)
	}
}

func TestRedactBounds(t *testing.T) {
	long := strings.Repeat("x", 1000)
	in := map[string]any{"s": long, "l": make([]any, 50)}
	for i := 0; i < 40; i++ {
		in["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = i
	}
	out := Redact(in)
	if len(out) > maxEvidenceKeys {
		t.Fatalf("keys = %d", len(out))
	}
	if s, ok := out["l"].([]any); ok && len(s) > maxEvidenceList {
		t.Fatalf("list len = %d", len(s))
	}
	deep := map[string]any{"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": 1}}}}
	b, _ := json.Marshal(Redact(deep))
	if !strings.Contains(string(b), "nested too deep") {
		t.Fatalf("depth not bounded: %s", b)
	}
	if Redact(nil) != nil {
		t.Fatal("nil in, non-nil out")
	}
	if len([]rune(Redact(map[string]any{"s": long})["s"].(string))) != maxEvidenceString+1 {
		t.Fatal("string not truncated to bound")
	}
}

func TestSeverityNum(t *testing.T) {
	for sev, want := range map[string]int{"critical": 10, "High": 8, "medium": 5, "low": 3, "info": 1, "weird": 0} {
		if got := SeverityNum(sev); got != want {
			t.Errorf("%s = %d, want %d", sev, got, want)
		}
	}
}

func TestParseEvidenceMode(t *testing.T) {
	for in, want := range map[string]EvidenceMode{"": EvidenceRedacted, "Redacted": EvidenceRedacted, "none": EvidenceNone} {
		got, ok := ParseEvidenceMode(in)
		if !ok || got != want {
			t.Errorf("%q → %q, %v", in, got, ok)
		}
	}
	if _, ok := ParseEvidenceMode("all"); ok {
		t.Error("accepted unknown mode")
	}
}
