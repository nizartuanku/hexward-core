package sink

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
)

var at = time.Date(2026, 10, 28, 9, 12, 44, 0, time.UTC)

func event(kind hfs.Kind, sev string) hfs.Event {
	return hfs.New(kind, hfs.Meta{Product: "rulehawk", Version: "0.1.2", Host: "fw-audit-01"}, hfs.Source{
		ID: "f_1", Fingerprint: "fp1", Check: "rule.permissive",
		Title: "Rule | allows any=any", Target: "ftd-hq:ACP/rule 42", Severity: sev,
		Remediation: "Restrict source\nto mgmt VLAN", FirstSeen: at, LastSeen: at,
		Evidence: map[string]any{"src_ip": "203.0.113.7", "token": "s3cret"},
	}, at, hfs.Options{})
}

func TestFileAppendAndRotate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "rulehawk.ndjson")
	s := &File{Path: p, MaxBytes: 600, Keep: 2}
	for i := 0; i < 6; i++ {
		if err := s.Send(context.Background(), []hfs.Event{event(hfs.KindOpened, "high")}); err != nil {
			t.Fatal(err)
		}
	}
	defer s.Close()
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Fatalf("no rotation: %v", err)
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Fatal("kept more than Keep files")
	}
	b, _ := os.ReadFile(p + ".1")
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e hfs.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil || e.Schema != hfs.SchemaV1 {
			t.Fatalf("bad line %q: %v", line, err)
		}
	}
	if strings.Contains(string(b), "s3cret") {
		t.Fatal("secret evidence written to file")
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o640 {
		t.Fatalf("file mode %v", st.Mode().Perm())
	}
}

func TestSyslogFrames(t *testing.T) {
	s := &Syslog{Addr: "127.0.0.1:514", Hostname: "h1", now: func() time.Time { return at }}
	f, err := s.Frame(event(hfs.KindOpened, "high"))
	if err != nil {
		t.Fatal(err)
	}
	// local0 (16) * 8 + err (3) = 131
	if !strings.HasPrefix(f, "<131>1 2026-10-28T09:12:44.000Z h1 hexward ") || !strings.HasSuffix(f, "\n") {
		t.Fatalf("5424 frame: %q", f)
	}
	body := f[strings.Index(f, "{"):]
	var e hfs.Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &e); err != nil {
		t.Fatalf("json body: %v in %q", err, f)
	}
	s.RFC = 3164
	f, _ = s.Frame(event(hfs.KindResolved, "high"))
	if !strings.HasPrefix(f, "<133>Oct 28 09:12:44 h1 hexward[") {
		t.Fatalf("3164 resolved frame: %q", f)
	}
	if strings.Count(f, "\n") != 1 {
		t.Fatalf("frame not single-line: %q", f)
	}
}

func TestCEF(t *testing.T) {
	c := CEF(event(hfs.KindOpened, "critical"))
	want := `CEF:0|Hexward Labs|rulehawk|0.1.2|rule.permissive|Rule \| allows any=any|10|`
	if !strings.HasPrefix(c, want) {
		t.Fatalf("header:\n%s\nwant prefix\n%s", c, want)
	}
	for _, part := range []string{"rt=1793178764000", "act=opened", "src=203.0.113.7", `cs1=ftd-hq:ACP/rule 42`, `msg=Restrict source to mgmt VLAN`} {
		if !strings.Contains(c, part) {
			t.Errorf("missing %q in %s", part, c)
		}
	}
	if got := cefExt(`a=b\c`); got != `a\=b\\c` {
		t.Errorf("ext escape = %q", got)
	}
	if strings.ContainsAny(c, "\n\r") {
		t.Error("raw newline in CEF")
	}
}

func TestSyslogTCPAndUDP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lines []string
		sc := bufio.NewScanner(c)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		got <- lines
	}()
	s := &Syslog{Addr: ln.Addr().String(), Network: "tcp", Format: FormatCEF}
	if err := s.Send(context.Background(), []hfs.Event{event(hfs.KindOpened, "high"), event(hfs.KindResolved, "low")}); err != nil {
		t.Fatal(err)
	}
	lines := <-got
	if len(lines) != 2 || !strings.Contains(lines[0], "CEF:0|Hexward Labs|") {
		t.Fatalf("tcp lines: %q", lines)
	}

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	u := &Syslog{Addr: pc.LocalAddr().String()}
	if err := u.Send(context.Background(), []hfs.Event{event(hfs.KindOpened, "medium")}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil || !strings.Contains(string(buf[:n]), `"schema":"hexward.finding/1"`) {
		t.Fatalf("udp: %v %q", err, buf[:n])
	}
}

func TestSyslogTLSVerifies(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS()
	defer srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan string, 1)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b, _ := io.ReadAll(c)
			c.Close()
			if len(b) > 0 {
				got <- string(b)
			}
		}
	}()
	// Untrusted certificate: must fail, never silently skip verification.
	bad := &Syslog{Addr: ln.Addr().String(), Network: "tls"}
	if err := bad.Send(context.Background(), []hfs.Event{event(hfs.KindOpened, "high")}); err == nil {
		t.Fatal("sent to an untrusted TLS collector")
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	ok := &Syslog{Addr: ln.Addr().String(), Network: "tls", TLS: &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12}}
	if err := ok.Send(context.Background(), []hfs.Event{event(hfs.KindOpened, "high")}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if !strings.Contains(s, "hexward.finding/1") {
			t.Fatalf("tls payload %q", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no TLS payload")
	}
}

func TestSyslogValidate(t *testing.T) {
	for _, s := range []*Syslog{
		{Addr: "h:1", Format: "xml"}, {Addr: "h:1", Network: "sctp"}, {Addr: "h:1", RFC: 9999}, {Addr: "nohost"},
	} {
		if s.Validate() == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}

func TestHEC(t *testing.T) {
	var bodies []string
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/collector/event" {
			http.Error(w, "bad path "+r.URL.Path, 404)
			return
		}
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.Write([]byte(`{"text":"Success","code":0}`))
	}))
	defer srv.Close()
	s := &HEC{URL: srv.URL, Token: "tok-123", Index: "hexward", BatchSize: 2}
	evs := []hfs.Event{event(hfs.KindOpened, "high"), event(hfs.KindOpened, "low"), event(hfs.KindResolved, "high")}
	if err := s.Send(context.Background(), evs); err != nil {
		t.Fatal(err)
	}
	if auth != "Splunk tok-123" {
		t.Fatalf("auth header %q", auth)
	}
	if len(bodies) != 2 {
		t.Fatalf("batches = %d", len(bodies))
	}
	dec := json.NewDecoder(strings.NewReader(bodies[0]))
	n := 0
	for dec.More() {
		var env struct {
			Time       float64   `json:"time"`
			Sourcetype string    `json:"sourcetype"`
			Source     string    `json:"source"`
			Index      string    `json:"index"`
			Event      hfs.Event `json:"event"`
		}
		if err := dec.Decode(&env); err != nil {
			t.Fatal(err)
		}
		if env.Sourcetype != "hexward:finding" || env.Source != "hexward:rulehawk" || env.Index != "hexward" || env.Time != float64(at.Unix()) || env.Event.Schema != hfs.SchemaV1 {
			t.Fatalf("envelope %+v", env)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("events in first batch = %d", n)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"text":"Invalid token","code":4}`, 403)
	}))
	defer failing.Close()
	if err := (&HEC{URL: failing.URL, Token: "x"}).Send(context.Background(), evs); err == nil || !strings.Contains(err.Error(), "Invalid token") {
		t.Fatalf("want auth error, got %v", err)
	}
	if err := (&HEC{URL: "ftp://x", Token: "x"}).Send(context.Background(), evs); err == nil {
		t.Fatal("accepted ftp URL")
	}
}

func TestWebhookV2(t *testing.T) {
	var hdr http.Header
	var payload struct {
		Version int         `json:"version"`
		Schema  string      `json:"schema"`
		Events  []hfs.Event `json:"events"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hdr = r.Header
		_ = json.NewDecoder(r.Body).Decode(&payload)
	}))
	defer srv.Close()
	s := &Webhook{URL: srv.URL, Secret: "shh"}
	if err := s.Send(context.Background(), []hfs.Event{event(hfs.KindOpened, "high")}); err != nil {
		t.Fatal(err)
	}
	if hdr.Get("X-Hexward-Token") != "shh" || hdr.Get("X-Sentinel-Token") != "shh" {
		t.Fatalf("token headers %v", hdr)
	}
	if payload.Version != 2 || payload.Schema != hfs.SchemaV1 || len(payload.Events) != 1 || payload.Events[0].Finding.Fingerprint != "fp1" {
		t.Fatalf("payload %+v", payload)
	}
}

func TestReadSecretFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok")
	os.WriteFile(p, []byte("  abc\n"), 0o600)
	if s, err := ReadSecretFile(p); err != nil || s != "abc" {
		t.Fatalf("%q %v", s, err)
	}
	os.WriteFile(p, []byte("\n"), 0o600)
	if _, err := ReadSecretFile(p); err == nil {
		t.Fatal("accepted empty secret")
	}
}
