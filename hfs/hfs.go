// Package hfs defines the Hexward Finding Schema (HFS), version 1: one JSON
// event per finding transition, identical across every Hexward product.
//
// HFS is the contract between Hexward products and the systems that consume
// their findings — Wazuh, Splunk, Elastic, Loglight, or a plain log file.
// Products build an Event with New, and every sink in package sink renders
// that same Event, so a decoder or search written once works for all
// products.
//
// Compatibility promise: fields are only ever added. A field is never
// renamed, retyped or removed within schema version 1; consumers must ignore
// fields they do not know.
package hfs

import (
	"encoding/json"
	"net"
	"strings"
	"time"
)

// SchemaV1 is the value of the "schema" field on every version-1 event.
// Decoders and SIEM rules key on it.
const SchemaV1 = "hexward.finding/1"

// Kind says why an event was emitted.
type Kind string

const (
	// KindOpened: a finding appeared, or reappeared after being resolved.
	KindOpened Kind = "opened"
	// KindResolved: a finding stopped appearing on its target.
	KindResolved Kind = "resolved"
	// KindSnapshot: a full export of current state, not a transition.
	KindSnapshot Kind = "snapshot"
)

// Event is one HFS record. Field order here is the wire order.
type Event struct {
	Schema         string  `json:"schema"`
	Event          Kind    `json:"event"`
	TS             string  `json:"ts"`
	Product        string  `json:"product"`
	ProductVersion string  `json:"product_version,omitempty"`
	Host           string  `json:"host,omitempty"`
	SrcIP          string  `json:"src_ip,omitempty"`
	Finding        Finding `json:"finding"`
}

// Finding is the finding carried by an Event. It mirrors the Hexward Core
// finding model so products convert field by field, without interpretation.
type Finding struct {
	ID          string         `json:"id,omitempty"`
	Fingerprint string         `json:"fingerprint"`
	Check       string         `json:"check"`
	Title       string         `json:"title"`
	Target      string         `json:"target"`
	Severity    string         `json:"severity"`
	SeverityNum int            `json:"severity_num"`
	Status      string         `json:"status"`
	Remediation string         `json:"remediation,omitempty"`
	FirstSeen   string         `json:"first_seen,omitempty"`
	LastSeen    string         `json:"last_seen,omitempty"`
	ResolvedAt  string         `json:"resolved_at,omitempty"`
	GroupID     string         `json:"group_id,omitempty"`
	Evidence    map[string]any `json:"evidence,omitempty"`
}

// Source is what a product knows about one finding, in its own terms.
// Times may be zero; empty strings are omitted on the wire.
type Source struct {
	ID          string
	Fingerprint string
	Check       string
	Title       string
	Target      string
	Severity    string
	Status      string
	Remediation string
	FirstSeen   time.Time
	LastSeen    time.Time
	ResolvedAt  *time.Time
	GroupID     *string
	Evidence    map[string]any
}

// Meta identifies the emitting product instance.
type Meta struct {
	Product string // lower-case product id, e.g. "rulehawk"
	Version string // product version, e.g. "0.1.2"
	Host    string // hostname of the instance; empty is allowed
}

// Options controls how New builds an event.
type Options struct {
	// Evidence selects how much evidence leaves the product:
	// EvidenceRedacted (default) or EvidenceNone.
	Evidence EvidenceMode
}

// EvidenceMode selects the evidence policy for exported events.
type EvidenceMode string

const (
	// EvidenceRedacted exports evidence after Redact: secret-like keys
	// dropped, strings, lists and nesting bounded.
	EvidenceRedacted EvidenceMode = "redacted"
	// EvidenceNone exports no evidence at all.
	EvidenceNone EvidenceMode = "none"
)

// ParseEvidenceMode accepts "redacted", "none" or "" (redacted).
func ParseEvidenceMode(s string) (EvidenceMode, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "redacted":
		return EvidenceRedacted, true
	case "none":
		return EvidenceNone, true
	}
	return "", false
}

// New builds a version-1 event. at is the event time; the zero time means
// now. Status for KindResolved is always "resolved", whatever src says.
func New(kind Kind, meta Meta, src Source, at time.Time, opt Options) Event {
	if at.IsZero() {
		at = time.Now()
	}
	sev := strings.ToLower(strings.TrimSpace(src.Severity))
	status := src.Status
	if kind == KindResolved {
		status = "resolved"
	}
	if status == "" {
		status = "open"
	}
	f := Finding{
		ID:          src.ID,
		Fingerprint: src.Fingerprint,
		Check:       src.Check,
		Title:       oneLine(src.Title),
		Target:      src.Target,
		Severity:    sev,
		SeverityNum: SeverityNum(sev),
		Status:      status,
		Remediation: oneLine(src.Remediation),
		FirstSeen:   stamp(src.FirstSeen),
		LastSeen:    stamp(src.LastSeen),
	}
	if src.ResolvedAt != nil {
		f.ResolvedAt = stamp(*src.ResolvedAt)
	}
	if src.GroupID != nil {
		f.GroupID = *src.GroupID
	}
	if opt.Evidence != EvidenceNone {
		f.Evidence = Redact(src.Evidence)
	}
	return Event{
		Schema:         SchemaV1,
		Event:          kind,
		TS:             stamp(at),
		Product:        strings.ToLower(meta.Product),
		ProductVersion: meta.Version,
		Host:           meta.Host,
		SrcIP:          EvidenceIP(src.Evidence),
		Finding:        f,
	}
}

// Marshal renders an event as one line of JSON, without a trailing newline.
// Map keys inside evidence are sorted by encoding/json, so the output is
// deterministic for a given event.
func Marshal(e Event) ([]byte, error) {
	return json.Marshal(e)
}

// SeverityNum maps a severity to the 0–10 scale shared by CEF and most
// SIEMs: critical 10, high 8, medium 5, low 3, info 1, unknown 0.
func SeverityNum(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	case "info":
		return 1
	}
	return 0
}

// EvidenceIP returns a source address from evidence when one of the
// conventional keys holds a valid IP, else "". The key order matches the
// Hexward syslog channel, so both formats agree on src.
func EvidenceIP(ev map[string]any) string {
	for _, key := range []string{"source_ip", "src_ip", "src", "actor", "client_ip", "ip"} {
		v, ok := ev[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// oneLine keeps titles and remediation on a single line so line-oriented
// consumers (syslog, CEF, grep) never see a broken record.
func oneLine(s string) string {
	if !strings.ContainsAny(s, "\r\n\x00") {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
}
