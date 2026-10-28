package sink

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
)

// Syslog formats.
const (
	FormatJSON = "json" // message body = the HFS event as one JSON line
	FormatCEF  = "cef"  // message body = ArcSight Common Event Format
)

// Syslog sends one syslog message per event to a collector.
//
// Network is "udp" (default), "tcp" or "tls". TCP and TLS frames are
// newline-terminated; HFS JSON and CEF never contain a raw newline, so the
// framing is unambiguous.
//
// RFC selects the header: 5424 (default — full date, UTC, year included) or
// 3164 (the legacy BSD header, for collectors that only speak it).
type Syslog struct {
	Addr     string // host:port
	Network  string // udp | tcp | tls
	Format   string // json | cef
	RFC      int    // 5424 | 3164
	Facility int    // 0 = local0 (16)
	Hostname string // empty = OS hostname
	AppName  string // empty = "hexward"
	TLS      *tls.Config

	// now is overridable in tests.
	now func() time.Time
}

func (s *Syslog) Name() string { return "syslog-" + s.format() }

func (s *Syslog) format() string {
	if s.Format == "" {
		return FormatJSON
	}
	return s.Format
}

// Validate reports configuration errors before the first send.
func (s *Syslog) Validate() error {
	switch s.format() {
	case FormatJSON, FormatCEF:
	default:
		return fmt.Errorf("syslog: unknown format %q (want json or cef)", s.Format)
	}
	switch s.network() {
	case "udp", "tcp", "tls":
	default:
		return fmt.Errorf("syslog: unknown network %q (want udp, tcp or tls)", s.Network)
	}
	switch s.RFC {
	case 0, 3164, 5424:
	default:
		return fmt.Errorf("syslog: unknown RFC %d (want 5424 or 3164)", s.RFC)
	}
	if _, _, err := net.SplitHostPort(s.Addr); err != nil {
		return fmt.Errorf("syslog: address %q: %w", s.Addr, err)
	}
	return nil
}

func (s *Syslog) network() string {
	if s.Network == "" {
		return "udp"
	}
	return s.Network
}

// Send dials the collector, writes one frame per event and closes.
func (s *Syslog) Send(ctx context.Context, events []hfs.Event) error {
	if len(events) == 0 {
		return nil
	}
	if err := s.Validate(); err != nil {
		return err
	}
	frames := make([]string, 0, len(events))
	for _, e := range events {
		f, err := s.Frame(e)
		if err != nil {
			return err
		}
		frames = append(frames, f)
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	}
	for _, f := range frames {
		if _, err := io.WriteString(conn, f); err != nil {
			return err
		}
	}
	return nil
}

func (s *Syslog) dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	switch s.network() {
	case "tls":
		cfg := s.TLS
		if cfg == nil {
			host, _, _ := net.SplitHostPort(s.Addr)
			cfg = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
		}
		td := tls.Dialer{NetDialer: &d, Config: cfg}
		return td.DialContext(ctx, "tcp", s.Addr)
	default:
		return d.DialContext(ctx, s.network(), s.Addr)
	}
}

// Frame renders one event as a complete, newline-terminated syslog frame.
func (s *Syslog) Frame(e hfs.Event) (string, error) {
	var body string
	switch s.format() {
	case FormatCEF:
		body = CEF(e)
	default:
		b, err := hfs.Marshal(e)
		if err != nil {
			return "", err
		}
		body = string(b)
	}
	facility := s.Facility
	if facility == 0 {
		facility = 16 // local0
	}
	pri := facility*8 + syslogSeverity(e)
	host := s.Hostname
	if host == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			host = h
		} else {
			host = "-"
		}
	}
	app := s.AppName
	if app == "" {
		app = "hexward"
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	t := now().UTC()
	pid := os.Getpid()
	if s.RFC == 3164 {
		return fmt.Sprintf("<%d>%s %s %s[%d]: %s\n", pri, t.Format(time.Stamp), host, app, pid, body), nil
	}
	// RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	return fmt.Sprintf("<%d>1 %s %s %s %d finding - %s\n",
		pri, t.Format("2006-01-02T15:04:05.000Z"), host, app, pid, body), nil
}

// syslogSeverity maps a finding onto the syslog numeric severity, so
// existing routing ("page me on crit") works unchanged. A resolution is
// good news and travels as notice.
func syslogSeverity(e hfs.Event) int {
	if e.Event == hfs.KindResolved {
		return 5
	}
	switch e.Finding.Severity {
	case "critical":
		return 2
	case "high":
		return 3
	case "medium":
		return 4
	case "low":
		return 5
	}
	return 6
}

// CEF renders an event in ArcSight Common Event Format:
//
//	CEF:0|Hexward Labs|<product>|<version>|<check>|<title>|<0-10>|<extension>
func CEF(e hfs.Event) string {
	f := e.Finding
	var b strings.Builder
	b.WriteString("CEF:0|Hexward Labs|")
	b.WriteString(cefHeader(e.Product))
	b.WriteByte('|')
	b.WriteString(cefHeader(e.ProductVersion))
	b.WriteByte('|')
	b.WriteString(cefHeader(f.Check))
	b.WriteByte('|')
	b.WriteString(cefHeader(f.Title))
	b.WriteByte('|')
	b.WriteString(strconv.Itoa(f.SeverityNum))
	b.WriteByte('|')

	ext := []struct{ k, v string }{
		{"rt", cefTime(e.TS)},
		{"act", string(e.Event)},
		{"dvchost", e.Host},
		{"src", e.SrcIP},
		{"externalId", f.ID},
		{"cs1Label", "target"}, {"cs1", f.Target},
		{"cs2Label", "fingerprint"}, {"cs2", f.Fingerprint},
		{"cs3Label", "status"}, {"cs3", f.Status},
		{"cs4Label", "severity"}, {"cs4", f.Severity},
		{"cs5Label", "schema"}, {"cs5", e.Schema},
		{"msg", f.Remediation},
	}
	first := true
	for _, kv := range ext {
		if kv.v == "" {
			continue
		}
		if !first {
			b.WriteByte(' ')
		}
		first = false
		b.WriteString(kv.k)
		b.WriteByte('=')
		b.WriteString(cefExt(kv.v))
	}
	return b.String()
}

// cefTime renders the event time as epoch milliseconds, which every CEF
// parser accepts without locale or time-zone guessing.
func cefTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(t.UnixMilli(), 10)
}

func cefHeader(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `|`, `\|`)
	return oneLine(s)
}

func cefExt(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `=`, `\=`)
	s = strings.ReplaceAll(s, "\r\n", `\n`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	return s
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
}
