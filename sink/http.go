package sink

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
)

// HEC sends events to a Splunk HTTP Event Collector.
//
// URL is the collector base ("https://splunk.example:8088") or the full
// event endpoint; "/services/collector/event" is appended when the URL has
// no path. Events are batched as concatenated JSON objects, the format the
// collector documents, at most BatchSize per request.
type HEC struct {
	URL        string
	Token      string
	Index      string // optional; must be allowed for the token
	Sourcetype string // default "hexward:finding"
	BatchSize  int    // default 100
	TLS        *tls.Config

	client *http.Client
}

func (s *HEC) Name() string { return "splunk-hec" }

// Endpoint returns the resolved event endpoint.
func (s *HEC) Endpoint() (string, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("splunk-hec: URL must start with https:// or http://")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/services/collector/event"
	}
	return u.String(), nil
}

type hecEnvelope struct {
	Time       float64   `json:"time"`
	Host       string    `json:"host,omitempty"`
	Source     string    `json:"source"`
	Sourcetype string    `json:"sourcetype"`
	Index      string    `json:"index,omitempty"`
	Event      hfs.Event `json:"event"`
}

// Body renders a batch as the request body Splunk expects.
func (s *HEC) Body(events []hfs.Event) ([]byte, error) {
	st := s.Sourcetype
	if st == "" {
		st = "hexward:finding"
	}
	var buf bytes.Buffer
	for _, e := range events {
		var ts float64
		if t, err := time.Parse(time.RFC3339, e.TS); err == nil {
			ts = float64(t.Unix())
		}
		b, err := json.Marshal(hecEnvelope{
			Time: ts, Host: e.Host, Source: "hexward:" + e.Product,
			Sourcetype: st, Index: s.Index, Event: e,
		})
		if err != nil {
			return nil, err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

func (s *HEC) Send(ctx context.Context, events []hfs.Event) error {
	if len(events) == 0 {
		return nil
	}
	if s.Token == "" {
		return fmt.Errorf("splunk-hec: no token")
	}
	endpoint, err := s.Endpoint()
	if err != nil {
		return err
	}
	if s.client == nil {
		s.client = httpClient(s.TLS)
	}
	size := s.BatchSize
	if size <= 0 {
		size = 100
	}
	for start := 0; start < len(events); start += size {
		end := min(start+size, len(events))
		body, err := s.Body(events[start:end])
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Splunk "+s.Token)
		req.Header.Set("Content-Type", "application/json")
		if err := do(s.client, req, "splunk-hec"); err != nil {
			return err
		}
	}
	return nil
}

// Webhook posts HFS events as JSON to any URL (payload version 2):
//
//	{"version":2,"schema":"hexward.finding/1","events":[ ...HFS events... ]}
//
// Secret, when set, is sent as X-Hexward-Token (and, until 1 March 2027, as
// the pre-rename X-Sentinel-Token) so the receiver can authenticate us.
type Webhook struct {
	URL    string
	Secret string
	TLS    *tls.Config

	client *http.Client
}

func (s *Webhook) Name() string { return "webhook-v2" }

type webhookV2 struct {
	Version int         `json:"version"`
	Schema  string      `json:"schema"`
	Events  []hfs.Event `json:"events"`
}

func (s *Webhook) Send(ctx context.Context, events []hfs.Event) error {
	if len(events) == 0 {
		return nil
	}
	if s.client == nil {
		s.client = httpClient(s.TLS)
	}
	body, err := json.Marshal(webhookV2{Version: 2, Schema: hfs.SchemaV1, Events: events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.Secret != "" {
		req.Header.Set("X-Hexward-Token", s.Secret)
		req.Header.Set("X-Sentinel-Token", s.Secret) // compatibility, removed 1 March 2027
	}
	return do(s.client, req, "webhook")
}

func do(c *http.Client, req *http.Request, name string) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s returned %s: %s", name, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}
