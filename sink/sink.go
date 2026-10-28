// Package sink delivers HFS events (package hfs) to the places SIEMs read
// from: an NDJSON file, a syslog collector, a Splunk HTTP Event Collector,
// or a generic webhook. Every sink renders the same hfs.Event, so one
// product setting reaches Wazuh, Splunk, Elastic and Loglight alike.
//
// Sinks hold no retry or batching logic of their own: products already run
// a dispatcher that batches, deduplicates and retries, and call Send with
// one batch at a time. Send must be safe for concurrent use.
package sink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nizartuanku/hexward-core/hfs"
)

// Sink delivers a batch of events somewhere.
type Sink interface {
	Name() string
	Send(ctx context.Context, events []hfs.Event) error
}

// ReadSecretFile reads a token or secret from a file, trimming surrounding
// whitespace. Secrets come from files, never flags, so they stay out of
// process listings and shell history.
func ReadSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}

// TLSConfig builds a client TLS config that trusts the system roots, plus
// the PEM certificates in caFile when it is set. Verification is never
// disabled: an untrusted collector is a configuration error to fix, not a
// check to skip.
func TLSConfig(caFile, serverName string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caFile == "" {
		return cfg, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no PEM certificates in " + caFile)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// httpClient returns a client with a bounded timeout and the given TLS
// config (nil = Go defaults).
func httpClient(tc *tls.Config) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if tc != nil {
		tr.TLSClientConfig = tc
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}
}
