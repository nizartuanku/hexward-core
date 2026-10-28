package sink

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/nizartuanku/hexward-core/hfs"
)

// File appends events as NDJSON (one JSON object per line) to Path, the
// format the Wazuh agent (log_format json), the Splunk Universal Forwarder
// and Elastic Agent all tail natively.
//
// When the file grows past MaxBytes it is rotated to Path.1, Path.2, …
// keeping Keep old files. Rotated names deliberately do not end in .ndjson,
// so a "*.ndjson" collector glob never reads a record twice.
type File struct {
	Path     string
	MaxBytes int64 // default 50 MiB
	Keep     int   // default 5

	mu   sync.Mutex
	f    *os.File
	size int64
}

func (s *File) Name() string { return "file" }

func (s *File) maxBytes() int64 {
	if s.MaxBytes <= 0 {
		return 50 << 20
	}
	return s.MaxBytes
}

func (s *File) keep() int {
	if s.Keep <= 0 {
		return 5
	}
	return s.Keep
}

// Send appends the batch in a single write, then rotates if needed.
func (s *File) Send(_ context.Context, events []hfs.Event) error {
	if len(events) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, e := range events {
		line, err := hfs.Marshal(e)
		if err != nil {
			return err
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.openLocked(); err != nil {
		return err
	}
	n, err := s.f.Write(buf.Bytes())
	s.size += int64(n)
	if err != nil {
		return err
	}
	if s.size >= s.maxBytes() {
		return s.rotateLocked()
	}
	return nil
}

// Close closes the current file, if open.
func (s *File) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

func (s *File) openLocked() error {
	if s.f != nil {
		return nil
	}
	if s.Path == "" {
		return fmt.Errorf("file sink: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	s.f, s.size = f, st.Size()
	return nil
}

func (s *File) rotateLocked() error {
	if err := s.f.Close(); err != nil {
		return err
	}
	s.f = nil
	keep := s.keep()
	_ = os.Remove(fmt.Sprintf("%s.%d", s.Path, keep))
	for i := keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", s.Path, i)
		if _, err := os.Stat(from); err == nil {
			if err := os.Rename(from, fmt.Sprintf("%s.%d", s.Path, i+1)); err != nil {
				return err
			}
		}
	}
	if err := os.Rename(s.Path, s.Path+".1"); err != nil {
		return err
	}
	return s.openLocked()
}
