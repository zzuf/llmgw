package safeguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"llmgw/internal/domain"
)

// Captured owns an unlinked temporary file. The caller must Close after either a
// rejected verdict or Replay. Text is the complete, bounded guard projection.
type Captured struct {
	Text         string
	Applicable   bool
	Usage        domain.Usage
	UpstreamTTFT time.Duration
	file         *os.File
}

func streamFailure(message string) error {
	return &Error{Code: "guard_unavailable", Message: message, Status: 503}
}
func streamUnsupported() error {
	return &Error{Code: "unsupported_guard_content", Message: "Streaming content cannot be safely inspected", Status: 400}
}
func streamLimit() error {
	return &Error{Code: "guard_limit_exceeded", Message: "Safeguard buffering or inspection limit exceeded", Status: 503}
}
func streamContext(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return &Error{Code: "guard_timeout", Message: "Safeguard request timed out", Status: 504}
	}
	return err
}
func newCapture(dir string) (*Captured, error) {
	dir = filepath.Join(dir, "safeguard-spool")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, streamFailure("Cannot create private safeguard storage")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, streamFailure("Safeguard storage is not a private directory")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, streamFailure("Cannot protect safeguard storage")
	}
	f, err := os.CreateTemp(dir, "response-")
	if err != nil {
		return nil, streamFailure("Cannot open safeguard storage")
	}
	if err = os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, streamFailure("Cannot anonymize safeguard storage")
	}
	return &Captured{file: f}, nil
}
func (c *Captured) Close() error {
	if c == nil || c.file == nil {
		return nil
	}
	err := c.file.Close()
	c.file = nil
	return err
}

// Replay is called only after the complete output has passed its guard verdict.
func (c *Captured) Replay(ctx context.Context, w http.ResponseWriter) (time.Duration, error) {
	started := time.Now()
	var ttft time.Duration
	if c == nil || c.file == nil {
		return 0, streamFailure("Safeguard response is closed")
	}
	if _, err := c.file.Seek(0, io.SeekStart); err != nil {
		return 0, streamFailure("Cannot read safeguard response")
	}
	if err := ctx.Err(); err != nil {
		return 0, streamContext(err)
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	controller := http.NewResponseController(w)
	buffer := make([]byte, 32<<10)
	for {
		if err := ctx.Err(); err != nil {
			return ttft, streamContext(err)
		}
		n, err := c.file.Read(buffer)
		if n > 0 {
			written, writeErr := w.Write(buffer[:n])
			if written > 0 && ttft == 0 {
				ttft = time.Since(started)
				if ttft == 0 {
					ttft = time.Nanosecond
				}
			}
			if writeErr != nil {
				return ttft, writeErr
			}
			if written != n {
				return ttft, io.ErrShortWrite
			}
			if err := controller.Flush(); err != nil {
				return ttft, err
			}
		}
		if err == io.EOF {
			return ttft, nil
		}
		if err != nil {
			return ttft, streamFailure("Cannot read safeguard response")
		}
	}
}

type captureWriter struct {
	f        *os.File
	header   http.Header
	limit, n int64
	err      error
}

func (w *captureWriter) Header() http.Header { return w.header }
func (w *captureWriter) WriteHeader(int)     {}
func (w *captureWriter) Flush()              {}
func (w *captureWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if int64(len(p)) > w.limit-w.n {
		w.err = streamLimit()
		return 0, w.err
	}
	n, err := w.f.Write(p)
	w.n += int64(n)
	if err != nil || n != len(p) {
		w.err = streamFailure("Cannot write safeguard response")
		return n, w.err
	}
	return n, nil
}
