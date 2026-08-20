// Package capture is an auth-internal test helper: a slog.Handler that records
// log records so tests can assert on auth's logging decisions, plus a helper to
// install it as the default logger.
//
// It is deliberately auth-internal rather than a dependency on an external
// logging helper (e.g. slogx/capture): auth is a foundational library, and a
// ~50-line, never-changing test handler is not worth a new module edge. Import
// it only from auth's _test.go files.
package capture

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// Recorder is a slog.Handler that captures every record regardless of level so
// tests can assert on what was logged. It is safe for concurrent use.
type Recorder struct {
	records []slog.Record
	mu      sync.Mutex
}

// New returns a Recorder and an *slog.Logger writing to it, for code that takes
// an injected logger. It does not touch the global default, so a test using it
// may run in parallel.
func New() (*slog.Logger, *Recorder) {
	rec := &Recorder{}
	return slog.New(rec), rec
}

// Default installs a fresh Recorder as slog's default logger and restores the
// previous default via tb.Cleanup. Use it for code that logs through
// slog.Default(); because it mutates global state the test must not run in
// parallel.
func Default(tb testing.TB) *Recorder {
	tb.Helper()
	rec := &Recorder{}
	prev := slog.Default()
	slog.SetDefault(slog.New(rec))
	tb.Cleanup(func() { slog.SetDefault(prev) })
	return rec
}

// Enabled reports true for every level so nothing is filtered before capture.
func (rec *Recorder) Enabled(context.Context, slog.Level) bool { return true }

// Handle records a clone of r. It satisfies slog.Handler.
//
//nolint:gocritic // Handle's signature is fixed by the slog.Handler interface; r cannot be a pointer.
func (rec *Recorder) Handle(_ context.Context, r slog.Record) error {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	rec.records = append(rec.records, r.Clone())
	return nil
}

// WithAttrs returns the Recorder unchanged; base attributes are not captured.
func (rec *Recorder) WithAttrs([]slog.Attr) slog.Handler { return rec }

// WithGroup returns the Recorder unchanged; groups are not captured.
func (rec *Recorder) WithGroup(string) slog.Handler { return rec }

// CountMsg returns how many captured records have a message containing sub.
// Reached only by tests, like the rest of this package — see the package doc.
func (rec *Recorder) CountMsg(sub string) int {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	n := 0
	for i := range rec.records {
		if strings.Contains(rec.records[i].Message, sub) {
			n++
		}
	}
	return n
}
