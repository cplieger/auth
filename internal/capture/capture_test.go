package capture

import (
	"log/slog"
	"testing"
)

func TestNewCapturesAndCounts(t *testing.T) {
	t.Parallel()
	logger, rec := New()
	logger.Info("session activity update failed")
	logger.Warn("session activity update failed")
	logger.Info("something else")

	if got := rec.CountMsg("session activity update failed"); got != 2 {
		t.Errorf("CountMsg = %d, want 2", got)
	}
	if got := rec.CountMsg("absent"); got != 0 {
		t.Errorf("CountMsg(absent) = %d, want 0", got)
	}
}

func TestWithAttrsAndGroupStillCapture(t *testing.T) {
	t.Parallel()
	logger, rec := New()
	// WithAttrs/WithGroup return the Recorder unchanged; the record still lands.
	logger.With("base", 1).WithGroup("grp").Info("nested")
	if rec.CountMsg("nested") != 1 {
		t.Error("WithAttrs/WithGroup dropped the record")
	}
}

func TestDefaultCapturesGlobalAndRestores(t *testing.T) {
	// Not parallel: mutates the global slog default.
	before := slog.Default()
	t.Run("captures", func(t *testing.T) {
		rec := Default(t)
		slog.Info("via default")
		if rec.CountMsg("via default") != 1 {
			t.Error("Default did not capture a slog.Default() log")
		}
	})
	if slog.Default() != before {
		t.Error("Default did not restore slog.Default() after the subtest ended")
	}
}
