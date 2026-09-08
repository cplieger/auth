package capture

import (
	"log"
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
	beforeWriter, beforeFlags := log.Writer(), log.Flags()
	t.Run("captures", func(t *testing.T) {
		rec := Default(t)
		slog.Info("via default")
		if rec.CountMsg("via default") != 1 {
			t.Error("Default did not capture a slog.Default() log")
		}
		if log.Writer() == beforeWriter {
			t.Fatal("slog.SetDefault did not redirect log's writer, so this test cannot observe the restore")
		}
	})
	if slog.Default() != before {
		t.Error("Default did not restore slog.Default() after the subtest ended")
	}
	// The log half is what silences the rest of the binary: the stock default
	// handler emits through log.Output, so a leaked redirect discards every
	// later slog call.
	if log.Writer() != beforeWriter {
		t.Error("Default did not restore log.Writer(); later slog calls write into the Recorder")
	}
	if got := log.Flags(); got != beforeFlags {
		t.Errorf("log.Flags() = %d, want %d", got, beforeFlags)
	}
}
