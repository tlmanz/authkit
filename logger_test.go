package authkit

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestDefaultLogger_InfoWithArgs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	log.SetFlags(0) // remove timestamp for predictable output
	defer log.SetFlags(log.LstdFlags)

	l := defaultLogger{}
	l.Info("hello %s %d", "world", 42)

	got := strings.TrimSpace(buf.String())
	if got != "hello world 42" {
		t.Errorf("Info with args: got %q, want %q", got, "hello world 42")
	}
}

func TestDefaultLogger_InfoWithoutArgs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	log.SetFlags(0)
	defer log.SetFlags(log.LstdFlags)

	l := defaultLogger{}
	l.Info("simple message")

	got := strings.TrimSpace(buf.String())
	if got != "simple message" {
		t.Errorf("Info without args: got %q, want %q", got, "simple message")
	}
}

func TestDefaultLogger_ErrorWithArgs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	log.SetFlags(0)
	defer log.SetFlags(log.LstdFlags)

	l := defaultLogger{}
	l.Error("error: %v", "something broke")

	got := strings.TrimSpace(buf.String())
	if got != "error: something broke" {
		t.Errorf("Error with args: got %q, want %q", got, "error: something broke")
	}
}

func TestDefaultLogger_ErrorWithoutArgs(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	log.SetFlags(0)
	defer log.SetFlags(log.LstdFlags)

	l := defaultLogger{}
	l.Error("plain error")

	got := strings.TrimSpace(buf.String())
	if got != "plain error" {
		t.Errorf("Error without args: got %q, want %q", got, "plain error")
	}
}

// testLogger captures log calls for assertions.
type testLogger struct {
	infos  []string
	errors []string
}

func (l *testLogger) Info(msg string, args ...any)  { l.infos = append(l.infos, msg) }
func (l *testLogger) Error(msg string, args ...any) { l.errors = append(l.errors, msg) }

func TestCustomLogger_UsedByNew(t *testing.T) {
	logger := &testLogger{}
	_, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  false, // triggers the Info warning
		UserStore:     newMockUserStore(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(logger.infos) == 0 {
		t.Error("expected custom logger to receive SecureCookie warning")
	}
	found := false
	for _, msg := range logger.infos {
		if strings.Contains(msg, "SecureCookie") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected SecureCookie warning in logger.infos, got: %v", logger.infos)
	}
}

func TestCustomLogger_NoWarningWhenSecureCookieTrue(t *testing.T) {
	logger := &testLogger{}
	_, err := New(Config{
		Mode:          AuthModePassword,
		SessionSecret: "test-secret-that-is-at-least-32-bytes-long!!",
		SecureCookie:  true,
		UserStore:     newMockUserStore(),
		Logger:        logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, msg := range logger.infos {
		if strings.Contains(msg, "SecureCookie") {
			t.Errorf("should not warn about SecureCookie when set to true, got: %q", msg)
		}
	}
}
