package authkit

import "log"

// Logger is the interface authkit uses for diagnostic output. Provide your own
// implementation to route authkit logs into your application's logging system
// (e.g. slog, zap, zerolog). If not set in Config, a default logger that
// writes to the standard library log package is used.
type Logger interface {
	// Info logs informational messages (e.g. startup warnings).
	Info(msg string, args ...any)

	// Error logs error messages (e.g. failed OAuth callbacks, session errors).
	Error(msg string, args ...any)
}

// defaultLogger wraps the standard library log package.
type defaultLogger struct{}

func (defaultLogger) Info(msg string, args ...any) {
	if len(args) > 0 {
		log.Printf(msg, args...)
	} else {
		log.Println(msg)
	}
}

func (defaultLogger) Error(msg string, args ...any) {
	if len(args) > 0 {
		log.Printf(msg, args...)
	} else {
		log.Println(msg)
	}
}
