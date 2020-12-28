package logger

// Logger is an interface for logger
type Logger interface {
	Error(message string)
	Warn(message string)
	Info(message string)
	Debug(message string)
}

// NilLogger is a logger stub
type NilLogger struct{}

// Error logs message as an error
func (l *NilLogger) Error(message string) {}

// Warn logs message as a warning
func (l *NilLogger) Warn(message string) {}

// Info logs message as an info
func (l *NilLogger) Info(message string) {}

// Debug logs message as a debug
func (l *NilLogger) Debug(message string) {}
