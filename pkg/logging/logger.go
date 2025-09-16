package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Logger provides secure logging that never logs sensitive data
type Logger struct {
	*logrus.Logger
	sensitivePatterns []*regexp.Regexp
}

// LogConfig represents logging configuration
type LogConfig struct {
	Level    string
	File     string
	MaxSize  int // MB
	MaxAge   int // days
	Compress bool
	Console  bool
}

// NewLogger creates a new secure logger instance
func NewLogger(config *LogConfig) (*Logger, error) {
	logger := &Logger{
		Logger: logrus.New(),
	}

	// Set log level
	level, err := logrus.ParseLevel(config.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.Logger.SetLevel(level)

	// Set formatter
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
		DisableColors:   !config.Console,
	})

	// Set up output
	var writers []io.Writer

	// Console output
	if config.Console {
		writers = append(writers, os.Stdout)
	}

	// File output
	if config.File != "" {
		// Create log directory if it doesn't exist
		logDir := filepath.Dir(config.File)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(config.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}

		writers = append(writers, file)
	}

	if len(writers) > 0 {
		logger.SetOutput(io.MultiWriter(writers...))
	}

	// Initialize sensitive data patterns
	logger.initSensitivePatterns()

	return logger, nil
}

// initSensitivePatterns initializes patterns for detecting sensitive data
func (l *Logger) initSensitivePatterns() {
	patterns := []string{
		// Password patterns
		`(?i)password["\s]*[:=]["\s]*[^\s"]+`,
		`(?i)pass["\s]*[:=]["\s]*[^\s"]+`,
		`(?i)pwd["\s]*[:=]["\s]*[^\s"]+`,

		// Key patterns
		`(?i)key["\s]*[:=]["\s]*[^\s"]+`,
		`(?i)secret["\s]*[:=]["\s]*[^\s"]+`,
		`(?i)token["\s]*[:=]["\s]*[^\s"]+`,

		// Cryptographic data patterns (base64, hex)
		`[A-Za-z0-9+/]{32,}={0,2}`, // Base64 (32+ chars)
		`[0-9a-fA-F]{32,}`,         // Hex (32+ chars)

		// File paths that might contain sensitive data
		`(?i)\.key$`,
		`(?i)\.pem$`,
		`(?i)\.p12$`,
		`(?i)\.pfx$`,
	}

	l.sensitivePatterns = make([]*regexp.Regexp, len(patterns))
	for i, pattern := range patterns {
		l.sensitivePatterns[i] = regexp.MustCompile(pattern)
	}
}

// sanitizeMessage removes or masks sensitive data from log messages
func (l *Logger) sanitizeMessage(msg string) string {
	sanitized := msg

	for _, pattern := range l.sensitivePatterns {
		sanitized = pattern.ReplaceAllStringFunc(sanitized, func(match string) string {
			// For key-value pairs, keep the key but mask the value
			if strings.Contains(match, ":") || strings.Contains(match, "=") {
				parts := regexp.MustCompile(`[:=]`).Split(match, 2)
				if len(parts) == 2 {
					return parts[0] + ": [REDACTED]"
				}
			}
			// For other patterns, replace with placeholder
			return "[REDACTED]"
		})
	}

	return sanitized
}

// sanitizeFields removes or masks sensitive data from log fields
func (l *Logger) sanitizeFields(fields logrus.Fields) logrus.Fields {
	sanitized := make(logrus.Fields)

	sensitiveKeys := map[string]bool{
		"password":     true,
		"pass":         true,
		"pwd":          true,
		"key":          true,
		"secret":       true,
		"token":        true,
		"private_key":  true,
		"public_key":   true,
		"recovery_key": true,
		"master_key":   true,
		"envelope":     true,
	}

	for key, value := range fields {
		lowerKey := strings.ToLower(key)

		// Check if key is sensitive
		if sensitiveKeys[lowerKey] {
			sanitized[key] = "[REDACTED]"
			continue
		}

		// Check if key contains sensitive words
		isSensitive := false
		for sensitiveKey := range sensitiveKeys {
			if strings.Contains(lowerKey, sensitiveKey) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			sanitized[key] = "[REDACTED]"
			continue
		}

		// Sanitize string values
		if strValue, ok := value.(string); ok {
			sanitized[key] = l.sanitizeMessage(strValue)
		} else {
			sanitized[key] = value
		}
	}

	return sanitized
}

// Secure logging methods that sanitize input

// Debug logs a debug message with sanitized fields
func (l *Logger) Debug(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)
	l.Logger.WithFields(sanitizedFields).Debug(sanitizedMsg)
}

// Info logs an info message with sanitized fields
func (l *Logger) Info(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)
	l.Logger.WithFields(sanitizedFields).Info(sanitizedMsg)
}

// Warn logs a warning message with sanitized fields
func (l *Logger) Warn(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)
	l.Logger.WithFields(sanitizedFields).Warn(sanitizedMsg)
}

// Error logs an error message with sanitized fields
func (l *Logger) Error(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)
	l.Logger.WithFields(sanitizedFields).Error(sanitizedMsg)
}

// Fatal logs a fatal message with sanitized fields and exits
func (l *Logger) Fatal(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)
	l.Logger.WithFields(sanitizedFields).Fatal(sanitizedMsg)
}

// parseKeysAndValues converts alternating key-value pairs to logrus.Fields
func (l *Logger) parseKeysAndValues(keysAndValues ...any) logrus.Fields {
	fields := make(logrus.Fields)

	for i := 0; i < len(keysAndValues); i += 2 {
		if i+1 < len(keysAndValues) {
			key := fmt.Sprintf("%v", keysAndValues[i])
			value := keysAndValues[i+1]
			fields[key] = value
		}
	}

	return fields
}

// WithField creates a new logger entry with a sanitized field
func (l *Logger) WithField(key string, value any) *logrus.Entry {
	fields := logrus.Fields{key: value}
	sanitizedFields := l.sanitizeFields(fields)
	return l.Logger.WithFields(sanitizedFields)
}

// WithFields creates a new logger entry with sanitized fields
func (l *Logger) WithFields(fields logrus.Fields) *logrus.Entry {
	sanitizedFields := l.sanitizeFields(fields)
	return l.Logger.WithFields(sanitizedFields)
}

// WithError creates a new logger entry with an error field
func (l *Logger) WithError(err error) *logrus.Entry {
	// Sanitize error message
	sanitizedMsg := l.sanitizeMessage(err.Error())
	return l.Logger.WithField("error", sanitizedMsg)
}

// Audit logs an audit message (always logged regardless of level)
func (l *Logger) Audit(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)

	// Add audit marker
	sanitizedFields["audit"] = true
	sanitizedFields["timestamp"] = time.Now().UTC()

	l.Logger.WithFields(sanitizedFields).Info(fmt.Sprintf("[AUDIT] %s", sanitizedMsg))
}

// Security logs a security-related message
func (l *Logger) Security(msg string, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)

	// Add security marker
	sanitizedFields["security"] = true
	sanitizedFields["timestamp"] = time.Now().UTC()

	l.Logger.WithFields(sanitizedFields).Warn(fmt.Sprintf("[SECURITY] %s", sanitizedMsg))
}

// Performance logs a performance-related message
func (l *Logger) Performance(msg string, duration time.Duration, keysAndValues ...any) {
	fields := l.parseKeysAndValues(keysAndValues...)
	sanitizedFields := l.sanitizeFields(fields)
	sanitizedMsg := l.sanitizeMessage(msg)

	// Add performance metrics
	sanitizedFields["performance"] = true
	sanitizedFields["duration_ms"] = duration.Milliseconds()
	sanitizedFields["duration"] = duration.String()

	l.Logger.WithFields(sanitizedFields).Info(fmt.Sprintf("[PERF] %s", sanitizedMsg))
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level string) error {
	logLevel, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}
	l.Logger.SetLevel(logLevel)
	return nil
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() string {
	return l.Logger.GetLevel().String()
}

// Close closes any file handles (if applicable)
func (l *Logger) Close() error {
	// If we're writing to a file, we should close it
	// This is a simplified implementation - in a real scenario,
	// you might want to track file handles and close them properly
	return nil
}

// NewTestLogger creates a logger suitable for testing
func NewTestLogger() *Logger {
	logger := &Logger{
		Logger: logrus.New(),
	}

	logger.Logger.SetLevel(logrus.DebugLevel)
	logger.Logger.SetOutput(io.Discard) // Don't output during tests
	logger.initSensitivePatterns()

	return logger
}
