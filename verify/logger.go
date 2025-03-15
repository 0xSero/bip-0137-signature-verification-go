package verify

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel determines the verbosity of logging
type LogLevel int

const (
	LogLevelNone LogLevel = iota
	LogLevelError
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

var (
	// Current log level, default to info
	currentLogLevel = LogLevelInfo

	// Logger instance
	Logger = log.New(os.Stdout, "", log.LstdFlags)
)

// SetLogLevel sets the current logging level
func SetLogLevel(level LogLevel) {
	currentLogLevel = level
}

// GetLogLevel returns the current logging level
func GetLogLevel() LogLevel {
	return currentLogLevel
}

// LogError logs an error message
func LogError(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelError {
		Logger.Printf("[ERROR] "+format, args...)
	}
}

// LogInfo logs an info message
func LogInfo(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelInfo {
		Logger.Printf("[INFO] "+format, args...)
	}
}

// LogDebug logs a debug message
func LogDebug(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelDebug {
		Logger.Printf("[DEBUG] "+format, args...)
	}
}

// LogTrace logs a trace message (most detailed)
func LogTrace(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelTrace {
		Logger.Printf("[TRACE] "+format, args...)
	}
}

// DumpHex returns a hexadecimal representation of the data
func DumpHex(data []byte) string {
	if len(data) == 0 {
		return "<empty>"
	}

	hexStr := make([]string, len(data))
	for i, b := range data {
		hexStr[i] = fmt.Sprintf("%02x", b)
	}

	return strings.Join(hexStr, " ")
}

// MaskSensitive masks part of a sensitive string (like a private key)
func MaskSensitive(data string) string {
	if len(data) <= 8 {
		return "****"
	}

	// Show first 4 and last 4 characters
	return data[:4] + "..." + data[len(data)-4:]
}
