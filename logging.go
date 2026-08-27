package main

import (
	"io"
	"log"
)

// logLevel controls how much detail is written to the log.
type logLevel string

const (
	logLevelNone  logLevel = "none"
	logLevelInfo  logLevel = "info"
	logLevelDebug logLevel = "debug"
)

// level is the active log level, set from the command line.
var level = logLevelInfo

// applyLogLevel configures the standard logger for the active level.
func applyLogLevel() {
	if level == logLevelNone {
		log.SetFlags(0)
		log.SetOutput(io.Discard)
		return
	}
	log.SetFlags(log.LstdFlags)
}

// debugEnabled reports whether debug level output is wanted.
func debugEnabled() bool {
	return level == logLevelDebug
}

// logInfo writes a message at info level.
func logInfo(format string, args ...any) {
	if level == logLevelNone {
		return
	}
	log.Printf(format, args...)
}

// logDebug writes a message at debug level only.
func logDebug(format string, args ...any) {
	if !debugEnabled() {
		return
	}
	log.Printf(format, args...)
}
