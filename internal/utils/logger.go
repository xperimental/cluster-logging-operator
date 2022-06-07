package utils

import (
	stdlog "log"
	"os"
	"strconv"

	"github.com/ViaQ/logerr/v2/log"
	"github.com/go-logr/logr"
)

const (
	envLogLevel = "LOG_LEVEL"
)

// InitLogger creates a logger and optionally initializes the verbosity with the value in LOG_LEVEL.
func InitLogger(component string) logr.Logger {
	logOptions := []log.Option{}
	if rawVerbosity, ok := os.LookupEnv(envLogLevel); ok {
		verbosity, err := strconv.Atoi(rawVerbosity)
		if err != nil {
			stdlog.Panicf("%q must be an integer", envLogLevel)
		}

		logOptions = append(logOptions, log.WithVerbosity(verbosity))
	}

	return log.NewLogger(component, logOptions...)
}
