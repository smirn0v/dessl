package logger

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

type customWriter struct {
	mu         sync.Mutex
	writerFunc func(string)
}

var logger *logrus.Logger
var loggerEntry *logrus.Entry

func (w *customWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writerFunc(string(p))
	return len(p), nil
}

func ContextLogger(ctx context.Context) *logrus.Entry {
	if ctx == nil {
		return loggerEntry
	}
	ctxLogger := ctx.Value("logger")
	if ctxLogger == nil {
		return loggerEntry
	}
	return ctxLogger.(*logrus.Entry)
}

func CreateContextWithLogger(ctx context.Context, fields logrus.Fields) context.Context {
	return context.WithValue(ctx, "logger", loggerEntry.WithFields(fields))
}

func SetWriterFunc(f func(string)) {
	if f != nil {
		logger.SetOutput(&customWriter{
			writerFunc: f,
		})
	} else {
		logger.SetOutput(os.Stdout)
	}
}

func init() {

	logger = logrus.New()

	logger.SetOutput(os.Stdout)
	logger.SetReportCaller(true)

	level := getLogLevel()
	logger.SetLevel(level)

	execPath, err := os.Executable()
	var appName string
	if err != nil {
		appName = "UnknownApp"
	} else {
		appName = filepath.Base(execPath)
	}

	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			_, filename := path.Split(f.File)
			return "", filename + ":" + strconv.Itoa(f.Line)
		},
	})
	loggerEntry = logrus.NewEntry(logger).WithField("appName", appName)
}

func getLogLevel() logrus.Level {
	envLevel := os.Getenv("LOG_LEVEL")
	return parseLogLevel(envLevel)
}

func parseLogLevel(level string) logrus.Level {
	switch strings.ToLower(level) {
	case "debug":
		return logrus.DebugLevel
	case "info":
		return logrus.InfoLevel
	case "warn":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	default:
		return logrus.InfoLevel
	}
}
