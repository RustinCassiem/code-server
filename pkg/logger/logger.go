package logger

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
)

type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
	Fatal(msg string, args ...interface{})
	GinMiddleware() gin.HandlerFunc
}

type structuredLogger struct {
	logger *slog.Logger
}

func New(level string) Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	return &structuredLogger{
		logger: logger,
	}
}

func (l *structuredLogger) Info(msg string, args ...interface{}) {
	l.logger.Info(msg, args...)
}

func (l *structuredLogger) Error(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
}

func (l *structuredLogger) Warn(msg string, args ...interface{}) {
	l.logger.Warn(msg, args...)
}

func (l *structuredLogger) Debug(msg string, args ...interface{}) {
	l.logger.Debug(msg, args...)
}

func (l *structuredLogger) Fatal(msg string, args ...interface{}) {
	l.logger.Error(msg, args...)
	os.Exit(1)
}

func (l *structuredLogger) GinMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// Use structured logging for Gin requests
		l.logger.Info("HTTP Request",
			slog.String("method", param.Method),
			slog.String("path", param.Path),
			slog.Int("status", param.StatusCode),
			slog.Duration("latency", param.Latency),
			slog.String("client_ip", param.ClientIP),
			slog.String("user_agent", param.Request.UserAgent()),
			slog.Time("timestamp", param.TimeStamp),
		)
		return ""
	})
}
