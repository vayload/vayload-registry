
package logger

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Config holds logger configuration
type Config struct {
	// Level minimum log level
	Level Level
	// FilePath for file output (empty = stdout only)
	FilePath string
	// MaxSize is max size in MB before rotation
	MaxSize int
	// MaxBackups is max number of old log files
	MaxBackups int
	// MaxAge is max days to retain old logs
	MaxAge int
	// Compress old log files
	Compress bool
	// Console enables pretty console output
	Console bool
	// TimeFormat for log timestamps
	TimeFormat string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() Config {
	return Config{
		Level:      InfoLevel,
		FilePath:   "",
		MaxSize:    100,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
		Console:    true,
		TimeFormat: time.RFC3339,
	}
}

// zerologger implements Logger using zerolog
type zerologger struct {
	log zerolog.Logger
}

// New creates a new Logger with the given config
func New(cfg Config) Logger {
	zerolog.TimeFieldFormat = cfg.TimeFormat
	zerolog.SetGlobalLevel(toZerologLevel(cfg.Level))

	var writers []io.Writer

	// File output with rotation
	if cfg.FilePath != "" {
		fileWriter := &lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
		writers = append(writers, fileWriter)
	}

	// Console output
	if cfg.Console {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: cfg.TimeFormat,
		}
		writers = append(writers, consoleWriter)
	}

	// Fallback to stdout if no writers
	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	multi := zerolog.MultiLevelWriter(writers...)
	log := zerolog.New(multi).With().Timestamp().Stack().Logger()

	return &zerologger{log: log}
}

// NewWithFile creates a logger that writes to both file and console
func NewWithFile(filePath string, level Level) Logger {
	cfg := DefaultConfig()
	cfg.FilePath = filePath
	cfg.Level = level
	return New(cfg)
}

// NewConsoleOnly creates a console-only logger
func NewConsoleOnly(level Level) Logger {
	cfg := DefaultConfig()
	cfg.Level = level
	cfg.Console = true
	return New(cfg)
}

func (z *zerologger) Debug(msg string, fields ...Fields) {
	evt := z.log.Debug()
	applyFields(evt, fields...)
	evt.Msg(msg)
}

func (z *zerologger) Info(msg string, fields ...Fields) {
	evt := z.log.Info()
	applyFields(evt, fields...)
	evt.Msg(msg)
}

func (z *zerologger) Warn(msg string, fields ...Fields) {
	evt := z.log.Warn()
	applyFields(evt, fields...)
	evt.Msg(msg)
}

func (z *zerologger) Error(err error, fields ...Fields) {
	evt := z.log.Error().Err(err)
	applyFields(evt, fields...)
	evt.Send()
}

func (z *zerologger) Fatal(err error, fields ...Fields) {
	evt := z.log.Fatal().Err(err)
	applyFields(evt, fields...)
	evt.Send()
}

func (z *zerologger) With(fields Fields) Logger {
	ctx := z.log.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &zerologger{log: ctx.Logger()}
}

func (z *zerologger) WithContext(ctx context.Context) Logger {
	return &zerologger{log: z.log.With().Ctx(ctx).Logger()}
}

// applyFields applies optional fields to a zerolog event
func applyFields(evt *zerolog.Event, fields ...Fields) {
	for _, f := range fields {
		for k, v := range f {
			evt.Interface(k, v)
		}
	}
}

func toZerologLevel(l Level) zerolog.Level {
	switch l {
	case DebugLevel:
		return zerolog.DebugLevel
	case InfoLevel:
		return zerolog.InfoLevel
	case WarnLevel:
		return zerolog.WarnLevel
	case ErrorLevel:
		return zerolog.ErrorLevel
	case FatalLevel:
		return zerolog.FatalLevel
	default:
		return zerolog.InfoLevel
	}
}
