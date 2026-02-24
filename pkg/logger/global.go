package logger

import "sync"

var (
	globalLogger Logger
	once         sync.Once
)

func Init(cfg Config) {
	once.Do(func() {
		globalLogger = New(cfg)
	})
}

func Get() Logger {
	if globalLogger == nil {
		globalLogger = NewConsoleOnly(InfoLevel)
	}
	return globalLogger
}

func D(msg string, fields ...Fields) {
	Get().Debug(msg, fields...)
}

func I(msg string, fields ...Fields) {
	Get().Info(msg, fields...)
}

// W logs a warning message
func W(msg string, fields ...Fields) {
	Get().Warn(msg, fields...)
}

func E(err error, fields ...Fields) {
	Get().Error(err, fields...)
}

func F(err error, fields ...Fields) {
	Get().Fatal(err, fields...)
}
