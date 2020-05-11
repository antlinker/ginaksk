package aksk

// Logger 日志
type Logger interface {
	Printf(format string, args ...interface{})
}

// SetLogger 设置日志
func SetLogger(l Logger) {
	if l != nil {
		logger = l
	}
}

// discardLogger 空日志
type discardLogger struct{}

// Printf 忽略打印日志
func (l *discardLogger) Printf(format string, args ...interface{}) {}
