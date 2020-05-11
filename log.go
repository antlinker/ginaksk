package ginaksk

// Logger 日志
type Logger interface {
	Printf(format string, args ...interface{})
}

var logger Logger = &discardLogger{}

// SetLogger 设置自定义的日志输出,使用Validate后再次调用会panic
func SetLogger(l Logger) {
	if initialized {
		panic("必须在使用Validate前调用")
	}
	if l != nil {
		logger = l
	}
}

// discardLogger 空日志
type discardLogger struct{}

// Printf 忽略打印日志
func (l *discardLogger) Printf(format string, args ...interface{}) {}
