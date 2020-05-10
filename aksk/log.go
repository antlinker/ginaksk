package aksk

// Logger 日志
type Logger interface {
	Printf(format string, args ...interface{})
}

var logger Logger = &NullLogger{}

// SetLogger 设置日志
func SetLogger(l Logger) {
	if l == nil {
		return
	}
	lock.Lock()
	logger = l
	lock.Unlock()
}

// NullLogger 空日志
type NullLogger struct{}

// Printf 忽略打印日志
func (l *NullLogger) Printf(format string, args ...interface{}) {}
