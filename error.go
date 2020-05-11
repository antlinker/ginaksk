package ginaksk

import "fmt"

// Error aksk的错误定义
type Error struct {
	// 错误消息
	Message string `json:"message"`
}

func newError(msg string) *Error {
	return &Error{Message: msg}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

var (
	// ErrTimestrampExpired 时间戳过期
	ErrTimestrampExpired = newError("请求时间戳过期")
	// ErrTimestrampInvalid 时间戳无效
	ErrTimestrampInvalid = newError("请求时间戳无效")

	// ErrTimestrampEmpty 缺少时间戳
	ErrTimestrampEmpty = newError("请求缺少时间戳")
	// ErrSignatueEmpty 请求签名为空
	ErrSignatueEmpty = newError("请求缺少签名")
	// ErrSignatureInvalid 请求签名无效
	ErrSignatureInvalid = newError("请求签名无效")
	// ErrBodyInvalid 请求内容无效
	ErrBodyInvalid = newError("请求内容无效")
	// ErrBodyHashInvalid 请求内容哈希值无效
	ErrBodyHashInvalid = newError("请求内容哈希值无效")
)
