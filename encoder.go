package ginaksk

import (
	"encoding/hex"
)

// Encoder 编码方法接口
type Encoder interface {
	// EncodeToString 编码成字符串
	EncodeToString(b []byte) string
	// DecodeString 将字符串解码成字节切片
	DecodeString(s string) ([]byte, error)
}

// hexEncoder 16进制编码格式
type hexEncoder struct{}

var encoder Encoder = &hexEncoder{}

// SetEncoder 设置编码实现,使用Validate后再次调用会panic
func SetEncoder(enc Encoder) {
	if initialized {
		panic("必须在使用Validate前调用")
	}
	if enc != nil {
		encoder = enc
	}
}

// EncodeToString 编码为16进制字符串
func (h *hexEncoder) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeString 解码给定的16进制字符串得到MAC
func (h *hexEncoder) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
