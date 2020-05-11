package aksk

import (
	"encoding/hex"
)

// SetEncoder 设置编码实现
func SetEncoder(enc Encoder) {
	if enc == nil {
		return
	}
	encoder = enc
}

// HexEncoder 16进制编码格式
type HexEncoder struct{}

// EncodeToString 编码为16进制字符串
func (h *HexEncoder) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeString 解码给定的16进制字符串得到MAC
func (h *HexEncoder) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
