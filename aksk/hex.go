package aksk

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// HexEncoder 16进制的编码器
type HexEncoder struct{}

// NewHexEncoder 新建16进制编码器
func NewHexEncoder() Encoder {
	return &HexEncoder{}
}

// Encode 编码为16进制字符串
func (enc *HexEncoder) Encode(b []byte) string {
	return hex.EncodeToString(b)
}

// Decode 解码给定的16进制字符串得到MAC
func (enc *HexEncoder) Decode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Mac 使用SHA256的算法计算MAC
func (enc *HexEncoder) Mac(b []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(b)
	return h.Sum(nil)
}

// Hmac 使用sha256作为hash算法计算MAC
func (enc *HexEncoder) Hmac(key []byte, args ...string) []byte {
	if len(key) == 0 || len(args) == 0 {
		return nil
	}
	sort.Strings(args)
	s := strings.Join(args, "")
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}
