package aksk

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// SetValidator 设置自定义个验证方法
func SetValidator(validator Validator) {
	if validator == nil {
		return
	}
	lock.Lock()
	defaultValidator = validator
	lock.Unlock()
}

// ValidatorWithHexSha256 使用hex编码和sha256算法的校验方法
type ValidatorWithHexSha256 struct{}

// EncodeToString 编码为16进制字符串
func (h *ValidatorWithHexSha256) EncodeToString(b []byte) string {
	return hex.EncodeToString(b)
}

// DecodeString 解码给定的16进制字符串得到MAC
func (h *ValidatorWithHexSha256) DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// NewHash 返回一个sha256的hash.Hash
func (h *ValidatorWithHexSha256) NewHash() hash.Hash {
	return sha256.New()
}
