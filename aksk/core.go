/*
Package aksk 基于ak, sk实现的服务认证中间件
*/
package aksk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var lock sync.Mutex

// Encoder 编码方法接口
type Encoder interface {
	// EncodeToString 编码成字符串
	EncodeToString(b []byte) string
	// DecodeString 将字符串解码成字节切片
	DecodeString(s string) ([]byte, error)
}

// HashFunc 返回一个hash.Hash接口
type HashFunc func() hash.Hash

var hashFunc HashFunc = sha256.New

// KeyFunc 查询secretkey
type KeyFunc func(accessKey string) (secretKey string)

const (
	// HeaderAccessKey 访问key
	HeaderAccessKey = `x-auth-accesskey`
	// HeaderTimestramp 访问时间戳, 前1分钟或者后5分钟之内有效
	HeaderTimestramp = `x-auth-timestramp`
	// HeaderSignature 签名hmac的签名
	HeaderSignature = `x-auth-signature`
	// HeaderBodyHash http的Body hash计算的mac
	HeaderBodyHash = `x-auth-body-hash`
	// HeaderRandomStr 随即字符串
	HeaderRandomStr = `x-auth-random-str`
)

const (
	maxDuration = 5 * time.Minute
	minDuration = -1 * time.Minute
)

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
	// ErrTimestrampEmpty 缺少时间戳
	ErrTimestrampEmpty = newError("未提供timestramp")
	// ErrTimestrampExpired 时间戳过期
	ErrTimestrampExpired = newError("timestramp过期")
	// ErrTimestrampInvalid 时间戳无效
	ErrTimestrampInvalid = newError("timestramp无效")
)

// parseTimestramp 解析时间戳
func parseTimestramp(s string) error {
	if s == "" {
		return ErrTimestrampEmpty
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	t := time.Unix(n, 0)
	d := time.Now().Sub(t)
	if d > maxDuration {
		return ErrTimestrampExpired
	} else if d < minDuration {
		return ErrTimestrampInvalid
	}
	return nil
}

func hashSum(b []byte) []byte {
	h := hashFunc()
	h.Write(b)
	return h.Sum(nil)

}

func hmacSum(key []byte, elems ...string) []byte {
	h := hmac.New(hashFunc, key)
	sort.Strings(elems)
	s := strings.Join(elems, "")
	h.Write([]byte(s))
	return h.Sum(nil)
}

// validBytes 通过计算请求b的sha256值验证请求内容
// 如果b长度为0, 返回真; 否则检查mac和编码器计算的Mac是否一致
func validBytes(b []byte, s string) error {
	if len(b) == 0 {
		return nil
	}
	if s == "" {
		return ErrBodyHashInvalid
	}
	mac, err := encoder.DecodeString(s)
	if err != nil {
		return ErrBodyHashInvalid
	}
	if ok := bytes.Equal(mac, hashSum(b)); ok {
		return nil
	}
	return ErrBodyHashInvalid
}

// validSignature 校验头部签名
func validSignature(sk, sign string, elems ...string) error {
	// 解码签名,得道原始的字节切片
	mac, err := encoder.DecodeString(sign)
	if err != nil {
		return ErrSignatureInvalid
	}
	if ok := hmac.Equal(mac, hmacSum([]byte(sk), elems...)); ok {
		return nil
	}
	return ErrSignatureInvalid
}
