/*
Package ginaksk 基于ak, sk实现的服务认证中间件
*/
package ginaksk

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"sort"
	"strconv"
	"strings"
	"time"
)

// HashFunc 返回一个hash.Hash接口
type HashFunc func() hash.Hash

var hashFunc HashFunc = sha256.New

// SetHash 使用自定义Hash算法,使用Validate后再次调用会panic
func SetHash(h HashFunc) {
	if initialized {
		panic("必须在使用Validate前调用")
	}
	if h != nil {
		hashFunc = h
	}
}

// KeyFunc 查询accesskey,返回secretKey的函数
type KeyFunc func(accessKey string) (secretKey string)

const (
	// headerAccessKey 访问key
	headerAccessKey = `x-auth-accesskey`
	// headerTimestamp 访问时间戳, 前1分钟或者后5分钟之内有效
	headerTimestamp = `x-auth-timestamp`
	// headerSignature 签名hmac的签名
	headerSignature = `x-auth-signature`
	// headerBodyHash http的Body hash计算的mac
	headerBodyHash = `x-auth-body-hash`
	// headerRandomStr 随机字符串
	headerRandomStr = `x-auth-random-str`
)

const (
	maxDuration = 5 * time.Minute
	minDuration = -1 * time.Minute
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
