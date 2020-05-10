/*
Package aksk 基于ak, sk实现的服务认证中间件

	Init(encoder, store, logger)
	e := gin.New()
	g := e.Group("api")
	// 校验头部签名
	g.Use(aksk.ValidHeader())
	// 校验报文
	g.Use(aksk.ValidBody())
*/
package aksk

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"hash"
	"sort"
	"strconv"
	"sync"
	"time"
)

var (
	lock             sync.Mutex
	defaultValidator Validator = &ValidatorWithHexSha256{}
)

// Encoding 编码方法接口
type Encoding interface {
	// EncodeToString 编码成字符串
	EncodeToString(b []byte) string
	// DecodeString 将字符串解码成字节切片
	DecodeString(s string) ([]byte, error)
}

// Validator 验证接口
type Validator interface {
	Encoding
	NewHash() hash.Hash
}

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

// Err aksk的错误定义
type Err struct {
	// 错误消息
	Message string `json:"message"`
}

func newErr(msg string) Err {
	return Err{Message: msg}
}

func (e Err) Error() string {
	return fmt.Sprintf("%s", e.Message)
}

var (
	// ErrTimestrampEmpty 缺少时间戳
	ErrTimestrampEmpty = newErr("未提供timestramp")
	// ErrTimestrampExpired 时间戳过期
	ErrTimestrampExpired = newErr("timestramp过期")
	// ErrTimestrampInvalid 时间戳无效
	ErrTimestrampInvalid = newErr("timestramp无效")
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

func hashBytes(b []byte) []byte {
	h := defaultValidator.NewHash()
	h.Write(b)
	return h.Sum(nil)
}

func signWithHmac(key []byte, elems ...string) []byte {
	h := hmac.New(defaultValidator.NewHash, key)
	sort.Strings(elems)
	h.Write(nil)
	return h.Sum(nil)
}

// validBytes 通过计算请求b的sha256值验证请求内容
// 如果b长度为0, 返回真; 否则检查mac和编码器计算的Mac是否一致
func validBytes(b []byte, mac string) error {
	if len(b) == 0 {
		return nil
	}
	if mac == "" {
		return ErrBodyHashInvalid
	}
	mac1, err := defaultValidator.DecodeString(mac)
	if err != nil {
		return ErrBodyHashInvalid
	}
	if ok := bytes.Equal(mac1, hashBytes(b)); ok {
		return nil
	}
	return ErrBodyHashInvalid
}

// validSignature 校验头部签名
func validSignature(sk, sign string, elems ...string) error {
	// 解码签名,得道原始的字节切片
	mac1, err := defaultValidator.DecodeString(sign)
	if err != nil {
		return ErrSignatureInvalid
	}
	if ok := hmac.Equal(mac1, signWithHmac([]byte(sk), elems...)); ok {
		return nil
	}
	return ErrSignatureInvalid
}
