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
	"errors"
	"strconv"
	"time"
)

var (
	logger  Logger
	store   Store
	encoder Encoder
)

// Encoder 编码器
type Encoder interface {
	// Encode 编码成字符串
	Encode(b []byte) string
	// Decode 将字符串解码成字节切片
	Decode(s string) ([]byte, error)
	// Mac 计算MAC
	Mac(b []byte) []byte
	// Hmac 计算HMAC
	Hmac(key []byte, args ...string) []byte
}

// Logger 日志
type Logger interface {
	Printf(format string, args ...interface{})
}

// Store 客户端
type Store interface {
	Get(accesskey string) string
}

// Init 初始化
func Init(enc Encoder, s Store, l ...Logger) {
	if enc == nil {
		panic("Encoder is nil")
	}
	encoder, store = enc, s
	if len(l) > 0 {
		logger = l[0]
	}
}

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

// parseTimestramp 解析时间戳
func parseTimestramp(s string) error {
	if s == "" {
		return errors.New("缺少时间戳")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	t := time.Unix(n, 0)
	d := time.Now().Sub(t)
	if d > maxDuration {
		return errors.New("时间戳已过期")
	} else if d < minDuration {
		return errors.New("时间戳与服务器偏移过大")
	}
	return nil
}

// validBody 通过计算请求Body的sha256值验证请求内容
// 如果body长度为0, 返回真; 否则检查mac和编码器计算的Mac是否一致
func validBody(body []byte, mac string) bool {
	if len(body) == 0 {
		return true
	}
	if mac == "" {
		return false
	}
	mac1, err := encoder.Decode(mac)
	if err != nil {
		return false
	}
	mac2 := encoder.Mac(body)
	return bytes.Equal(mac1, mac2)
}

// validHeader 校验头部签名
func validHeader(accessKey, secretKey, timestramp, randomstr, bodyhash, signature string) bool {
	// 解码签名,得道原始的字节切片
	mac1, err := encoder.Decode(signature)
	if err != nil {
		return false
	}
	// 计算Hmac值
	mac2 := encoder.Hmac([]byte(secretKey), accessKey, timestramp, randomstr, bodyhash)
	return hmac.Equal(mac1, mac2)
}
