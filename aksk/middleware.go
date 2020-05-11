package aksk

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

var (
	// ErrSignatueEmpty 请求签名为空
	ErrSignatueEmpty = newError("请求签名为空")
	// ErrSignatureInvalid 请求签名无效
	ErrSignatureInvalid = newError("请求签名无效")
	// ErrBodyInvalid 请求内容无效
	ErrBodyInvalid = newError("请求内容无效")
	// ErrBodyHashInvalid 请求内容哈希值无效
	ErrBodyHashInvalid = newError("请求内容哈希值无效")
)

// ErrorHandler 错误处理函数
type ErrorHandler func(c *gin.Context, err error)

func handleError(c *gin.Context, err error) {
	e, ok := err.(*Error)
	if !ok {
		e = &Error{Message: err.Error()}
	}
	logger.Printf("valid request error: %s", err)
	c.AbortWithStatusJSON(http.StatusUnauthorized, e)
}

// Validate 返回一个验证请求的gin中间件, keyFn指定了查询SecretKey的函数, 如果skipBody为true, 跳过检查body的hash值是否一致, fn不为空时,使用自定义的错误处理函数
func Validate(keyFn KeyFunc, skipBody bool, fn ErrorHandler) gin.HandlerFunc {
	logger.Printf("启用aksk认证")
	if keyFn == nil {
		panic("store is nil")
	}
	if fn == nil {
		fn = handleError
	}
	return func(c *gin.Context) {
		if err := validRequest(c, keyFn, skipBody); err != nil {
			fn(c, err)
			if !c.IsAborted() {
				c.Abort()
			}
		}
	}
}

func validRequest(c *gin.Context, keyFn KeyFunc, skipBody bool) error {
	ak := c.GetHeader(HeaderAccessKey)
	if ak == "" {
		return ErrAccessKeyEmpty
	}
	sk := keyFn(ak)
	if sk == "" {
		return ErrSecretKeyEmpty
	}
	ts := c.GetHeader(HeaderTimestramp)
	if err := parseTimestramp(ts); err != nil {
		return err
	}
	signature := c.GetHeader(HeaderSignature)
	if signature == "" {
		return ErrSignatueEmpty
	}
	bodyhash := c.GetHeader(HeaderBodyHash)
	randomstr := c.GetHeader(HeaderRandomStr)
	if err := validSignature(sk, signature, ak, ts, randomstr, bodyhash); err != nil {
		return err
	}
	if skipBody {
		return nil
	}
	b, err := readBody(c)
	if err != nil {
		return err
	}
	if err := validBytes(b, bodyhash); err != nil {
		return ErrBodyInvalid
	}
	return nil
}

// readBody 读取body
func readBody(c *gin.Context) ([]byte, error) {
	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("读取Body发生错误: %s", err)
	}
	c.Request.Body = ioutil.NopCloser(bytes.NewReader(b))

	return bytes.TrimSpace(b), nil
}
