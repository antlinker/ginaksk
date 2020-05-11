package ginaksk_test

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/antlinker/ginaksk"
	"github.com/gin-gonic/gin"
)

type store map[string]string

var keyStore = store{"ak": "sk"}

// GetKeyFunc 返回aksk.KeyFunc
func GetKeyFunc() ginaksk.KeyFunc {
	return func(ak string) string {
		return keyStore[ak]
	}
}

type logger struct{}

var testLogger = &logger{}

func (l *logger) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func handlError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var aErr *ginaksk.Error
	if errors.As(err, &aErr) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, map[string]interface{}{
			"err_code": 1,
			"err_msg":  err.Error(),
		})
		return
	}
	testLogger.Printf("aksk error: %s", err)
	c.AbortWithStatusJSON(http.StatusInternalServerError, map[string]interface{}{
		"err_code": -1,
		"err_msg":  err.Error(),
	})
}

type base64Encoder struct {
	enc *base64.Encoding
}

func (b64 *base64Encoder) EncodeToString(b []byte) string {
	return b64.enc.EncodeToString(b)
}

func (b64 *base64Encoder) DecodeString(s string) (b []byte, err error) {
	return b64.enc.DecodeString(s)
}

func Example_aksk() {
	ginaksk.SetLogger(testLogger)                                  // 可选
	ginaksk.SetHash(md5.New)                                       // 可选
	ginaksk.SetEncoder(&base64Encoder{enc: base64.RawStdEncoding}) // 可选
	e := gin.New()
	// 验证请求签名, 并验证请求内容, 自定义错误处理
	e.Use(ginaksk.Validate(GetKeyFunc(), false, handlError))
	ginaksk.SetHash(sha1.New)
}
