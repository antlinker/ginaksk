package aksk

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

// ValidHeader 通过AccessKey签名验证请求
func ValidHeader() gin.HandlerFunc {
	return func(c *gin.Context) {
		if store == nil {
			logger.Printf("未初始化accesskey")
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		ak := c.GetHeader(HeaderAccessKey)
		if ak == "" {
			logger.Printf("access_key为空")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		sk := store.Get(ak)
		if sk == "" {
			logger.Printf("未找到secret_key")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		ts := c.GetHeader(HeaderTimestramp)
		if err := parseTimestramp(ts); err != nil {
			logger.Printf("时间戳%v校验失败: %s", ts, err)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		signature := c.GetHeader(HeaderSignature)
		if len(signature) != 64 {
			logger.Printf("头部签名为空")
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		bodyhash := c.GetHeader(HeaderBodyHash)
		randomstr := c.GetHeader(HeaderRandomStr)
		if !validHeader(ak, sk, ts, randomstr, bodyhash, signature) {
			logger.Printf("请求路径:%s,请求签名失败", c.Request.URL)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

// readBody 读取body
func readBody(c *gin.Context) ([]byte, error) {
	if c.Request == nil {
		return nil, nil
	}
	b, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		return nil, fmt.Errorf("读取Body发生错误: %s", err)
	}
	c.Request.Body = ioutil.NopCloser(bytes.NewReader(b))

	return bytes.TrimSpace(b), nil
}

// ValidBody 中间件验证请求Body
func ValidBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := readBody(c)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		bodyhash := c.GetHeader(HeaderBodyHash)
		if !validBody(body, bodyhash) {
			logger.Printf("请求路径: %s, 请求主体验证失败", c.Request.URL)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
