# aksk 实现gin的中间件, 用于认证客户端请求和校验请求内容

### 使用方法

```go

// GetKeyFunc 返回aksk.KeyFunc
func GetKeyFunc() aksk.KeyFunc {
	return func(ak string) string {
		return keyStore[ak]
	}
}

type store struct{}

// Get 查找客户端密钥
func (s store) Get(accessKey string) string {
	return s[accessKey]
}

type logger struct{}

func (l *logger) Printf(format string, args ...interface{}) {
	log.SugaredLogger().Infof(format, args...)
}

func handlError(c *gin.Context, err error) {
	if err == nil {
		return
	}
	var aErr *aksk.Error
	if errors.As(err, &aErr) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, response.Error(response.CodeUnauthorized, err.Error()))
		return
	}
	log.SugaredLogger().Errorf("aksk error: %w", err)
	c.AbortWithStatusJSON(http.StatusInternalServerError, response.ErrorCode(response.CodeUndifined))
}

// UseAKSK 通过aksk认证请求
func UseAKSK(g *gin.RouterGroup, a []config.Authentication) {
	keyStore = newStore(a)
	aksk.SetLogger(&logger{})
	g.Use(aksk.Validate(GetKeyFunc(), false, handlError))
}
```