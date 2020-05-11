# aksk 实现gin的中间件, 用于认证客户端请求和校验请求内容

### 使用方法

```go

var keyStore = make(map[string]string)

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


type base64Encoder struct {
	enc *base64.Encoding
}

func (b64 *base64Encoder) EncodeToString(b []byte) string {
	return b64.enc.EncodeToString(b)
}

func (b64 *base64Encoder) DecodeString(s string) (b []byte, err error) {
	return b64.enc.DecodeString(s)
}

// UseAKSK 通过aksk认证请求
func UseAKSK(g *gin.RouterGroup, a []config.Authentication) {
	keyStore = newStore(a)
	aksk.SetLogger(&logger{}) // 可选
	aksk.SetHash(md5.New) // 可选
	aksk.SetEncoder(&base64Encoder{enc: base64.RawStdEncoding})
	g.Use(aksk.Validate(GetKeyFunc(), false, handlError))
}
```