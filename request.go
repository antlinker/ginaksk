package ginaksk

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

var (
	// ErrAccessKeyEmpty ak为空
	ErrAccessKeyEmpty = newError("accesskey为空")
	// ErrSecretKeyEmpty sk为空
	ErrSecretKeyEmpty = newError("secretkey为空")
)

// RequestFunc aksk的请求构造函数
type RequestFunc func(ctx context.Context, method, url string, body []byte) (*http.Request, error)

// NewRequestFunc 返回一个RequestFunc
func NewRequestFunc(ak, sk string) (RequestFunc, error) {
	if ak == "" {
		return nil, ErrAccessKeyEmpty
	}
	if sk == "" {
		return nil, ErrSecretKeyEmpty
	}
	fn := func(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("创建HTTP请求发生错误:%w", err)
		}

		// 随即字符串
		b := make([]byte, 6)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return nil, fmt.Errorf("读取随即字符串发生错误:%w", err)
		}
		randomstr := encoder.EncodeToString(b)

		ss := make([]string, 0, 5)
		ss = append(ss, ak, randomstr)
		// ak头部
		req.Header.Set(HeaderAccessKey, ak)
		// randomstr头部
		req.Header.Set(HeaderRandomStr, randomstr)

		ts := strconv.FormatInt(time.Now().Unix(), 10)
		ss = append(ss, ts)
		// 时间戳头部
		req.Header.Set(HeaderTimestramp, ts)

		if len(body) > 0 {
			bodyhash := encoder.EncodeToString(hashSum(body))
			ss = append(ss, bodyhash)
			// body的hash头部
			req.Header.Set(HeaderBodyHash, bodyhash)
		}

		// 签名头部
		b = hmacSum([]byte(sk), ss...)
		req.Header.Set(HeaderSignature, encoder.EncodeToString(b))
		return req, nil
	}
	return fn, nil
}
