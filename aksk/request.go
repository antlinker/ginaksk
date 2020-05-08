package aksk

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

const randomLen = 8

// NewRequestWithAKSK 新建HTTP请求, 使用aksk认证
func NewRequestWithAKSK(ctx context.Context, method, url, ak string, body []byte) (*http.Request, error) {
	sk := store.Get(ak)
	if sk == "" {
		return nil, fmt.Errorf("未找到access_key:%s的secret_key", ak)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("创建HTTP请求发生错误:%s", err)
	}

	// 随即字符串
	b := make([]byte, randomLen)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("读取随即字符串发生错误:%w", err)
	}
	randomstr := string(b)

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
		bodyhash := encoder.Encode(encoder.Mac(body))
		ss = append(ss, bodyhash)
		// body的hash头部
		req.Header.Set(HeaderBodyHash, bodyhash)
	}
	mac := encoder.Hmac([]byte(sk), ss...)
	s := encoder.Encode(mac)
	// 签名头部
	req.Header.Set(HeaderSignature, s)
	return req, nil
}
