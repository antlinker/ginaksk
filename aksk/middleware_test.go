package aksk

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func cleanup() {
	hashFunc = sha256.New
	encoder = &HexEncoder{}
	logger = &discardLogger{}
}

func generateRequest(ak, sk string) *http.Request {
	f, _ := NewRequestFunc(ak, sk)
	r, _ := f(context.TODO(), "POST", `http://localhost:8080/e`, []byte(`{"param":"a"}`))
	return r
}

func generateRequestWithHeader(ak, sk, key, value string) *http.Request {
	r := generateRequest(ak, sk)
	r.Header.Set(key, value)
	return r
}

func generateRequestWithEmptyBody(ak, sk string) *http.Request {
	f, _ := NewRequestFunc(ak, sk)
	r, _ := f(context.TODO(), "POST", `http://localhost:8080/e`, nil)
	return r
}

type printLogger struct{}

func (p *printLogger) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func Test_validRequest(t *testing.T) {
	SetLogger(&printLogger{})
	type args struct {
		c        *gin.Context
		keyFn    KeyFunc
		skipBody bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Ok",
			args: args{
				c: &gin.Context{
					Request: generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					if ak == "202cb962ac59075b964b07152d234b70" {
						return "250cf8b51c773f3f8dc8b4be867a9a02"
					}
					return ""
				},
			},
			wantErr: false,
		},
		{
			name: "NoSk",
			args: args{
				c: &gin.Context{
					Request: generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					return ""
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithoutAk",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderAccessKey, ""),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithoutTs",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderTimestramp, ""),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithoutSign",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderSignature, ""),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithInvalidSign",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderSignature, "37d8cf705e8b8327687e3c0025ac711bc309810196307cb8e1180cddcf3573b"),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithInvalidBodyHash",
			args: args{
				c: &gin.Context{
					Request: func() *http.Request {
						req := generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02")
						req.Body = ioutil.NopCloser(strings.NewReader(`{"param":"b"}`))
						return req
					}(),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithEmptyBody",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithEmptyBody("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: false,
		},
		{
			name: "SkipBody",
			args: args{
				c: &gin.Context{
					Request: generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
				skipBody: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validRequest(tt.args.c, tt.args.keyFn, tt.args.skipBody); (err != nil) != tt.wantErr {
				t.Errorf("validRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			// t.Logf("%+v", tt.args.c.Request)
		})
	}
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

func Test_validRequestWithMD5AndBase64(t *testing.T) {
	t.Cleanup(cleanup)
	SetHash(md5.New)
	SetEncoder(&base64Encoder{enc: base64.RawStdEncoding})
	SetLogger(&printLogger{})
	type args struct {
		c        *gin.Context
		keyFn    KeyFunc
		skipBody bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Ok",
			args: args{
				c: &gin.Context{
					Request: generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: false,
		},
		{
			name: "NoSk",
			args: args{
				c: &gin.Context{
					Request: generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					return ""
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithoutAk",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderAccessKey, ""),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithoutTs",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderTimestramp, ""),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithoutSign",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderSignature, ""),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithInvalidSign",
			args: args{
				c: &gin.Context{
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderSignature, "ClKfZE+/Ke788i/NZuIuQ"),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "HeaderWithInvalidBodyHash",
			args: args{
				c: &gin.Context{
					Request: func() *http.Request {
						req := generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02")
						req.Body = ioutil.NopCloser(strings.NewReader(`{"param":"b"}`))
						return req
					}(),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
			},
			wantErr: true,
		},
		{
			name: "SkipBody",
			args: args{
				c: &gin.Context{
					Request: generateRequest("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02"),
				},
				keyFn: func(ak string) string {
					return "250cf8b51c773f3f8dc8b4be867a9a02"
				},
				skipBody: true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validRequest(tt.args.c, tt.args.keyFn, tt.args.skipBody)
			if (err != nil) != tt.wantErr {
				t.Errorf("validRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				t.Logf("%s", err)
			}
			// t.Logf("%+v", tt.args.c.Request)
		})
	}
}
