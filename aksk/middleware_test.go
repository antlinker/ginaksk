package aksk

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
)

func generateRequest(ak, sk string) *http.Request {
	f, _ := NewRequestFunc(ak, sk)
	r, _ := f(context.TODO(), "POST", `http://localhost:8080/e`, []byte(`{"param":"a"}`))
	return r
}

func generateRequestWithHeader(ak, sk string, key, value string) *http.Request {
	r := generateRequest(ak, sk)
	r.Header.Set(key, value)
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
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderSignature, "111111"),
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
					Request: generateRequestWithHeader("202cb962ac59075b964b07152d234b70", "250cf8b51c773f3f8dc8b4be867a9a02", HeaderBodyHash, "111111"),
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
			if err := validRequest(tt.args.c, tt.args.keyFn, tt.args.skipBody); (err != nil) != tt.wantErr {
				t.Errorf("validRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}