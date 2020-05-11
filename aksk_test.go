/*
Package ginaksk 基于ak, sk实现的服务认证中间件
*/
package ginaksk

import (
	"crypto/md5"
	"encoding/base64"
	"strings"
	"testing"
)

func TestSet(t *testing.T) {
	var f = func(s string) {
		switch {
		case strings.Contains(s, "Hash"):
			SetHash(md5.New)
		case strings.Contains(s, "Encoder"):
			SetEncoder(&base64Encoder{enc: base64.RawURLEncoding})
		case strings.Contains(s, "Logger"):
			SetLogger(&testLogger{})
		}
	}
	t.Cleanup(cleanup)
	tests := []struct {
		name      string
		wantPanic bool
	}{
		{
			name:      "SetHashOk",
			wantPanic: false,
		},
		{
			name:      "SetHashPanic",
			wantPanic: true,
		},
		{
			name:      "SetEncoderOk",
			wantPanic: false,
		},
		{
			name:      "SetEncoderPanic",
			wantPanic: true,
		},
		{
			name:      "SetLoggerOk",
			wantPanic: false,
		},
		{
			name:      "SetLoggerPanic",
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if err := recover(); err != nil {
					if tt.wantPanic {
						t.Log("except panic:", err)
						return
					}
					t.Fatal(err)
				}
			}()
			if tt.wantPanic {
				initialized = true
			} else {
				initialized = false
			}
			f(tt.name)
		})
	}
}
