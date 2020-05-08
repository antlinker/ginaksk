package aksk

import (
	"fmt"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	encoder = NewHexEncoder()
	m.Run()
}

func Test_validBody(t *testing.T) {
	type args struct {
		body string
		mac  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Success",
			args: args{
				body: `{
  "exporter_name": "node",
  "target": "192.168.162.93:9100",
  "scrape_interval": 20,
  "labels": {}
}`,
				mac: `84c4507de209a5b7746877416959f927f5b6d0f58791a77f8837ecb23af2bc5a`,
			},
			want: true,
		},
		{
			name: "FailedBody",
			args: args{
				body: `{
  "exporter_name": "node",
  "target": "192.168.162.94:9100",
  "scrape_interval": 20,
  "labels": {}
}`,
				mac: `84c4507de209a5b7746877416959f927f5b6d0f58791a77f8837ecb23af2bc5a`,
			},
			want: false,
		},
		{
			name: "FailedMac",
			args: args{
				body: `{
  "exporter_name": "node",
  "target": "192.168.162.93:9100",
  "scrape_interval": 20,
  "labels": {}
}`,
				mac: `1-84c4507de209a5b7746877416959f927f5b6d0f58791a77f8837ecb23af2bc5a`,
			},
			want: false,
		},
		{
			name: "SuccessBodyEmpty",
			args: args{mac: "123456"},
			want: true,
		},
		{
			name: "FailedMacEmpty",
			args: args{body: "123456", mac: ""},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validBody([]byte(tt.args.body), tt.args.mac); got != tt.want {
				t.Errorf("validBody() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_validHeader(t *testing.T) {
	type args struct {
		accessKey  string
		secretKey  string
		timestramp string
		randomstr  string
		bodyhash   string
		signature  string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Success",
			args: args{
				accessKey:  "202cb962ac59075b964b07152d234b70",
				secretKey:  "250cf8b51c773f3f8dc8b4be867a9a02",
				timestramp: "1588908190",
				randomstr:  "123456",
				bodyhash:   "84c4507de209a5b7746877416959f927f5b6d0f58791a77f8837ecb23af2bc5a",
				signature:  "4061f6ec16d6ab0567e32f4f7a1367dc7ce7dcd881f361952150453ca9477f2c",
			},
			want: true,
		},
		{
			name: "FailedSigatureLen",
			args: args{
				accessKey:  "202cb962ac59075b964b07152d234b70",
				secretKey:  "250cf8b51c773f3f8dc8b4be867a9a02",
				timestramp: "1588908190",
				randomstr:  "123456",
				bodyhash:   "84c4507de209a5b7746877416959f927f5b6d0f58791a77f8837ecb23af2bc5a",
				signature:  "461f6ec16d6ab0567e32f4f7a1367dc7ce7dcd881f361952150453ca9477f2c",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validHeader(tt.args.accessKey, tt.args.secretKey, tt.args.timestramp, tt.args.randomstr, tt.args.bodyhash, tt.args.signature); got != tt.want {
				t.Errorf("validHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseTimestramp(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Expired",
			args:    args{s: fmt.Sprintf("%d", time.Now().Add(-maxDuration).Unix())},
			wantErr: true,
		},
		{
			name:    "Success",
			args:    args{s: fmt.Sprintf("%d", time.Now().Unix())},
			wantErr: false,
		},
		{
			name:    "Empty",
			args:    args{s: ""},
			wantErr: true,
		},
		{
			name:    "Invalid",
			args:    args{s: "s123"},
			wantErr: true,
		},
		{
			name:    "TooEarly",
			args:    args{s: fmt.Sprintf("%d", time.Now().Add(time.Second-minDuration).Unix())},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := parseTimestramp(tt.args.s); (err != nil) != tt.wantErr {
				t.Errorf("parseTimestramp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

type _logger struct{}

func (l *_logger) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func TestInit(t *testing.T) {

	type args struct {
		enc Encoder
		s   Store
		l   Logger
	}
	tests := []struct {
		name      string
		args      args
		wantPanic bool
	}{
		{
			name:      "Success",
			args:      args{enc: NewHexEncoder(), l: Logger(new(_logger))},
			wantPanic: false,
		},
		{
			name:      "Failed",
			args:      args{enc: nil},
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantPanic {
				defer func() {
					if err := recover(); err != nil {
						t.Logf("%v", err)
					}
				}()
			}
			Init(tt.args.enc, tt.args.s, tt.args.l)
		})
	}
}
