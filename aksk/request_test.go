package aksk

import (
	"context"
	"net/http"
	"testing"
)

type _store map[string]string

func (s _store) Get(ak string) (sk string) {
	sk = s[ak]
	return
}

func TestNewRequestWithAKSK(t *testing.T) {
	store = Store(_store{
		"202cb962ac59075b964b07152d234b70": "250cf8b51c773f3f8dc8b4be867a9a02",
	})
	type args struct {
		ctx    context.Context
		method string
		url    string
		ak     string
		body   []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Success",
			args: args{
				ctx:    context.TODO(),
				method: http.MethodPost,
				url:    "http://localhost:9221/api/set/one",
				ak:     "202cb962ac59075b964b07152d234b70",
				body:   []byte(`{"target":"127.0.0.1:9110"}`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRequestWithAKSK(tt.args.ctx, tt.args.method, tt.args.url, tt.args.ak, tt.args.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewRequestWithAKSK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("%v", got)
			// if !reflect.DeepEqual(got, tt.want) {
			// 	t.Errorf("NewRequestWithAKSK() = %v, want %v", got, tt.want)
			// }
		})
	}
}
