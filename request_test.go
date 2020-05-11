package ginaksk

import (
	"context"
	"testing"
)

func TestRequest(t *testing.T) {
	type args struct {
		ak string
		sk string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Request",
			args: args{
				ak: "202cb962ac59075b964b07152d234b70",
				sk: "250cf8b51c773f3f8dc8b4be867a9a02",
			},
			wantErr: false,
		},
		{
			name:    "RequestEmptyAccessKey",
			wantErr: true,
		},
		{
			name: "RequestEmptySecretKey",
			args: args{
				ak: "202cb962ac59075b964b07152d234b70",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewRequestFunc(tt.args.ak, tt.args.sk)
			if (err != nil) != tt.wantErr {
				t.Errorf("Request() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got == nil {
				return
			}
			req, err := got(context.TODO(), "POST", `http://localhost:8080/e`, []byte(`{"param":"a"}`))
			if (err != nil) != tt.wantErr {
				t.Errorf("Request() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("%+v", req)
		})
	}
}
