# ginaksk 实现gin的中间件, 用于认证客户端请求和校验请求内容

[godoc](https://pkg.go.dev/github.com/antlinker/ginaksk?tab=doc)

## 编码格式

ginaksk默认使用encoding/hex生成字符串，添加到HTTP请求的头部；可以在使用Validate中间件之前，调用SetEncoder修改为其他编码格式，如示例中的base64

## Hash算法

ginaksk默认使用sha256.New作为hmac.New的hash.Hash类型；可以在使用Validate中间件之前，调用SetHash修改为其他算法，如sha512.New

