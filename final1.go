package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gilbsgilbs/jwit"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	types.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) types.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	types.DefaultPluginContext
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpLifecycle{}
}

type httpLifecycle struct {
	types.DefaultHttpContext
	jwt string
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Extract JWT from Authorization header
	authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogError("failed to get Authorization header: ", err.Error())
		return types.ActionContinue
	}

	// Assuming the Authorization header format is "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		proxywasm.LogError("invalid Authorization header format")
		return types.ActionContinue
	}
	ctx.jwt = parts[1]

	// Fetch JWKS asynchronously
	jwksURL := "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	_, err = proxywasm.DispatchHttpCall(
		"azure_entra",
		[][2]string{
			{"method", "GET"},
			{"path", jwksURL},
			{"Host", "login.microsoftonline.com"},
		},
		nil, nil, 5000,
		ctx.onJWKSFetch,
	)
	if err != nil {
		proxywasm.LogError("failed to dispatch JWKS fetch request: ", err.Error())
	}

	return types.ActionContinue
}

func (ctx *httpLifecycle) onJWKSFetch(numHeaders, bodySize, numTrailers int) {
	body, err := proxywasm.GetHttpCallResponseBody()
	if err != nil {
		proxywasm.LogError("failed to get JWKS response body: ", err.Error())
		return
	}

	jwks, err := jwit.ParseJWKS(body)
	if err != nil {
		proxywasm.LogError("failed to parse JWKS: ", err.Error())
		return
	}

	// Validate JWT with the JWKS
	if _, err := jwit.VerifyString(ctx.jwt, jwks); err != nil {
		proxywasm.LogError("JWT validation failed: ", err.Error())
		// Optionally, send a response indicating unauthorized access or invalid token
		// proxywasm.SendHttpResponse(401, nil, []byte("Unauthorized"), -1)
	} else {
		proxywasm.LogInfo("JWT validation succeeded")
		// JWT is valid, proceed with the request
	}
}

// Additional functions for plugin lifecycle events if needed...
