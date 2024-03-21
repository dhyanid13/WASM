package main

import (
	"fmt"
	"github.com/gilbsgilbs/jwit"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
	"strings"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	proxywasm.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) proxywasm.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	proxywasm.DefaultPluginContext
}

func (*pluginContext) NewHttpContext(contextID uint32) proxywasm.HttpContext {
	return &httpLifecycle{}
}

type httpLifecycle struct {
	proxywasm.DefaultHttpContext
	jwt string
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Extract JWT from Authorization header
	authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogError("Failed to get Authorization header:", err.Error())
		return types.ActionContinue
	}

	// Assuming the Authorization header format is "Bearer <token>"
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		proxywasm.LogError("Invalid Authorization header format")
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
		proxywasm.LogError("Failed to dispatch JWKS fetch request:", err.Error())
	}

	return types.ActionContinue
}

// onJWKSFetch is the callback function for the JWKS HTTP call.
func (ctx *httpLifecycle) onJWKSFetch(numHeaders, bodySize, numTrailers int) {
	body, err := proxywasm.GetHttpCallResponseBody()
	if err != nil {
		proxywasm.LogError("Failed to get JWKS response body:", err.Error())
		return
	}

	jwks, err := jwit.ParseJWKS(body)
	if err != nil {
		proxywasm.LogError("Failed to parse JWKS:", err.Error())
		return
	}

	_, err = jwit.VerifyString(ctx.jwt, jwks)
	if err != nil {
		proxywasm.LogError("JWT validation failed:", err.Error())
		// You could choose to end the request here, but that requires careful consideration
		// about your proxy's behavior and what should happen on a JWT validation failure.
	} else {
		proxywasm.LogInfo("JWT is valid")
	}
}

// Other necessary methods...
