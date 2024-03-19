package main

import (
	"fmt"
	"time"
	"strings"
	"github.com/gilbsgilbs/jwit"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct{}

func (vmContext) NewPluginContext(contextID uint32) proxywasm.PluginContext {
	return &pluginContext{}
}

type pluginContext struct{}

func (pluginContext) NewHttpContext(contextID uint32) proxywasm.HttpContext {
	return &httpLifecycle{}
}

type httpLifecycle struct {
	proxywasm.DefaultHttpContext
	jwt string // Store the JWT for use in the JWKS fetch callback.
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) proxywasm.Action {
	authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogCritical("Failed to get Authorization header")
		return proxywasm.ActionContinue
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		proxywasm.LogCritical("Invalid Authorization header format")
		return proxywasm.ActionContinue
	}
	ctx.jwt = parts[1]

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
		proxywasm.LogCritical("Failed to dispatch JWKS fetch request: " + err.Error())
	}

	return proxywasm.ActionContinue
}

func (ctx *httpLifecycle) onJWKSFetch(numHeaders, bodySize, numTrailers int) {
	body, err := proxywasm.GetHttpCallResponseBody()
	if err != nil {
		proxywasm.LogCritical("Failed to get JWKS response body")
		return
	}

	jwks, err := jwit.ParseJWKS(body)
	if err != nil {
		proxywasm.LogCritical("Failed to parse JWKS: " + err.Error())
		return
	}

	if valid, err := validateJWTWithClaims(ctx.jwt, jwks); !valid {
		proxywasm.LogCritical("JWT validation failed: " + err.Error())
		// Here you could decide to terminate the request. This is just an example.
		// proxywasm.SendHttpResponse(401, nil, []byte("Unauthorized"), -1)
	} else {
		proxywasm.LogInfo("JWT is valid")
		// Proceed with the request
	}
}

func validateJWTWithClaims(jwt string, jwks *jwit.JWKS) (bool, error) {
	token, err := jwit.VerifyString(jwt, jwks)
	if err != nil {
		return false, fmt.Errorf("JWT signature validation failed: %w", err)
	}

	if token.Claims.Expiry != nil && token.Claims.Expiry.Time().Before(time.Now()) {
		return false, fmt.Errorf("JWT is expired")
	}

	// Implement additional claims validation as needed.

	return true, nil
}
