package main

import (
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
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) proxywasm.Action {
	// Extract JWT from Authorization header
	jwt, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogCritical("Failed to get Authorization header")
		return proxywasm.ActionContinue
	}
	proxywasm.LogInfo("Extracted JWT: " + jwt)

	// Fetch JWKS (example URL, replace with actual)
	jwksURL := "https://login.microsoftonline.com/common/discovery/v2.0/keys"
	_, err = proxywasm.DispatchHttpCall(
		"jwks_cluster",
		[][2]string{
			{"method", "GET"},
			{"path", jwksURL},
			{"Host", "login.microsoftonline.com"},
		},
		nil, nil, 5000,
		func(numHeaders, bodySize, numTrailers int) {
			body, err := proxywasm.GetHttpCallResponseBody()
			if err != nil {
				proxywasm.LogCritical("Failed to get JWKS response body")
				return
			}
			proxywasm.LogInfo("Fetched JWKS: " + string(body))
			// Placeholder for JWKS parsing and JWT validation logic
		},
	)
	if err != nil {
		proxywasm.LogCritical("Failed to dispatch JWKS fetch request: " + err.Error())
	}

	return proxywasm.ActionContinue
}
