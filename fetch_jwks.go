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
	// Initiate an HTTP call to fetch the JWKS
	const jwksURL = "<your-jwks-url>" // Replace with your actual JWKS URL
	if _, err := proxywasm.DispatchHttpCall(
		"jwks_cluster", // The logical name of the cluster configured in Envoy for the JWKS endpoint
		[][2]string{
			{"method", "GET"},
			{"path", jwksURL}, // You might need to adjust this if your JWKS URL contains a path
			{"authority", "login.microsoftonline.com"}, // Adjust if necessary
		},
		nil,    // No body
		nil,    // No trailers
		5000,   // Timeout in milliseconds
		ctx.onJWKSResponse, // Callback function to handle the response
	); err != nil {
		proxywasm.LogError("Failed to dispatch JWKS fetch request: " + err.Error())
	}
	return proxywasm.ActionContinue
}

func (ctx *httpLifecycle) onJWKSResponse(numHeaders int, bodySize int, numTrailers int) {
	// Retrieve the body of the HTTP response
	body, err := proxywasm.GetHttpCallResponseBody()
	if err != nil {
		proxywasm.LogError("Failed to get JWKS response body: " + err.Error())
		return
	}
	// Log the JWKS
	proxywasm.LogInfo("Fetched JWKS: " + string(body))
}
