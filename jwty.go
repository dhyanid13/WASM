package main

import (
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
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

// Called when HTTP request headers are received.
func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Try to get the Authorization header from the incoming HTTP request.
	authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogError("failed to get Authorization header: " + err.Error())
		return types.ActionContinue
	}

	// The Authorization header is expected to be in the format "Bearer <token>".
	// We split the header on whitespace and extract the token part.
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		proxywasm.LogError("Authorization header format is not 'Bearer <token>'")
		return types.ActionContinue
	}
	jwtToken := parts[1]

	// Log the extracted JWT token.
	proxywasm.LogInfo("Extracted JWT token: " + jwtToken)

	return types.ActionContinue
}
