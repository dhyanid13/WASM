package main

import (
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetVMContext(&vmContext{})
}

type vmContext struct {
	// Embed the default VM context here,
	// so that you don't need to implement all the methods.
	proxywasm.DefaultVMContext
}

func (*vmContext) NewPluginContext(contextID uint32) proxywasm.PluginContext {
	return &pluginContext{}
}

type pluginContext struct {
	// Embed the default plugin context here,
	// so that you don't need to implement all the methods.
	proxywasm.DefaultPluginContext
}

func (*pluginContext) NewHttpContext(contextID uint32) proxywasm.HttpContext {
	return &httpLifecycle{}
}

type httpLifecycle struct {
	// Embed the default http context here,
	// so that you don't need to implement all the methods.
	proxywasm.DefaultHttpContext
}

// Override the methods you're interested in, e.g., onRequestHeaders.
func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Implement your JWT validation logic here
	// For demonstration, we're just logging an HTTP request header.
	if headerValue, err := proxywasm.GetHttpRequestHeader("authorization"); err == nil {
		proxywasm.LogInfo("Authorization header: " + headerValue)
	}

	// Continue the filter chain execution.
	return types.ActionContinue
}
