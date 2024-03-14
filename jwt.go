package main

import (
    "encoding/base64"
    "strings"

    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
    "github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
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
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
    headerValue, err := proxywasm.GetHttpRequestHeader("authorization")
    if err != nil {
        proxywasm.LogCritical("Failed to get Authorization header")
        return types.ActionContinue
    }

    // Assuming the Authorization header format is "Bearer <token>"
    splitToken := strings.Split(headerValue, " ")
    if len(splitToken) != 2 {
        proxywasm.LogCritical("Invalid Authorization header format")
        return types.ActionContinue
    }

    jwt := splitToken[1]
    parts := strings.Split(jwt, ".")
    if len(parts) != 3 {
        proxywasm.LogCritical("Invalid JWT format")
        return types.ActionContinue
    }

    // Base64 decode the payload
    payload, err := base64.RawURLEncoding.DecodeString(parts[1])
    if err != nil {
        proxywasm.LogCritical("Failed to decode JWT payload")
        return types.ActionContinue
    }

    // Log the decoded payload
    proxywasm.LogInfo("JWT Payload: " + string(payload))

    return types.ActionContinue
}
