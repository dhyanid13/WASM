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
    // Extract the JWT from the Authorization header
    authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
    if err != nil {
        proxywasm.LogError("Could not get Authorization header: " + err.Error())
        return proxywasm.ActionContinue
    }
    jwtToken := authHeader[len("Bearer "):] // Assuming the header format is "Bearer <token>"
    proxywasm.LogInfo("Extracted JWT: " + jwtToken)

    // Fetch JWKS from a remote URL
    ctx.fetchJWKS()

    return proxywasm.ActionContinue
}

func (ctx *httpLifecycle) fetchJWKS() {
    const jwksURL = "/.well-known/jwks.json" // Path to the JWKS on the JWKS server
    const jwksHost = "jwks.server.com"      // Hostname of the JWKS server
    const clusterName = "jwks_cluster"       // Cluster name defined in Envoy configuration for the JWKS server

    _, err := proxywasm.DispatchHttpCall(
        clusterName,
        [][2]string{
            {"method", "GET"},
            {"path", jwksURL},
            {"Host", jwksHost},
        },
        nil, nil, 5000, ctx.onJWKSResponse,
    )
    if err != nil {
        proxywasm.LogError("Failed to dispatch JWKS fetch request: " + err.Error())
    }
}

func (ctx *httpLifecycle) onJWKSResponse(numHeaders int, bodySize int, numTrailers int) {
    body, err := proxywasm.GetHttpCallResponseBody()
    if err != nil {
        proxywasm.LogError("Failed to get JWKS response body: " + err.Error())
        return
    }
    proxywasm.LogInfo("Fetched JWKS: " + string(body))
    // Here, you would add logic to validate the JWT with the fetched JWKS
}
