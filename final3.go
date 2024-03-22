package main

import (
	"strings"
	"time"

	"github.com/gilbsgilbs/jwit"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

const JWKSURL = "https://login.microsoftonline.com/<tenant>/v2.0/.well-known/jwks.json"

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
	verifier *jwit.Verifier
}

func (ctx *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	var err error
	ctx.verifier, err = jwit.NewVerifier(
		&jwit.Issuer{
			Name:    "https://sts.windows.net/e29b8111-49f8-418d-ac2a-935335a52614/",
			JWKSURL: JWKSURL,
			TTL:     24 * time.Hour, // Or any TTL that fits your use case.
		},
	)
	if err != nil {
		proxywasm.LogErrorf("error creating JWT verifier: %v", err)
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	// Pass the verifier to the httpLifecycle.
	return &httpLifecycle{
		verifier: ctx.verifier,
	}
}

type httpLifecycle struct {
	types.DefaultHttpContext
	verifier *jwit.Verifier
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Extract JWT from Authorization header.
	authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogErrorf("error getting Authorization header: %v", err)
		return types.ActionContinue // Or you may choose to terminate the request.
	}

	// Trim the "Bearer" prefix to extract the token
	jwt := strings.TrimPrefix(authHeader, "Bearer ")
	if jwt == authHeader {
		proxywasm.LogError("JWT token not found in the Authorization header")
		return types.ActionContinue // Or you may choose to terminate the request.
	}

	// Validate the JWT
	isValid, err := ctx.verifier.VerifyJWT(jwt)
	if err != nil {
		proxywasm.LogErrorf("JWT validation error: %v", err)
		return types.ActionContinue // Or you may choose to terminate the request.
	}

	if !isValid {
		proxywasm.LogError("JWT is not valid")
		return types.ActionContinue // Or you may choose to terminate the request.
	}

	proxywasm.LogInfo("JWT is valid")
	// Proceed with the request as it is now validated.
	return types.ActionContinue
}
