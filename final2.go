package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gilbsgilbs/jwit"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

const JWKS_URL = "https://login.microsoftonline.com/<tenant>/v2.0/.well-known/jwks.json"

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
	// Initialize the JWT verifier with the JWKS URL
	ctx.verifier, err = jwit.NewVerifier(&jwit.Issuer{
		Name:    "https://sts.windows.net/e29b8111-49f8-418d-ac2a-935335a52614/", // Replace with the issuer name from the JWT
		JWKSURL: JWKS_URL,
		TTL:     10 * time.Hour,
	})
	if err != nil {
		proxywasm.LogErrorf("Failed to create JWT verifier: %v", err)
		return types.OnPluginStartStatusFailed
	}
	return types.OnPluginStartStatusOK
}

func (ctx *pluginContext) NewHttpContext(contextID uint32) types.HttpContext {
	return &httpLifecycle{}
}

type httpLifecycle struct {
	types.DefaultHttpContext
	verifier *jwit.Verifier
}

func (ctx *httpLifecycle) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Extract JWT from Authorization header
	authHeader, err := proxywasm.GetHttpRequestHeader("Authorization")
	if err != nil {
		proxywasm.LogErrorf("Failed to get Authorization header: %v", err)
		return types.ActionContinue
	}

	jwt, err := extractJWT(authHeader)
	if err != nil {
		proxywasm.LogErrorf("Failed to extract JWT from the Authorization header: %v", err)
		return types.ActionContinue
	}

	// Verify the JWT using the verifier from the plugin context
	isValid, err := ctx.verifier.VerifyJWT(jwt)
	if err != nil {
		proxywasm.LogErrorf("Failed to verify JWT: %v", err)
		return types.ActionContinue
	}
	if !isValid {
		proxywasm.LogError("JWT is not valid")
		return types.ActionContinue
	}

	proxywasm.LogInfo("JWT is valid")
	return types.ActionContinue
}

// Helper function to extract the JWT token from the Authorization header
func extractJWT(authHeader string) (string, error) {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("authorization header format must be 'Bearer {token}'")
	}
	return parts[1], nil
}
