//go:build integration

package zai

import (
	"os"
	"testing"
)

// TestLiveNativeNoWriteRoundTrip is intentionally opt-in. It makes one
// no-tool streaming completion using only a separately authorized native API
// key; it never falls back to a Coding Plan / Claude-compatible credential.
func TestLiveNativeNoWriteRoundTrip(t *testing.T) {
	if os.Getenv("NTM_LIVE_ZAI_NATIVE") != "1" {
		t.Skip("set NTM_LIVE_ZAI_NATIVE=1 to authorize the live Z.ai native transport test")
	}
	key := os.Getenv("ZAI_NATIVE_API_KEY")
	model := os.Getenv("NTM_LIVE_ZAI_NATIVE_MODEL")
	if key == "" || model == "" {
		t.Skip("ZAI_NATIVE_API_KEY and NTM_LIVE_ZAI_NATIVE_MODEL are required")
	}
	nonce, err := newNonce()
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunNative(t.Context(), DefaultNativeHTTPClient(), NativeRequest{
		Endpoint: NativeChatCompletionsEndpoint, Model: model,
		Prompt:        "Reply with this exact nonce on its own line and no other text: " + nonce,
		ExpectedNonce: nonce, NativeAPIKey: key, ExplicitOptIn: true,
	})
	if err != nil || !result.NonceVerified || result.Model == "" {
		t.Fatalf("native Z.ai receipt failed: err=%v nonce=%t model=%q status=%d code=%q", err, result.NonceVerified, result.Model, result.HTTPStatus, result.ErrorCode)
	}
}
