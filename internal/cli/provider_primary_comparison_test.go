package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/config"
)

func TestPrimaryComparisonCommandRequiresExplicitBindingsBeforeDispatch(t *testing.T) {
	for _, args := range [][]string{{}, {"--live"}, {"--profile", "primary", "--signer-profile", "signer"}, {"--live", "--profile", "primary", "--signer-profile", "signer", "--timeout", "6m"}} {
		cmd := newProviderPrimaryComparisonCmd()
		cmd.SetArgs(args)
		if err := cmd.Execute(); err == nil {
			t.Fatalf("accepted incomplete live comparison: %v", args)
		}
	}
}

func TestPrimaryComparisonProfileCannotRelabelZaiAsPrimary(t *testing.T) {
	p := config.ProviderProfileConfig{Provider: "openai", AccountAlias: "explicit-account", Model: "gpt-6-astra", Endpoint: "https://chatgpt.com/backend-api/codex", Runtime: "codex", CredentialClass: "oauth", BillingClass: "subscription", Entitlement: "primary_cli", Command: "/bin/codex", RuntimeHome: "/isolated/account", RuntimeVersion: "0.153.0", RuntimeSHA256: strings.Repeat("a", 64), AutomationPolicy: primaryComparisonPolicy, ExactTargetOnly: true}
	p.ConfigSHA256 = p.CanonicalManifestSHA256()
	if _, transport, err := validatePrimaryComparisonProfile(p); err != nil || transport != "openai_codex_comparison" {
		t.Fatalf("valid primary manifest: %s %v", transport, err)
	}
	p.Endpoint = "https://api.z.ai/api/coding/paas/v4"
	p.ConfigSHA256 = p.CanonicalManifestSHA256()
	if _, _, err := validatePrimaryComparisonProfile(p); err == nil {
		t.Fatal("provider endpoint relabeling accepted")
	}
	p.Endpoint = "https://chatgpt.com/backend-api/codex"
	p.ConfigSHA256 = p.CanonicalManifestSHA256()
	p.Model = "gpt-5.5"
	if _, _, err := validatePrimaryComparisonProfile(p); err == nil {
		t.Fatal("manifest drift accepted")
	}
	p.Provider = "anthropic"
	p.Runtime = "claude"
	p.Model = "claude-fable-20260901"
	p.Endpoint = "https://api.anthropic.com"
	p.ConfigSHA256 = p.CanonicalManifestSHA256()
	if _, transport, err := validatePrimaryComparisonProfile(p); err != nil || transport != "anthropic_claude_comparison" {
		t.Fatalf("canonical Anthropic endpoint: %s %v", transport, err)
	}
}

func TestPrimaryComparisonCredentialsCannotSwitchBillingToAPI(t *testing.T) {
	if primaryComparisonCredentialValid([]byte(`{"auth_mode":"apikey","OPENAI_API_KEY":"synthetic-api-canary"}`), "codex") {
		t.Fatal("API billing accepted")
	}
	if !primaryComparisonCredentialValid([]byte(`{"auth_mode":"chatgpt","tokens":{"access_token":"synthetic-oauth-canary"}}`), "codex") {
		t.Fatal("subscription format rejected")
	}
	if primaryComparisonCredentialValid([]byte(`{"tokens":{"access_token":"synthetic-oauth-canary"}}`), "codex") {
		t.Fatal("unspecified auth mode accepted")
	}
	if !primaryComparisonCredentialValid([]byte(`{"claudeAiOauth":{"accessToken":"synthetic-oauth-canary"}}`), "claude") {
		t.Fatal("Claude subscription format rejected")
	}
}

func TestPrimaryComparisonStreamsDoNotInferModelOrAcknowledgement(t *testing.T) {
	const nonce = "NTM_ACK_1234567890abcdef1234567890abcdef"
	var codex primaryComparisonObservation
	codex.observe([]byte(`{"type":"thread.started","model":"gpt-6-astra"}`), "codex", nonce)
	codex.observe([]byte(`{"type":"item.completed","item":{"type":"mcp_tool_call","text":"`+nonce+`"}}`), "codex", nonce)
	codex.observe([]byte(`{"type":"turn.completed"}`), "codex", nonce)
	if codex.ServedModel != "" || codex.NonceVerified || !codex.Completed {
		t.Fatalf("configured model or tool text became authoritative: %+v", codex)
	}
	var claude primaryComparisonObservation
	claude.observe([]byte(`{"type":"system","subtype":"init","model":"claude-fable"}`), "claude", nonce)
	claude.observe([]byte(`{"type":"assistant","message":{"model":"claude-fable-20260901","content":[{"type":"tool_use","name":"Bash"}]}}`), "claude", nonce)
	claude.observe([]byte(`{"type":"result","subtype":"success","result":"`+nonce+`"}`), "claude", nonce)
	if !claude.Completed || !claude.NonceVerified || !claude.UnexpectedTool || claude.ServedModel != "claude-fable-20260901" {
		t.Fatalf("incorrect primary stream evidence: %+v", claude)
	}
	claude.observe([]byte(`{"type":"assistant","message":{"model":"credential-canary-do-not-retain"}}`), "claude", nonce)
	data, _ := json.Marshal(claude)
	if !claude.Malformed || strings.Contains(string(data), "credential-canary") {
		t.Fatal("arbitrary provider data retained as model")
	}
}

func TestPrimaryComparisonEnvironmentExcludesAmbientCredentials(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "credential-canary")
	t.Setenv("ANTHROPIC_BASE_URL", "https://unexpected.invalid")
	for _, runtime := range []string{"claude", "codex"} {
		env := strings.Join(primaryComparisonEnvironment("/isolated", runtime), "\n")
		if strings.Contains(env, "credential-canary") || strings.Contains(env, "unexpected.invalid") {
			t.Fatal("ambient provider identity leaked into primary child")
		}
	}
}
