package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
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

func TestPrimaryComparisonExactModelRequiresCompleteUnconflictedTerminalEvidence(t *testing.T) {
	passing := primaryComparisonObservation{ServedModel: "claude-fable-5", Completed: true, NonceVerified: true, ExitOK: true}
	if !passing.exactModelVerified("claude-fable-5") || passing.exactModelVerified("other") || passing.exactModelVerified("") {
		t.Fatal("exact model comparison is not bound to requested model")
	}
	for _, invalidate := range []func(*primaryComparisonObservation){
		func(o *primaryComparisonObservation) { o.Completed = false },
		func(o *primaryComparisonObservation) { o.NonceVerified = false },
		func(o *primaryComparisonObservation) { o.ExitOK = false },
		func(o *primaryComparisonObservation) { o.ModelConflict = true },
		func(o *primaryComparisonObservation) { o.Malformed = true },
		func(o *primaryComparisonObservation) { o.UnexpectedTool = true },
	} {
		copy := passing
		invalidate(&copy)
		if copy.exactModelVerified("claude-fable-5") {
			t.Fatal("incomplete or conflicting model evidence passed")
		}
	}
}

func TestPrimaryComparisonTerminalHintsNeverRetainTextOrGrantAcknowledgement(t *testing.T) {
	for _, tc := range []struct{ text, category string }{
		{"This is read-only; secret-canary", "read_only_mentioned"},
		{"I do not have the requested tool; secret-canary", "tools_unavailable_mentioned"},
		{"Permission is missing; secret-canary", "permission_mentioned"},
		{"secret-canary", "other_text"},
		{"", "empty"},
	} {
		var observation primaryComparisonObservation
		line, _ := json.Marshal(map[string]any{"type": "item.completed", "item": map[string]string{"type": "agent_message", "text": tc.text}})
		observation.observe(line, "codex", "expected-nonce")
		data, _ := json.Marshal(observation)
		if observation.TerminalCategory != tc.category || observation.NonceVerified || strings.Contains(string(data), "secret-canary") {
			t.Fatalf("unsafe terminal classification: %s", data)
		}
	}
	var observation primaryComparisonObservation
	observation.observe([]byte(`{"type":"item.completed","item":{"type":"mcp_tool_call","text":"read-only"}}`), "codex", "nonce")
	if observation.TerminalCategory != "" {
		t.Fatal("tool payload became a terminal explanation")
	}
}

func TestPrimaryComparisonCodexApprovesOnlyRequiredConstrainedBroker(t *testing.T) {
	settings := primaryCodexComparisonSettings("gpt-6-astra", "/bound/ntm", []string{"provider", "broker"})
	servers := settings["mcp_servers"].(map[string]any)
	if len(servers) != 1 || settings["approval_policy"] != "never" || settings["sandbox_mode"] != "read-only" {
		t.Fatal("comparison broadened ambient permissions")
	}
	broker := servers[grok.WorkspaceBrokerMCPName].(map[string]any)
	if broker["required"] != true || broker["default_tools_approval_mode"] != "approve" || strings.Join(broker["enabled_tools"].([]string), ",") != "read_file,write_file,verify_worktree" {
		t.Fatal("comparison broker can be omitted or needs an unavailable approval prompt")
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
	t.Setenv("PATH", "/mnt/c/ambient-windows-helper-canary")
	t.Setenv("ANTHROPIC_BASE_URL", "https://unexpected.invalid")
	for _, runtime := range []string{"claude", "codex"} {
		env := strings.Join(primaryComparisonEnvironment("/isolated", runtime), "\n")
		if strings.Contains(env, "credential-canary") || strings.Contains(env, "unexpected.invalid") || strings.Contains(env, "ambient-windows-helper-canary") {
			t.Fatal("ambient provider identity leaked into primary child")
		}
		if runtime == "claude" && !strings.Contains(env, "CLAUDE_CODE_DISABLE_AGENT_VIEW=1") {
			t.Fatal("shared Agent View supervisor can reconnect another account")
		}
	}
}
