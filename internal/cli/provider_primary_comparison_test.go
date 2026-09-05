package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
)

// Loads the production-generated configuration in the reviewed executable.
// features list does not authenticate or dispatch generation.
func TestPrimaryCodexPinnedRuntimeLoadsControlledCatalogOffline(t *testing.T) {
	binary := os.Getenv("NTM_PRIMARY_CODEX_OFFLINE_BINARY")
	if binary == "" {
		t.Skip("reviewed runtime not supplied")
	}
	home := t.TempDir()
	catalog, err := writePrimaryCodexToolCatalog(home, "gpt-6-astra")
	if err != nil {
		t.Fatal(err)
	}
	settings := primaryCodexComparisonSettings("gpt-6-astra", "/bin/false", nil)
	settings["model_catalog_json"] = catalog
	var config bytes.Buffer
	if err := toml.NewEncoder(&config).Encode(settings); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), config.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "features", "list")
	cmd.Env = primaryComparisonEnvironment(home, "codex")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("controlled runtime configuration rejected: %v\n%s", err, output)
	}
	for _, name := range []string{"shell_tool", "multi_agent", "apps", "plugins", "view_image"} {
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == name {
				found = fields[len(fields)-1] == "false"
			}
		}
		if !found {
			t.Fatalf("feature %s not disabled in runtime output: %s", name, output)
		}
	}
}

func TestPrimaryCodexBoundaryDisablesEveryUnboundedFileAndExecutionTool(t *testing.T) {
	settings := primaryCodexComparisonSettings("gpt-6-astra", "/broker", []string{"controlled"})
	features := settings["features"].(map[string]any)
	for _, name := range []string{"shell_tool", "multi_agent", "apps", "plugins", "view_image", "image_generation", "request_permissions_tool"} {
		if features[name] != false {
			t.Fatalf("unsafe feature %s", name)
		}
	}
	if settings["web_search"] != "disabled" || settings["sandbox_mode"] != "read-only" {
		t.Fatal("unbounded network or write authority")
	}
	path, err := writePrimaryCodexToolCatalog(t.TempDir(), "gpt-6-astra")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	var catalog struct{ Models []map[string]any }
	if json.Unmarshal(data, &catalog) != nil || len(catalog.Models) != 1 {
		t.Fatal("invalid static tool catalog")
	}
	entry := catalog.Models[0]
	if entry["apply_patch_tool_type"] != nil || entry["shell_type"] != "disabled" || entry["slug"] != "gpt-6-astra" {
		t.Fatal("static catalog changed model or exposes patch/shell")
	}
	if primaryWorkspacePolicySHA("openai_codex_comparison", strings.Repeat("a", 64)) == primaryWorkspacePolicySHA("openai_codex_comparison", strings.Repeat("b", 64)) {
		t.Fatal("policy lost companion binding")
	}
}

func TestPrimaryCodexCompanionRequiredBeforePaidComparison(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "codex")
	path := filepath.Join(root, "codex-code-mode-host")
	content := []byte("offline-companion-fixture")
	pin := sha256TextCLI(content)
	if _, err := primaryCodexCompanionDigest(binary, pin); err == nil {
		t.Fatal("missing Code Mode host accepted despite successful inventory")
	}
	if err := os.WriteFile(path, content, 0700); err != nil {
		t.Fatal(err)
	}
	if digest, err := primaryCodexCompanionDigest(binary, pin); err != nil || digest != pin {
		t.Fatalf("bound companion: %s %v", digest, err)
	}
	for _, bad := range []string{"", strings.Repeat("a", 64)} {
		if _, err := primaryCodexCompanionDigest(binary, bad); err == nil {
			t.Fatal("unreviewed companion accepted")
		}
	}
	if err := os.WriteFile(path, []byte("changed-companion"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := primaryCodexCompanionDigest(binary, pin); err == nil {
		t.Fatal("changed companion accepted")
	}
}

func TestPrimaryRuntimeDiagnosticsAreClosedAndPayloadFree(t *testing.T) {
	var o primaryComparisonObservation
	o.observeWarnings([]byte("Code Mode is unavailable because /private/credential-canary. Defaulting to fallback metadata"))
	o.observe([]byte(`{"type":"item.started","item":{"type":"mcp_tool_call","server":"ntm-controlled-workspace","arguments":{"credential":"credential-canary"}}}`), "codex", "nonce")
	o.observe([]byte(`{"type":"item.completed","item":{"type":"mcp_tool_call","status":"failed","error":{"message":"credential-canary"}}}`), "codex", "nonce")
	data, err := json.Marshal(o)
	if err != nil || !o.CodeModeUnavailable || !o.MetadataFallback || o.MCPStarted != 1 || o.MCPFailed != 1 || strings.Contains(string(data), "credential-canary") {
		t.Fatalf("unsafe diagnostics: %s %v", data, err)
	}
}

func TestPrimaryClaudeStreamDecodesOnlyAssistantMessageShape(t *testing.T) {
	var o primaryComparisonObservation
	// Anthropic SDKUserMessage uses MessageParam, whose content may be text.
	o.observe([]byte(`{"type":"user","message":{"role":"user","content":"private-canary"}}`), "claude", "nonce")
	o.observe([]byte(`{"type":"system","subtype":"notification","message":"private-canary"}`), "claude", "nonce")
	o.observe([]byte(`{"type":"assistant","message":{"model":"claude-fable-5","content":[{"type":"text"}]}}`), "claude", "nonce")
	o.observe([]byte(`{"type":"result","subtype":"success","result":"nonce"}`), "claude", "nonce")
	o.ExitOK = true
	if !o.exactModelVerified("claude-fable-5") {
		t.Fatalf("valid union stream rejected: %+v", o)
	}
	data, _ := json.Marshal(o)
	if strings.Contains(string(data), "private-canary") {
		t.Fatal("message payload retained")
	}
	o.observe([]byte(`{"type":"assistant","message":"private-canary"}`), "claude", "nonce")
	if !o.Malformed || o.FailureCategory != "invalid_assistant_envelope" {
		t.Fatal("invalid assistant shape accepted")
	}
}

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

func TestPrimaryRuntimeMismatchDoesNotExecuteVersionCommand(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "executed")
	binary := filepath.Join(root, "replacement")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntouch '"+marker+"'\nprintf 'codex-cli 0.153.0\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	p := config.ProviderProfileConfig{Command: binary, RuntimeSHA256: strings.Repeat("a", 64), RuntimeVersion: "0.153.0"}
	if _, err := primaryPinnedRuntimeVersion(t.Context(), p); err == nil {
		t.Fatal("replacement executable accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("untrusted version command was executed")
	}
}
