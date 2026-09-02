package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

const providerProfileTestHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func validZAIProviderProfile() ProviderProfileConfig {
	return ProviderProfileConfig{
		Provider:                "zai",
		AccountAlias:            "kevin-dev",
		Model:                   "glm-5.3-flash",
		Endpoint:                "https://api.z.ai/api/anthropic",
		Runtime:                 "claude-code",
		CredentialClass:         provider.CredentialClassCodingPlan,
		BillingClass:            provider.BillingClassCodingPlan,
		Entitlement:             provider.EntitlementClaudeCompat,
		ConfigSHA256:            providerProfileTestHash,
		Command:                 "claude",
		AutomationPolicy:        provider.DefaultZAIAutomationPolicyName,
		ExactTargetOnly:         true,
		ProbeRequired:           true,
		ModelProbeState:         "qualified",
		ModelProbeReceiptSHA256: providerProfileTestHash,
	}
}

func TestValidateProviderProfilesEnforcesZAITransportEntitlement(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.CredentialClass = provider.CredentialClassAPIKey
	joined := errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-coding-plan": profile}))
	if !strings.Contains(joined, "claude_compatible transport requires") {
		t.Fatalf("coding plan authorization error = %q", joined)
	}

	profile = validZAIProviderProfile()
	profile.CredentialClass = provider.CredentialClassAPIKey
	profile.BillingClass = provider.BillingClassAPIUsage
	profile.Entitlement = provider.EntitlementNativeAPI
	profile.Runtime = "zai-api"
	profile.Endpoint = zai.NativeChatCompletionsEndpoint
	profile.AutomationPolicy = provider.NativeZAINoToolsPolicyName
	profile.Command = ""
	if errs := ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-native-api": profile}); len(errs) != 0 {
		t.Fatalf("native API profile errors = %v", errs)
	}
	profile.Command = "zai-api"
	joined = errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-native-api": profile}))
	if !strings.Contains(joined, "must leave command empty") {
		t.Fatalf("native API command error = %q", joined)
	}
	profile.Command = ""
	profile.AutomationPolicy = "native-bypass"
	joined = errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-native-api": profile}))
	if !strings.Contains(joined, provider.NativeZAINoToolsPolicyName) {
		t.Fatalf("native API policy error = %q", joined)
	}
}

func TestValidateProviderProfilesAcceptsOnlyIsolatedZaiCodexCodingPlan(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.Model, profile.Endpoint, profile.Runtime, profile.Command = "glm-5.3", zai.OfficialCodexEndpoint, "codex", "/usr/bin/codex"
	profile.Entitlement, profile.AutomationPolicy, profile.RuntimeHome = provider.EntitlementCodexResponses, provider.DefaultZAICodexAutomationPolicyName, "/tmp/zai-codex"
	profile.BrokerCredentialID = "ntm.zai.coding_plan.kevin"
	profile.RuntimeSHA256, profile.BrokerCommand, profile.BrokerCommandSHA256 = providerProfileTestHash, "/usr/bin/caam", providerProfileTestHash
	profile.CredentialBridgeCommand, profile.CredentialBridgeCommandSHA256 = "/usr/bin/ntm-provider-bridge", providerProfileTestHash
	profile.RuntimeVersion = "0.149.0"
	if errs := ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-codex-plan": profile}); len(errs) != 0 {
		t.Fatalf("Z.ai Codex profile errors = %v", errs)
	}
	profile.RuntimeHome = "relative-home"
	joined := errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-codex-plan": profile}))
	if !strings.Contains(joined, "runtime_home dedicated to CODEX_HOME") {
		t.Fatalf("runtime home error = %q", joined)
	}
}

func TestValidateProviderProfilesRejectsInvalidCodingPlanBrokerCredentialID(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.Model, profile.Endpoint, profile.Runtime, profile.Command = "glm-5.3", zai.OfficialCodexEndpoint, "codex", "/usr/bin/codex"
	profile.Entitlement, profile.AutomationPolicy, profile.RuntimeHome = provider.EntitlementCodexResponses, provider.DefaultZAICodexAutomationPolicyName, "/tmp/zai-codex"
	profile.RuntimeSHA256, profile.BrokerCommand, profile.BrokerCommandSHA256 = providerProfileTestHash, "/usr/bin/caam", providerProfileTestHash
	profile.CredentialBridgeCommand, profile.CredentialBridgeCommandSHA256 = "/usr/bin/ntm-provider-bridge", providerProfileTestHash
	profile.RuntimeVersion = "0.149.0"
	joined := errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-codex-plan": profile}))
	if !strings.Contains(joined, "broker_credential_id") {
		t.Fatalf("missing broker credential validation: %q", joined)
	}
	profile.BrokerCredentialID = "ntm.zai.coding_plan.kevin"
	if errs := ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-codex-plan": profile}); len(errs) != 0 {
		t.Fatalf("valid broker id rejected: %v", errs)
	}
	profile.Entitlement, profile.Runtime, profile.Endpoint = provider.EntitlementNativeAPI, "zai-api", zai.NativeChatCompletionsEndpoint
	profile.CredentialClass, profile.BillingClass, profile.Command, profile.AutomationPolicy = provider.CredentialClassAPIKey, provider.BillingClassAPIUsage, "", provider.NativeZAINoToolsPolicyName
	joined = errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-native": profile}))
	if !strings.Contains(joined, "only valid") {
		t.Fatalf("native broker id was accepted: %q", joined)
	}
}

func TestProviderProfileBindsValidatedImmutableIdentity(t *testing.T) {
	profile := validZAIProviderProfile()
	identity, err := profile.Identity()
	if err != nil {
		t.Fatalf("Identity() error: %v", err)
	}
	if got, want := identity.Provider(), "zai"; got != want {
		t.Fatalf("provider = %q, want %q", got, want)
	}
	if got, want := identity.CapacityScope().String(), "provider:"+identity.Hash(); got != want {
		t.Fatalf("capacity scope = %q, want identity-specific scope", got)
	}
}

func TestValidateProviderProfilesRejectsUnqualifiedZAIAndAmbiguousTargets(t *testing.T) {
	profile := validZAIProviderProfile()
	profiles := map[string]ProviderProfileConfig{
		"zai-missing-gates": {
			Provider:         profile.Provider,
			AccountAlias:     profile.AccountAlias,
			Model:            profile.Model,
			Endpoint:         profile.Endpoint,
			Runtime:          profile.Runtime,
			ConfigSHA256:     profile.ConfigSHA256,
			Command:          profile.Command,
			AutomationPolicy: profile.AutomationPolicy,
		},
		"claude": profile,
	}

	errs := ValidateProviderProfiles(profiles)
	joined := errorsString(errs)
	for _, want := range []string{"exact_target_only", "probe_required", "ambiguous Claude-wide target"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ValidateProviderProfiles() = %q, want %q", joined, want)
		}
	}
}

func TestProviderProfileLookupProhibitsClaudeWideTargeting(t *testing.T) {
	cfg := Default()
	cfg.ProviderProfiles = map[string]ProviderProfileConfig{
		"zai-kevin-glm53": validZAIProviderProfile(),
	}

	got, err := cfg.ProviderProfile("zai-kevin-glm53")
	if err != nil {
		t.Fatalf("ProviderProfile(exact) error: %v", err)
	}
	if got.Provider != "zai" {
		t.Fatalf("ProviderProfile(exact).Provider = %q, want zai", got.Provider)
	}
	if _, err := cfg.ProviderProfile("claude"); err == nil || !strings.Contains(err.Error(), "ambiguous Claude-wide") {
		t.Fatalf("ProviderProfile(claude) error = %v, want an ambiguous-target error", err)
	}
	if _, err := cfg.ProviderProfile("ZAI-KEVIN-GLM53"); err == nil || !strings.Contains(err.Error(), "requires an exact target") {
		t.Fatalf("ProviderProfile(case-variant) error = %v, want an exact-target error", err)
	}

	unsafe := validZAIProviderProfile()
	unsafe.ProbeRequired = false
	cfg.ProviderProfiles["zai-unprobed"] = unsafe
	if _, err := cfg.ProviderProfile("zai-unprobed"); err == nil || !strings.Contains(err.Error(), "probe_required") {
		t.Fatalf("ProviderProfile(unprobed) error = %v, want probe gate", err)
	}
}

func TestPrintProviderProfilesRoundTripsWithoutCredentials(t *testing.T) {
	cfg := Default()
	cfg.ProviderProfiles = map[string]ProviderProfileConfig{
		"zai-kevin-glm53": validZAIProviderProfile(),
	}

	var buf bytes.Buffer
	if err := Print(cfg, &buf); err != nil {
		t.Fatalf("Print() error: %v", err)
	}
	printed := buf.String()
	if !strings.Contains(printed, `[provider_profiles."zai-kevin-glm53"]`) {
		t.Fatalf("Print() omitted provider profile table: %s", printed)
	}
	if strings.Contains(strings.ToLower(printed), "api_key") || strings.Contains(printed, "xai-") {
		t.Fatalf("Print() rendered an unexpected credential-shaped value: %s", printed)
	}

	var decoded Config
	if _, err := toml.Decode(printed, &decoded); err != nil {
		t.Fatalf("decode printed config: %v", err)
	}
	decodedProfile, err := decoded.ProviderProfile("zai-kevin-glm53")
	if err != nil {
		t.Fatalf("decoded ProviderProfile() error: %v", err)
	}
	if _, err := decodedProfile.Identity(); err != nil {
		t.Fatalf("decoded profile Identity() error: %v", err)
	}
}

func TestPrintNativeZAIProfileOmitsExternalCommand(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.CredentialClass = provider.CredentialClassAPIKey
	profile.BillingClass = provider.BillingClassAPIUsage
	profile.Entitlement = provider.EntitlementNativeAPI
	profile.Runtime = "zai-api"
	profile.Endpoint = zai.NativeChatCompletionsEndpoint
	profile.AutomationPolicy, profile.Command = provider.NativeZAINoToolsPolicyName, ""
	cfg := Default()
	cfg.ProviderProfiles = map[string]ProviderProfileConfig{"zai-native-api": profile}
	var buf bytes.Buffer
	if err := Print(cfg, &buf); err != nil {
		t.Fatal(err)
	}
	providerSection := buf.String()[strings.Index(buf.String(), `[provider_profiles."zai-native-api"]`):]
	providerSection = providerSection[:strings.Index(providerSection, "\n[tmux]")]
	if strings.Contains(providerSection, "command =") {
		t.Fatalf("native API print must not imply an external command: %s", providerSection)
	}
}

func TestValidateProviderProfilesRejectsUnsafeCommandAndInvalidIdentity(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.Command = "claude\n--unsafe"
	profile.Endpoint = "http://api.z.ai"
	profile.AutomationPolicy = ""
	errs := ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-kevin-glm53": profile})
	joined := errorsString(errs)
	for _, want := range []string{"endpoint must be an absolute HTTPS URL", "command must be non-empty", "automation_policy must be non-empty"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ValidateProviderProfiles() = %q, want %q", joined, want)
		}
	}
}

func TestValidateProviderProfilesRejectsACPCommandArgumentsAndWrongPolicy(t *testing.T) {
	profile := ProviderProfileConfig{
		Provider:         "xai",
		AccountAlias:     "kevin-dev",
		Model:            "grok-code-fast-1",
		Endpoint:         "https://api.x.ai",
		Runtime:          "grok",
		ConfigSHA256:     providerProfileTestHash,
		Command:          "grok --no-auto-update",
		AutomationPolicy: "always-approve",
		ExactTargetOnly:  true,
	}
	joined := errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"xai-grok-primary": profile}))
	for _, want := range []string{"must be one executable name", "grok-readonly-ci"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ValidateProviderProfiles() = %q, want %q", joined, want)
		}
	}
}

func TestValidateProviderProfilesAllowsAbsoluteACPExecutablePathWithSpaces(t *testing.T) {
	profile := ProviderProfileConfig{
		Provider:         "xai",
		AccountAlias:     "kevin-dev",
		Model:            "grok-code-fast-1",
		Endpoint:         "https://api.x.ai",
		Runtime:          "grok",
		ConfigSHA256:     providerProfileTestHash,
		Command:          "/opt/Grok CLI/grok",
		AutomationPolicy: agent.DefaultGrokAutomationPolicyName,
		ExactTargetOnly:  true,
	}
	if errs := ValidateProviderProfiles(map[string]ProviderProfileConfig{"xai-grok-primary": profile}); len(errs) != 0 {
		t.Fatalf("ValidateProviderProfiles() errors = %v", errs)
	}
}

func TestValidateProviderProfilesRejectsZAIPolicyAndPermissionBypass(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.AutomationPolicy = "custom"
	profile.Command = "claude --dangerously-skip-permissions"
	joined := errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-kevin-glm53": profile}))
	for _, want := range []string{provider.DefaultZAIAutomationPolicyName, "must be one executable"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ValidateProviderProfiles() = %q, want %q", joined, want)
		}
	}
}

func TestValidateProviderProfilesRejectsUnofficialZAIEndpointAndRuntime(t *testing.T) {
	profile := validZAIProviderProfile()
	profile.Endpoint = "https://example.invalid/api/anthropic"
	profile.Runtime = "claude-glm"
	joined := errorsString(ValidateProviderProfiles(map[string]ProviderProfileConfig{"zai-kevin-glm53": profile}))
	for _, want := range []string{"official Claude-compatible endpoint", "runtime must be claude-code"} {
		if !strings.Contains(joined, want) {
			t.Errorf("ValidateProviderProfiles() = %q, want %q", joined, want)
		}
	}
}

func errorsString(errs []error) string {
	parts := make([]string, 0, len(errs))
	for _, err := range errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "\n")
}
