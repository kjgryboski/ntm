package robot

import (
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
)

func TestGetProviderConformanceRunsSyntheticHarnessWithoutCoordinationStores(t *testing.T) {
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{
		"xai-primary": syntheticGrokProviderProfile("test", "grok-code", "/tmp/grok-test"),
		"zai-primary": {
			Provider: "zai", AccountAlias: "test", Model: "glm-5.3-flash", Endpoint: "https://api.z.ai/api/anthropic",
			Runtime: "claude-code", ConfigSHA256: strings.Repeat("b", 64), Command: "claude",
			CredentialClass: provider.CredentialClassCodingPlan, BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementClaudeCompat,
			AutomationPolicy: provider.DefaultZAIAutomationPolicyName, ExactTargetOnly: true, ProbeRequired: true,
			ModelProbeState: "qualified", ModelProbeReceiptSHA256: strings.Repeat("c", 64),
		},
		"zai-native": {
			Provider: "zai", AccountAlias: "native-test", Model: "glm-test", Endpoint: "https://api.z.ai/api/paas/v4/chat/completions",
			Runtime: "zai-api", RuntimeVersion: "zai-native-http-v1", ConfigSHA256: strings.Repeat("d", 64),
			CredentialClass: provider.CredentialClassAPIKey, BillingClass: provider.BillingClassAPIUsage, Entitlement: provider.EntitlementNativeAPI,
			AutomationPolicy: provider.NativeZAINoToolsPolicyName, ExactTargetOnly: true, ProbeRequired: true,
		},
		"zai-codex": {
			Provider: "zai", AccountAlias: "coding-plan", Model: "glm-5.3", Endpoint: "https://api.z.ai/api/v1",
			Runtime: "codex", RuntimeVersion: "0.149.0", ConfigSHA256: strings.Repeat("e", 64), Command: "/usr/bin/codex", RuntimeHome: "/tmp/zai-codex",
			CredentialClass: provider.CredentialClassCodingPlan, BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementCodexResponses,
			AutomationPolicy: provider.DefaultZAICodexAutomationPolicyName, ExactTargetOnly: true, ProbeRequired: true,
			BrokerCredentialID: "ntm.zai.coding_plan.test-account",
			RuntimeSHA256:      strings.Repeat("f", 64), BrokerCommand: "/usr/bin/caam", BrokerCommandSHA256: strings.Repeat("1", 64),
			CredentialBridgeCommand: "/usr/bin/ntm-provider-bridge", CredentialBridgeCommandSHA256: strings.Repeat("2", 64),
		},
	}}
	for _, test := range []struct {
		profile, transport string
		fixtureComplete    bool
	}{
		{"xai-primary", "xai_acp", true},
		{"xai-primary", "xai_headless_session", false},
		{"xai-primary", "xai_grok_tui", false},
		{"zai-primary", "zai_claude_runtime", false},
		{"zai-codex", "zai_codex_runtime", true},
		{"zai-native", "zai_native_api", false},
	} {
		out, err := GetProviderConformance(t.Context(), cfg, test.profile, test.transport)
		if err != nil || out.Mode != "synthetic_offline" || out.Report.Coverage.Satisfied != 7 || out.Passed != test.fixtureComplete || out.Success != test.fixtureComplete {
			t.Fatalf("%s output=%+v err=%v", test.transport, out, err)
		}
		if test.fixtureComplete && (out.Report.EventContract == nil || !out.Report.EventContract.Passed || out.Report.EventContract.ReceiptSHA256 == "" || !out.Report.Fixture.GoldenSignatureValid || out.Report.Fixture.SignedEventModel == "") {
			t.Fatalf("%s did not replay the shared event contract: %+v", test.transport, out.Report.EventContract)
		}
		if !test.fixtureComplete && (out.Report.EventContract == nil || out.Report.EventContract.Passed || len(out.Report.EventContract.Violations) == 0) {
			t.Fatalf("%s fabricated offline event-contract coverage: %+v", test.transport, out.Report.EventContract)
		}
	}
}

func TestGetProviderConformanceRejectsProviderTransportMismatch(t *testing.T) {
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{
		"xai-primary": syntheticGrokProviderProfile("test", "grok-code", "/tmp/grok-test"),
	}}
	if _, err := GetProviderConformance(t.Context(), cfg, "xai-primary", "zai_claude_runtime"); err == nil {
		t.Fatal("provider/transport mismatch was accepted")
	}
}
