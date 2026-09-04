package robot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
)

func TestGetProviderCapabilitiesRedactsConfiguredProfiles(t *testing.T) {
	configHash := strings.Repeat("a", 64)
	probeHash := strings.Repeat("b", 64)
	cfg := &config.Config{}
	cfg.ProviderProfiles = map[string]config.ProviderProfileConfig{
		"zai-operator-glm": {
			Provider: "zai", AccountAlias: "operator", Model: "glm-5.3-flash",
			Endpoint: "https://api.z.ai/api/anthropic", Runtime: "claude-code", ConfigSHA256: configHash,
			CredentialClass: provider.CredentialClassCodingPlan, BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementClaudeCompat,
			Command: "claude", AutomationPolicy: provider.DefaultZAIAutomationPolicyName,
			ExactTargetOnly: true, ProbeRequired: true, ModelProbeState: "live_verified", ModelProbeReceiptSHA256: probeHash,
		},
		"invalid-profile-with-secret": {
			Provider: "zai", AccountAlias: "bad", Model: "glm", Endpoint: "https://example.invalid/?token=secret-token",
			Runtime: "claude-code", ConfigSHA256: configHash, Command: "do-not-leak-secret-command", AutomationPolicy: "secret-policy",
			ModelProbeState: "not-a-real-state",
		},
	}

	output, err := GetProviderCapabilities(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !output.Success || !output.ConfigSupplied || len(output.ProviderProfiles) != 2 {
		t.Fatalf("output = %+v", output)
	}
	acp := output.Transports["xai_acp"]
	if acp.Completion != provider.EvidenceAuthoritative || acp.Cancellation != provider.EvidenceAuthoritative || acp.CancellationAuthorityScope != provider.EvidenceAuthorityScopeAgentACP || acp.Cleanup != provider.EvidenceAuthoritative || acp.CleanupAuthorityScope != provider.EvidenceAuthorityScopeLocalProcessTree || acp.CapacityControlScope != provider.CapacityControlScopeLocalShared || !output.OfflineConformanceHarness.Available {
		t.Fatalf("transport/conformance capability = %+v", output)
	}
	if len(output.GrokAutomationPolicies) != 2 || output.GrokAutomationPolicy.Name == "" || output.GrokAutomationPolicy.Sandbox != "strict" || output.GrokAutomationPolicy.SHA256 == "" || output.GrokAutomationPolicy.SystemRequirementsSHA256 == "" || output.GrokAutomationPolicy.SystemRequirementsScope != "global" || output.GrokAutomationPolicy.AllowRuleCount == 0 || output.GrokAutomationPolicy.DenyRuleCount == 0 {
		t.Fatalf("Grok policy capability = %+v", output.GrokAutomationPolicy)
	}
	workspace := output.GrokAutomationPolicies[1]
	if workspace.Name != "grok-workspace-write-ci" || workspace.Sandbox != "strict" || workspace.SystemRequirementsSHA256 == "" || workspace.SystemRequirementsScope != "global" || workspace.AllowRuleCount == 0 || workspace.DenyRuleCount == 0 {
		t.Fatalf("workspace policy capability = %+v", workspace)
	}
	if output.GrokAutomationPolicy.SystemRequirementsSHA256 != workspace.SystemRequirementsSHA256 {
		t.Fatalf("global system requirements digest differs by invocation policy: observe=%+v workspace=%+v", output.GrokAutomationPolicy, workspace)
	}
	native := output.Transports["zai_native_api"]
	if native.Completion != provider.EvidenceAuthoritative || native.CompletionAuthorityScope != provider.EvidenceAuthorityScopeProvider || native.LiveErrorFeedback != provider.EvidenceAuthoritative || native.Cancellation != provider.EvidenceUnavailable || native.CancellationAuthorityScope != provider.EvidenceAuthorityScopeUnavailable || native.Resume != provider.EvidenceUnavailable || native.Cleanup != provider.EvidenceSubmission || native.CleanupAuthorityScope != provider.EvidenceAuthorityScopeLocalClient || native.CapacityControlScope != provider.CapacityControlScopeLocalShared {
		t.Fatalf("native Z.ai capability = %+v", native)
	}
	headless := output.Transports["xai_headless_session"]
	if headless.Completion != provider.EvidenceAuthoritative || headless.CompletionAuthorityScope != provider.EvidenceAuthorityScopeProvider || headless.Resume != provider.EvidenceAuthoritative || headless.Cancellation != provider.EvidenceAuthoritative || headless.CancellationAuthorityScope != provider.EvidenceAuthorityScopeLocalProcessTree || headless.Cleanup != provider.EvidenceAuthoritative || headless.CleanupAuthorityScope != provider.EvidenceAuthorityScopeLocalProcessTree || headless.CapacityControlScope != provider.CapacityControlScopeLocalShared {
		t.Fatalf("native Grok headless capability = %+v", headless)
	}

	valid := output.ProviderProfiles[1]
	if valid.IdentityState != "valid" || valid.ProfileState != "live_probe_required" || valid.IdentitySHA256 == "" || !valid.ProbeRequired || !valid.ExactTargetOnly || valid.ModelProbeState != "live_verified" || valid.ModelProbeQualified {
		t.Fatalf("valid profile capability = %+v", valid)
	}
	invalid := output.ProviderProfiles[0]
	if invalid.IdentityState != "invalid" || invalid.ProfileState != "invalid" || invalid.IdentitySHA256 != "" || invalid.ModelProbeState != "unknown" || invalid.ModelProbeQualified {
		t.Fatalf("invalid profile capability = %+v", invalid)
	}

	encoded, err := json.Marshal(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"zai-operator-glm", "invalid-profile-with-secret", "https://api.z.ai", "credential.example", "secret-token", "do-not-leak-secret-command", "secret-policy", "XAI_API_KEY", configHash, probeHash} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("provider capability output leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestGetProviderCapabilitiesDoesNotCallConfiguredGrokProfileLaunchable(t *testing.T) {
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{
		"xai-grok": syntheticGrokProviderProfile("operator", "grok-4.6", "/tmp/grok-operator"),
	}}
	output, err := GetProviderCapabilities(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := output.ProviderProfiles[0].ProfileState; got != "operation_evidence_required" {
		t.Fatalf("configured Grok profile state = %q", got)
	}
}

func syntheticGrokProviderProfile(accountAlias, model, runtimeHome string) config.ProviderProfileConfig {
	profile := config.ProviderProfileConfig{
		Provider:                      "xai",
		AccountAlias:                  accountAlias,
		Model:                         model,
		Endpoint:                      "https://api.x.ai/v1",
		Runtime:                       "grok",
		RuntimeVersion:                "test",
		Command:                       "grok",
		RuntimeHome:                   runtimeHome,
		CredentialBridgeCommand:       "/usr/local/libexec/ntm/test-provider-bridge.exe",
		CredentialBridgeCommandSHA256: strings.Repeat("a", 64),
		AutomationPolicy:              "grok-readonly-ci",
		ExactTargetOnly:               true,
	}
	profile.ConfigSHA256 = profile.CanonicalManifestSHA256()
	return profile
}

func TestGetProviderCapabilitiesDoesNotPromoteTupleValidUnlaunchableProfile(t *testing.T) {
	hash := strings.Repeat("a", 64)
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{
		"zai-valid-tuple-invalid-policy": {
			Provider: "zai", AccountAlias: "operator", Model: "glm-5.3-flash",
			Endpoint: "https://api.z.ai/api/anthropic", Runtime: "claude-code", ConfigSHA256: hash,
			CredentialClass: provider.CredentialClassCodingPlan, BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementClaudeCompat,
			Command: "claude", AutomationPolicy: "",
			ExactTargetOnly: true, ProbeRequired: true, ModelProbeState: "qualified", ModelProbeReceiptSHA256: hash,
		},
	}}

	output, err := GetProviderCapabilities(cfg)
	if err != nil {
		t.Fatal(err)
	}
	profile := output.ProviderProfiles[0]
	if profile.IdentityState != "valid" || profile.IdentitySHA256 == "" {
		t.Fatalf("tuple evidence should remain independently valid: %+v", profile)
	}
	if profile.ProfileState != "invalid" || profile.ModelProbeQualified {
		t.Fatalf("unlaunchable profile was promoted: %+v", profile)
	}
}

func TestGetProviderCapabilitiesWithoutConfigUsesEmptyProfileArray(t *testing.T) {
	output, err := GetProviderCapabilities(nil)
	if err != nil {
		t.Fatal(err)
	}
	if output.ConfigSupplied || output.ProviderProfiles == nil || len(output.ProviderProfiles) != 0 {
		t.Fatalf("nil-config receipt = %+v", output)
	}
}

func TestPrintProviderCapabilitiesEmitsRobotJSON(t *testing.T) {
	original := GetOutputFormat()
	SetOutputFormat(FormatJSON)
	t.Cleanup(func() { SetOutputFormat(original) })
	stdout, err := captureStdout(t, func() error { return PrintProviderCapabilities(nil) })
	if err != nil {
		t.Fatal(err)
	}
	var decoded ProviderCapabilitiesOutput
	if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
		t.Fatalf("decode PrintProviderCapabilities output: %v; output=%q", err, stdout)
	}
	if !decoded.Success || decoded.ProviderProfiles == nil || decoded.OfflineConformanceHarness.Description == "" {
		t.Fatalf("printed output = %+v", decoded)
	}
}
