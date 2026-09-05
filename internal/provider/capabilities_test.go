package provider

import "testing"

func TestPrimaryCapabilitiesSeparateLocalRestartFromResumeAndRequestAccounting(t *testing.T) {
	for _, transport := range []string{"openai_codex_comparison", "anthropic_claude_comparison"} {
		c, ok := CapabilityMatrix()[transport]
		if !ok || c.IdentityEvidence != IdentityEvidenceProfileAttested || c.CancellationAuthorityScope != EvidenceAuthorityScopeLocalProcessTree || c.Resume != EvidenceUnavailable || c.RequestCapacityControl != EvidenceUnavailable || c.LocalLifecycleSupported() {
			t.Fatalf("primary capability overstatement for %s: %+v", transport, c)
		}
	}
}
