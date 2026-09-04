package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

func TestAuthorizeProviderOperationUsesSignedPartialPromotion(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	checks := make([]providerqualification.Check, 0, len(providerqualification.CodexRequiredChecks()))
	for _, name := range providerqualification.CodexRequiredChecks() {
		passed := name == providerqualification.CheckIdentity || name == providerqualification.CheckSecretDenied || name == providerqualification.CheckPushDenied
		detail := ""
		if name == providerqualification.CheckIdentity {
			detail = providerCodexQualificationModelGate
		}
		checks = append(checks, providerqualification.Check{Name: name, Passed: passed, Provenance: "live", EvidenceSHA256: strings.Repeat("a", 64), Detail: detail})
	}
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "zai", Transport: "zai_codex_runtime",
		IdentitySHA256: identity.Hash(), PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: profile.RuntimeSHA256,
		StartedAt: now.Add(-time.Minute), CompletedAt: now, DisposableRepoHash: strings.Repeat("b", 64), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := newProviderNativeTestSigner()(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatal(err)
	}
	input := providerOperationAuthorization{
		Identity: identity, Transport: "zai_codex_runtime", PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: profile.RuntimeSHA256,
		Operation: providerOperationReview, MaxQualificationAge: time.Hour, TrustedSigner: signature.KeyMetadata,
	}
	deps := providerOperationAuthorizationDependencies{
		load: func(_, _, transport string) (providerqualification.Receipt, string, error) {
			if transport != "zai_codex_runtime" {
				t.Fatalf("unexpected qualification transport %q", transport)
			}
			return receipt, "receipt.json", nil
		},
		now: func() time.Time { return now.Add(time.Minute) },
	}
	if digest, err := authorizeProviderOperationWithDependencies(input, deps); err != nil || digest != receipt.ReceiptSHA256 {
		t.Fatalf("review authorization digest=%q err=%v", digest, err)
	}
	input.RuntimeSHA256 = strings.Repeat("d", 64)
	if _, err := authorizeProviderOperationWithDependencies(input, deps); err == nil {
		t.Fatal("review authorization reused a same-version qualification across a runtime digest change")
	}
	input.RuntimeSHA256 = profile.RuntimeSHA256
	input.TrustedSigner.PublicKeySHA256 = strings.Repeat("c", 64)
	if _, err := authorizeProviderOperationWithDependencies(input, deps); err == nil {
		t.Fatal("review authorization ignored trusted signer mismatch")
	}
	input.TrustedSigner = signature.KeyMetadata
	input.Operation = providerOperationWorkspaceWrite
	if _, err := authorizeProviderOperationWithDependencies(input, deps); err == nil {
		t.Fatal("workspace-write authorization ignored failed edit/test checks")
	}
	weakReceipt := receipt
	for index := range weakReceipt.Checks {
		if weakReceipt.Checks[index].Name == providerqualification.CheckIdentity {
			weakReceipt.Checks[index].EvidenceSHA256 = ""
		}
	}
	if err := weakReceipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	weakPayload, err := weakReceipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	weakSignature, err := newProviderNativeTestSigner()(context.Background(), weakPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := weakReceipt.AttachAttestation(weakSignature); err != nil {
		t.Fatal(err)
	}
	deps.load = func(string, string, string) (providerqualification.Receipt, string, error) {
		return weakReceipt, "weak.json", nil
	}
	input.Operation = providerOperationReview
	input.TrustedSigner = weakSignature.KeyMetadata
	if _, err := authorizeProviderOperationWithDependencies(input, deps); err == nil {
		t.Fatal("review authorization accepted a positive check without authoritative evidence")
	}
}

func TestAuthorizeProviderOperationRejectsUnsignedInvalidReceipt(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	input := providerOperationAuthorization{
		Identity: identity, Transport: "zai_codex_runtime", PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: profile.RuntimeSHA256,
		Operation: providerOperationReview, MaxQualificationAge: time.Hour,
	}
	deps := providerOperationAuthorizationDependencies{
		load: func(string, string, string) (providerqualification.Receipt, string, error) {
			return providerqualification.Receipt{}, "", nil
		},
		now: time.Now,
	}
	if _, err := authorizeProviderOperationWithDependencies(input, deps); err == nil {
		t.Fatal("unsigned invalid receipt was authorized")
	}
}

func TestAuthorizeProviderOperationRejectsPartialGrokHeadlessLineageReceipt(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	checks := make([]providerqualification.Check, 0, len(providerqualification.GrokRequiredChecks()))
	for _, name := range providerqualification.GrokRequiredChecks() {
		passed := name == providerqualification.CheckIdentity || name == providerqualification.CheckResume || name == providerqualification.CheckProcessCleanup
		checks = append(checks, providerqualification.Check{
			Name: name, Passed: passed, Provenance: "live", EvidenceSHA256: strings.Repeat("a", 64), Detail: "headless lineage qualification check",
		})
	}
	policySHA256 := agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
	runtimeSHA256 := strings.Repeat("c", 64)
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "xai", Transport: "xai_headless_session",
		IdentitySHA256: identity.Hash(), PolicySHA256: policySHA256, RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: runtimeSHA256,
		StartedAt: now.Add(-time.Minute), CompletedAt: now, DisposableRepoHash: strings.Repeat("b", 64), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := newProviderNativeTestSigner()(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatal(err)
	}
	input := providerOperationAuthorization{
		Identity: identity, Transport: receipt.Transport, PolicySHA256: policySHA256, RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: runtimeSHA256,
		MaxQualificationAge: time.Hour, TrustedSigner: signature.KeyMetadata,
	}
	deps := providerOperationAuthorizationDependencies{
		load: func(_, _, transport string) (providerqualification.Receipt, string, error) {
			if transport != receipt.Transport {
				t.Fatalf("unexpected qualification transport %q", transport)
			}
			return receipt, "headless-lineage.json", nil
		},
		now: func() time.Time { return now.Add(time.Minute) },
	}
	for _, operation := range []string{providerOperationReview, providerOperationWorkspaceWrite, providerOperationLifecycle} {
		input.Operation = operation
		if digest, err := authorizeProviderOperationWithDependencies(input, deps); err == nil || digest != "" {
			t.Fatalf("operation %q accepted partial Grok lineage receipt: digest=%q err=%v", operation, digest, err)
		}
	}
}

func TestAuthorizeProviderOperationPromotesOnlyQualifiedGrokWorkspaceOperations(t *testing.T) {
	profile := providerTestGrokProfile(agent.GrokWorkspaceWritePolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	workspaceChecks := map[string]bool{
		providerqualification.CheckIdentity:       true,
		providerqualification.CheckWorkspaceEdit:  true,
		providerqualification.CheckTestCommand:    true,
		providerqualification.CheckSecretDenied:   true,
		providerqualification.CheckPushDenied:     true,
		providerqualification.CheckProcessCleanup: true,
	}
	checks := make([]providerqualification.Check, 0, len(providerqualification.GrokRequiredChecks()))
	for _, name := range providerqualification.GrokRequiredChecks() {
		checks = append(checks, providerqualification.Check{
			Name: name, Passed: workspaceChecks[name], Provenance: "live", EvidenceSHA256: strings.Repeat("a", 64), Detail: "workspace qualification check",
		})
	}
	policySHA256 := agent.GrokAutomationPolicySHA256(profile.AutomationPolicy)
	runtimeSHA256 := strings.Repeat("c", 64)
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "xai", Transport: "xai_acp",
		IdentitySHA256: identity.Hash(), PolicySHA256: policySHA256, RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: runtimeSHA256,
		StartedAt: now.Add(-time.Minute), CompletedAt: now, DisposableRepoHash: strings.Repeat("b", 64), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := newProviderNativeTestSigner()(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatal(err)
	}
	input := providerOperationAuthorization{
		Identity: identity, Transport: receipt.Transport, PolicySHA256: policySHA256, RuntimeVersion: profile.RuntimeVersion, RuntimeSHA256: runtimeSHA256,
		MaxQualificationAge: time.Hour, TrustedSigner: signature.KeyMetadata,
	}
	deps := providerOperationAuthorizationDependencies{
		load: func(_, _, transport string) (providerqualification.Receipt, string, error) {
			if transport != receipt.Transport {
				t.Fatalf("unexpected qualification transport %q", transport)
			}
			return receipt, "workspace.json", nil
		},
		now: func() time.Time { return now.Add(time.Minute) },
	}
	for _, operation := range []string{providerOperationReview, providerOperationWorkspaceWrite} {
		input.Operation = operation
		if digest, err := authorizeProviderOperationWithDependencies(input, deps); err != nil || digest != receipt.ReceiptSHA256 {
			t.Fatalf("operation %q digest=%q err=%v", operation, digest, err)
		}
	}
	input.Operation = providerOperationLifecycle
	if digest, err := authorizeProviderOperationWithDependencies(input, deps); err == nil || digest != "" {
		t.Fatalf("lifecycle accepted workspace-only receipt: digest=%q err=%v", digest, err)
	}

	locallyAsserted := receipt
	for index := range locallyAsserted.Checks {
		if locallyAsserted.Checks[index].Name == providerqualification.CheckIdentity {
			locallyAsserted.Checks[index].Provenance = "local_authoritative"
		}
	}
	if err := locallyAsserted.Finalize(); err != nil {
		t.Fatal(err)
	}
	localPayload, err := locallyAsserted.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	localSignature, err := newProviderNativeTestSigner()(context.Background(), localPayload)
	if err != nil {
		t.Fatal(err)
	}
	if err := locallyAsserted.AttachAttestation(localSignature); err != nil {
		t.Fatal(err)
	}
	deps.load = func(string, string, string) (providerqualification.Receipt, string, error) {
		return locallyAsserted, "locally-asserted-workspace.json", nil
	}
	input.Operation = providerOperationReview
	input.TrustedSigner = localSignature.KeyMetadata
	if digest, err := authorizeProviderOperationWithDependencies(input, deps); err == nil || digest != "" {
		t.Fatalf("locally asserted Grok identity was accepted: digest=%q err=%v", digest, err)
	}
}
