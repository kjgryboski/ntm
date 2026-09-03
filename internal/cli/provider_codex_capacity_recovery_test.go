package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

type providerCodexCapacityRecoveryAdmissionFake struct {
	status       ratelimit.CapacityStatus
	before       ratelimit.SubscriptionCapacitySnapshot
	after        ratelimit.SubscriptionCapacitySnapshot
	credits      float64
	recoverErr   error
	recoverCalls int
}

func (f *providerCodexCapacityRecoveryAdmissionFake) CapacityStatus() ratelimit.CapacityStatus {
	return f.status
}

func (f *providerCodexCapacityRecoveryAdmissionFake) Snapshot(provider.Identity) ratelimit.SubscriptionCapacitySnapshot {
	if f.recoverCalls == 0 {
		return f.before
	}
	return f.after
}

func (f *providerCodexCapacityRecoveryAdmissionFake) ApplyLegacyUnknownUsageAuthorization(provider.Identity, ratelimit.TokenUsage, time.Time, string) (float64, error) {
	f.recoverCalls++
	return f.credits, f.recoverErr
}

func TestProviderCodexCapacityRecoveryRequiresExplicitApply(t *testing.T) {
	called := false
	deps := providerCodexCapacityRecoveryDependencies{loadConfig: func() *config.Config {
		called = true
		return nil
	}}
	err := runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "op-1", rolloutFile: "/isolated/rollout.jsonl"}, deps)
	if err == nil || called {
		t.Fatalf("err=%v dependency_called=%t", err, called)
	}
}

func TestProviderCodexCapacityRecoveryRequiresExplicitLegacyAcceptance(t *testing.T) {
	called := false
	deps := providerCodexCapacityRecoveryDependencies{loadConfig: func() *config.Config {
		called = true
		return nil
	}}
	err := runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "op-1", rolloutFile: "/isolated/rollout.jsonl", apply: true}, deps)
	if err == nil || called {
		t.Fatalf("err=%v dependency_called=%t", err, called)
	}
}

func TestProviderCodexCapacityRecoveryRejectsUnboundRollout(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Unix(2_000_000_100, 0).UTC()
	evidence := providerCodexRecoveryEvidenceForTest(completedAt)
	manifest := providerCodexManifestForTest(profile)
	ledger := &providerNativeLedgerFake{}
	_, _, err = ledger.ClaimSendOperation(&state.SendOperation{
		OperationID: "legacy-op", SessionName: providerCodexOperationScope,
		BindingHash: strings.Repeat("9", 64), PayloadSHA256: strings.Repeat("8", 64), PayloadBytes: 10,
		CreatedAt: completedAt.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := providerCodexRecoveryAdmissionForTest(identity)
	deps := providerCodexRecoveryDependenciesForTest(profile, manifest, evidence, admission, ledger, completedAt.Add(time.Minute))
	err = runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "legacy-op", rolloutFile: "/isolated/rollout.jsonl", apply: true, acceptUnboundLegacy: true}, deps)
	if err == nil || admission.recoverCalls != 0 {
		t.Fatalf("err=%v recovery_calls=%d", err, admission.recoverCalls)
	}
}

func TestProviderCodexCapacityRecoveryStoresSignedReceiptAndKeepsOperationBlocked(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Unix(2_000_000_100, 0).UTC()
	evidence := providerCodexRecoveryEvidenceForTest(completedAt)
	manifest := providerCodexManifestForTest(profile)
	operationID := "legacy-op"
	payloadSHA := strings.Repeat("8", 64)
	binding := providerCodexBindingHashFromDigests(identity, payloadSHA, evidence.CWDSHA256, false, providerCodexWorkloadImplementation, false, sha256StringCLI(""), manifest)
	ledger := &providerNativeLedgerFake{}
	_, _, err = ledger.ClaimSendOperation(&state.SendOperation{
		OperationID: operationID, SessionName: providerCodexOperationScope,
		BindingHash: binding, PayloadSHA256: payloadSHA, PayloadBytes: 10,
		CreatedAt: completedAt.Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := providerCodexRecoveryAdmissionForTest(identity)
	deps := providerCodexRecoveryDependenciesForTest(profile, manifest, evidence, admission, ledger, completedAt.Add(time.Minute))
	recoveryDir := t.TempDir()
	deps.recoveryStoreDir = func() string { return recoveryDir }
	stored := false
	deps.store = func(baseDir string, receipt providerqualification.Receipt) (string, error) {
		stored = true
		if baseDir != recoveryDir || receipt.Transport != "zai_codex_capacity_recovery_authorization" || receipt.Provider != "zai" || receipt.IdentitySHA256 != identity.Hash() || !receipt.Passed || receipt.Attestation == nil || receipt.Validate() != nil {
			t.Fatalf("base=%q receipt=%+v", baseDir, receipt)
		}
		return "/redacted/recovery.json", nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderCodexCapacityRecovery(cmd, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: operationID, rolloutFile: "/isolated/rollout.jsonl", apply: true, acceptUnboundLegacy: true}, deps)
	if err != nil || !stored || admission.recoverCalls != 1 || !strings.Contains(output.String(), "evidence remains unbound") {
		t.Fatalf("err=%v stored=%t calls=%d output=%q", err, stored, admission.recoverCalls, output.String())
	}
	operation, err := ledger.GetSendOperation(operationID, providerCodexOperationScope)
	if err != nil || !validBlockedProviderCodexOperation(operation) {
		t.Fatalf("operation=%+v err=%v", operation, err)
	}
}

func TestProviderCodexCapacityRecoveryStoresAuthorizationBeforeMutation(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	completedAt := time.Unix(2_000_000_100, 0).UTC()
	evidence := providerCodexRecoveryEvidenceForTest(completedAt)
	manifest := providerCodexManifestForTest(profile)
	payloadSHA := strings.Repeat("8", 64)
	binding := providerCodexBindingHashFromDigests(identity, payloadSHA, evidence.CWDSHA256, false, providerCodexWorkloadImplementation, false, sha256StringCLI(""), manifest)
	ledger := &providerNativeLedgerFake{}
	_, _, err = ledger.ClaimSendOperation(&state.SendOperation{OperationID: "legacy-op", SessionName: providerCodexOperationScope, BindingHash: binding, PayloadSHA256: payloadSHA, PayloadBytes: 10, CreatedAt: completedAt.Add(-time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	admission := providerCodexRecoveryAdmissionForTest(identity)
	deps := providerCodexRecoveryDependenciesForTest(profile, manifest, evidence, admission, ledger, completedAt.Add(time.Minute))
	deps.store = func(string, providerqualification.Receipt) (string, error) { return "", errors.New("disk unavailable") }
	err = runProviderCodexCapacityRecovery(&cobra.Command{}, providerCodexCapacityRecoveryOptions{profile: "zai-codex", operationID: "legacy-op", rolloutFile: "/isolated/rollout.jsonl", apply: true, acceptUnboundLegacy: true}, deps)
	if err == nil || admission.recoverCalls != 0 {
		t.Fatalf("err=%v recovery_calls=%d", err, admission.recoverCalls)
	}
}

func providerCodexRecoveryEvidenceForTest(completedAt time.Time) zai.CodexRolloutRecoveryEvidence {
	return zai.CodexRolloutRecoveryEvidence{
		RolloutSHA256: strings.Repeat("1", 64), SessionSHA256: strings.Repeat("2", 64),
		TurnSHA256: strings.Repeat("3", 64), NonceSHA256: strings.Repeat("4", 64), CWDSHA256: strings.Repeat("5", 64),
		InputTokens: 100, CachedTokens: 20, OutputTokens: 5, CompletedAt: completedAt, RuntimeVersion: "0.149.0",
	}
}

func providerCodexManifestForTest(profile config.ProviderProfileConfig) zai.CodexManifestAttestation {
	return zai.CodexManifestAttestation{
		ConfigSHA256: profile.ConfigSHA256, BinarySHA256: profile.RuntimeSHA256,
		AuthHelperSHA256: profile.BrokerCommandSHA256, CredentialBridgeSHA256: profile.CredentialBridgeCommandSHA256,
		RuntimeVersion: profile.RuntimeVersion,
	}
}

func providerCodexRecoveryAdmissionForTest(identity provider.Identity) *providerCodexCapacityRecoveryAdmissionFake {
	scope := strings.Repeat("6", 64)
	return &providerCodexCapacityRecoveryAdmissionFake{
		status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}, credits: 3.84,
		before: ratelimit.SubscriptionCapacitySnapshot{
			IdentityHash: identity.Hash(), SubscriptionScopeSHA256: scope, Scope: provider.CapacityControlScopeLocalShared,
			FiveHourCreditsUsed: 10_000, FiveHourCreditsLimit: 2_000, WeeklyCreditsUsed: 10_000, WeeklyCreditsLimit: 10_000,
			UnknownUsageReserved: true,
		},
		after: ratelimit.SubscriptionCapacitySnapshot{
			IdentityHash: identity.Hash(), SubscriptionScopeSHA256: scope, Scope: provider.CapacityControlScopeLocalShared,
			FiveHourCreditsUsed: 3.84, FiveHourCreditsLimit: 2_000, WeeklyCreditsUsed: 3.84, WeeklyCreditsLimit: 10_000,
			ConservativeUsage: true, LegacyRecoveryAuthorized: true,
		},
	}
}

func providerCodexRecoveryDependenciesForTest(profile config.ProviderProfileConfig, manifest zai.CodexManifestAttestation, evidence zai.CodexRolloutRecoveryEvidence, admission providerCodexCapacityRecoveryAdmission, ledger providerNativeOperationLedger, now time.Time) providerCodexCapacityRecoveryDependencies {
	return providerCodexCapacityRecoveryDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-codex": profile}}
		},
		attest: func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error) {
			return manifest, nil
		},
		pinnedSigner: func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
			return newProviderNativeTestSigner(), nil
		},
		admission: admission,
		openLedger: func() (providerNativeOperationLedger, func() error, error) {
			return ledger, func() error { return nil }, nil
		},
		readRollout:      func(string, string, string) (zai.CodexRolloutRecoveryEvidence, error) { return evidence, nil },
		store:            func(string, providerqualification.Receipt) (string, error) { return "", errors.New("unexpected store") },
		recoveryStoreDir: func() string { return "/recovery" },
		now:              func() time.Time { return now },
	}
}
