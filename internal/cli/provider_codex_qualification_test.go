package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

type orderedCodexQualificationAdmissionFake struct {
	codexQualificationAdmissionFake
	claimedBeforeAcquire func() bool
}

func (f *orderedCodexQualificationAdmissionFake) Acquire(identity provider.Identity) ratelimit.SubscriptionDecision {
	if f.claimedBeforeAcquire != nil && !f.claimedBeforeAcquire() {
		return ratelimit.SubscriptionDecision{Reason: ratelimit.ErrorUnknown, NoFailover: true}
	}
	return f.codexQualificationAdmissionFake.Acquire(identity)
}

type codexQualificationAdmissionFake struct {
	decision                                                                       ratelimit.SubscriptionDecision
	status                                                                         ratelimit.CapacityStatus
	acquires, releases, bindings, successes, usages, conservative, unknownReserved int
	canceledReservations                                                           int
	bindErr, usageErr, unknownErr, cancelErr                                       error
}

func (f *codexQualificationAdmissionFake) Acquire(provider.Identity) ratelimit.SubscriptionDecision {
	f.acquires++
	return f.decision
}
func (f *codexQualificationAdmissionFake) Release(provider.Identity, ratelimit.SubscriptionDecision) {
	f.releases++
}
func (f *codexQualificationAdmissionFake) BindReservation(provider.Identity, ratelimit.SubscriptionDecision, string, string) error {
	f.bindings++
	return f.bindErr
}
func (f *codexQualificationAdmissionFake) RecordUsage(provider.Identity, ratelimit.SubscriptionDecision, string, ratelimit.TokenUsage, time.Time) error {
	f.usages++
	return f.usageErr
}
func (f *codexQualificationAdmissionFake) RecordConservativeUsage(provider.Identity, ratelimit.SubscriptionDecision, ratelimit.TokenUsage, time.Time) error {
	f.conservative++
	return f.usageErr
}
func (f *codexQualificationAdmissionFake) RecordUnknownUsage(provider.Identity, ratelimit.SubscriptionDecision) error {
	f.unknownReserved++
	return f.unknownErr
}
func (f *codexQualificationAdmissionFake) CancelReservation(provider.Identity, ratelimit.SubscriptionDecision) error {
	f.canceledReservations++
	return f.cancelErr
}
func (f *codexQualificationAdmissionFake) RecordSuccess(provider.Identity)          { f.successes++ }
func (f *codexQualificationAdmissionFake) CapacityStatus() ratelimit.CapacityStatus { return f.status }

func TestProviderCodexQualificationProducesTenGateReceiptAndCleansGeneratedRoot(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	var workspace providerCodexQualificationWorkspace
	var storedPath string
	var storedChecks int
	var accountingDetail string
	var preflightStored providerqualification.Receipt
	calls := 0
	var preflightCWD string
	deps := codexQualificationDepsForTest(profile, admission, func(ctx context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		if spec.ManifestVerifier == nil || spec.ManifestVerifier(ctx) != nil {
			t.Fatal("qualification turn omitted its manifest verifier")
		}
		if calls == 1 {
			preflightCWD = spec.CWD
			if spec.WorkspaceWrite || spec.ExpectedFileChange != "" || spec.ExpectedToolCommand != "" {
				t.Fatal("identity preflight was not read-only and no-tool")
			}
		}
		if calls == 2 {
			if !spec.WorkspaceWrite {
				t.Fatal("edit turn did not receive workspace write")
			}
			if spec.ExpectedFileChange != "qualification.go" {
				t.Fatalf("edit expected file=%q", spec.ExpectedFileChange)
			}
			if err := os.WriteFile(filepath.Join(spec.CWD, "qualification.go"), []byte(workspace.ExpectedContent), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if calls == 4 && spec.ExpectedToolCommand != "git push origin HEAD:refs/heads/qualification-push" {
			t.Fatalf("push command=%q", spec.ExpectedToolCommand)
		}
		if calls == 4 && !providerCodexQualificationRemoteRefAbsent(ctx, workspace.Remote, "refs/heads/qualification-push") {
			t.Fatal("controlled remote unexpectedly contains the qualification ref")
		}
		if calls == 5 { // cancellation turn
			if spec.SessionObserver == nil {
				t.Fatal("cancellation session observer missing")
			}
			spec.SessionObserver("11111111-1111-1111-1111-111111111111")
			<-ctx.Done()
			r := successfulProviderCodexReceipt(spec)
			r.OutcomeKnown, r.CompletionConfirmed, r.NonceVerified = false, false, false
			r.Cancellation.LocalTermination = "observed_tree_terminated_verified"
			r.ZeroResiduals = true
			return r, ctx.Err()
		}
		r := successfulProviderCodexReceipt(spec)
		if spec.ExpectedFileChange != "" {
			r.ToolEventCount = 1
			r.ExpectedFileObserved = true
		}
		if spec.ExpectedToolCommand != "" {
			r.ToolEventCount = 1
			r.ExpectedToolObserved, r.ExpectedToolDenied = true, true
		}
		if spec.Resume {
			if spec.WorkspaceWrite {
				t.Fatal("resume turn must be read-only")
			}
			r.SessionIDSHA256 = sha256StringCLI(spec.ParentSession)
			r.ParentSessionSHA256 = sha256StringCLI(spec.ParentSession)
		}
		refreshProviderCodexRuntimeContract(&r, spec)
		return r, nil
	})
	deps.prepare = func(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
		var e error
		workspace, e = prepareProviderCodexQualificationWorkspace(ctx, token)
		return workspace, e
	}
	deps.store = func(_ string, receipt providerqualification.Receipt) (string, error) {
		storedChecks = countPassedQualificationChecks(receipt)
		for _, check := range receipt.Checks {
			if check.Name == "capacity_accounting" {
				accountingDetail = check.Detail
			}
		}
		storedPath = filepath.Join(workspace.Root, "receipt.json")
		return storedPath, nil
	}
	deps.storePreflight = func(receipt providerqualification.Receipt) (string, error) {
		preflightStored = receipt
		return "/redacted/passed-identity-preflight.json", nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := runProviderCodexQualification(cmd, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute, exerciseUnknownOutcomeLifecycle: true, acceptFullWeekReservation: true}, profile, identity, deps); err != nil {
		t.Fatal(err)
	}
	if calls != 6 || storedChecks != 10 || admission.acquires != 6 || admission.releases != 6 || admission.bindings != 6 || admission.successes != 1 || admission.usages != 5 || admission.unknownReserved != 1 || admission.canceledReservations != 0 || !strings.Contains(accountingDetail, "Identity preflight: provider_usage_reconciled=1") || !strings.Contains(accountingDetail, "provider_usage_reconciled=4") || !strings.Contains(output.String(), "10/10") {
		t.Fatalf("calls=%d checks=%d admission=%+v output=%q", calls, storedChecks, admission, output.String())
	}
	if !codexQualificationWorkspaceRemoved(workspace) || strings.Contains(storedPath, "qualification.go") || preflightCWD == "" {
		t.Fatalf("unsafe cleanup/path: root=%q stored=%q", workspace.Root, storedPath)
	}
	if _, err := os.Stat(preflightCWD); !os.IsNotExist(err) {
		t.Fatalf("identity preflight directory was not removed: %q err=%v", preflightCWD, err)
	}
	if preflightStored.Transport != "zai_codex_identity_preflight" || !preflightStored.Passed || preflightStored.Attestation == nil || preflightStored.Validate() != nil {
		t.Fatalf("signed passed preflight receipt=%+v validate=%v", preflightStored, preflightStored.Validate())
	}
}

func TestProviderCodexIdentityOnlyRunsExactlyOneSignedReadOnlyPreflight(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{
		decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	calls := 0
	var stored providerqualification.Receipt
	deps := codexQualificationDepsForTest(profile, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		if spec.WorkspaceWrite || spec.Resume || spec.ExpectedToolCommand != "" || spec.ExpectedFileChange != "" {
			t.Fatalf("identity-only preflight received mutating/lifecycle spec: %+v", spec)
		}
		return successfulProviderCodexReceipt(spec), nil
	})
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		t.Fatal("identity-only preflight prepared a coding worktree")
		return providerCodexQualificationWorkspace{}, nil
	}
	deps.store = func(string, providerqualification.Receipt) (string, error) {
		t.Fatal("identity-only preflight stored a coding qualification")
		return "", nil
	}
	deps.storePreflight = func(receipt providerqualification.Receipt) (string, error) {
		stored = receipt
		return "/redacted/identity-only.json", nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderCodexQualification(cmd, providerQualificationOptions{
		profile: "zai-codex", live: true, identityOnly: true, timeout: time.Second, suiteTimeout: time.Minute,
	}, profile, identity, deps)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || admission.acquires != 1 || admission.releases != 1 || admission.bindings != 1 || admission.usages != 1 || admission.successes != 1 {
		t.Fatalf("identity-only dispatch/admission counts: calls=%d admission=%+v", calls, admission)
	}
	if !stored.Passed || stored.Transport != "zai_codex_identity_preflight" || stored.Attestation == nil || stored.Validate() != nil || !strings.Contains(output.String(), "11/11") {
		t.Fatalf("identity-only receipt=%+v output=%q", stored, output.String())
	}
}

func TestCodexQualificationTurnClaimsBeforeReservationAndPersistsSignedBoundArtifact(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	ledger := &providerNativeLedgerFake{}
	admission := &orderedCodexQualificationAdmissionFake{codexQualificationAdmissionFake: codexQualificationAdmissionFake{
		decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
	}}
	admission.claimedBeforeAcquire = func() bool { return len(ledger.ops) == 1 }
	manifest := providerCodexManifestForTest(profile)
	workspace := providerCodexQualificationWorkspace{Worktree: t.TempDir()}
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	signer := newProviderNativeTestSigner()
	metadata, err := signer(context.Background(), []byte(providerattestation.ProviderAttestationPreflight))
	if err != nil {
		t.Fatal(err)
	}
	turn := runAdmittedCodexQualificationTurn(context.Background(), time.Second, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return successfulProviderCodexReceipt(spec), nil
	}, ledger, signer, metadata.KeyMetadata, func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }, profile, identity, manifest, workspace, func(context.Context) error { return nil }, "reply with the nonce only", nonce, "", false, "", "", nil)
	if turn.err != nil || !turn.admitted || admission.acquires != 1 || admission.bindings != 1 {
		t.Fatalf("turn=%+v admission=%+v", turn, admission)
	}
	operationID := "zai-qualification-" + turn.binding[:32]
	op, err := ledger.GetSendOperation(operationID, providerCodexQualificationOperationScope)
	if err != nil || op == nil || op.Status != state.SendOperationCompleted || op.BindingHash != turn.binding || op.PayloadSHA256 != sha256StringCLI(nonce) {
		t.Fatalf("operation=%+v err=%v", op, err)
	}
	var artifact providerCodexQualificationTurnArtifact
	if err := json.Unmarshal([]byte(op.OutcomeJSON), &artifact); err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalProviderCodexQualificationTurnArtifact(artifact)
	if err != nil || artifact.Attestation == nil || providerattestation.Verify(payload, *artifact.Attestation) != nil || artifact.BindingSHA256 != turn.binding || artifact.NonceSHA256 != sha256StringCLI(nonce) || artifact.ReceiptSHA256 != digestSafeJSON(artifact.Receipt) {
		t.Fatalf("artifact=%+v err=%v", artifact, err)
	}
	if strings.Contains(op.OutcomeJSON, nonce) || strings.Contains(op.OutcomeJSON, workspace.Worktree) || strings.Contains(op.OutcomeJSON, "reply with the nonce only") {
		t.Fatalf("sensitive qualification input leaked into artifact: %s", op.OutcomeJSON)
	}
	for _, mutate := range []func(*providerCodexQualificationTurnArtifact){
		func(value *providerCodexQualificationTurnArtifact) { value.State = "outcome_unknown" },
		func(value *providerCodexQualificationTurnArtifact) { value.ConfigSHA256 = strings.Repeat("f", 64) },
		func(value *providerCodexQualificationTurnArtifact) { value.RuntimeVersion = "other-runtime" },
		func(value *providerCodexQualificationTurnArtifact) {
			value.CompletedAt = value.StartedAt.Add(-time.Second)
		},
		func(value *providerCodexQualificationTurnArtifact) { value.ErrorSHA256 = strings.Repeat("e", 64) },
	} {
		tampered := artifact
		mutate(&tampered)
		tamperedPayload, tamperedErr := canonicalProviderCodexQualificationTurnArtifact(tampered)
		if tamperedErr != nil || providerattestation.Verify(tamperedPayload, *tampered.Attestation) == nil {
			t.Fatalf("tampered signed authority field unexpectedly verified: %+v err=%v", tampered, tamperedErr)
		}
	}
}

func TestCodexQualificationTurnSignsAdmissionDeniedAndOutcomeUnknown(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	manifest := providerCodexManifestForTest(profile)
	workspace := providerCodexQualificationWorkspace{Worktree: t.TempDir()}
	for _, tc := range []struct {
		name     string
		decision ratelimit.SubscriptionDecision
		run      func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error)
		want     string
	}{
		{name: "admission denied", decision: ratelimit.SubscriptionDecision{Reason: ratelimit.ErrorRateLimited, NoFailover: true}, run: func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
			t.Fatal("denied turn dispatched")
			return zai.CodexRunReceipt{}, nil
		}, want: "admission_denied"},
		{name: "outcome unknown", decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, run: func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
			r := successfulProviderCodexReceipt(spec)
			r.OutcomeKnown = false
			return r, errors.New("interrupted")
		}, want: "outcome_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ledger := &providerNativeLedgerFake{}
			admission := &codexQualificationAdmissionFake{decision: tc.decision}
			signer := newProviderNativeTestSigner()
			metadata, signErr := signer(context.Background(), []byte(providerattestation.ProviderAttestationPreflight))
			if signErr != nil {
				t.Fatal(signErr)
			}
			turn := runAdmittedCodexQualificationTurn(context.Background(), time.Second, admission, tc.run, ledger, signer, metadata.KeyMetadata, func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }, profile, identity, manifest, workspace, func(context.Context) error { return nil }, "reply", "NTM_ACK_0123456789abcdef0123456789abcdef", "", false, "", "", nil)
			if turn.err == nil || len(ledger.ops) != 1 {
				t.Fatalf("turn=%+v ops=%d", turn, len(ledger.ops))
			}
			for _, op := range ledger.ops {
				var artifact providerCodexQualificationTurnArtifact
				if op.Status != state.SendOperationCompleted || json.Unmarshal([]byte(op.OutcomeJSON), &artifact) != nil || artifact.State != tc.want || artifact.Attestation == nil {
					t.Fatalf("operation=%+v artifact=%+v", op, artifact)
				}
			}
		})
	}
}

func TestCodexQualificationTurnSignatureFailureLeavesClaimBlocked(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	ledger := &providerNativeLedgerFake{}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}}
	turn := runAdmittedCodexQualificationTurn(context.Background(), time.Second, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return successfulProviderCodexReceipt(spec), nil
	}, ledger, func(context.Context, []byte) (providerattestation.SignatureMetadata, error) {
		return providerattestation.SignatureMetadata{}, errors.New("signer unavailable")
	}, providerattestation.KeyMetadata{}, func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }, profile, identity, providerCodexManifestForTest(profile), providerCodexQualificationWorkspace{Worktree: t.TempDir()}, func(context.Context) error { return nil }, "reply", "NTM_ACK_0123456789abcdef0123456789abcdef", "", false, "", "", nil)
	if turn.err == nil || !strings.Contains(turn.err.Error(), "terminal artifact") {
		t.Fatalf("turn=%+v", turn)
	}
	for _, op := range ledger.ops {
		if op.Status != state.SendOperationInProgress || op.OutcomeJSON != "" {
			t.Fatalf("signing failure must fail closed with blocked operation: %+v", op)
		}
	}
}

func TestProviderCodexQualificationRejectsBridgeWithoutTurnSchemaBeforeAdmission(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{
		decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	providerCalls := 0
	deps := codexQualificationDepsForTest(profile, admission, func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		providerCalls++
		return zai.CodexRunReceipt{}, nil
	})
	baseSigner := newProviderNativeTestSigner()
	deps.pinnedSigner = func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
		return func(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
			if bytes.Contains(payload, []byte(`"schema_version":"ntm.provider-codex-qualification-turn.v1"`)) {
				return providerattestation.SignatureMetadata{}, errors.New("qualification-turn schema unsupported")
			}
			return baseSigner(ctx, payload)
		}, nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "qualification-turn receipt schema support") || providerCalls != 0 || admission.acquires != 0 {
		t.Fatalf("err=%v provider_calls=%d admission=%+v", err, providerCalls, admission)
	}
}

func TestProviderCodexQualificationRejectsSignerChangeOnFinalReceipt(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	var workspace providerCodexQualificationWorkspace
	providerCalls, signCalls := 0, 0
	finalStored := false
	deps := codexQualificationDepsForTest(profile, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		providerCalls++
		if spec.ExpectedFileChange != "" {
			if err := os.WriteFile(filepath.Join(spec.CWD, spec.ExpectedFileChange), []byte(workspace.ExpectedContent), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		receipt := successfulProviderCodexReceipt(spec)
		if spec.ExpectedFileChange != "" {
			receipt.ToolEventCount, receipt.ExpectedFileObserved = 1, true
		}
		if spec.ExpectedToolCommand != "" {
			receipt.ToolEventCount, receipt.ExpectedToolObserved, receipt.ExpectedToolDenied = 1, true, true
		}
		refreshProviderCodexRuntimeContract(&receipt, spec)
		return receipt, nil
	})
	deps.prepare = func(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
		var prepareErr error
		workspace, prepareErr = prepareProviderCodexQualificationWorkspace(ctx, token)
		return workspace, prepareErr
	}
	firstSigner, secondSigner := newProviderNativeTestSigner(), newProviderNativeTestSigner()
	deps.pinnedSigner = func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
		return func(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
			signCalls++
			if signCalls <= 7 {
				return firstSigner(ctx, payload)
			}
			return secondSigner(ctx, payload)
		}, nil
	}
	deps.store = func(string, providerqualification.Receipt) (string, error) {
		finalStored = true
		return "/redacted/unexpected-final.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "signer changed after preflight") || providerCalls != 4 || signCalls != 8 || finalStored || !codexQualificationWorkspaceRemoved(workspace) {
		t.Fatalf("err=%v provider_calls=%d sign_calls=%d final_stored=%t workspace=%+v", err, providerCalls, signCalls, finalStored, workspace)
	}
}

func TestProviderCodexQualificationSkipsUnknownOutcomeLifecycleByDefault(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	var workspace providerCodexQualificationWorkspace
	var stored providerqualification.Receipt
	calls := 0
	deps := codexQualificationDepsForTest(profile, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		if calls == 2 {
			if err := os.WriteFile(filepath.Join(spec.CWD, "qualification.go"), []byte(workspace.ExpectedContent), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		receipt := successfulProviderCodexReceipt(spec)
		if spec.ExpectedFileChange != "" {
			receipt.ToolEventCount, receipt.ExpectedFileObserved = 1, true
		}
		if spec.ExpectedToolCommand != "" {
			receipt.ToolEventCount, receipt.ExpectedToolObserved, receipt.ExpectedToolDenied = 1, true, true
		}
		refreshProviderCodexRuntimeContract(&receipt, spec)
		return receipt, nil
	})
	deps.prepare = func(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
		var prepareErr error
		workspace, prepareErr = prepareProviderCodexQualificationWorkspace(ctx, token)
		return workspace, prepareErr
	}
	deps.store = func(_ string, receipt providerqualification.Receipt) (string, error) {
		stored = receipt
		return "/redacted/scoped-no-go.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	var noGo *providerQualificationExitError
	if !errors.As(err, &noGo) || calls != 4 || admission.bindings != 4 || admission.usages != 4 || admission.unknownReserved != 0 || stored.Passed || stored.Attestation == nil || stored.Validate() != nil || !codexQualificationWorkspaceRemoved(workspace) {
		t.Fatalf("err=%v calls=%d admission=%+v receipt=%+v", err, calls, admission, stored)
	}
	for _, name := range []string{"cancellation", "crash_recovery", "session_resumption"} {
		found := false
		for _, check := range stored.Checks {
			if check.Name == name {
				found = true
				if check.Passed || !strings.Contains(check.Detail, "Not exercised") {
					t.Fatalf("unsafe default lifecycle check %s=%+v", name, check)
				}
			}
		}
		if !found {
			t.Fatalf("missing lifecycle check %q", name)
		}
	}
}

func TestProviderCodexQualificationAccountingRequiresProviderStart(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	receipt := successfulProviderCodexReceipt(zai.CodexRunSpec{RequestedModel: identity.Model()})
	receipt.ProviderStarted = false
	admission := &codexQualificationAdmissionFake{}
	state, err := reconcileProviderCodexQualificationUsage(admission, identity, codexQualificationTurn{
		receipt: receipt, admitted: true, decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
	})
	if err != nil || admission.usages != 0 || admission.conservative != 0 || admission.unknownReserved != 1 || !strings.Contains(state, "unknown_full_week_reserved=1") {
		t.Fatalf("state=%q err=%v admission=%+v", state, err, admission)
	}
}

func TestProviderCodexQualificationPreflightsBrokerBeforeWorkspace(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	prepared := false
	deps := codexQualificationDepsForTest(profile, &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}, func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return zai.CodexRunReceipt{}, errors.New("not reached")
	})
	deps.credentialStatus = func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error) {
		return providercredential.Status{Available: true, Present: false}, nil
	}
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return providerCodexQualificationWorkspace{}, nil
	}
	if err := runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps); err == nil || prepared {
		t.Fatalf("err=%v prepared=%t", err, prepared)
	}
}

func TestProviderCodexQualificationRejectsSignerChangeOnIdentityPreflight(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	providerCalls, signCalls := 0, 0
	prepared, stored := false, false
	deps := codexQualificationDepsForTest(profile, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		providerCalls++
		return successfulProviderCodexReceipt(spec), nil
	})
	firstSigner, secondSigner := newProviderNativeTestSigner(), newProviderNativeTestSigner()
	deps.pinnedSigner = func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
		return func(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
			signCalls++
			if signCalls <= 3 {
				return firstSigner(ctx, payload)
			}
			return secondSigner(ctx, payload)
		}, nil
	}
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return providerCodexQualificationWorkspace{}, nil
	}
	deps.storePreflight = func(providerqualification.Receipt) (string, error) {
		stored = true
		return "/redacted/unexpected.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "signer changed after preflight") || providerCalls != 1 || signCalls != 4 || prepared || stored {
		t.Fatalf("err=%v provider_calls=%d sign_calls=%d prepared=%t stored=%t", err, providerCalls, signCalls, prepared, stored)
	}
}

func TestProviderCodexQualificationAppliesSuiteTimeoutBeforeWorkspace(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	prepared := false
	deps := codexQualificationDepsForTest(profile, &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}, func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		return zai.CodexRunReceipt{}, errors.New("not reached")
	})
	deps.attest = func(ctx context.Context, _ zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error) {
		<-ctx.Done()
		return zai.CodexManifestAttestation{}, ctx.Err()
	}
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return providerCodexQualificationWorkspace{}, nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Millisecond}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) || prepared {
		t.Fatalf("err=%v prepared=%t", err, prepared)
	}
}

func TestProviderCodexQualificationModelGapStopsBeforeWorkspace(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	prepared := false
	stored := false
	var preflightStored providerqualification.Receipt
	calls := 0
	deps := codexQualificationDepsForTest(profile, admission, func(ctx context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		if spec.ManifestVerifier == nil || spec.ManifestVerifier(ctx) != nil {
			t.Fatal("missing manifest verifier")
		}
		r := successfulProviderCodexReceipt(spec)
		r.ResolvedModel = ""
		r.ModelEvidence = ""
		r.ModelVerified = false
		r.ToolEventCount = 1
		if spec.ExpectedFileChange != "" {
			r.ExpectedFileObserved = true
		}
		if spec.ExpectedToolCommand != "" {
			r.ExpectedToolObserved = true
			r.ExpectedToolDenied = true
		}
		if spec.Resume {
			r.SessionIDSHA256 = sha256StringCLI(spec.ParentSession)
			r.ParentSessionSHA256 = sha256StringCLI(spec.ParentSession)
		}
		refreshProviderCodexRuntimeContract(&r, spec)
		return r, nil
	})
	deps.prepare = func(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return prepareProviderCodexQualificationWorkspace(ctx, token)
	}
	deps.store = func(_ string, receipt providerqualification.Receipt) (string, error) {
		stored = true
		if receipt.Passed || receipt.Attestation == nil || receipt.Validate() != nil {
			t.Fatalf("receipt=%+v", receipt)
		}
		return "/redacted/model-gap.json", nil
	}
	deps.storePreflight = func(receipt providerqualification.Receipt) (string, error) {
		preflightStored = receipt
		return "/redacted/model-gap-preflight.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "signed read-only identity preflight") || prepared || stored || calls != 1 || admission.acquires != 1 || admission.releases != 1 || admission.bindings != 1 || admission.usages != 0 || admission.conservative != 1 || admission.unknownReserved != 0 || admission.successes != 0 {
		t.Fatalf("err=%v prepared=%t stored=%t calls=%d admission=%+v", err, prepared, stored, calls, admission)
	}
	if preflightStored.Transport != "zai_codex_identity_preflight" || preflightStored.Passed || preflightStored.Attestation == nil || preflightStored.Validate() != nil {
		t.Fatalf("signed model-gap preflight receipt=%+v validate=%v", preflightStored, preflightStored.Validate())
	}
}

func TestProviderCodexQualificationBindingFailureCancelsBeforeDispatch(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{
		decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
		bindErr:  errors.New("binding unavailable"),
	}
	prepared, calls := false, 0
	deps := codexQualificationDepsForTest(profile, admission, func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		return zai.CodexRunReceipt{}, nil
	})
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return providerCodexQualificationWorkspace{}, nil
	}
	var preflightStored providerqualification.Receipt
	deps.storePreflight = func(receipt providerqualification.Receipt) (string, error) {
		preflightStored = receipt
		return "/redacted/binding-failure-preflight.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "capacity accounting failed") || prepared || calls != 0 || admission.acquires != 1 || admission.releases != 1 || admission.bindings != 1 || admission.canceledReservations != 1 {
		t.Fatalf("err=%v prepared=%t calls=%d admission=%+v", err, prepared, calls, admission)
	}
	if preflightStored.Transport != "zai_codex_identity_preflight" || preflightStored.Passed || preflightStored.Attestation == nil || preflightStored.Validate() != nil {
		t.Fatalf("signed binding-failure preflight receipt=%+v validate=%v", preflightStored, preflightStored.Validate())
	}
}

func TestProviderCodexQualificationRejectsPreflightToolActivityBeforeWorkspace(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{
		decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	prepared, calls := false, 0
	deps := codexQualificationDepsForTest(profile, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		receipt := successfulProviderCodexReceipt(spec)
		receipt.ToolEventCount = 1
		refreshProviderCodexRuntimeContract(&receipt, spec)
		return receipt, nil
	})
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return providerCodexQualificationWorkspace{}, nil
	}
	var preflightStored providerqualification.Receipt
	deps.storePreflight = func(receipt providerqualification.Receipt) (string, error) {
		preflightStored = receipt
		return "/redacted/tool-activity-preflight.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "signed read-only identity preflight") || prepared || calls != 1 || admission.bindings != 1 || admission.usages != 1 || admission.unknownReserved != 0 {
		t.Fatalf("err=%v prepared=%t calls=%d admission=%+v", err, prepared, calls, admission)
	}
	if preflightStored.Transport != "zai_codex_identity_preflight" || preflightStored.Passed || preflightStored.Attestation == nil || preflightStored.Validate() != nil {
		t.Fatalf("signed tool-activity preflight receipt=%+v validate=%v", preflightStored, preflightStored.Validate())
	}
}

func TestProviderCodexQualificationRejectsContradictoryPreflightResidualsBeforeWorkspace(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{
		decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	prepared, calls := false, 0
	deps := codexQualificationDepsForTest(profile, admission, func(_ context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		receipt := successfulProviderCodexReceipt(spec)
		receipt.ZeroResiduals = true
		receipt.Cancellation.ResidualProcessIDs = []int{4242}
		refreshProviderCodexRuntimeContract(&receipt, spec)
		return receipt, nil
	})
	deps.prepare = func(context.Context, string) (providerCodexQualificationWorkspace, error) {
		prepared = true
		return providerCodexQualificationWorkspace{}, nil
	}
	var preflightStored providerqualification.Receipt
	deps.storePreflight = func(receipt providerqualification.Receipt) (string, error) {
		preflightStored = receipt
		return "/redacted/residual-preflight.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	if err == nil || !strings.Contains(err.Error(), "signed read-only identity preflight") || prepared || calls != 1 || admission.usages != 0 || admission.unknownReserved != 1 {
		t.Fatalf("err=%v prepared=%t calls=%d admission=%+v", err, prepared, calls, admission)
	}
	if preflightStored.Passed || preflightStored.Attestation == nil || preflightStored.Validate() != nil {
		t.Fatalf("signed residual preflight receipt=%+v validate=%v", preflightStored, preflightStored.Validate())
	}
	for _, check := range preflightStored.Checks {
		if check.Name == "zero_residual_cleanup" && check.Passed {
			t.Fatalf("contradictory residual process receipt passed cleanup: %+v", check)
		}
	}
}

func codexQualificationDepsForTest(profile config.ProviderProfileConfig, admission providerCodexQualificationAdmission, run func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error)) providerCodexQualificationDependencies {
	ledger := &providerNativeLedgerFake{}
	return providerCodexQualificationDependencies{
		attest: func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error) {
			return zai.CodexManifestAttestation{ConfigSHA256: profile.ConfigSHA256, BinarySHA256: profile.RuntimeSHA256, AuthHelperSHA256: profile.BrokerCommandSHA256, CredentialBridgeSHA256: profile.CredentialBridgeCommandSHA256, RuntimeVersion: profile.RuntimeVersion}, nil
		},
		credentialStatus: func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error) {
			return providercredential.Status{Available: true, Present: true, Evidence: providercredential.EvidenceOSProtectedProcessReadable}, nil
		},
		pinnedSigner: func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
			return newProviderNativeTestSigner(), nil
		},
		run: run, newNonce: func() (string, error) { return "NTM_ACK_0123456789abcdef0123456789abcdef", nil },
		prepare: prepareProviderCodexQualificationWorkspace, cleanup: cleanupProviderCodexQualificationWorkspace,
		verifier: codexQualificationVerifierFake{},
		store:    func(string, providerqualification.Receipt) (string, error) { return "/redacted/receipt.json", nil },
		storePreflight: func(providerqualification.Receipt) (string, error) {
			return "/redacted/identity-preflight.json", nil
		},
		admission: admission,
		openLedger: func() (providerNativeOperationLedger, func() error, error) {
			return ledger, func() error { return nil }, nil
		},
		now: func() time.Time { return time.Unix(2_000_000_000, 0).UTC() },
	}
}

type codexQualificationVerifierFake struct{}

func (codexQualificationVerifierFake) Run(context.Context, string) (providerqualification.VerificationOutcome, error) {
	return providerqualification.VerificationOutcome{ExitCode: 0, NetworkIsolated: true, CredentialsIsolated: true, PIDNamespace: true, OutputSHA256: strings.Repeat("d", 64)}, nil
}
