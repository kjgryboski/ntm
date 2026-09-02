package cli

import (
	"bytes"
	"context"
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
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

type codexQualificationAdmissionFake struct {
	decision                                               ratelimit.SubscriptionDecision
	status                                                 ratelimit.CapacityStatus
	acquires, releases, successes, usages, unknownReserved int
	canceledReservations                                   int
	usageErr, unknownErr, cancelErr                        error
}

func (f *codexQualificationAdmissionFake) Acquire(provider.Identity) ratelimit.SubscriptionDecision {
	f.acquires++
	return f.decision
}
func (f *codexQualificationAdmissionFake) Release(provider.Identity, ratelimit.SubscriptionDecision) {
	f.releases++
}
func (f *codexQualificationAdmissionFake) RecordUsage(provider.Identity, ratelimit.SubscriptionDecision, string, ratelimit.TokenUsage, time.Time) error {
	f.usages++
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
	calls := 0
	deps := codexQualificationDepsForTest(profile, admission, func(ctx context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		if spec.ManifestVerifier == nil || spec.ManifestVerifier(ctx) != nil {
			t.Fatal("qualification turn omitted its manifest verifier")
		}
		if calls == 1 {
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
		if calls == 3 && spec.ExpectedToolCommand != "git push origin HEAD:refs/heads/qualification-push" {
			t.Fatalf("push command=%q", spec.ExpectedToolCommand)
		}
		if calls == 3 && !providerCodexQualificationRemoteRefAbsent(ctx, workspace.Remote, "refs/heads/qualification-push") {
			t.Fatal("controlled remote unexpectedly contains the qualification ref")
		}
		if calls == 4 { // cancellation turn
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
		r.ToolEventCount = 1
		if spec.ExpectedFileChange != "" {
			r.ExpectedFileObserved = true
		}
		if spec.ExpectedToolCommand != "" {
			r.ExpectedToolObserved, r.ExpectedToolDenied = true, true
		}
		if spec.Resume {
			r.SessionIDSHA256 = sha256StringCLI(spec.ParentSession)
			r.ParentSessionSHA256 = sha256StringCLI(spec.ParentSession)
		}
		return r, nil
	})
	deps.prepare = func(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
		var e error
		workspace, e = prepareProviderCodexQualificationWorkspace(ctx, token)
		return workspace, e
	}
	deps.store = func(_ string, receipt providerqualification.Receipt) (string, error) {
		storedChecks = countPassedQualificationChecks(receipt)
		storedPath = filepath.Join(workspace.Root, "receipt.json")
		return storedPath, nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	if err := runProviderCodexQualification(cmd, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps); err != nil {
		t.Fatal(err)
	}
	if calls != 5 || storedChecks != 10 || admission.acquires != 5 || admission.releases != 5 || admission.successes != 1 || admission.usages != 4 || admission.unknownReserved != 1 || admission.canceledReservations != 0 || !strings.Contains(output.String(), "10/10") {
		t.Fatalf("calls=%d checks=%d admission=%+v output=%q", calls, storedChecks, admission, output.String())
	}
	if !codexQualificationWorkspaceRemoved(workspace) || strings.Contains(storedPath, "qualification.go") {
		t.Fatalf("unsafe cleanup/path: root=%q stored=%q", workspace.Root, storedPath)
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

func TestProviderCodexQualificationStoresSignedModelGapNoGo(t *testing.T) {
	profile := providerCodexProfile(t.TempDir())
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &codexQualificationAdmissionFake{decision: ratelimit.SubscriptionDecision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	var workspace providerCodexQualificationWorkspace
	stored := false
	calls := 0
	deps := codexQualificationDepsForTest(profile, admission, func(ctx context.Context, spec zai.CodexRunSpec) (zai.CodexRunReceipt, error) {
		calls++
		if spec.ManifestVerifier == nil || spec.ManifestVerifier(ctx) != nil {
			t.Fatal("missing manifest verifier")
		}
		if calls == 1 {
			if err := os.WriteFile(filepath.Join(spec.CWD, "qualification.go"), []byte(workspace.ExpectedContent), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if calls == 4 {
			if spec.SessionObserver != nil {
				spec.SessionObserver("22222222-2222-2222-2222-222222222222")
			}
			<-ctx.Done()
			r := successfulProviderCodexReceipt(spec)
			r.OutcomeKnown = false
			r.Cancellation.LocalTermination = "observed_tree_terminated_verified"
			r.ZeroResiduals = true
			return r, ctx.Err()
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
		return r, nil
	})
	deps.prepare = func(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
		var e error
		workspace, e = prepareProviderCodexQualificationWorkspace(ctx, token)
		return workspace, e
	}
	deps.store = func(_ string, receipt providerqualification.Receipt) (string, error) {
		stored = true
		if receipt.Passed || receipt.Attestation == nil || receipt.Validate() != nil {
			t.Fatalf("receipt=%+v", receipt)
		}
		return "/redacted/model-gap.json", nil
	}
	err = runProviderCodexQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-codex", live: true, timeout: time.Second, suiteTimeout: time.Minute}, profile, identity, deps)
	var noGo *providerQualificationExitError
	if !errors.As(err, &noGo) || !stored || calls != 5 || admission.acquires != 5 || admission.releases != 5 || admission.usages != 0 || admission.unknownReserved != 5 || admission.successes != 0 || !codexQualificationWorkspaceRemoved(workspace) {
		t.Fatalf("err=%v stored=%t calls=%d success=%d root=%q", err, stored, calls, admission.successes, workspace.Root)
	}
}

func codexQualificationDepsForTest(profile config.ProviderProfileConfig, admission providerCodexQualificationAdmission, run func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error)) providerCodexQualificationDependencies {
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
		verifier: codexQualificationVerifierFake{}, store: func(string, providerqualification.Receipt) (string, error) { return "/redacted/receipt.json", nil }, admission: admission, now: func() time.Time { return time.Unix(2_000_000_000, 0).UTC() },
	}
}

type codexQualificationVerifierFake struct{}

func (codexQualificationVerifierFake) Run(context.Context, string) (providerqualification.VerificationOutcome, error) {
	return providerqualification.VerificationOutcome{ExitCode: 0, NetworkIsolated: true, CredentialsIsolated: true, PIDNamespace: true, OutputSHA256: strings.Repeat("d", 64)}, nil
}
