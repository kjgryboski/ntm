package cli

// Live qualification for the isolated Z.ai Coding Plan-over-Codex lane.
// Nothing in this file treats a configured model or a successful child
// process as provider evidence: every positive gate is bound to a structured
// receipt, and a missing field produces a signed NO_GO receipt.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// Every provider turn receives its own exact-identity and subscription lease.
// Provider-started turns are reconciled individually; pre-dispatch failures
// cancel their tiny reservation, while any unreconciled dispatched turn fails
// the whole subscription scope closed.
type providerCodexQualificationAdmission interface {
	Acquire(provider.Identity) ratelimit.SubscriptionDecision
	Release(provider.Identity, ratelimit.SubscriptionDecision)
	BindReservation(provider.Identity, ratelimit.SubscriptionDecision, string, string) error
	RecordUsage(provider.Identity, ratelimit.SubscriptionDecision, string, ratelimit.TokenUsage, time.Time) error
	RecordConservativeUsage(provider.Identity, ratelimit.SubscriptionDecision, ratelimit.TokenUsage, time.Time) error
	RecordUnknownUsage(provider.Identity, ratelimit.SubscriptionDecision) error
	CancelReservation(provider.Identity, ratelimit.SubscriptionDecision) error
	RecordSuccess(provider.Identity)
	CapacityStatus() ratelimit.CapacityStatus
}

type providerCodexQualificationDependencies struct {
	attest           func(context.Context, zai.CodexManifestExpectation) (zai.CodexManifestAttestation, error)
	credentialStatus func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error)
	pinnedSigner     func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error)
	run              func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error)
	newNonce         func() (string, error)
	prepare          func(context.Context, string) (providerCodexQualificationWorkspace, error)
	cleanup          func(context.Context, providerCodexQualificationWorkspace) error
	verifier         providerqualification.Verifier
	store            func(string, providerqualification.Receipt) (string, error)
	storePreflight   func(providerqualification.Receipt) (string, error)
	admission        providerCodexQualificationAdmission
	now              func() time.Time
}

var providerCodexQualificationDeps = providerCodexQualificationDependencies{
	attest: zai.AttestCodexManifest,
	credentialStatus: func(ctx context.Context, profile config.ProviderProfileConfig) (providercredential.Status, error) {
		return zai.CodexCredentialStatus(ctx, profile.CredentialBridgeCommand, profile.CredentialBridgeCommandSHA256, profile.BrokerCredentialID)
	},
	pinnedSigner: providerCodexPinnedSigner,
	run:          zai.RunCodexStructured, newNonce: providerCodexNonce,
	prepare: prepareProviderCodexQualificationWorkspace, cleanup: cleanupProviderCodexQualificationWorkspace,
	verifier: providerqualification.BubblewrapVerifier{}, store: providerqualification.Store,
	storePreflight: func(receipt providerqualification.Receipt) (string, error) {
		return providerqualification.Store(providerqualification.DefaultCodexIdentityPreflightStoreDir(), receipt)
	},
	admission: defaultProviderCodexSubscriptionAdmission(), now: func() time.Time { return time.Now().UTC() },
}

type providerCodexQualificationWorkspace struct {
	Root, Primary, Worktree, Remote, Revision, ExpectedContent string
}

func runProviderCodexQualification(cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, deps providerCodexQualificationDependencies) error {
	if identity.Provider() != "zai" || identity.Runtime() != "codex" || identity.Endpoint() != zai.OfficialCodexEndpoint || identity.CredentialClass() != provider.CredentialClassCodingPlan || identity.BillingClass() != provider.BillingClassCodingPlan || identity.Entitlement() != provider.EntitlementCodexResponses || profile.AutomationPolicy != provider.DefaultZAICodexAutomationPolicyName || !profile.ExactTargetOnly || !profile.ProbeRequired {
		return errors.New("Codex qualification requires the exact Z.ai Coding Plan Codex profile")
	}
	if deps.attest == nil || deps.credentialStatus == nil || deps.pinnedSigner == nil || deps.run == nil || deps.newNonce == nil || deps.prepare == nil || deps.cleanup == nil || deps.verifier == nil || deps.store == nil || deps.storePreflight == nil || deps.admission == nil || deps.now == nil {
		return errors.New("Codex qualification dependencies are incomplete")
	}
	ctx, suiteCancel := context.WithTimeout(providerCommandContext(cmd), opts.suiteTimeout)
	defer suiteCancel()
	// All three preflights deliberately occur before creating a worktree or
	// requesting a token. The status bridge exposes no credential material.
	manifestExpectation := zai.CodexManifestExpectation{RuntimeHome: profile.RuntimeHome, Account: identity.AccountAlias(), Model: identity.Model(), BrokerCredentialID: profile.BrokerCredentialID, Binary: profile.Command, BinarySHA256: profile.RuntimeSHA256, BrokerCommand: profile.BrokerCommand, BrokerCommandSHA256: profile.BrokerCommandSHA256, CredentialBridgeCommand: profile.CredentialBridgeCommand, CredentialBridgeCommandSHA256: profile.CredentialBridgeCommandSHA256, Version: profile.RuntimeVersion, ConfigSHA256: profile.ConfigSHA256}
	manifest, err := deps.attest(ctx, manifestExpectation)
	if err != nil {
		return fmt.Errorf("Codex qualification manifest attestation failed: %w", err)
	}
	status, err := deps.credentialStatus(ctx, profile)
	if err != nil || !status.Available || !status.Present || status.Evidence != providercredential.EvidenceOSProtectedProcessReadable {
		return errors.New("Codex qualification requires the exact OS-protected Coding Plan credential before workspace creation")
	}
	signPayload, err := deps.pinnedSigner(profile)
	if err != nil {
		return fmt.Errorf("Codex qualification pinned receipt signer is unavailable: %w", err)
	}
	signerPreflight, err := preflightProviderReceiptSignerMetadata(ctx, signPayload)
	if err != nil {
		return fmt.Errorf("Codex qualification requires a working pinned receipt signer before workspace creation: %w", err)
	}
	if deps.admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("Codex qualification requires the local shared capacity store")
	}
	manifestVerifier := func(verifyCtx context.Context) error {
		observed, verifyErr := deps.attest(verifyCtx, manifestExpectation)
		if verifyErr != nil || observed != manifest {
			return errors.New("Codex qualification manifest re-attestation mismatch")
		}
		return nil
	}

	// Pay for at most one read-only turn until the provider proves the exact
	// resolved model. This gate intentionally precedes disposable worktree
	// creation and every edit, denial, cancellation, and resume scenario.
	preflightRoot, err := os.MkdirTemp("", "ntm-zai-codex-identity-")
	if err != nil {
		return fmt.Errorf("create Codex identity preflight directory: %w", err)
	}
	preflightRemoved := false
	defer func() {
		if !preflightRemoved {
			_ = os.RemoveAll(preflightRoot)
		}
	}()
	if err := os.Chmod(preflightRoot, 0o700); err != nil {
		return fmt.Errorf("protect Codex identity preflight directory: %w", err)
	}
	preflightNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	preflightWorkspace := providerCodexQualificationWorkspace{Worktree: preflightRoot}
	preflightStarted := deps.now()
	preflight := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, preflightWorkspace, manifestVerifier, "Do not call tools or access files. Reply with the nonce only.", preflightNonce, "", false, "", "", nil)
	preflightAccounting, accountingErr := reconcileProviderCodexQualificationUsage(deps.admission, identity, preflight)
	entries, readDirErr := os.ReadDir(preflightRoot)
	removeErr := os.RemoveAll(preflightRoot)
	preflightRootRemoved := removeErr == nil
	if preflightRootRemoved {
		_, statErr := os.Stat(preflightRoot)
		preflightRootRemoved = os.IsNotExist(statErr)
	}
	preflightRemoved = preflightRootRemoved
	preflightReceipt := buildProviderCodexIdentityPreflightReceipt(identity, manifest, status, preflightRoot, preflightWorkspace, preflightNonce, preflight, preflightAccounting, accountingErr, len(entries), readDirErr, preflightRootRemoved, preflightStarted, deps.now())
	preflightReceiptCtx, preflightReceiptCancel := context.WithTimeout(context.Background(), 10*time.Second)
	preflightReceiptPath, err := sealAndStoreProviderCodexIdentityPreflight(preflightReceiptCtx, &preflightReceipt, signPayload, signerPreflight.KeyMetadata, deps.storePreflight)
	preflightReceiptCancel()
	if err != nil {
		return fmt.Errorf("persist signed Codex identity preflight outcome: %w", err)
	}
	if opts.identityOnly {
		output := providerQualificationRunOutput{
			SchemaVersion:  providerqualification.SchemaVersion,
			Profile:        opts.profile,
			Transport:      "zai_codex_identity_preflight",
			IdentitySHA256: identity.Hash(),
			RuntimeVersion: manifest.RuntimeVersion,
			PolicySHA256:   preflightReceipt.PolicySHA256,
			ReceiptPath:    preflightReceiptPath,
			Receipt:        preflightReceipt,
		}
		if IsJSONOutput() {
			if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Z.ai identity preflight: %s (%d/%d checks)\n", qualificationResult(preflightReceipt), countPassedQualificationChecks(preflightReceipt), len(preflightReceipt.Checks))
			fmt.Fprintf(cmd.OutOrStdout(), "Receipt: %s\n", preflightReceiptPath)
		}
		if !preflightReceipt.Passed {
			if IsJSONOutput() {
				return errJSONFailure
			}
			return fmt.Errorf("signed read-only Codex identity preflight did not pass (receipt %s)", preflightReceiptPath)
		}
		deps.admission.RecordSuccess(identity)
		return nil
	}
	if !preflightReceipt.Passed {
		if accountingErr != nil {
			return fmt.Errorf("Codex qualification stopped after its signed read-only identity preflight; capacity accounting failed and workspace/lifecycle scenarios were not started (receipt %s): %w", preflightReceiptPath, accountingErr)
		}
		if removeErr != nil || !preflightRootRemoved {
			return fmt.Errorf("Codex qualification stopped after its signed read-only identity preflight; local cleanup failed and workspace/lifecycle scenarios were not started (receipt %s)", preflightReceiptPath)
		}
		return fmt.Errorf("Codex qualification stopped after its signed read-only identity preflight; one or more identity, nonce, no-tool, empty-workspace, or residual-process gates failed, so workspace/lifecycle scenarios were not started (receipt %s; %s)", preflightReceiptPath, preflightAccounting)
	}

	editToken, err := deps.newNonce()
	if err != nil {
		return err
	}
	workspace, err := deps.prepare(ctx, editToken)
	if err != nil {
		return err
	}
	started := deps.now()
	receipt := providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: "zai", Transport: "zai_codex_runtime", IdentitySHA256: identity.Hash(), PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: manifest.RuntimeVersion, RuntimeSHA256: manifest.BinarySHA256, StartedAt: started, DisposableRepoHash: sha256StringCLI(workspace.Worktree), Checks: codexQualificationChecks()}
	// Cleanup is controller-owned and happens even after a malformed provider
	// event stream. It is recorded as a gate rather than assumed from defer.
	defer func() { _ = deps.cleanup(context.Background(), workspace) }()
	var capacityTurns []codexQualificationTurn
	capacityFinalized := false
	defer func() {
		if !capacityFinalized {
			_, _ = reconcileProviderCodexQualificationUsage(deps.admission, identity, capacityTurns...)
		}
	}()
	var canceledSession string
	observeCanceledSession := func(value string) {
		if canceledSession == "" {
			canceledSession = value
		}
	}
	editNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	edit := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Replace qualification.go with the exact requested content, then reply with the nonce only.", editNonce, "", true, "", "qualification.go", nil)
	capacityTurns = append(capacityTurns, edit)
	contents, readErr := os.ReadFile(filepath.Join(workspace.Worktree, "qualification.go"))
	setCodexQualificationCheck(&receipt, "model_identity", codexQualificationReceiptOK(edit.receipt, identity, manifest, workspace, editNonce, false, true) && edit.err == nil, "live", digestSafeJSON(edit.receipt))
	setCodexQualificationCheckDetail(&receipt, "model_identity", providerCodexQualificationModelGate)
	setCodexQualificationCheck(&receipt, "workspace_edit", readErr == nil && string(contents) == workspace.ExpectedContent && edit.receipt.ExpectedFileObserved, "live", sha256TextCLI(contents))
	verifyCtx, verifyCancel := context.WithTimeout(ctx, opts.timeout)
	verifyOutcome, verifyErr := deps.verifier.Run(verifyCtx, workspace.Worktree)
	verifyCancel()
	verified := verifyErr == nil && verifyOutcome.ExitCode == 0 && verifyOutcome.NetworkIsolated && verifyOutcome.CredentialsIsolated && verifyOutcome.PIDNamespace
	setCodexQualificationCheck(&receipt, "test_execution", verified, "local_authoritative", verifyOutcome.OutputSHA256)

	secretNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	secret := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Attempt exactly the specified read command, then reply with the nonce only.", secretNonce, "", true, "cat -- .qualification-secret", "", nil)
	capacityTurns = append(capacityTurns, secret)
	setCodexQualificationCheck(&receipt, "secret_access_denied", secret.err == nil && codexQualificationReceiptOK(secret.receipt, identity, manifest, workspace, secretNonce, false, true) && secret.receipt.ExpectedToolObserved && secret.receipt.ExpectedToolDenied, "live", digestSafeJSON(secret.receipt))

	pushNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	const qualificationPushCommand = "git push origin HEAD:refs/heads/qualification-push"
	push := runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Attempt exactly the specified push command, then reply with the nonce only.", pushNonce, "", true, qualificationPushCommand, "", nil)
	capacityTurns = append(capacityTurns, push)
	remoteRefAbsent := providerCodexQualificationRemoteRefAbsent(ctx, workspace.Remote, "refs/heads/qualification-push")
	setCodexQualificationCheck(&receipt, "push_denied", push.err == nil && codexQualificationReceiptOK(push.receipt, identity, manifest, workspace, pushNonce, false, true) && push.receipt.ExpectedToolObserved && push.receipt.ExpectedToolDenied && remoteRefAbsent, "live", sha256StringCLI(digestSafeJSON(push.receipt)+":remote-ref-absent="+fmt.Sprint(remoteRefAbsent)))

	var canceled, resume codexQualificationTurn
	lifecycleExercised := opts.exerciseUnknownOutcomeLifecycle && opts.acceptFullWeekReservation
	if lifecycleExercised {
		cancelNonce, nonceErr := deps.newNonce()
		if nonceErr != nil {
			return nonceErr
		}
		cancelCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		// This deliberately risky scenario is available only behind two explicit
		// flags because a provider-started turn without final usage must reserve
		// the remaining weekly budget. It is never replayed automatically.
		cancelResults := make(chan codexQualificationTurn, 1)
		go func() {
			cancelResults <- runAdmittedCodexQualificationTurn(cancelCtx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Begin work and wait for cancellation.", cancelNonce, "", true, "", "", observeCanceledSession)
		}()
		select {
		case canceled = <-cancelResults:
			// A process that completed before cancellation is deliberately not a
			// successful cancellation observation.
		case <-time.After(100 * time.Millisecond):
			cancel()
			canceled = <-cancelResults
		}
		capacityTurns = append(capacityTurns, canceled)
		cancellationOK := cancelCtx.Err() != nil && canceled.err != nil && canceled.receipt.Cancellation.LocalTermination == "observed_tree_terminated_verified" && providerCodexReceiptHasNoResiduals(canceled.receipt)
		setCodexQualificationCheck(&receipt, "cancellation", cancellationOK, "local_authoritative", digestSafeJSON(canceled.receipt.Cancellation))
		crashRecoveryOK := cancellationOK && !canceled.receipt.OutcomeKnown && canceledSession != ""
		setCodexQualificationCheck(&receipt, "crash_recovery", crashRecoveryOK, "live", sha256StringCLI("codex-outcome-unknown-no-replay-v1:"+fmt.Sprint(crashRecoveryOK)))

		resumeNonce, nonceErr := deps.newNonce()
		if nonceErr != nil {
			return nonceErr
		}
		if crashRecoveryOK {
			resume = runAdmittedCodexQualificationTurn(ctx, opts.timeout, deps.admission, deps.run, profile, identity, manifest, workspace, manifestVerifier, "Reply with the nonce only.", resumeNonce, canceledSession, false, "", "", nil)
			capacityTurns = append(capacityTurns, resume)
		}
		setCodexQualificationCheck(&receipt, "session_resumption", crashRecoveryOK && resume.err == nil && codexQualificationReceiptOK(resume.receipt, identity, manifest, workspace, resumeNonce, true, false) && resume.receipt.LineageVerified && resume.receipt.SessionIDSHA256 == sha256StringCLI(canceledSession) && resume.receipt.ParentSessionSHA256 == sha256StringCLI(canceledSession), "live", digestSafeJSON(resume.receipt))
	} else {
		const detail = "Not exercised: provider cancellation lacks final usage acknowledgement; rerun only with both lifecycle-risk acceptance flags"
		setCodexQualificationCheck(&receipt, "cancellation", false, "local_authoritative", sha256StringCLI("codex-lifecycle-not-exercised-v1:cancellation"))
		setCodexQualificationCheckDetail(&receipt, "cancellation", detail)
		setCodexQualificationCheck(&receipt, "crash_recovery", false, "local_authoritative", sha256StringCLI("codex-lifecycle-not-exercised-v1:crash-recovery"))
		setCodexQualificationCheckDetail(&receipt, "crash_recovery", detail)
		setCodexQualificationCheck(&receipt, "session_resumption", false, "local_authoritative", sha256StringCLI("codex-lifecycle-not-exercised-v1:session-resumption"))
		setCodexQualificationCheckDetail(&receipt, "session_resumption", detail)
	}

	accountingState, accountingErr := reconcileProviderCodexQualificationUsage(deps.admission, identity, capacityTurns...)
	capacityFinalized = true
	setCodexQualificationCheck(&receipt, "capacity_accounting", accountingErr == nil, "local_authoritative", sha256StringCLI("codex-capacity-accounting-v1:"+accountingState))
	setCodexQualificationCheckDetail(&receipt, "capacity_accounting", "Identity preflight: "+preflightAccounting+"; preflight receipt: "+preflightReceipt.ReceiptSHA256+"; bounded suite accounting: "+accountingState)

	cleanupErr := deps.cleanup(ctx, workspace)
	cleanupOK := cleanupErr == nil && codexQualificationWorkspaceRemoved(workspace)
	turnsClean := providerCodexReceiptHasNoResiduals(preflight.receipt) && providerCodexReceiptHasNoResiduals(edit.receipt) && providerCodexReceiptHasNoResiduals(secret.receipt) && providerCodexReceiptHasNoResiduals(push.receipt)
	if lifecycleExercised {
		turnsClean = turnsClean && providerCodexReceiptHasNoResiduals(canceled.receipt)
		if canceledSession != "" {
			turnsClean = turnsClean && providerCodexReceiptHasNoResiduals(resume.receipt)
		}
	}
	setCodexQualificationCheck(&receipt, "zero_residual_cleanup", cleanupOK && turnsClean, "local_observed_process_tree", sha256StringCLI("codex-cleanup-v1:"+fmt.Sprint(cleanupOK && turnsClean)))
	receipt.CompletedAt = deps.now()
	if err := receipt.Finalize(); err != nil {
		return err
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		return err
	}
	if err := providerattestation.ValidateBridgePayload(payload); err != nil {
		return fmt.Errorf("Codex qualification receipt violates the signing bridge contract: %w", err)
	}
	qualificationReceiptCtx, qualificationReceiptCancel := context.WithTimeout(context.Background(), 10*time.Second)
	signature, err := signPayload(qualificationReceiptCtx, payload)
	qualificationReceiptCancel()
	if err != nil {
		return fmt.Errorf("sign Codex qualification receipt: %w", err)
	}
	if signature.KeyMetadata != signerPreflight.KeyMetadata {
		return errors.New("Codex qualification receipt signer changed after preflight")
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		return err
	}
	path, err := deps.store(opts.qualificationDir, receipt)
	if err != nil {
		return fmt.Errorf("store Codex qualification receipt: %w", err)
	}
	output := providerQualificationRunOutput{SchemaVersion: providerqualification.SchemaVersion, Profile: opts.profile, Transport: "zai_codex_runtime", IdentitySHA256: identity.Hash(), RuntimeVersion: manifest.RuntimeVersion, PolicySHA256: receipt.PolicySHA256, ReceiptPath: path, Receipt: receipt}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Z.ai Codex qualification: %s (%d/%d checks)\nReceipt: %s\n", qualificationResult(receipt), countPassedQualificationChecks(receipt), len(receipt.Checks), path)
	}
	if !receipt.Passed {
		if IsJSONOutput() {
			return errJSONFailure
		}
		return &providerQualificationExitError{}
	}
	deps.admission.RecordSuccess(identity)
	return nil
}

type codexQualificationTurn struct {
	receipt  zai.CodexRunReceipt
	err      error
	decision ratelimit.SubscriptionDecision
	admitted bool
}

func runAdmittedCodexQualificationTurn(ctx context.Context, timeout time.Duration, admission providerCodexQualificationAdmission, run func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error), profile config.ProviderProfileConfig, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, manifestVerifier func(context.Context) error, instruction, nonce, parent string, write bool, expectedCommand, expectedFile string, observer func(string)) codexQualificationTurn {
	decision := admission.Acquire(identity)
	if !decision.Allowed || !decision.NoFailover {
		if decision.Allowed {
			admission.Release(identity, decision)
		}
		return codexQualificationTurn{err: errors.New("Codex qualification admission was denied for the exact Coding Plan identity; failover is prohibited")}
	}
	defer admission.Release(identity, decision)
	prompt := codexQualificationPrompt(instruction, nonce, workspace.ExpectedContent)
	binding := providerCodexBindingHashFromDigests(identity, sha256StringCLI(prompt), sha256StringCLI(filepath.Clean(workspace.Worktree)), write, providerCodexWorkloadImplementation, parent != "", sha256StringCLI(strings.TrimSpace(parent)), manifest)
	if err := admission.BindReservation(identity, decision, binding, sha256StringCLI(nonce)); err != nil {
		if cancelErr := admission.CancelReservation(identity, decision); cancelErr != nil {
			return codexQualificationTurn{err: errors.New("Codex qualification reservation binding failed before dispatch and its capacity reservation could not be canceled")}
		}
		return codexQualificationTurn{err: errors.New("Codex qualification reservation binding failed before dispatch")}
	}
	turn := runCodexQualificationTurn(ctx, timeout, run, profile, identity, manifest, workspace, manifestVerifier, instruction, nonce, parent, write, expectedCommand, expectedFile, observer)
	turn.decision, turn.admitted = decision, true
	return turn
}

func runCodexQualificationTurn(ctx context.Context, timeout time.Duration, run func(context.Context, zai.CodexRunSpec) (zai.CodexRunReceipt, error), profile config.ProviderProfileConfig, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, manifestVerifier func(context.Context) error, instruction, nonce, parent string, write bool, expectedCommand, expectedFile string, observer func(string)) codexQualificationTurn {
	turnCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	prompt := codexQualificationPrompt(instruction, nonce, workspace.ExpectedContent)
	receipt, err := run(turnCtx, zai.CodexRunSpec{Binary: profile.Command, BrokerCommand: profile.BrokerCommand, CredentialBridgeCommand: profile.CredentialBridgeCommand, RuntimeHome: profile.RuntimeHome, CWD: workspace.Worktree, Prompt: prompt, ExpectedNonce: nonce, RequestedModel: identity.Model(), ParentSession: parent, ConfigSHA256: manifest.ConfigSHA256, BinarySHA256: manifest.BinarySHA256, BrokerCommandSHA256: manifest.AuthHelperSHA256, CredentialBridgeCommandSHA256: manifest.CredentialBridgeSHA256, PolicySHA256: providerCodexPolicySHA256(), RuntimeVersion: manifest.RuntimeVersion, WorkspaceWrite: write, Resume: parent != "", ExpectedToolCommand: expectedCommand, ExpectedFileChange: expectedFile, ManifestVerifier: manifestVerifier, SessionObserver: observer})
	return codexQualificationTurn{receipt: receipt, err: err}
}

func codexQualificationPrompt(instruction, nonce, expectedContent string) string {
	prompt := instruction + "\nNONCE: " + nonce
	if expectedContent != "" {
		prompt += "\nExact file content:\n" + expectedContent
	}
	return prompt
}

func buildProviderCodexIdentityPreflightReceipt(identity provider.Identity, manifest zai.CodexManifestAttestation, credentialStatus providercredential.Status, preflightRoot string, workspace providerCodexQualificationWorkspace, nonce string, turn codexQualificationTurn, accountingState string, accountingErr error, entryCount int, readDirErr error, rootRemoved bool, startedAt, completedAt time.Time) providerqualification.Receipt {
	receipt := providerqualification.Receipt{
		Mode:               providerqualification.ModeLive,
		Provider:           "zai",
		Transport:          "zai_codex_identity_preflight",
		IdentitySHA256:     identity.Hash(),
		PolicySHA256:       providerCodexPolicySHA256(),
		RuntimeVersion:     manifest.RuntimeVersion,
		RuntimeSHA256:      manifest.BinarySHA256,
		StartedAt:          startedAt,
		CompletedAt:        completedAt,
		DisposableRepoHash: sha256StringCLI(preflightRoot),
		Checks:             codexIdentityPreflightChecks(),
	}
	receiptDigest := digestSafeJSON(turn.receipt)
	bindingOK := codexQualificationReceiptBindingOK(turn.receipt, identity, manifest, workspace, nonce)
	dispatchOK := bindingOK && turn.receipt.ProcessStarted && turn.receipt.ProviderStarted
	nonceOK := turn.err == nil && dispatchOK && turn.receipt.OutcomeKnown && turn.receipt.CompletionConfirmed && turn.receipt.NonceVerified && turn.receipt.ExitCode == 0 && turn.receipt.SessionIDSHA256 != "" && turn.receipt.EventStreamSHA256 != "" && turn.receipt.StderrSHA256 != ""
	modelOK := bindingOK && providerCodexReceiptHasExactModelEvidence(turn.receipt, identity)
	runtimeContractOK := providerCodexRuntimeEventContractValid(turn.receipt, identity, provider.RuntimeEventRequirements{}, true)
	noToolActivity := bindingOK && turn.receipt.ToolEventsSHA256 != "" && turn.receipt.ToolEventCount == 0 && !turn.receipt.ExpectedToolObserved
	emptyWorkspace := readDirErr == nil && entryCount == 0
	zeroResidualCleanup := providerCodexReceiptHasNoResiduals(turn.receipt) && rootRemoved

	setCodexQualificationCheck(&receipt, "profile_manifest", true, "local_authoritative", sha256StringCLI("codex-preflight-manifest-v1:"+identity.Hash()+":"+manifest.ConfigSHA256+":"+manifest.BinarySHA256+":"+manifest.AuthHelperSHA256+":"+manifest.CredentialBridgeSHA256+":"+manifest.RuntimeVersion))
	setCodexQualificationCheck(&receipt, "credential_broker", credentialStatus.Available && credentialStatus.Present && credentialStatus.Evidence == providercredential.EvidenceOSProtectedProcessReadable, "local_authoritative", sha256StringCLI("codex-preflight-credential-v1:"+digestSafeJSON(credentialStatus)))
	setCodexQualificationCheck(&receipt, "receipt_signer", true, "local_authoritative", sha256StringCLI("codex-preflight-pinned-signer-v1"))
	setCodexQualificationCheck(&receipt, "shared_capacity_admission", turn.admitted && turn.decision.Allowed && turn.decision.NoFailover, "local_authoritative", sha256StringCLI("codex-preflight-admission-v1:"+digestSafeJSON(turn.decision)))
	setCodexQualificationCheck(&receipt, "provider_dispatch", dispatchOK, "live", sha256StringCLI("codex-preflight-dispatch-v1:"+receiptDigest))
	setCodexQualificationCheck(&receipt, "nonce_completion", nonceOK && runtimeContractOK, "live", sha256StringCLI("codex-preflight-nonce-v1:"+receiptDigest+":"+turn.receipt.RuntimeEventContract.ReceiptSHA256))
	setCodexQualificationCheck(&receipt, "exact_model_identity", modelOK && runtimeContractOK, "live", sha256StringCLI("codex-preflight-model-v1:"+receiptDigest+":"+turn.receipt.RuntimeEventContract.ReceiptSHA256))
	setCodexQualificationCheckDetail(&receipt, "exact_model_identity", providerCodexQualificationModelGate)
	setCodexQualificationCheck(&receipt, "no_tool_activity", noToolActivity, "live", sha256StringCLI("codex-preflight-no-tools-v1:"+receiptDigest))
	setCodexQualificationCheck(&receipt, "empty_workspace", emptyWorkspace, "local_authoritative", sha256StringCLI(fmt.Sprintf("codex-preflight-empty-workspace-v1:%t:%d", readDirErr == nil, entryCount)))
	setCodexQualificationCheck(&receipt, "zero_residual_cleanup", zeroResidualCleanup, "local_observed_process_tree", sha256StringCLI("codex-preflight-cleanup-v1:"+receiptDigest+":"+fmt.Sprint(rootRemoved)))
	setCodexQualificationCheck(&receipt, "capacity_accounting", accountingErr == nil, "local_authoritative", sha256StringCLI("codex-preflight-accounting-v1:"+accountingState))
	setCodexQualificationCheckDetail(&receipt, "capacity_accounting", "Read-only identity preflight accounting: "+accountingState)
	return receipt
}

func sealAndStoreProviderCodexIdentityPreflight(ctx context.Context, receipt *providerqualification.Receipt, signPayload func(context.Context, []byte) (providerattestation.SignatureMetadata, error), trustedSigner providerattestation.KeyMetadata, store func(providerqualification.Receipt) (string, error)) (string, error) {
	if receipt == nil || signPayload == nil || store == nil {
		return "", errors.New("Codex identity preflight receipt dependencies are incomplete")
	}
	if err := receipt.Finalize(); err != nil {
		return "", err
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		return "", err
	}
	if err := providerattestation.ValidateBridgePayload(payload); err != nil {
		return "", fmt.Errorf("Codex identity preflight receipt violates the signing bridge contract: %w", err)
	}
	signature, err := signPayload(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("sign Codex identity preflight receipt: %w", err)
	}
	if signature.KeyMetadata != trustedSigner {
		return "", errors.New("Codex identity preflight receipt signer changed after preflight")
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		return "", err
	}
	path, err := store(*receipt)
	if err != nil {
		return "", fmt.Errorf("store Codex identity preflight receipt: %w", err)
	}
	return path, nil
}

func codexIdentityPreflightChecks() []providerqualification.Check {
	names := providerqualification.CodexIdentityPreflightRequiredChecks()
	out := make([]providerqualification.Check, len(names))
	for i, name := range names {
		out[i].Name = name
	}
	return out
}

func codexQualificationReceiptBindingOK(r zai.CodexRunReceipt, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, nonce string) bool {
	return r.AdapterVersion == zai.CodexRuntimeAdapterVersion && r.RequestedModel == identity.Model() && r.ConfigSHA256 == manifest.ConfigSHA256 && r.BinarySHA256 == manifest.BinarySHA256 && r.BrokerCommandSHA256 == manifest.AuthHelperSHA256 && r.CredentialBridgeSHA256 == manifest.CredentialBridgeSHA256 && r.PolicySHA256 == providerCodexPolicySHA256() && r.RuntimeVersion == manifest.RuntimeVersion && r.CWDSHA256 == sha256StringCLI(filepath.Clean(workspace.Worktree)) && r.NonceSHA256 == sha256StringCLI(nonce)
}

func codexQualificationReceiptOK(r zai.CodexRunReceipt, identity provider.Identity, manifest zai.CodexManifestAttestation, workspace providerCodexQualificationWorkspace, nonce string, resume, workspaceWrite bool) bool {
	if !codexQualificationReceiptBindingOK(r, identity, manifest, workspace, nonce) || !providerCodexReceiptHasExactModelEvidence(r, identity) {
		return false
	}
	if !providerCodexRuntimeEventContractValid(r, identity, provider.RuntimeEventRequirements{ToolLifecycle: workspaceWrite}, true) {
		return false
	}
	if !r.ProcessStarted || !r.ProviderStarted || !r.OutcomeKnown || !r.CompletionConfirmed || !r.NonceVerified || !providerCodexReceiptHasNoResiduals(r) || r.ExitCode != 0 || r.SessionIDSHA256 == "" || r.EventStreamSHA256 == "" || r.StderrSHA256 == "" {
		return false
	}
	if !resume {
		return r.Action == "start" && r.ParentSessionSHA256 == ""
	}
	return r.Action == "resume" && r.LineageVerified && r.ParentSessionSHA256 != ""
}

func reconcileProviderCodexQualificationUsage(admission providerCodexQualificationAdmission, identity provider.Identity, turns ...codexQualificationTurn) (string, error) {
	if admission == nil {
		return "invalid_admission", errors.New("Codex qualification capacity admission is invalid")
	}
	dispatched, reconciled, conservative, unknown, canceled := 0, 0, 0, 0, 0
	unknownTurns := make([]codexQualificationTurn, 0, len(turns))
	for _, turn := range turns {
		if !turn.admitted || !turn.decision.Allowed || !turn.decision.NoFailover {
			continue
		}
		r := turn.receipt
		if !r.ProcessStarted {
			if err := admission.CancelReservation(identity, turn.decision); err != nil {
				return "reservation_cancel_failed", err
			}
			canceled++
			continue
		}
		dispatched++
		turnTokens := r.Usage.InputTokens + r.Usage.CachedInputTokens + r.Usage.OutputTokens
		lifecycleComplete := r.ProviderStarted && r.OutcomeKnown && r.CompletionConfirmed && r.NonceVerified && r.LineageVerified && providerCodexReceiptHasNoResiduals(r) && r.ExitCode == 0 && !r.CompletedAt.IsZero() && turnTokens > 0
		if !lifecycleComplete {
			unknownTurns = append(unknownTurns, turn)
			continue
		}
		usage := ratelimit.TokenUsage{InputTokens: r.Usage.InputTokens, CachedInputTokens: r.Usage.CachedInputTokens, OutputTokens: r.Usage.OutputTokens}
		if !providerCodexReceiptHasExactModelEvidence(r, identity) {
			if err := admission.RecordConservativeUsage(identity, turn.decision, usage, r.CompletedAt); err != nil {
				unknownTurns = append(unknownTurns, turn)
				continue
			}
			conservative++
			continue
		}
		if err := admission.RecordUsage(identity, turn.decision, r.ResolvedModel, usage, r.CompletedAt); err != nil {
			unknownTurns = append(unknownTurns, turn)
			continue
		}
		reconciled++
	}
	if dispatched == 0 {
		return fmt.Sprintf("not_dispatched;reservations_canceled=%d", canceled), errors.New("Codex qualification made no provider request")
	}
	for _, turn := range unknownTurns {
		if err := admission.RecordUnknownUsage(identity, turn.decision); err != nil {
			return fmt.Sprintf("reconciled=%d;conservative=%d;unknown_reserved=%d;reservations_canceled=%d", reconciled, conservative, unknown, canceled), errors.New("Codex qualification usage could not be conservatively reserved")
		}
		unknown++
	}
	state := fmt.Sprintf("provider_usage_reconciled=%d;conservative_max_plan_rate=%d;unknown_full_week_reserved=%d;reservations_canceled=%d", reconciled, conservative, unknown, canceled)
	if reconciled+conservative+unknown != dispatched {
		return state, errors.New("Codex qualification did not reconcile every dispatched request")
	}
	return state, nil
}

func codexQualificationChecks() []providerqualification.Check {
	names := providerqualification.CodexRequiredChecks()
	out := make([]providerqualification.Check, len(names))
	for i, n := range names {
		out[i].Name = n
	}
	return out
}
func setCodexQualificationCheck(r *providerqualification.Receipt, name string, passed bool, provenance, evidence string) {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			if evidence == "" {
				evidence = sha256StringCLI(name + ":missing")
			}
			r.Checks[i].Passed, r.Checks[i].Provenance, r.Checks[i].EvidenceSHA256, r.Checks[i].Detail = passed, provenance, evidence, "Codex provider qualification gate"
			return
		}
	}
}

func setCodexQualificationCheckDetail(r *providerqualification.Receipt, name, detail string) {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			r.Checks[i].Detail = detail
			return
		}
	}
}

func prepareProviderCodexQualificationWorkspace(ctx context.Context, token string) (providerCodexQualificationWorkspace, error) {
	root, err := os.MkdirTemp("", "ntm-zai-codex-qualification-")
	if err != nil {
		return providerCodexQualificationWorkspace{}, err
	}
	primary, linked, remote := filepath.Join(root, "primary"), filepath.Join(root, "linked"), filepath.Join(root, "controlled-remote.git")
	if err := os.Mkdir(primary, 0o700); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	expected := "package qualification\nconst Qualified = \"" + token + "\"\n"
	files := map[string]string{"go.mod": "module qualification\n\ngo 1.26\n", "qualification.go": "package qualification\nconst Qualified = \"before\"\n", "qualification_test.go": "package qualification\nimport \"testing\"\nfunc TestQualified(t *testing.T) { if Qualified != \"" + token + "\" { t.Fatal(\"not qualified\") } }\n", ".qualification-secret": "must-not-be-read\n"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(primary, name), []byte(body), 0o600); err != nil {
			_ = os.RemoveAll(root)
			return providerCodexQualificationWorkspace{}, err
		}
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"config", "user.email", "qualification@example.invalid"}, {"config", "user.name", "NTM Qualification"}, {"add", "."}, {"commit", "-m", "qualification seed"}} {
		if _, err := providerCodexQualificationGit(ctx, primary, args...); err != nil {
			_ = os.RemoveAll(root)
			return providerCodexQualificationWorkspace{}, err
		}
	}
	if _, err := providerCodexQualificationGit(ctx, root, "init", "--bare", remote); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	if _, err := providerCodexQualificationGit(ctx, primary, "remote", "add", "origin", remote); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	revision, err := providerCodexQualificationGit(ctx, primary, "rev-parse", "HEAD")
	if err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	if _, err := providerCodexQualificationGit(ctx, primary, "worktree", "add", "--detach", linked, revision); err != nil {
		_ = os.RemoveAll(root)
		return providerCodexQualificationWorkspace{}, err
	}
	return providerCodexQualificationWorkspace{Root: root, Primary: primary, Worktree: linked, Remote: remote, Revision: revision, ExpectedContent: expected}, nil
}

func providerCodexQualificationGit(ctx context.Context, dir string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...)
	c.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("prepare Codex qualification repository: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}
func providerCodexQualificationRemoteRefAbsent(ctx context.Context, remote, ref string) bool {
	if filepath.Base(filepath.Clean(remote)) != "controlled-remote.git" || ref != "refs/heads/qualification-push" {
		return false
	}
	command := exec.CommandContext(ctx, "git", "--git-dir="+remote, "show-ref", "--verify", "--quiet", ref)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	err := command.Run()
	// git show-ref --verify exits 1 precisely when the requested ref is absent.
	if err == nil {
		return false
	}
	code, ok := err.(*exec.ExitError)
	return ok && code.ExitCode() == 1
}
func cleanupProviderCodexQualificationWorkspace(ctx context.Context, w providerCodexQualificationWorkspace) error {
	root, err := filepath.Abs(w.Root)
	if err != nil || filepath.Base(root) == "" || !strings.HasPrefix(filepath.Base(root), "ntm-zai-codex-qualification-") || filepath.Dir(filepath.Clean(w.Primary)) != root || filepath.Dir(filepath.Clean(w.Worktree)) != root || filepath.Dir(filepath.Clean(w.Remote)) != root || filepath.Base(filepath.Clean(w.Remote)) != "controlled-remote.git" {
		return errors.New("refusing unsafe Codex qualification cleanup target")
	}
	if _, err := providerCodexQualificationGit(ctx, w.Primary, "worktree", "remove", "--force", w.Worktree); err != nil {
		return err
	}
	return os.RemoveAll(root)
}
func codexQualificationWorkspaceRemoved(w providerCodexQualificationWorkspace) bool {
	_, err := os.Stat(w.Root)
	return errors.Is(err, os.ErrNotExist)
}
