package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

type providerNativeQualificationDependencies struct {
	credential    providerCredentialStore
	newNonce      func() (string, error)
	runTools      func(context.Context, zai.NativeHTTPClient, zai.NativeToolRequest) (zai.NativeToolReceipt, error)
	client        zai.NativeHTTPClient
	newController func(context.Context, providerNativeRunOptions) (providerNativeToolController, error)
	prepare       func(context.Context, string) (providerNativeQualificationWorkspace, error)
	store         func(string, providerqualification.Receipt) (string, error)
	sign          func(context.Context, *providerqualification.Receipt) error
	preflight     func(context.Context) error
	admission     providerNativeAdmission
	now           func() time.Time
}

var providerNativeQualificationDeps = providerNativeQualificationDependencies{
	credential: providerCredentialDeps.store, newNonce: providerNativeNonce, runTools: zai.RunNativeTools,
	client: zai.DefaultNativeHTTPClient(), newController: newProviderNativeController,
	prepare: prepareProviderNativeQualificationWorkspace, store: providerqualification.Store,
	sign: signProviderQualificationReceipt,
	preflight: func(ctx context.Context) error {
		return preflightProviderReceiptSigner(ctx, signProviderReceiptPayload)
	},
	admission: providerNativeRunDeps.admission, now: func() time.Time { return time.Now().UTC() },
}

type providerNativeQualificationWorkspace struct {
	Root, Worktree, Revision, EditToken, ExpectedContent string
}

func runProviderNativeQualification(cmd *cobra.Command, opts providerQualificationOptions, profile config.ProviderProfileConfig, identity provider.Identity, deps providerNativeQualificationDependencies) error {
	if profile.AutomationPolicy != provider.NativeZAIToolsPolicyName || profile.RuntimeVersion != providerNativeAdapterVersion {
		return errors.New("native Z.ai qualification requires the exact controller-tools policy and pinned adapter version")
	}
	if deps.credential == nil || deps.newNonce == nil || deps.runTools == nil || deps.client == nil || deps.newController == nil || deps.prepare == nil || deps.store == nil || deps.sign == nil || deps.preflight == nil || deps.admission == nil || deps.now == nil {
		return errors.New("native Z.ai qualification dependencies are incomplete")
	}
	if err := deps.preflight(providerCommandContext(cmd)); err != nil {
		return fmt.Errorf("native Z.ai qualification requires an initialized receipt signing key before dispatch: %w", err)
	}
	key, err := deps.credential.Get(providerCommandContext(cmd), providerCredentialID(identity))
	if err != nil || len(key) == 0 {
		return errors.New("native Z.ai qualification requires the exact credential in OS-protected storage")
	}
	defer zeroProviderSecret(key)
	if deps.admission.CapacityStatus().Scope != provider.CapacityControlScopeLocalShared {
		return errors.New("native Z.ai qualification requires the local shared capacity store")
	}
	decision := deps.admission.Acquire(identity)
	if !decision.Allowed || !decision.NoFailover {
		if decision.Allowed {
			deps.admission.Release(identity, decision)
		}
		return errors.New("native Z.ai qualification admission was denied for the exact identity")
	}
	defer deps.admission.Release(identity, decision)

	editToken, err := deps.newNonce()
	if err != nil {
		return err
	}
	ackNonce, err := deps.newNonce()
	if err != nil {
		return err
	}
	workspace, err := deps.prepare(providerCommandContext(cmd), editToken)
	if err != nil {
		return err
	}
	started := deps.now()
	receipt := providerqualification.Receipt{
		Mode: providerqualification.ModeLive, Provider: "zai", Transport: "zai_native_api", IdentitySHA256: identity.Hash(),
		PolicySHA256: providerNativeToolsPolicySHA256(), RuntimeVersion: providerNativeAdapterVersion,
		StartedAt: started, DisposableRepoHash: sha256StringCLI(workspace.Worktree), Checks: nativeQualificationChecks(),
	}
	controllerOpts := providerNativeRunOptions{tools: true, worktree: workspace.Worktree, revision: workspace.Revision, commands: []string{"go-test"}}
	controller, controllerErr := deps.newController(providerCommandContext(cmd), controllerOpts)
	var toolReceipt zai.NativeToolReceipt
	var runErr error
	if controllerErr == nil {
		requestID := providerNativeRequestID(providerNativeBindingHashForPolicy(identity, "native-qualification", provider.NativeZAIToolsPolicyName, providerNativeToolManifestBinding(controllerOpts)), "qualify:"+editToken)
		prompt := "In this disposable Go worktree, use only the offered tools. Read qualification.go and replace the entire file with the exact content between the markers below. Then call verify_worktree.\n---BEGIN EXACT FILE---\n" + workspace.ExpectedContent + "---END EXACT FILE---\nAfter verification succeeds, return " + ackNonce + " on its own line and no other final text. Do not attempt secrets, network, shell, git push, or paths outside the worktree."
		runCtx, cancel := context.WithTimeout(providerCommandContext(cmd), opts.suiteTimeout)
		toolReceipt, runErr = deps.runTools(runCtx, deps.client, zai.NativeToolRequest{
			NativeRequest: zai.NativeRequest{Endpoint: identity.Endpoint(), Model: identity.Model(), Prompt: prompt, ExpectedNonce: ackNonce, ExpectedRequestID: requestID, NativeAPIKey: string(key), ExplicitOptIn: true, AllowTools: true},
			Tools:         providerNativeToolDefinitions(), Executor: controller, MaxRounds: 8,
		})
		cancel()
	}
	controllerReceipt := providerNativeControllerReceipt{}
	if controller != nil {
		controllerReceipt = controller.Receipt()
	}
	setNativeQualificationCheck(&receipt, "exact_model_request_id", controllerErr == nil && runErr == nil && toolReceipt.Model == identity.Model() && toolReceipt.ProviderRequestIDSHA256 != "" && toolReceipt.NonceVerified, "live", digestSafeJSON(toolReceipt))
	setNativeQualificationCheck(&receipt, "controller_tool_loop", runErr == nil && toolReceipt.ControllerOwnedExecutor && toolReceipt.ToolCallCount > 0 && len(toolReceipt.ToolExecutions) > 0, "live", digestSafeJSON(toolReceipt.ToolExecutions))

	contents, readErr := os.ReadFile(filepath.Join(workspace.Worktree, "qualification.go"))
	exactEdit := readErr == nil && string(contents) == workspace.ExpectedContent
	setNativeQualificationCheck(&receipt, "workspace_edit", runErr == nil && exactEdit, "live", sha256TextCLI(contents))
	verified := controllerErr == nil && controller != nil && controller.CompletedVerification() && controllerReceipt.Verification != nil
	setNativeQualificationCheck(&receipt, "isolated_verification", verified, "local_authoritative", controllerReceipt.VerificationSHA256)

	policyBroker, policyErr := provider.NewWorkspaceBroker(providerCommandContext(cmd), workspace.Worktree, workspace.Revision)
	protectedDenied := false
	if policyErr == nil {
		_, _, protectedErr := policyBroker.ReadFile(providerCommandContext(cmd), ".env")
		protectedDenied = protectedErr != nil
	}
	setNativeQualificationCheck(&receipt, "protected_path_denial", protectedDenied, "local_authoritative", sha256StringCLI("workspace-broker:.env:denied="+fmt.Sprint(protectedDenied)))
	setNativeQualificationCheck(&receipt, "shell_and_push_absent", nativeQualificationNoShellTools(), "local_authoritative", providerNativeToolsPolicySHA256())
	setNativeQualificationCheck(&receipt, "local_inflight_http_cancellation", nativeQualificationInFlightHTTPCancel(identity, string(key), ackNonce), "local_authoritative", sha256StringCLI("local-inflight-http-cancel-v1"))
	setNativeQualificationCheck(&receipt, "outcome_unknown_no_replay", nativeQualificationNoReplayInvariant(identity), "local_authoritative", sha256StringCLI("durable-binding-no-replay-v1"))
	setNativeQualificationCheck(&receipt, "local_sandbox_process_cleanup", nativeQualificationSandboxCleanup(controllerReceipt), "local_authoritative", digestSafeJSON(controllerReceipt.Verification))

	receipt.CompletedAt = deps.now()
	if finalizeErr := receipt.Finalize(); finalizeErr != nil {
		return finalizeErr
	}
	if signErr := deps.sign(providerCommandContext(cmd), &receipt); signErr != nil {
		return fmt.Errorf("sign native Z.ai qualification receipt: %w", signErr)
	}
	path, storeErr := deps.store(opts.qualificationDir, receipt)
	if storeErr != nil {
		return fmt.Errorf("store native Z.ai qualification receipt: %w", storeErr)
	}
	output := providerQualificationRunOutput{SchemaVersion: providerqualification.SchemaVersion, Profile: opts.profile, Transport: "zai_native_api", IdentitySHA256: identity.Hash(), RuntimeVersion: providerNativeAdapterVersion, PolicySHA256: receipt.PolicySHA256, ReceiptPath: path, Receipt: receipt}
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Native Z.ai qualification: %s (%d/%d checks)\nReceipt: %s\n", qualificationResult(receipt), countPassedQualificationChecks(receipt), len(receipt.Checks), path)
		for _, check := range receipt.Checks {
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", qualificationCheckStatus(check.Passed), check.Name, check.Detail)
		}
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

func prepareProviderNativeQualificationWorkspace(ctx context.Context, editToken string) (providerNativeQualificationWorkspace, error) {
	root, err := os.MkdirTemp("", "ntm-zai-native-qualification-")
	if err != nil {
		return providerNativeQualificationWorkspace{}, err
	}
	primary, linked := filepath.Join(root, "primary"), filepath.Join(root, "linked")
	if err := os.Mkdir(primary, 0o700); err != nil {
		return providerNativeQualificationWorkspace{}, err
	}
	expected := "package qualification\nconst Qualified = \"" + editToken + "\"\n"
	files := map[string]string{
		"go.mod":                "module qualification\n\ngo 1.26\n",
		"qualification.go":      "package qualification\nconst Qualified = \"before\"\n",
		"qualification_test.go": "package qualification\nimport \"testing\"\nfunc TestQualified(t *testing.T) { if Qualified != \"" + editToken + "\" { t.Fatalf(\"not qualified: %s\", Qualified) } }\n",
		".env":                  "NTM_QUALIFICATION_SECRET=must-not-be-read\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(primary, name), []byte(content), 0o600); err != nil {
			return providerNativeQualificationWorkspace{}, err
		}
	}
	for _, args := range [][]string{{"init", "-b", "main"}, {"config", "user.email", "qualification@example.invalid"}, {"config", "user.name", "NTM Qualification"}, {"add", "go.mod", "qualification.go", "qualification_test.go", ".env"}, {"commit", "-m", "qualification seed"}} {
		if _, err := providerNativeQualificationGit(ctx, primary, args...); err != nil {
			return providerNativeQualificationWorkspace{}, err
		}
	}
	revision, err := providerNativeQualificationGit(ctx, primary, "rev-parse", "HEAD")
	if err != nil {
		return providerNativeQualificationWorkspace{}, err
	}
	if _, err := providerNativeQualificationGit(ctx, primary, "worktree", "add", "--detach", linked, revision); err != nil {
		return providerNativeQualificationWorkspace{}, err
	}
	return providerNativeQualificationWorkspace{Root: root, Worktree: linked, Revision: revision, EditToken: editToken, ExpectedContent: expected}, nil
}

func providerNativeQualificationGit(ctx context.Context, directory string, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", directory}, args...)...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C"}
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("prepare native qualification repository: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func nativeQualificationChecks() []providerqualification.Check {
	names := providerqualification.NativeRequiredChecks()
	checks := make([]providerqualification.Check, len(names))
	for i, name := range names {
		checks[i].Name = name
	}
	return checks
}

func setNativeQualificationCheck(receipt *providerqualification.Receipt, name string, passed bool, provenance, evidence string) {
	for i := range receipt.Checks {
		if receipt.Checks[i].Name == name {
			receipt.Checks[i].Passed, receipt.Checks[i].Provenance = passed, provenance
			if evidence == "" {
				evidence = sha256StringCLI(name + ":missing")
			}
			receipt.Checks[i].EvidenceSHA256 = evidence
			receipt.Checks[i].Detail = "native provider qualification gate"
			return
		}
	}
}

func providerNativeToolsPolicySHA256() string {
	return sha256StringCLI(provider.NativeZAIToolsPolicyName + "\x00" + digestSafeJSON(providerNativeToolDefinitions()) + "\x00" + providerNativeAdapterVersion)
}

func providerNativeNoToolsPolicySHA256() string {
	return sha256StringCLI(provider.NativeZAINoToolsPolicyName + "\x00" + providerNativeAdapterVersion)
}

func nativeQualificationNoShellTools() bool {
	for _, definition := range providerNativeToolDefinitions() {
		name := strings.ToLower(definition.Name)
		if strings.Contains(name, "shell") || strings.Contains(name, "bash") || strings.Contains(name, "push") || strings.Contains(name, "command") {
			return false
		}
	}
	return true
}

func nativeQualificationInFlightHTTPCancel(identity provider.Identity, key, nonce string) bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := nativeQualificationBlockingClient{started: make(chan struct{}, 1)}
	type result struct {
		receipt zai.NativeToolReceipt
		err     error
	}
	done := make(chan result, 1)
	go func() {
		receipt, err := zai.RunNativeTools(ctx, client, zai.NativeToolRequest{
			NativeRequest: zai.NativeRequest{Endpoint: identity.Endpoint(), Model: identity.Model(), Prompt: "ack " + nonce, ExpectedNonce: nonce, ExpectedRequestID: "ntm-local-cancel-check", NativeAPIKey: key, ExplicitOptIn: true, AllowTools: true},
			Tools:         providerNativeToolDefinitions(), Executor: nativeQualificationNeverExecutor{}, MaxRounds: 1,
		})
		done <- result{receipt: receipt, err: err}
	}()
	select {
	case <-client.started:
		cancel()
	case <-time.After(time.Second):
		return false
	}
	select {
	case result := <-done:
		return errors.Is(result.err, context.Canceled) && result.receipt.Cancellation.LocalRequestCanceled
	case <-time.After(time.Second):
		return false
	}
}

type nativeQualificationBlockingClient struct{ started chan struct{} }

func (c nativeQualificationBlockingClient) Do(request *http.Request) (*http.Response, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-request.Context().Done()
	return nil, request.Context().Err()
}

type nativeQualificationNeverExecutor struct{}

func (nativeQualificationNeverExecutor) ExecuteNativeTool(context.Context, zai.NativeToolCall) (zai.NativeToolResult, error) {
	return zai.NativeToolResult{}, errors.New("canceled qualification reached executor")
}

func nativeQualificationNoReplayInvariant(identity provider.Identity) bool {
	binding := providerNativeBindingHashForPolicy(identity, "qualification", provider.NativeZAIToolsPolicyName, "manifest")
	requestID := providerNativeRequestID(binding, "qualification-no-replay")
	unknown := providerNativeRunOutput{SchemaVersion: providerNativeRunSchema, Profile: "qualification", Transport: "zai_native_api", IdentitySHA256: identity.Hash(), AdapterVersion: providerNativeAdapterVersion, OperationID: "qualification-no-replay", BindingSHA256: binding, ReceiptState: "outcome_unknown", State: "outcome_unknown"}
	return len(requestID) == 64 && !validRecordedProviderNativeOutput(unknown, unknown.OperationID, binding, unknown.Profile, identity.Hash())
}

func nativeQualificationSandboxCleanup(receipt providerNativeControllerReceipt) bool {
	if receipt.Verification == nil || len(receipt.Verification.Commands) == 0 || !receipt.Verification.PIDNamespaceIsolated || !receipt.Verification.CleanupVerified {
		return false
	}
	for _, command := range receipt.Verification.Commands {
		if !command.ProcessWaited || !command.CleanupVerified || command.TimedOut || command.ExitCode != 0 || command.ErrorSHA256 != "" {
			return false
		}
	}
	return true
}
