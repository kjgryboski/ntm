package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
)

func grokQualificationDepsForTest(t *testing.T, profile config.ProviderProfileConfig, result grok.Result) (providerGrokQualificationDependencies, *providerSessionAdmissionFake, *providerqualification.Receipt, *grok.Request, *int) {
	t.Helper()
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	var stored providerqualification.Receipt
	var request grok.Request
	calls := 0
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	diagnosticDir := t.TempDir()
	deps := providerGrokQualificationDependencies{
		storeProtocolDiagnostic: func(identity, policy, runtime string, started, observed time.Time, phase string, observation provider.ProtocolObservation) (string, error) {
			return providerqualification.StoreProtocolDiagnostics(diagnosticDir, identity, policy, runtime, started, observed, phase, observation)
		},
		authority: func(context.Context, string, config.ProviderProfileConfig, provider.Identity) (string, error) {
			return "/usr/local/bin/grok", nil
		},
		version: func(context.Context, string) (string, error) { return profile.RuntimeVersion, nil },
		hashBinary: func(string) (string, error) {
			return strings.Repeat("b", 64), nil
		},
		run: func(_ context.Context, _ grok.Runner, got grok.Request) (grok.Result, error) {
			calls++
			request = got
			if got.BeforeCleanup != nil {
				if err := got.BeforeCleanup(result.ProtocolObservation); err != nil {
					return result, err
				}
			}
			return result, nil
		},
		store: func(_ string, receipt providerqualification.Receipt) (string, error) {
			stored = receipt
			return "/redacted/grok-observe-only.json", nil
		},
		sign:      func(context.Context, *providerqualification.Receipt) error { return nil },
		preflight: func(context.Context) error { return nil },
		admission: admission,
		now:       func() time.Time { return now },
		getwd:     func() (string, error) { return "/qualification", nil },
		newNonce:  func() (string, error) { return "NTM_ACK_GROK_QUALIFICATION", nil },
	}
	return deps, admission, &stored, &request, &calls
}

type providerGrokQualificationAdmissionFake struct {
	decisions                     []ratelimit.Decision
	acquires, releases, successes int
}

func (f *providerGrokQualificationAdmissionFake) Acquire(provider.Identity) ratelimit.Decision {
	f.acquires++
	if len(f.decisions) == 0 {
		return ratelimit.Decision{NoFailover: true}
	}
	decision := f.decisions[0]
	if len(f.decisions) > 1 {
		f.decisions = f.decisions[1:]
	}
	return decision
}

func (f *providerGrokQualificationAdmissionFake) Release(provider.Identity, ratelimit.Decision) {
	f.releases++
}

func (f *providerGrokQualificationAdmissionFake) RecordSuccess(provider.Identity) {
	f.successes++
}

func (f *providerGrokQualificationAdmissionFake) CapacityStatus() ratelimit.CapacityStatus {
	return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}
}

func TestAcquireProviderGrokQualificationTurnWaitsForExactIdentityCapacity(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	retryAt := time.Now().Add(time.Millisecond)
	admission := &providerGrokQualificationAdmissionFake{decisions: []ratelimit.Decision{
		{Reason: ratelimit.ErrorRateLimited, RetryAt: &retryAt, NoFailover: true},
		{Allowed: true, NoFailover: true},
	}}
	decision, err := acquireProviderGrokQualificationTurn(t.Context(), admission, identity)
	if err != nil || !decision.Allowed || !decision.NoFailover {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	if admission.acquires != 2 || admission.releases != 0 || admission.successes != 0 {
		t.Fatalf("admission=%+v", admission)
	}
}

func TestAcquireProviderGrokQualificationTurnContextExpiryDoesNotRelease(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	retryAt := time.Now().Add(time.Hour)
	admission := &providerGrokQualificationAdmissionFake{decisions: []ratelimit.Decision{{Reason: ratelimit.ErrorRateLimited, RetryAt: &retryAt, NoFailover: true}}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := acquireProviderGrokQualificationTurn(ctx, admission, identity); err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v, want context cancellation", err)
	}
	if admission.acquires != 1 || admission.releases != 0 || admission.successes != 0 {
		t.Fatalf("admission=%+v", admission)
	}
}

func TestAcquireProviderGrokQualificationTurnRejectsAllowedFailoverAndReleasesLease(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	admission := &providerGrokQualificationAdmissionFake{decisions: []ratelimit.Decision{{Allowed: true, NoFailover: false}}}
	if _, err := acquireProviderGrokQualificationTurn(t.Context(), admission, identity); err == nil || !strings.Contains(err.Error(), "did not prohibit provider failover") {
		t.Fatalf("err=%v", err)
	}
	if admission.acquires != 1 || admission.releases != 1 || admission.successes != 0 {
		t.Fatalf("admission=%+v", admission)
	}
}

func TestProviderGrokQualificationProducesHonestObserveOnlyNoGoReceipt(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	result := grok.Result{
		Success: true, AcknowledgementVerified: true, Authenticated: true,
		Model: identity.Model(), ModelEvidence: "completion_metadata",
		ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton",
		RuntimeEventContract: provider.EventContractReport{Passed: true},
		Cleanup:              grok.ProcessCleanupReceipt{ObservedAt: time.Date(2026, time.September, 3, 12, 0, 1, 0, time.UTC), Reaped: true, ResidualPIDs: []int32{}},
	}
	deps, admission, stored, request, calls := grokQualificationDepsForTest(t, profile, result)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderGrokQualification(cmd, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err=%v, want NO-GO exit", err)
	}
	if *calls != 1 || admission.acquires != 1 || admission.releases != 1 || admission.successes != 1 {
		t.Fatalf("calls=%d admission=%+v", *calls, admission)
	}
	if request.ExpectedNonce != "NTM_ACK_GROK_QUALIFICATION" || request.Model != identity.Model() || request.RuntimeVersion != profile.RuntimeVersion || request.CWD != "/qualification" || request.Binary != "/usr/local/bin/grok" || request.RuntimeHome != profile.RuntimeHome || len(request.AutomationPolicyArgs) == 0 {
		t.Fatalf("unsafe or incomplete observe request: %+v", *request)
	}
	if stored.Passed || stored.Transport != "xai_acp" || stored.Validate() != nil {
		t.Fatalf("receipt=%+v validate=%v", *stored, stored.Validate())
	}
	if stored.RuntimeSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("observe receipt omitted exact runtime digest: %q", stored.RuntimeSHA256)
	}
	passed := make(map[string]bool, len(stored.Checks))
	for _, check := range stored.Checks {
		passed[check.Name] = check.Passed
	}
	if !passed[providerqualification.CheckIdentity] || !passed[providerqualification.CheckProcessCleanup] {
		t.Fatalf("observed checks were not retained: %+v", stored.Checks)
	}
	for _, name := range providerqualification.GrokRequiredChecks() {
		if name != providerqualification.CheckIdentity && name != providerqualification.CheckProcessCleanup && passed[name] {
			t.Fatalf("unexercised lifecycle check %q was fabricated as passed", name)
		}
	}
}

func TestProviderGrokWorkspaceQualificationProducesOperationScopedReceipt(t *testing.T) {
	for _, protocolFailure := range []bool{false, true} {
		t.Run(fmt.Sprint(protocolFailure), func(t *testing.T) {
			profile := providerTestGrokProfile(agent.GrokWorkspaceWritePolicyName)
			identity, err := profile.Identity()
			if err != nil {
				t.Fatal(err)
			}
			result := grok.Result{
				Success: true, AcknowledgementVerified: true, Authenticated: true,
				Model: identity.Model(), ModelEvidence: "completion_metadata",
				ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton",
				ToolRequestCount: 4, ToolCompleteCount: 4,
				RuntimeEventContract: provider.EventContractReport{Passed: true},
				Cleanup:              grok.ProcessCleanupReceipt{ObservedAt: time.Now().UTC(), Reaped: true, ResidualPIDs: []int32{}, LocalTermination: "observed_tree_terminated_verified"},
			}
			deps, admission, stored, request, calls := grokQualificationDepsForTest(t, profile, result)
			if protocolFailure {
				run := deps.run
				deps.run = func(ctx context.Context, runner grok.Runner, req grok.Request) (grok.Result, error) {
					got, _ := run(ctx, runner, req)
					got.Success = false
					got.ProtocolFailureReason = provider.ProtocolUnexpectedRequest
					got.ToolRequestCount, got.ToolCompleteCount = 0, 0
					return got, errors.New("protocol failed after independently audited workspace operations")
				}
			}
			root := filepath.Join(t.TempDir(), "not-created-qualification-root")
			workspace := providerGrokLineageWorkspace{Root: root, Primary: filepath.Join(root, "primary"), Worktree: filepath.Join(root, "linked"), RuntimeHome: filepath.Join(root, "grok-home")}
			revision := strings.Repeat("a", 40)
			deps.prepareWorkspace = func(context.Context, string) (providerGrokLineageWorkspace, error) { return workspace, nil }
			deps.cleanupLineage = func(context.Context, providerGrokLineageWorkspace) error { return nil }
			deps.workspaceRevision = func(context.Context, string) (string, error) { return revision, nil }
			deps.workspaceBroker = func(_ context.Context, worktree, auditFile string) (*grok.WorkspaceBrokerDescriptor, error) {
				return grok.NewWorkspaceBrokerDescriptorWithAudit(worktree, revision, []string{"go-test", "go-vet"}, auditFile)
			}
			deps.createWorkspaceAudit = func(string, string) (*os.File, error) {
				return os.CreateTemp(t.TempDir(), "grok-audit-guard-")
			}
			deps.readWorkspaceFile = func(string) ([]byte, error) { return append([]byte(nil), providerGrokWorkspaceAfter...), nil }
			deps.readWorkspaceAudit = func(*os.File, string, string, string) (providerGrokWorkspaceAudit, error) {
				return providerGrokWorkspaceAuditForTest(workspace.Worktree, revision), nil
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			var output bytes.Buffer
			cmd.SetOut(&output)
			err = runProviderGrokQualification(cmd, providerQualificationOptions{profile: "grok-workspace", live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
			var exit *providerQualificationExitError
			if !errors.As(err, &exit) {
				t.Fatalf("err=%v, want partial qualification exit", err)
			}
			wantSuccesses := 1
			if protocolFailure {
				wantSuccesses = 0
			}
			if *calls != 1 || admission.acquires != 1 || admission.releases != 1 || admission.successes != wantSuccesses {
				t.Fatalf("calls=%d admission=%+v", *calls, admission)
			}
			if request.Broker == nil || request.Broker.BindingSHA256() == "" || request.CWD != workspace.Worktree || request.ExpectedNonce == "" || !strings.Contains(request.Prompt, providerGrokWorkspaceSecret) || !strings.Contains(request.Prompt, providerGrokWorkspaceTarget) {
				t.Fatalf("workspace request was incomplete: %+v", *request)
			}
			if stored.Passed || stored.Transport != "xai_acp" || stored.PolicySHA256 != agent.GrokAutomationPolicySHA256(agent.GrokWorkspaceWritePolicyName) || stored.Validate() != nil {
				t.Fatalf("receipt=%+v validate=%v", *stored, stored.Validate())
			}
			passed := make(map[string]bool, len(stored.Checks))
			for _, check := range stored.Checks {
				passed[check.Name] = check.Passed
			}
			for _, name := range []string{providerqualification.CheckIdentity, providerqualification.CheckWorkspaceEdit, providerqualification.CheckTestCommand, providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied, providerqualification.CheckProcessCleanup} {
				if name == providerqualification.CheckIdentity && protocolFailure {
					if passed[name] {
						t.Fatal("protocol failure promoted identity")
					}
					continue
				}
				if !passed[name] {
					t.Fatalf("workspace receipt omitted proven check %q: %+v", name, stored.Checks)
				}
			}
			for _, name := range []string{providerqualification.CheckCrashRecovery, providerqualification.CheckCancellation, providerqualification.CheckResume} {
				if passed[name] {
					t.Fatalf("workspace receipt fabricated unexercised check %q", name)
				}
			}
			if strings.Contains(output.String(), providerGrokWorkspaceSecret) || strings.Contains(output.String(), providerGrokWorkspaceTarget) {
				t.Fatal("workspace qualification output leaked fixture paths")
			}
		})
	}
}

func providerGrokWorkspaceAuditForTest(worktree, revision string) providerGrokWorkspaceAudit {
	now := time.Date(2026, time.September, 3, 12, 0, 0, 0, time.UTC)
	worktreeSHA256 := sha256StringCLI(filepath.Clean(worktree))
	revisionSHA256 := sha256StringCLI(revision)
	targetSHA256 := sha256StringCLI(providerGrokWorkspaceTarget)
	secretSHA256 := sha256StringCLI(providerGrokWorkspaceSecret)
	baseWorkspaceReceipt := func(action, pathSHA256 string) provider.WorkspaceOperationReceipt {
		return provider.WorkspaceOperationReceipt{SchemaVersion: providerGrokWorkspaceSchema, Action: action, WorktreeSHA256: worktreeSHA256, RevisionSHA256: revisionSHA256, PathSHA256: pathSHA256, StartedAt: now, CompletedAt: now}
	}
	readReceipt := baseWorkspaceReceipt("read", targetSHA256)
	readReceipt.ResultSHA256 = sha256TextCLI(providerGrokWorkspaceBefore)
	readReceipt.Bytes = int64(len(providerGrokWorkspaceBefore))
	writeReceipt := baseWorkspaceReceipt("write", targetSHA256)
	writeReceipt.BeforeSHA256 = sha256TextCLI(providerGrokWorkspaceBefore)
	writeReceipt.AfterSHA256 = sha256TextCLI(providerGrokWorkspaceAfter)
	writeReceipt.ResultSHA256 = writeReceipt.AfterSHA256
	writeReceipt.Bytes = int64(len(providerGrokWorkspaceAfter))
	writeReceipt.Mutated = true
	secretReceipt := baseWorkspaceReceipt("read", secretSHA256)
	secretReceipt.ErrorSHA256 = sha256StringCLI("protected")
	verifyReceipt := provider.VerificationReceipt{
		SchemaVersion: providerGrokVerifierSchema, ManifestSHA256: sha256StringCLI(filepath.Clean(worktree) + "\x00" + revision + "\x00go-test\x00go-vet"), WorktreeSHA256: worktreeSHA256, RevisionSHA256: revisionSHA256,
		NetworkIsolated: true, CredentialsCleared: true, PIDNamespaceIsolated: true, CleanupVerified: true, DisposableWorktree: true,
		Commands: []provider.CommandVerification{
			{ID: "go-test", CommandSHA256: sha256StringCLI("go-test\x00go\x00test\x00./..."), OutputSHA256: sha256StringCLI("test-output"), ProcessWaited: true, CleanupVerified: true, StartedAt: now, CompletedAt: now},
			{ID: "go-vet", CommandSHA256: sha256StringCLI("go-vet\x00go\x00vet\x00./..."), OutputSHA256: sha256StringCLI("vet-output"), ProcessWaited: true, CleanupVerified: true, StartedAt: now, CompletedAt: now},
		},
		StartedAt: now, CompletedAt: now,
	}
	return providerGrokWorkspaceAudit{
		Header: providerBrokerAuditHeader{SchemaVersion: providerBrokerAuditSchemaVersion, Kind: "header", WorktreeSHA256: worktreeSHA256, RevisionSHA256: revisionSHA256, CreatedAt: now},
		Events: []providerBrokerAuditEvent{
			{SchemaVersion: providerBrokerAuditSchemaVersion, Kind: "tool_call", Sequence: 1, Tool: "read_file", PathSHA256: targetSHA256, Success: true, WorkspaceReceipt: &readReceipt, OccurredAt: now},
			{SchemaVersion: providerBrokerAuditSchemaVersion, Kind: "tool_call", Sequence: 2, Tool: "write_file", PathSHA256: targetSHA256, Success: true, WorkspaceReceipt: &writeReceipt, OccurredAt: now},
			{SchemaVersion: providerBrokerAuditSchemaVersion, Kind: "tool_call", Sequence: 3, Tool: "read_file", PathSHA256: secretSHA256, Rejected: true, WorkspaceReceipt: &secretReceipt, ErrorSHA256: sha256StringCLI("protected"), OccurredAt: now},
			{SchemaVersion: providerBrokerAuditSchemaVersion, Kind: "tool_call", Sequence: 4, Tool: "verify_worktree", Success: true, VerificationReceipt: &verifyReceipt, OccurredAt: now},
		},
	}
}

func TestProviderGrokWorkspaceAuditRejectsReorderedEvidence(t *testing.T) {
	audit := providerGrokWorkspaceAuditForTest("/tmp/linked", strings.Repeat("a", 40))
	audit.Events[0], audit.Events[1] = audit.Events[1], audit.Events[0]
	assertions := evaluateProviderGrokWorkspaceAudit(audit, "/tmp/linked", strings.Repeat("a", 40))
	if assertions.ReadObserved || assertions.EditObserved || assertions.SecretDenied || assertions.TestObserved {
		t.Fatalf("reordered audit was accepted: %+v", assertions)
	}
}

func TestProviderGrokWorkspaceAuditPreservesVerifiedPrefix(t *testing.T) {
	for count := 0; count <= 4; count++ {
		audit := providerGrokWorkspaceAuditForTest("/workspace", "revision")
		audit.Events = audit.Events[:count]
		got := evaluateProviderGrokWorkspaceAudit(audit, "/workspace", "revision")
		if got.ReadObserved != (count >= 1) || got.EditObserved != (count >= 2) || got.SecretDenied != (count >= 3) || got.TestObserved != (count >= 4) {
			t.Fatalf("prefix=%d assertions=%+v", count, got)
		}
	}
}

func TestGrokQualificationDiagnosticStorageFailurePreventsPaidDispatch(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	deps, admission, _, _, calls := grokQualificationDepsForTest(t, profile, grok.Result{})
	deps.storeProtocolDiagnostic = func(string, string, string, time.Time, time.Time, string, provider.ProtocolObservation) (string, error) {
		return "", errors.New("private storage failure")
	}
	err = runProviderGrokQualification(&cobra.Command{}, providerQualificationOptions{live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	if err == nil || *calls != 0 || admission.acquires != 0 || strings.Contains(err.Error(), "private") {
		t.Fatalf("calls=%d admission=%+v err=%v", *calls, admission, err)
	}
}

func TestProviderGrokWorkspaceAuditRejectsEvidenceOutsideQualificationWindow(t *testing.T) {
	revision := strings.Repeat("a", 40)
	audit := providerGrokWorkspaceAuditForTest("/tmp/linked", revision)
	started := audit.Header.CreatedAt.Add(time.Minute)
	assertions := evaluateProviderGrokWorkspaceAudit(audit, "/tmp/linked", revision, started, started.Add(time.Minute))
	if assertions.ReadObserved || assertions.EditObserved || assertions.SecretDenied || assertions.TestObserved {
		t.Fatalf("out-of-window audit was accepted: %+v", assertions)
	}
}

func TestProviderGrokWorkspaceBrokerProducesRealQualificationEvidence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the production workspace verifier is Linux-only")
	}
	if _, err := exec.LookPath("bwrap"); err != nil {
		t.Skip("Bubblewrap is unavailable")
	}

	runtimeHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(runtimeHome, "auth.json"), []byte(`{"token":"synthetic-test-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := prepareProviderGrokWorkspaceQualification(t.Context(), runtimeHome)
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			_ = cleanupProviderGrokLineageWorkspace(context.Background(), workspace)
		}
	}()
	revision, err := providerGrokQualificationGit(t.Context(), workspace.Worktree, "rev-parse", "--verify", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(workspace.Root, providerGrokWorkspaceAuditFile)
	auditGuard, err := createProviderGrokWorkspaceAudit(auditPath, workspace.Worktree)
	if err != nil {
		t.Fatal(err)
	}
	defer auditGuard.Close()
	descriptor, err := grok.NewWorkspaceBrokerDescriptorWithAudit(workspace.Worktree, revision, []string{"go-test", "go-vet"}, auditPath)
	if err != nil {
		t.Fatal(err)
	}

	requests := []string{
		fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, providerGrokWorkspaceTarget),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":%q,"expected_sha256":%q,"content":%q}}}`, providerGrokWorkspaceTarget, sha256TextCLI(providerGrokWorkspaceBefore), string(providerGrokWorkspaceAfter)),
		fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":%q}}}`, providerGrokWorkspaceSecret),
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"verify_worktree","arguments":{}}}`,
	}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	var commandSpec struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal(descriptorJSON, &commandSpec); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), commandSpec.Command, commandSpec.Args...)
	command.Env = append(os.Environ(), "NTM_PROVIDER_BROKER_TEST_HELPER=1")
	command.Stdin = strings.NewReader(strings.Join(requests, "\n") + "\n")
	var output bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &output
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("spawn bound provider broker: %v (%s)", err, strings.TrimSpace(stderr.String()))
	}
	responses := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(responses) != len(requests) {
		t.Fatalf("response count = %d, want %d", len(responses), len(requests))
	}
	for index, raw := range responses {
		var response providerBrokerResponse
		if err := json.Unmarshal([]byte(raw), &response); err != nil {
			t.Fatalf("response %d is invalid JSON: %v", index, err)
		}
		if index == 2 {
			if response.Error == nil {
				t.Fatal("protected-path request unexpectedly succeeded")
			}
		} else if response.Error != nil {
			t.Fatalf("response %d failed: %+v", index, response.Error)
		}
	}

	audit, err := readProviderGrokWorkspaceAudit(auditGuard, auditPath, workspace.Worktree, revision)
	if err != nil {
		t.Fatal(err)
	}
	assertions := evaluateProviderGrokWorkspaceAudit(audit, workspace.Worktree, revision)
	if !assertions.ReadObserved || !assertions.EditObserved || !assertions.SecretDenied || !assertions.TestObserved {
		t.Fatalf("real broker evidence was incomplete: %+v", assertions)
	}
	content, err := os.ReadFile(filepath.Join(workspace.Worktree, filepath.FromSlash(providerGrokWorkspaceTarget)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, providerGrokWorkspaceAfter) {
		t.Fatalf("qualified target content = %q", content)
	}
	if err := cleanupProviderGrokLineageWorkspace(t.Context(), workspace); err != nil {
		t.Fatal(err)
	}
	cleaned = true
	if !providerGrokLineageWorkspaceRemoved(workspace) {
		t.Fatal("qualification workspace remained after cleanup")
	}
}

func TestProviderGrokWorkspaceAuditRejectsPathReplacement(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	worktree := filepath.Join(root, "linked")
	if err := os.Mkdir(worktree, 0o700); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(root, providerGrokWorkspaceAuditFile)
	guard, err := createProviderGrokWorkspaceAudit(auditPath, worktree)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	if err := os.Rename(auditPath, auditPath+".replaced"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(auditPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readProviderGrokWorkspaceAudit(guard, auditPath, worktree, strings.Repeat("a", 40)); err == nil {
		t.Fatal("replacement audit inode was accepted")
	}
}

func TestProviderGrokHeadlessLineageQualificationProducesSignedPartialReceipt(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := grok.Result{
		Success: true, AcknowledgementVerified: true, Authenticated: true, ProviderSessionID: "raw-parent-session",
		Model: identity.Model(), ModelEvidence: "completion_metadata",
		ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton",
		RuntimeEventContract: provider.EventContractReport{Passed: true},
		Cleanup:              grok.ProcessCleanupReceipt{ObservedAt: time.Now().UTC(), Reaped: true, ResidualPIDs: []int32{}, LocalTermination: "observed_tree_terminated_verified"},
	}
	deps, admission, stored, _, calls := grokQualificationDepsForTest(t, profile, bootstrap)
	workspace := providerGrokLineageWorkspace{Root: "/tmp/ntm-grok-lineage-qualification-test", Primary: "/tmp/ntm-grok-lineage-qualification-test/primary", Worktree: "/tmp/ntm-grok-lineage-qualification-test/linked", RuntimeHome: "/tmp/ntm-grok-lineage-qualification-test/grok-home"}
	deps.prepareLineage = func(context.Context, string) (providerGrokLineageWorkspace, error) { return workspace, nil }
	cleanups := 0
	deps.cleanupLineage = func(context.Context, providerGrokLineageWorkspace) error { cleanups++; return nil }
	deps.sessionRunner = grok.HeadlessOSRunner{}
	sessionCalls := 0
	deps.runSession = func(_ context.Context, _ grok.LifecycleRunner, req grok.SessionRequest) (grok.SessionReceipt, error) {
		sessionCalls++
		parent := sha256StringCLI(req.SessionID)
		child := parent
		if req.Action == grok.SessionFork {
			child = sha256StringCLI("fork-child")
		}
		zero := 0
		return grok.SessionReceipt{
			Action: req.Action, Fork: req.Action == grok.SessionFork,
			ParentSessionSHA256: parent, ChildSessionSHA256: child,
			CWDSHA256: sha256StringCLI(req.CWD), WorktreeSHA256: sha256StringCLI(req.Worktree),
			PolicySHA256: req.PolicySHA256, ConfigSHA256: req.ConfigSHA256, BinarySHA256: req.BinarySHA256,
			NonceSHA256: sha256StringCLI(req.ExpectedNonce), LineageBound: true, ProviderAcknowledged: true,
			CompletionConfirmed: true, StopReason: "end_turn", RequestedModel: req.Model,
			ExpectedReceiptModel: grok.ExpectedResolvedModel(req.RuntimeVersion, req.Model), Model: grok.ExpectedResolvedModel(req.RuntimeVersion, req.Model), ModelEvidence: "end.modelUsage_singleton",
			ExitCode: &zero, Cancellation: grok.CancellationReceipt{LocalTermination: "not_required_process_exited", ResidualPIDs: []int32{}, ObservedAt: time.Now().UTC()},
		}, nil
	}
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var output bytes.Buffer
	cmd.SetOut(&output)
	err = runProviderGrokQualification(cmd, providerQualificationOptions{profile: "grok", live: true, grokHeadlessLineage: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) {
		t.Fatalf("err=%v, want partial qualification exit", err)
	}
	if *calls != 1 || sessionCalls != 2 || cleanups != 1 || admission.acquires != 3 || admission.releases != 3 || admission.successes != 3 {
		t.Fatalf("ACP=%d sessions=%d cleanups=%d admission=%+v", *calls, sessionCalls, cleanups, admission)
	}
	if stored.Transport != "xai_headless_session" || stored.Passed || stored.Validate() != nil {
		t.Fatalf("stored receipt=%+v validate=%v", *stored, stored.Validate())
	}
	if stored.RuntimeSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("lineage receipt omitted exact runtime digest: %q", stored.RuntimeSHA256)
	}
	passed := make(map[string]bool, len(stored.Checks))
	for _, check := range stored.Checks {
		passed[check.Name] = check.Passed
	}
	for _, name := range []string{providerqualification.CheckIdentity, providerqualification.CheckResume, providerqualification.CheckProcessCleanup} {
		if !passed[name] {
			t.Fatalf("lineage receipt omitted proven check %q: %+v", name, stored.Checks)
		}
	}
	for _, name := range []string{providerqualification.CheckWorkspaceEdit, providerqualification.CheckTestCommand, providerqualification.CheckSecretDenied, providerqualification.CheckPushDenied, providerqualification.CheckCrashRecovery, providerqualification.CheckCancellation} {
		if passed[name] {
			t.Fatalf("lineage receipt fabricated unexercised check %q", name)
		}
	}
	if strings.Contains(output.String(), "raw-parent-session") {
		t.Fatal("lineage qualification output leaked the raw provider session id")
	}
}

func TestProviderGrokLineageWorkspaceIsDisposableAndCredentialIsolated(t *testing.T) {
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "auth.json"), []byte(`{"cached":"redacted-test-token"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	workspace, err := prepareProviderGrokLineageWorkspace(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	if workspace.Root == source || workspace.RuntimeHome == source || filepath.Dir(workspace.Worktree) != workspace.Root {
		t.Fatalf("workspace was not isolated: %+v", workspace)
	}
	if body, err := os.ReadFile(filepath.Join(workspace.RuntimeHome, "auth.json")); err != nil || string(body) != `{"cached":"redacted-test-token"}` {
		t.Fatalf("isolated auth copy invalid: body=%q err=%v", body, err)
	}
	if linked, err := providerIsLinkedGitWorktree(t.Context(), workspace.Worktree); err != nil || !linked {
		t.Fatalf("qualification worktree is not linked: linked=%v err=%v", linked, err)
	}
	if err := cleanupProviderGrokLineageWorkspace(t.Context(), workspace); err != nil {
		t.Fatal(err)
	}
	if !providerGrokLineageWorkspaceRemoved(workspace) {
		t.Fatal("qualification workspace or isolated session home remained after cleanup")
	}
}

func TestProviderGrokQualificationSignsBoundedProtocolReason(t *testing.T) {
	for _, reason := range []provider.ProtocolFailureReason{provider.ProtocolUnknownMethod, provider.ProtocolMalformedEnvelope, provider.ProtocolFailureReason("SENSITIVE_CANARY")} {
		profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
		identity, err := profile.Identity()
		if err != nil {
			t.Fatal(err)
		}
		result := grok.Result{FailureCode: grok.ErrProtocol, FailureStage: "session_new", ProtocolFailureReason: reason}
		deps, _, stored, _, _ := grokQualificationDepsForTest(t, profile, result)
		deps.run = func(context.Context, grok.Runner, grok.Request) (grok.Result, error) {
			return result, errors.New("SENSITIVE_CANARY")
		}
		want := reason
		if !want.Valid() {
			want = provider.ProtocolOther
		}
		signed := false
		deps.sign = func(_ context.Context, receipt *providerqualification.Receipt) error {
			payload, err := receipt.CanonicalPayload()
			if bridgeErr := providerattestation.ValidateBridgePayload(payload); bridgeErr != nil {
				t.Fatalf("diagnostic receipt rejected by signing bridge: %v", bridgeErr)
			}
			if err != nil || !strings.Contains(string(payload), `"failure_reason":"`+string(want)+`"`) || strings.Contains(string(payload), "SENSITIVE_CANARY") {
				t.Fatal("signer did not receive a bounded diagnostic in its canonical payload")
			}
			signed = true
			return nil
		}
		cmd := &cobra.Command{}
		cmd.SetOut(&bytes.Buffer{})
		_ = runProviderGrokQualification(cmd, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
		if !signed || stored.Validate() != nil {
			t.Fatal("failed provider run did not produce a valid signed-payload receipt")
		}
	}
}

func TestProviderGrokQualificationRejectsLegacySignerBeforeDispatch(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	deps, _, _, _, _ := grokQualificationDepsForTest(t, profile, grok.Result{})
	deps.pinnedSigner = func(config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
		return func(_ context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
			if !bytes.Contains(payload, []byte(`"failure_reason"`)) {
				t.Fatal("Grok preflight did not exercise the new bridge field")
			}
			return providerattestation.SignatureMetadata{}, providerattestation.ErrBridgePayloadDenied
		}, nil
	}
	dispatched := false
	deps.run = func(context.Context, grok.Runner, grok.Request) (grok.Result, error) {
		dispatched = true
		return grok.Result{}, nil
	}
	err = runProviderGrokQualification(&cobra.Command{}, providerQualificationOptions{live: true}, profile, identity, deps)
	if err == nil || dispatched || !strings.Contains(err.Error(), "before dispatch") {
		t.Fatalf("legacy signer did not block dispatch: dispatched=%v err=%v", dispatched, err)
	}
}

func TestProviderGrokQualificationFailsClosedForUnknownPolicy(t *testing.T) {
	profile := providerTestGrokProfile("custom-unmanaged-policy")
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	deps, _, _, _, calls := grokQualificationDepsForTest(t, profile, grok.Result{})
	err = runProviderGrokQualification(&cobra.Command{}, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, profile, identity, deps)
	if err == nil || *calls != 0 {
		t.Fatalf("err=%v calls=%d; unmanaged policy must not dispatch", err, *calls)
	}
}

func TestProviderQualificationRoutesGrokToObserveOnlyProducer(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	result := grok.Result{Success: true, AcknowledgementVerified: true, Authenticated: true, Model: identity.Model(), ModelEvidence: "completion_metadata", ResolvedModel: grok.ExpectedResolvedModel(profile.RuntimeVersion, identity.Model()), ResolvedModelEvidence: "completion_metadata.usage.model_usage_singleton", RuntimeEventContract: provider.EventContractReport{Passed: true}, Cleanup: grok.ProcessCleanupReceipt{ObservedAt: time.Now().UTC(), Reaped: true, ResidualPIDs: []int32{}}}
	grokDeps, _, _, _, calls := grokQualificationDepsForTest(t, profile, result)
	previous := providerGrokQualificationDeps
	providerGrokQualificationDeps = grokDeps
	t.Cleanup(func() { providerGrokQualificationDeps = previous })
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err = runProviderQualification(cmd, providerQualificationOptions{profile: "grok", live: true, timeout: time.Second, suiteTimeout: time.Second}, providerQualificationDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"grok": profile}}
		},
	})
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) || *calls != 1 {
		t.Fatalf("err=%v calls=%d; expected the dedicated Grok producer", err, *calls)
	}
}
