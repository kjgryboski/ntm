package grok

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	agentpkg "github.com/Dicklesworthstone/ntm/internal/agent"
)

func TestBuildSessionSpecResumeAndFork(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	for _, action := range []SessionAction{SessionResume, SessionFork} {
		spec, receipt, err := BuildSessionSpec(SessionRequest{Action: action, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		if receipt.ParentSessionSHA256 == "" || receipt.NonceSHA256 == "" || receipt.CWDSHA256 == "" || receipt.WorktreeSHA256 == "" || receipt.PolicySHA256 == "" || receipt.Fork != (action == SessionFork) || spec.Binary != "grok" {
			t.Fatalf("bad receipt/spec: %+v %+v", receipt, spec)
		}
		if action == SessionFork && !sameStrings(spec.Args[len(spec.Args)-1:], []string{"--fork-session"}) {
			t.Fatalf("fork args: %#v", spec.Args)
		}
	}
}

func TestBuildSessionSpecBindsExplicitNonSecretAttestationDigests(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	digest := strings.Repeat("a", 64)
	_, receipt, err := BuildSessionSpec(SessionRequest{
		Action: SessionFork, SessionID: "parent", Prompt: nonce, CWD: "/repo", Worktree: "/worktrees/child",
		ExpectedNonce: nonce, PolicySHA256: digest, ConfigSHA256: strings.Repeat("b", 64), BinarySHA256: strings.Repeat("c", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.PolicySHA256 != digest || receipt.ConfigSHA256 != strings.Repeat("b", 64) || receipt.BinarySHA256 != strings.Repeat("c", 64) {
		t.Fatalf("attestation digests not retained: %+v", receipt)
	}
	if receipt.CWDSHA256 == receipt.WorktreeSHA256 {
		t.Fatalf("distinct cwd/worktree context collapsed: %+v", receipt)
	}
}

func TestBuildSessionSpecRejectsMalformedAttestationDigest(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	_, _, err := BuildSessionSpec(SessionRequest{
		Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce,
		ConfigSHA256: "ABCDEF",
	})
	if err == nil || !strings.Contains(err.Error(), "config SHA-256") {
		t.Fatalf("malformed digest accepted: %v", err)
	}
}

func TestBuildSessionSpecAcceptsExactWorkspaceWritePolicy(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	policyArgs := agentpkg.GrokAutomationLifecyclePolicyArgs(agentpkg.GrokWorkspaceWritePolicyName)
	spec, _, err := BuildSessionSpec(SessionRequest{
		Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo",
		ExpectedNonce: nonce, PolicyArgs: policyArgs,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !sameStrings(spec.Args[1:1+len(policyArgs)], policyArgs) {
		t.Fatalf("workspace policy args = %#v", spec.Args)
	}
}

func TestBuildSessionSpecInheritsSessionSandboxButRetainsCompiledRules(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	policyArgs := agentpkg.GrokAutomationLifecyclePolicyArgs(agentpkg.DefaultGrokAutomationPolicyName)
	spec, _, err := BuildSessionSpec(SessionRequest{
		Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo",
		ExpectedNonce: nonce, PolicyArgs: policyArgs,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spec.Args, "\n")
	if strings.Contains(joined, "--sandbox=") {
		t.Fatalf("resume forced a sandbox instead of inheriting the parent session: %#v", spec.Args)
	}
	for _, required := range []string{"--permission-mode=dontAsk", "--allow=Read", "--deny=Edit", "--deny=Bash(*)", "--deny=Read(**/.grok/**)"} {
		if !strings.Contains(joined, required) {
			t.Fatalf("resume omitted compiled rule %q: %#v", required, spec.Args)
		}
	}
}

type lifecycleRunnerFake struct {
	spec  StartSpec
	proc  LifecycleProcess
	calls int
}

func (r *lifecycleRunnerFake) Start(_ context.Context, spec StartSpec) (LifecycleProcess, error) {
	r.calls++
	r.spec = spec
	return r.proc, nil
}

type lifecycleProcessFake struct {
	stdout string
	wait   chan error
	pid    int32
}

func (p *lifecycleProcessFake) Stdout() io.Reader { return strings.NewReader(p.stdout) }
func (p *lifecycleProcessFake) Stderr() io.Reader { return strings.NewReader("") }
func (p *lifecycleProcessFake) Wait() error       { return <-p.wait }
func (p *lifecycleProcessFake) PID() int32        { return p.pid }

func TestExecuteSessionBindsForkOnlyAfterStructuredNonceAndChildSession(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	p := &lifecycleProcessFake{stdout: "{\"type\":\"assistant\",\"delta\":{\"text\":\"work\"}}\n{\"type\":\"result\",\"subtype\":\"success\",\"session_id\":\"child\",\"model\":\"grok-4.6\",\"stop_reason\":\"end_turn\",\"result\":\"" + nonce + "\",\"usage\":{\"input_tokens\":2,\"output_tokens\":3}}\n", wait: make(chan error, 1)}
	p.wait <- nil
	runner := &lifecycleRunnerFake{proc: p}
	r, err := ExecuteSession(t.Context(), runner, SessionRequest{Action: SessionFork, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce, Model: "grok-4.6"})
	if err != nil || !r.LineageBound || !r.ProviderAcknowledged || !r.CompletionConfirmed || r.Model != "grok-4.6" || r.OutputSHA256 == "" {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
	if !strings.Contains(strings.Join(runner.spec.Args, " "), "--fork-session") {
		t.Fatalf("fork spec=%#v", runner.spec)
	}
}

func TestExecuteSessionAcceptsGrok1013StreamingEndSchema(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	stdout := strings.Join([]string{
		`{"type":"available_commands","commands":[{"name":"help"}]}`,
		`{"type":"thought","data":"redacted reasoning that must not be hashed"}`,
		`{"type":"text","data":"NTM_ACK_0123456789abcdef"}`,
		`{"type":"text","data":"0123456789abcdef"}`,
		`{"type":"usage","usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}`,
		`{"type":"end","stopReason":"end_turn","sessionId":"child","usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5},"modelUsage":{"grok-4.6-build":{"inputTokens":2,"outputTokens":3,"modelCalls":1}}}`,
	}, "\n") + "\n"
	p := &lifecycleProcessFake{stdout: stdout, wait: make(chan error, 1)}
	p.wait <- nil
	r, err := ExecuteSession(t.Context(), &lifecycleRunnerFake{proc: p}, SessionRequest{
		Action: SessionFork, SessionID: "parent", Prompt: nonce, CWD: "/repo",
		ExpectedNonce: nonce, Model: "grok-4.6", RuntimeVersion: "1.0.13",
	})
	wantHash := sha256.Sum256([]byte(nonce))
	if err != nil || !r.LineageBound || !r.ProviderAcknowledged || !r.CompletionConfirmed {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
	if r.RequestedModel != "grok-4.6" || r.ExpectedReceiptModel != "grok-4.6-build" || r.Model != "grok-4.6-build" || r.ModelEvidence != "end.modelUsage_singleton" || r.StopReason != "end_turn" {
		t.Fatalf("provider evidence=%+v", r)
	}
	if r.OutputSHA256 != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("output hash=%q want=%q", r.OutputSHA256, hex.EncodeToString(wantHash[:]))
	}
	if r.Usage == nil || r.Usage.TotalTokens == nil || *r.Usage.TotalTokens != 5 {
		t.Fatalf("usage=%+v", r.Usage)
	}
	if r.Cancellation.ProviderAcknowledged || r.Cancellation.LocalTermination != "not_required_process_exited" || len(r.Cancellation.ResidualPIDs) != 0 || r.Cancellation.ObservedAt.IsZero() {
		t.Fatalf("normal completion cleanup evidence=%+v", r.Cancellation)
	}
}

func TestExecuteSessionFailsClosedOnUndocumentedModelAliasAndRetainsEvidence(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	stdout := `{"type":"text","data":"` + nonce + `"}` + "\n" +
		`{"type":"end","stopReason":"end_turn","sessionId":"child","modelUsage":{"grok-4.6-build":{}}}` + "\n"
	p := &lifecycleProcessFake{stdout: stdout, wait: make(chan error, 1)}
	p.wait <- nil
	r, err := ExecuteSession(t.Context(), &lifecycleRunnerFake{proc: p}, SessionRequest{
		Action: SessionFork, SessionID: "parent", Prompt: nonce, CWD: "/repo",
		ExpectedNonce: nonce, Model: "grok-4.5", RuntimeVersion: "1.0.13",
	})
	var got *Error
	if !errors.As(err, &got) || got.Code != ErrIdentityMismatch {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
	if !r.CompletionConfirmed || r.Model != "grok-4.6-build" || r.ModelEvidence != "end.modelUsage_singleton" || r.LineageBound {
		t.Fatalf("identity mismatch evidence=%+v", r)
	}
}

func TestExecuteSessionRejectsReceiptModelOutsideExactPinnedBinding(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name, runtimeVersion, receiptModel string
	}{
		{name: "runtime drift", runtimeVersion: "1.0.130", receiptModel: "grok-4.6-build"},
		{name: "lookalike backend", runtimeVersion: "1.0.13", receiptModel: "grok-4.6-build-preview"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stdout := `{"type":"text","data":"` + nonce + `"}` + "\n" +
				`{"type":"end","stopReason":"end_turn","sessionId":"child","modelUsage":{"` + tc.receiptModel + `":{}}}` + "\n"
			p := &lifecycleProcessFake{stdout: stdout, wait: make(chan error, 1)}
			p.wait <- nil
			r, err := ExecuteSession(t.Context(), &lifecycleRunnerFake{proc: p}, SessionRequest{
				Action: SessionFork, SessionID: "parent", Prompt: nonce, CWD: "/repo",
				ExpectedNonce: nonce, Model: "grok-4.6", RuntimeVersion: tc.runtimeVersion,
			})
			var got *Error
			if !errors.As(err, &got) || got.Code != ErrIdentityMismatch || r.LineageBound {
				t.Fatalf("receipt=%+v err=%v", r, err)
			}
		})
	}
}

func TestParseLifecycleStreamRejectsAmbiguousEndModelEvidence(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	stream := `{"type":"text","data":"` + nonce + `"}` + "\n" +
		`{"type":"end","stopReason":"end_turn","sessionId":"child","modelUsage":{"grok-4.6":{},"other":{}}}` + "\n"
	result := parseLifecycleStream(strings.NewReader(stream), nonce, "grok-4.6")
	if result.err == nil || !strings.Contains(result.err.Error(), "multiple provider models") {
		t.Fatalf("result=%+v", result)
	}
}

func TestParseLifecycleStreamRejectsCompletionWithoutStopReason(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	stream := `{"type":"result","subtype":"success","session_id":"child","model":"grok-4.6","result":"` + nonce + `"}` + "\n"
	result := parseLifecycleStream(strings.NewReader(stream), nonce, "grok-4.6")
	if result.err == nil || !strings.Contains(result.err.Error(), "stop reason") {
		t.Fatalf("result=%+v", result)
	}
}

func TestExecuteSessionRejectsMissingNonceWithoutBinding(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	p := &lifecycleProcessFake{stdout: "{\"type\":\"result\",\"subtype\":\"success\",\"session_id\":\"child\",\"model\":\"grok-4.6\",\"stop_reason\":\"end_turn\",\"result\":\"wrong\"}\n", wait: make(chan error, 1)}
	p.wait <- nil
	r, err := ExecuteSession(t.Context(), &lifecycleRunnerFake{proc: p}, SessionRequest{Action: SessionFork, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce, Model: "grok-4.6"})
	var got *Error
	if !errors.As(err, &got) || got.Code != ErrAcknowledgementUnconfirmed || r.LineageBound {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
}

func TestExecuteSessionCancellationNeverClaimsProviderAcknowledgement(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	p := &lifecycleProcessFake{stdout: "", wait: make(chan error, 1), pid: 0}
	p.wait <- context.Canceled
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runner := &lifecycleRunnerFake{proc: p}
	r, err := ExecuteSession(ctx, runner, SessionRequest{Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce})
	var got *Error
	if !errors.As(err, &got) || got.Code != ErrOutcomeUnknown || r.Cancellation.ProviderAcknowledged || r.Cancellation.LocalTermination != "not_started" || runner.calls != 0 {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
}

func TestExecuteSessionCancellationInterruptsWaitAfterParserEOF(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	p := &lifecycleProcessFake{stdout: "", wait: make(chan error), pid: 0}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	r, err := ExecuteSession(ctx, &lifecycleRunnerFake{proc: p}, SessionRequest{Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce})
	var got *Error
	if !errors.As(err, &got) || got.Code != ErrOutcomeUnknown || r.Cancellation.ProviderAcknowledged || r.Cancellation.LocalTermination != "unsupported" {
		t.Fatalf("receipt=%+v err=%v", r, err)
	}
}

func TestBindSessionLineageRequiresNonceAndNewForkID(t *testing.T) {
	_, r, err := BuildSessionSpec(SessionRequest{
		Action: SessionFork, SessionID: "parent", Prompt: "NTM_ACK_0123456789abcdef0123456789abcdef", CWD: "/repo",
		ExpectedNonce: "NTM_ACK_0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindSessionLineage(r, "parent", true); err == nil {
		t.Fatal("same fork session accepted")
	}
	if _, err := BindSessionLineage(r, "child", false); err == nil {
		t.Fatal("missing nonce accepted")
	}
	got, err := BindSessionLineage(r, "child", true)
	if err != nil || !got.LineageBound || !got.ProviderAcknowledged {
		t.Fatalf("lineage: %+v %v", got, err)
	}
}

func TestBindSessionLineageFailsClosedWhenImmutableContextIsMissingOrInconsistent(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	_, r, err := BuildSessionSpec(SessionRequest{Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	r.CWDSHA256 = ""
	if _, err := BindSessionLineage(r, "child", true); err == nil || !strings.Contains(err.Error(), "cwd SHA-256") {
		t.Fatalf("missing cwd context accepted: %v", err)
	}

	_, r, err = BuildSessionSpec(SessionRequest{Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	r.Fork = true
	if _, err := BindSessionLineage(r, "child", true); err == nil || !strings.Contains(err.Error(), "fork flag") {
		t.Fatalf("inconsistent fork context accepted: %v", err)
	}
}

func TestBindSessionLineageAllowsResumeToRetainTheSameSession(t *testing.T) {
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	_, receipt, err := BuildSessionSpec(SessionRequest{Action: SessionResume, SessionID: "parent", Prompt: nonce, CWD: "/repo", ExpectedNonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindSessionLineage(receipt, "parent", true)
	if err != nil || !bound.LineageBound || bound.ChildSessionSHA256 != bound.ParentSessionSHA256 {
		t.Fatalf("resume did not retain parent lineage: %+v %v", bound, err)
	}
}

type treeInspector struct {
	children map[int32][]int32
	live     map[int32]bool
	killed   []int32
	failKill bool
}

func (i *treeInspector) Children(pid int32) ([]int32, error) { return i.children[pid], nil }
func (i *treeInspector) Exists(pid int32) (bool, error)      { return i.live[pid], nil }
func (i *treeInspector) Kill(pid int32) error {
	if i.failKill {
		return context.Canceled
	}
	i.killed = append(i.killed, pid)
	i.live[pid] = false
	return nil
}

func TestTerminateAndVerifyDistinguishesLocalTreeEvidence(t *testing.T) {
	// The descendant has a smaller PID so a numeric sort would incorrectly
	// terminate the parent first. Structural postorder must still win.
	i := &treeInspector{children: map[int32][]int32{10: {5}}, live: map[int32]bool{10: true, 5: true}}
	r := terminateAndVerify(t.Context(), 10, i)
	if r.LocalTermination != "observed_tree_terminated_verified" || r.ProviderAcknowledged || len(r.ResidualPIDs) != 0 {
		t.Fatalf("receipt: %+v", r)
	}
	if len(i.killed) != 2 || i.killed[0] != 5 || i.killed[1] != 10 {
		t.Fatalf("kill order=%v, want descendant before parent", i.killed)
	}
}

func TestTerminateAndVerifyReportsAlreadyExitedWithoutOverclaimingTreeTermination(t *testing.T) {
	i := &treeInspector{children: map[int32][]int32{}, live: map[int32]bool{10: false}}
	r := terminateAndVerify(t.Context(), 10, i)
	if r.LocalTermination != "already_exited_verified" || r.ProviderAcknowledged || len(r.ResidualPIDs) != 0 || len(i.killed) != 0 {
		t.Fatalf("receipt: %+v killed=%v", r, i.killed)
	}
}
