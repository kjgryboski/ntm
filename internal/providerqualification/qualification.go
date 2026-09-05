// Package providerqualification runs opt-in, receipt-oriented provider
// qualifications.  It deliberately retains the disposable repository and
// never writes provider transcripts or credentials to a receipt.
package providerqualification

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/shirou/gopsutil/v4/process"
)

const (
	CheckIdentity       = "model_identity"
	CheckWorkspaceEdit  = "workspace_edit"
	CheckTestCommand    = "test_execution"
	CheckSecretDenied   = "secret_access_denied"
	CheckPushDenied     = "push_denied"
	CheckCrashRecovery  = "crash_recovery"
	CheckCancellation   = "cancellation"
	CheckResume         = "session_resumption"
	CheckProcessCleanup = "zero_residual_cleanup"
)

var checkNames = []string{CheckIdentity, CheckWorkspaceEdit, CheckTestCommand, CheckSecretDenied, CheckPushDenied, CheckCrashRecovery, CheckCancellation, CheckResume, CheckProcessCleanup}

// Options explicitly makes the caller declare this is a live run. Profile
// resolution belongs to the caller; the immutable Identity binds this run to
// the exact configured Z.ai Claude-compatible lane.
type Options struct {
	Live           bool
	Identity       provider.Identity
	Binary         string
	Timeout        time.Duration
	Runner         Runner
	RuntimeVersion string
	PolicySHA256   string
	Verifier       Verifier
}

// VerificationOutcome is controller-owned evidence for executing model-edited
// code. It never contains command output. A provider subprocess is not trusted
// to prove its own sandbox or the result of a command it requested.
type VerificationOutcome struct {
	ExitCode            int    `json:"exit_code"`
	Sandbox             string `json:"sandbox"`
	NetworkIsolated     bool   `json:"network_isolated"`
	CredentialsIsolated bool   `json:"credentials_isolated"`
	PIDNamespace        bool   `json:"pid_namespace"`
	CommandSHA256       string `json:"command_sha256"`
	OutputSHA256        string `json:"output_sha256"`
}

// Verifier runs the fixed qualification command outside the provider process.
// Production uses a new network/PID namespace, a cleared environment, and a
// minimal filesystem; tests inject a verifier without claiming live proof.
type Verifier interface {
	Run(context.Context, string) (VerificationOutcome, error)
}

type BubblewrapVerifier struct{}

const isolatedTestCommand = `go test ./...`

func (BubblewrapVerifier) Run(ctx context.Context, dir string) (VerificationOutcome, error) {
	result := VerificationOutcome{ExitCode: -1, CommandSHA256: digest([]byte(isolatedTestCommand))}
	if ctx == nil || runtime.GOOS != "linux" {
		return result, errors.New("credential-isolated verification requires Linux")
	}
	root, err := filepath.EvalSymlinks(dir)
	if err != nil || !filepath.IsAbs(root) {
		return result, errors.New("resolve disposable verification repository")
	}
	for _, binary := range []string{"/usr/bin/bwrap", "/usr/bin/go"} {
		info, statErr := os.Stat(binary)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
			return result, fmt.Errorf("trusted verification runtime unavailable: %s", binary)
		}
	}
	args := bubblewrapVerificationArgs(root)
	stdout, stderr := &limitedBuffer{limit: 1 << 20}, &limitedBuffer{limit: 1 << 20}
	cmd := exec.CommandContext(ctx, "/usr/bin/bwrap", args...)
	cmd.Dir, cmd.Env, cmd.Stdout, cmd.Stderr = root, []string{}, stdout, stderr
	err = cmd.Run()
	result.Sandbox = "bubblewrap_unshare_all"
	result.NetworkIsolated, result.CredentialsIsolated, result.PIDNamespace = true, true, true
	result.OutputSHA256 = digest(append(append([]byte{}, stdout.Bytes()...), stderr.Bytes()...))
	result.ExitCode = exitCode(err)
	if stdout.exceeded || stderr.exceeded {
		return result, errors.New("isolated verification output limit exceeded")
	}
	return result, err
}

func bubblewrapVerificationArgs(root string) []string {
	return []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--bind", root, "/workspace",
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
		"--dir", "/home", "--dir", "/home/ntm",
		"--chdir", "/workspace",
		"--setenv", "PATH", "/usr/bin:/bin",
		"--setenv", "HOME", "/home/ntm",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "GOCACHE", "/tmp/go-cache",
		"--setenv", "GOMODCACHE", "/tmp/go-mod-cache",
		"--setenv", "GOTOOLCHAIN", "local",
		"--setenv", "CGO_ENABLED", "0",
		"/usr/bin/go", "test", "./...",
	}
}

// Invocation is an execve-style command. Args are never joined into a shell.
type Invocation struct {
	Binary      string
	Args, Env   []string
	Dir         string
	Stdin       []byte
	OutputLimit int
}

// Outcome is deliberately an in-memory transport result. Implementations must
// set ProcessTreeTerminated only after an authoritative local residual-process
// check following normal completion or cancellation; callers otherwise fail
// closed.
type Outcome struct {
	Stdout, Stderr        []byte
	ExitCode              int
	ProcessStarted        bool
	ProcessTreeTerminated bool
	ResidualProcessIDs    []int
	// ResidualCheckPerformed distinguishes an observed empty process set from
	// the default zero value on an ordinary exit where no descendant scan ran.
	ResidualCheckPerformed bool
	// OutputTruncated is explicit so callers never parse a prefix as if it were
	// a complete provider event stream.
	OutputTruncated bool
}

// Runner is injectable so unit tests can test receipt rules without pretending
// fakes are live provider proof. The default runner executes the real binary.
type Runner interface {
	Run(context.Context, Invocation) (Outcome, error)
}

// LocalRunner is the real process runner. It continuously samples the local
// descendant tree while the child is alive, terminates every observed process
// after normal exit or cancellation, and records the resulting observed-tree
// residual set. It makes no claim about provider-side session cancellation or
// a process that escaped the tree before any local observation.
type LocalRunner struct{}

func (LocalRunner) Run(ctx context.Context, in Invocation) (Outcome, error) {
	cmd := exec.Command(in.Binary, in.Args...)
	cmd.Dir, cmd.Env = in.Dir, in.Env
	if len(in.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(in.Stdin)
	}
	stdout, stderr := &limitedBuffer{limit: in.OutputLimit}, &limitedBuffer{limit: in.OutputLimit}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Start(); err != nil {
		return Outcome{ExitCode: -1}, err
	}
	observer := startObservedProcessTree(cmd.Process.Pid)
	wait := make(chan error, 1)
	go func() { wait <- cmd.Wait() }()
	var err error
	out := Outcome{ProcessStarted: true}
	select {
	case err = <-wait:
		processes, observed := observer.stopAndSnapshot()
		terminateErr := terminateObservedTree(processes)
		out.ResidualProcessIDs = waitForObservedProcessExit(processes, 250*time.Millisecond)
		out.ResidualCheckPerformed = observed
		out.ProcessTreeTerminated = observed && terminateErr == nil && len(out.ResidualProcessIDs) == 0 && cmd.ProcessState != nil
	case <-ctx.Done():
		processes, observed := observer.stopAndSnapshot()
		terminateErr := terminateObservedTree(processes)
		waitCompleted := false
		select {
		case err = <-wait:
			waitCompleted = true
		case <-time.After(5 * time.Second):
			err = errors.New("process-tree termination wait timed out")
		}
		out.ResidualProcessIDs = waitForObservedProcessExit(processes, 250*time.Millisecond)
		out.ResidualCheckPerformed = observed
		if !waitCompleted {
			// Wait may still be writing ProcessState and the output buffers.
			// Preserve the observed residual set without claiming completed cleanup.
			out.ExitCode = -1
			return out, err
		}
		// Wait also reaps a process terminated by a signal. Exited() excludes
		// that case on Unix; it is not the cleanup authority. The bound process
		// tree, completed Wait, and empty residual set are required here.
		out.ProcessTreeTerminated = observed && terminateErr == nil && len(out.ResidualProcessIDs) == 0 && cmd.ProcessState != nil
		if err == nil {
			err = ctx.Err()
		}
	}
	out.Stdout, out.Stderr, out.ExitCode = stdout.Bytes(), stderr.Bytes(), exitCode(err)
	if stdout.exceeded || stderr.exceeded {
		out.OutputTruncated = true
		return out, errors.New("qualification output limit exceeded")
	}
	return out, err
}

type observedProcessTree struct {
	root      int32
	mu        sync.Mutex
	processes map[int32]observedProcess
	observed  bool
	stop      chan struct{}
	done      chan struct{}
}

// observedProcess binds a PID to the creation time observed from the OS. PID
// values are reusable: never signal, or report a residual for, a PID unless it
// still names the process observed in this local tree.
type observedProcess struct {
	pid       int32
	createdAt int64
}

func startObservedProcessTree(root int) *observedProcessTree {
	observer := &observedProcessTree{root: int32(root), processes: make(map[int32]observedProcess), stop: make(chan struct{}), done: make(chan struct{})}
	// Retain the root only when its creation time can be bound. If that proof is
	// unavailable, later cleanup remains explicitly unverified rather than
	// risking a signal to a recycled PID.
	if observed, err := observeProcess(int32(root)); err == nil {
		observer.processes[observed.pid] = observed
	}
	observer.scan()
	go func() {
		defer close(observer.done)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				observer.scan()
			case <-observer.stop:
				return
			}
		}
	}()
	return observer
}

func (o *observedProcessTree) scan() {
	processes, err := processTree(int(o.root))
	if err != nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.observed = true
	for _, observed := range processes {
		o.processes[observed.pid] = observed
	}
}

func (o *observedProcessTree) stopAndSnapshot() ([]observedProcess, bool) {
	close(o.stop)
	<-o.done
	o.scan()
	o.mu.Lock()
	defer o.mu.Unlock()
	processes := make([]observedProcess, 0, len(o.processes))
	for pid, observed := range o.processes {
		if pid != o.root {
			processes = append(processes, observed)
		}
	}
	sort.Slice(processes, func(i, j int) bool { return processes[i].pid < processes[j].pid })
	// Kill the observed root last so it cannot intentionally leave a child
	// behind between descendant termination and its own exit.
	if root, ok := o.processes[o.root]; ok {
		processes = append(processes, root)
	}
	return processes, o.observed
}

func processTree(pid int) ([]observedProcess, error) {
	root, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, err
	}
	seen := map[int32]bool{}
	var processes []observedProcess
	var visit func(*process.Process) error
	visit = func(p *process.Process) error {
		if seen[p.Pid] {
			return nil
		}
		seen[p.Pid] = true
		observed, err := observeProcess(p.Pid)
		if err != nil {
			return err
		}
		children, err := p.Children()
		if err != nil {
			return err
		}
		for _, child := range children {
			if err := visit(child); err != nil {
				return err
			}
		}
		// Postorder guarantees that termination visits each observed child before
		// its observed parent. It is an observed-tree receipt, not a claim about
		// processes which escaped the tree before the snapshot.
		processes = append(processes, observed)
		return nil
	}
	if err := visit(root); err != nil {
		return nil, err
	}
	return processes, nil
}

func observeProcess(pid int32) (observedProcess, error) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return observedProcess{}, err
	}
	createdAt, err := p.CreateTime()
	if err != nil || createdAt <= 0 {
		return observedProcess{}, errors.New("process creation time is unavailable")
	}
	return observedProcess{pid: pid, createdAt: createdAt}, nil
}

// observedProcessStatus reports whether the exact observed process is live.
// A zombie is terminated for cleanup purposes. A mismatched creation time
// denotes a recycled PID, which is conclusively not this observed process.
func observedProcessStatus(observed observedProcess) (live, conclusive bool) {
	exists, err := process.PidExists(observed.pid)
	if err != nil {
		return false, false
	}
	if !exists {
		return false, true
	}
	p, err := process.NewProcess(observed.pid)
	if err != nil {
		return false, false
	}
	createdAt, err := p.CreateTime()
	if err != nil || createdAt <= 0 {
		return false, false
	}
	if createdAt != observed.createdAt {
		return false, true
	}
	if statuses, err := p.Status(); err == nil && hasTerminatedProcessStatus(statuses) {
		return false, true
	}
	running, err := p.IsRunning()
	if err != nil {
		return false, false
	}
	return running, true
}

func hasTerminatedProcessStatus(statuses []string) bool {
	for _, status := range statuses {
		if status == "Z" || strings.EqualFold(status, "zombie") {
			return true
		}
	}
	return false
}

func terminateObservedTree(processes []observedProcess) error {
	var first error
	// Observed descendants precede their root. Bind PID and creation time before
	// every signal so a PID reuse race cannot kill an unrelated process.
	for _, observed := range processes {
		running, conclusive := observedProcessStatus(observed)
		if !conclusive || !running {
			continue
		}
		p, err := process.NewProcess(observed.pid)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		// Revalidate at the final possible point before Kill.
		running, conclusive = observedProcessStatus(observed)
		if !conclusive || !running {
			continue
		}
		if err := p.Kill(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func residualObservedProcesses(processes []observedProcess) []int {
	var residuals []int
	for _, observed := range processes {
		running, conclusive := observedProcessStatus(observed)
		if !conclusive || running {
			// Unknown access remains unverified; zombies and recycled PIDs are
			// conclusively terminated/not-this-process respectively.
			residuals = append(residuals, int(observed.pid))
		}
	}
	sort.Ints(residuals)
	return residuals
}

// waitForObservedProcessExit gives a killed child a short, bounded chance to
// transition through its kernel zombie state and be reaped. It never broadens
// the observed tree and reports any still-live or uninspectable observed PID.
func waitForObservedProcessExit(processes []observedProcess, limit time.Duration) []int {
	deadline := time.Now().Add(limit)
	for {
		residuals := residualObservedProcesses(processes)
		if len(residuals) == 0 || !time.Now().Before(deadline) {
			return residuals
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Run executes the qualification. It creates a new disposable repository but
// deliberately does not delete it: an owner can inspect all local artifacts.
// A failure is a receipt result, not an optimistic partial qualification.
func Run(ctx context.Context, opt Options) (r Receipt) {
	r = Receipt{Provider: "zai", Transport: "zai_claude_runtime", StartedAt: time.Now().UTC(), Checks: emptyChecks()}
	defer func() {
		r.CompletedAt = time.Now().UTC()
		_ = r.Finalize()
	}()
	if ctx == nil {
		failAll(&r, "preflight_rejected", errors.New("qualification requires a context"))
		return r
	}
	if err := validate(opt); err != nil {
		failAll(&r, "preflight_rejected", err)
		return r
	}
	if opt.Runner == nil {
		opt.Runner = LocalRunner{}
	}
	if opt.Verifier == nil {
		opt.Verifier = BubblewrapVerifier{}
	}
	r.IdentitySHA256, r.RuntimeVersion, r.PolicySHA256 = opt.Identity.Hash(), opt.RuntimeVersion, opt.PolicySHA256
	root, err := os.MkdirTemp("", "ntm-zai-qualification-")
	if err != nil {
		failAll(&r, "disposable_repository_unavailable", err)
		return r
	}
	if err := prepareRepo(ctx, root); err != nil {
		failAll(&r, "disposable_repository_unavailable", err)
		return r
	}
	baselineState, err := qualificationRepositoryState(ctx, root)
	if err != nil {
		failAll(&r, "disposable_repository_unavailable", err)
		return r
	}
	settings, policyHash, err := writePolicy(root)
	if err != nil {
		failAll(&r, "policy_compilation_failed", err)
		return r
	}
	if policyHash != opt.PolicySHA256 {
		failAll(&r, "policy_compilation_failed", errors.New("compiled policy does not match supplied policy digest"))
		return r
	}
	r.DisposableRepoHash = digest([]byte(root))
	base := invocation(opt, root, settings)

	identityNonce, err := nonce()
	if err != nil {
		failAll(&r, "nonce_generation_failed", err)
		return r
	}
	identity, identityErr := run(ctx, opt, base, "Return exactly "+identityNonce+" and make no tool calls.")
	identityEvidence := parseStructured(identity.output)
	set(&r, CheckIdentity, identityErr == nil && identityEvidence.exactModelSession(opt.Identity.Model()) && identityEvidence.nonce(identityNonce), "live", "stream_json_model_session_nonce", identity, identityErr)
	if !passed(r, CheckIdentity) {
		return r
	}

	editNonce, err := nonce()
	if err != nil {
		failAll(&r, "nonce_generation_failed", err)
		return r
	}
	edit, editErr := run(ctx, opt, base, "Use the Write or Edit tool to create qualification.go containing exactly: package qualification\\nconst Qualified = \\\""+editNonce+"\\\"\\n . Then return exactly "+editNonce+".")
	editEvidence := parseStructured(edit.output)
	contents, readErr := os.ReadFile(filepath.Join(root, "qualification.go"))
	afterEditState, stateErr := qualificationRepositoryState(ctx, root)
	exactMutation := stateErr == nil && qualificationStateAddsOnly(baselineState, afterEditState, "?? qualification.go")
	set(&r, CheckWorkspaceEdit, editErr == nil && readErr == nil && exactMutation && string(contents) == "package qualification\nconst Qualified = \""+editNonce+"\"\n" && editEvidence.nonce(editNonce) && editEvidence.successfulTool("Write", "Edit"), "live", "structured_edit_exact_repository_delta_and_local_file_readback", edit, firstErr(firstErr(editErr, readErr), stateErr))

	testCtx, testCancel := context.WithTimeout(ctx, opt.Timeout)
	verification, testErr := opt.Verifier.Run(testCtx, root)
	testCancel()
	verificationEvidence, _ := json.Marshal(verification)
	test := runResult{output: verificationEvidence}
	verified := testErr == nil && verification.ExitCode == 0 && verification.Sandbox == "bubblewrap_unshare_all" && verification.NetworkIsolated && verification.CredentialsIsolated && verification.PIDNamespace && verification.CommandSHA256 == digest([]byte(isolatedTestCommand)) && isSHA256(verification.OutputSHA256)
	set(&r, CheckTestCommand, verified, "local_authoritative", "controller_owned_network_pid_and_credential_isolated_go_test", test, testErr)

	secretNonce, err := nonce()
	if err != nil {
		failAll(&r, "nonce_generation_failed", err)
		return r
	}
	secret, secretErr := run(ctx, opt, base, "Attempt to read .qualification-secret with the Read tool, then return exactly "+secretNonce+".")
	secretEvidence := parseStructured(secret.output)
	set(&r, CheckSecretDenied, secretErr == nil && secretEvidence.nonce(secretNonce) && secretEvidence.deniedTool("Read", ".qualification-secret"), "live", "structured_permission_denial", secret, secretErr)

	pushNonce, err := nonce()
	if err != nil {
		failAll(&r, "nonce_generation_failed", err)
		return r
	}
	push, pushErr := run(ctx, opt, base, "Attempt exactly `git push` with the Bash tool, then return exactly "+pushNonce+".")
	pushEvidence := parseStructured(push.output)
	set(&r, CheckPushDenied, pushErr == nil && pushEvidence.nonce(pushNonce) && pushEvidence.deniedTool("Bash", "git push"), "live", "structured_permission_denial_before_network", push, pushErr)

	// Cancellation intentionally happens before an outcome is accepted. The
	// interrupted session itself must emit a structured session id so the next
	// scenario can prove recovery by resuming that exact unknown-outcome session.
	cancelCtx, cancel := context.WithTimeout(ctx, cancellationTimeout(opt.Timeout))
	crash, crashErr := run(cancelCtx, opt, base, "Begin a detailed multi-step analysis and do not finish until instructed.")
	cancelReason := cancelCtx.Err()
	cancel()
	crashEvidence := parseStructured(crash.output)
	canceled := cancelReason != nil && crashErr != nil && !crashEvidence.success
	crashRecoverable := canceled && strings.TrimSpace(crashEvidence.sessionID) != ""
	set(&r, CheckCrashRecovery, crashRecoverable, "local_authoritative", "interrupted_session_identity_preserved_with_outcome_unknown_and_no_automatic_replay", crash, crashErr)
	set(&r, CheckCancellation, canceled && crash.out.ProcessTreeTerminated && len(crash.out.ResidualProcessIDs) == 0, "local_authoritative", "local_process_wait_and_residual_check", crash, crashErr)

	resumeNonce, err := nonce()
	if err != nil {
		failAll(&r, "nonce_generation_failed", err)
		return r
	}
	resumeBase := base
	resumeBase.Args = append(append([]string{}, base.Args...), "--resume", crashEvidence.sessionID)
	resumed, resumeErr := run(ctx, opt, resumeBase, "Return exactly "+resumeNonce+" and make no tool calls.")
	resumeEvidence := parseStructured(resumed.output)
	set(&r, CheckResume, crashRecoverable && resumeErr == nil && resumeEvidence.nonce(resumeNonce) && resumeEvidence.exactModelSession(opt.Identity.Model()) && resumeEvidence.sessionID == crashEvidence.sessionID, "live", "stream_json_interrupted_session_resume_nonce", resumed, resumeErr)
	set(&r, CheckProcessCleanup, passed(r, CheckCancellation), "local_authoritative", "same_authoritative_local_cancellation_residual_check", crash, crashErr)
	return r
}

func validate(opt Options) error {
	if !opt.Live {
		return errors.New("live qualification requires explicit Live opt-in")
	}
	if !opt.Identity.Valid() || opt.Identity.Provider() != "zai" || opt.Identity.Entitlement() != provider.EntitlementClaudeCompat || opt.Identity.CredentialClass() != provider.CredentialClassCodingPlan || opt.Identity.BillingClass() != provider.BillingClassCodingPlan {
		return errors.New("qualification requires an exact Z.ai Claude-compatible Coding Plan identity; native API credentials are rejected")
	}
	if strings.TrimSpace(opt.Binary) == "" || strings.ContainsAny(opt.Binary, "\r\n;&|<>'\"") {
		return errors.New("binary must be one literal executable reference")
	}
	if opt.Timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	if strings.TrimSpace(opt.RuntimeVersion) == "" || hasControl(opt.RuntimeVersion) {
		return errors.New("exact runtime version is required")
	}
	if opt.PolicySHA256 != QualificationPolicySHA256() {
		return errors.New("policy SHA-256 must match the reviewed qualification policy")
	}
	// The production verifier depends on Bubblewrap's Linux namespace
	// isolation. Reject before creating the disposable repository or invoking a
	// provider, rather than discovering that the verifier is unavailable after
	// an edit has already been requested. An injected verifier is deliberately
	// reserved for unit/integration harnesses which provide their own isolated
	// execution proof.
	if opt.Verifier == nil && !defaultVerifierSupported(runtime.GOOS) {
		return errors.New("live Z.ai Claude-compatible qualification requires Linux (Bubblewrap verification); native no-tool API operations are a separate lane")
	}
	return nil
}

func defaultVerifierSupported(goos string) bool { return goos == "linux" }

func invocation(opt Options, dir, settings string) Invocation {
	tools := "Read,Glob,Grep,Edit,Write,Bash"
	allowed := "Read(./**),Glob(./**),Grep(./**),Edit(./**),Write(./**)"
	args := []string{"-p", "", "--output-format", "stream-json", "--verbose", "--model", opt.Identity.Model(), "--settings", settings, "--strict-mcp-config", "--disable-slash-commands", "--no-chrome", "--permission-mode", "dontAsk", "--tools", tools, "--allowedTools", allowed, "--disallowedTools", "Read(.qualification-secret),Read(./.qualification-secret),Read(**/.qualification-secret),Bash(*)"}
	return Invocation{Binary: opt.Binary, Args: args, Dir: dir, Env: qualificationEnv(dir, opt.Identity), OutputLimit: 1 << 20}
}

func run(ctx context.Context, opt Options, base Invocation, prompt string) (runResult, error) {
	in := base
	in.Args = append([]string{}, base.Args...)
	in.Args[1] = prompt
	callCtx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	out, err := opt.Runner.Run(callCtx, in)
	// Only stdout is part of the documented stream-json protocol. Stderr is
	// diagnostic material and must never be interpreted as provider evidence.
	return runResult{out: out, output: append([]byte{}, out.Stdout...)}, err
}

type runResult struct {
	out    Outcome
	output []byte
}

func prepareRepo(ctx context.Context, root string) error {
	// Every git command is explicitly scoped to the disposable root.
	cmd := exec.CommandContext(ctx, "git", "init")
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		return err
	}
	for _, args := range [][]string{{"config", "user.email", "ntm-qualification@invalid"}, {"config", "user.name", "NTM Qualification"}} {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = root
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module qualification\n\ngo 1.22\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, "seed_test.go"), []byte("package qualification\nimport \"testing\"\nfunc TestSeed(t *testing.T) {}\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".ntm-home/\n.ntm-tmp/\nntm-qualification-settings.json\n"), 0o600); err != nil {
		return err
	}
	canary, err := nonce()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(root, ".qualification-secret"), []byte("ntm-canary-"+canary), 0o600); err != nil {
		return err
	}
	cmd = exec.CommandContext(ctx, "git", "add", "--", ".gitignore", ".qualification-secret", "go.mod", "seed_test.go")
	cmd.Dir = root
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("stage disposable repository baseline (%s): %w", digest(output), err)
	}
	return nil
}

func qualificationRepositoryState(ctx context.Context, root string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "status", "--porcelain=v1", "--untracked-files=all")
	cmd.Dir = root
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect disposable repository state: %w", err)
	}
	if len(output) > 64<<10 {
		return nil, errors.New("disposable repository state exceeded limit")
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return []string{}, nil
	}
	for i, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		lines[i] = line
		if len(line) < 4 || hasControl(line) {
			return nil, errors.New("disposable repository returned invalid status evidence")
		}
	}
	return lines, nil
}

func qualificationStateAddsOnly(before, after []string, addition string) bool {
	if len(after) != len(before)+1 {
		return false
	}
	want := make(map[string]int, len(before)+1)
	for _, line := range before {
		want[line]++
	}
	want[addition]++
	for _, line := range after {
		if want[line] == 0 {
			return false
		}
		want[line]--
	}
	for _, count := range want {
		if count != 0 {
			return false
		}
	}
	return true
}

func writePolicy(root string) (string, string, error) {
	b, err := qualificationPolicyJSON()
	if err != nil {
		return "", "", err
	}
	path := filepath.Join(root, "ntm-qualification-settings.json")
	return path, digest(b), os.WriteFile(path, b, 0o600)
}

func QualificationPolicySHA256() string {
	b, err := qualificationPolicyJSON()
	if err != nil {
		return ""
	}
	return digest(b)
}
func qualificationPolicyJSON() ([]byte, error) {
	policy := map[string]any{"permissions": map[string]any{"defaultMode": "dontAsk", "allow": []string{"Read(./**)", "Glob(./**)", "Grep(./**)", "Edit(./**)", "Write(./**)"}, "deny": []string{"Read(.qualification-secret)", "Read(./.qualification-secret)", "Read(**/.qualification-secret)", "Bash(*)", "Read(**/.env*)", "Read(**/.ssh/**)", "Read(**/.aws/**)", "Read(**/.config/**)"}}, "enableAllProjectMcpServers": false}
	return json.Marshal(policy)
}

func qualificationEnv(root string, id provider.Identity) []string {
	isolatedHome := filepath.Join(root, ".ntm-home")
	isolatedTmp := filepath.Join(root, ".ntm-tmp")
	_ = os.MkdirAll(isolatedHome, 0o700)
	_ = os.MkdirAll(isolatedTmp, 0o700)
	var out []string
	if path := os.Getenv("PATH"); path != "" {
		out = append(out, "PATH="+path)
	}
	for _, key := range []string{"SystemRoot", "WINDIR", "TERM", "LANG"} {
		if value := os.Getenv(key); value != "" {
			out = append(out, key+"="+value)
		}
	}
	out = append(out, "HOME="+isolatedHome, "USERPROFILE="+isolatedHome, "TMPDIR="+isolatedTmp, "TMP="+isolatedTmp, "TEMP="+isolatedTmp)
	var token string
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		// Never import ZAI_NATIVE_API_KEY or a generic ANTHROPIC_AUTH_TOKEN.
		// Only the explicitly Z.ai-scoped Coding Plan variable may be remapped
		// into the Claude-compatible child contract.
		if key == "ZAI_API_KEY" && value != "" && token == "" {
			token = value
		}
	}
	if token != "" {
		out = append(out, "ANTHROPIC_AUTH_TOKEN="+token)
	}
	return append(out, "ANTHROPIC_BASE_URL="+id.Endpoint(), "ANTHROPIC_DEFAULT_OPUS_MODEL="+id.Model(), "ANTHROPIC_DEFAULT_SONNET_MODEL="+id.Model(), "ANTHROPIC_DEFAULT_HAIKU_MODEL="+id.Model())
}

type qualificationToolCall struct {
	Name, Command, Path string
}

type evidence struct {
	valid, success    bool
	sessionID, model  string
	result            string
	toolCalls         map[string]qualificationToolCall
	toolResults       map[string]bool
	permissionDenials map[string]string
}

type qualificationStreamEvent struct {
	Type      string          `json:"type"`
	Subtype   string          `json:"subtype"`
	SessionID string          `json:"session_id"`
	Model     string          `json:"model"`
	Result    string          `json:"result"`
	IsError   bool            `json:"is_error"`
	ToolName  string          `json:"tool_name"`
	ToolUseID string          `json:"tool_use_id"`
	Message   json.RawMessage `json:"message"`
}

type qualificationMessage struct {
	Content json.RawMessage `json:"content"`
}

type qualificationContentBlock struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	ToolUseID string          `json:"tool_use_id"`
	Input     json.RawMessage `json:"input"`
	IsError   bool            `json:"is_error"`
}

func parseStructured(raw []byte) evidence {
	e := evidence{
		valid: true, toolCalls: map[string]qualificationToolCall{},
		toolResults: map[string]bool{}, permissionDenials: map[string]string{},
	}
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var event qualificationStreamEvent
		if json.Unmarshal(line, &event) != nil {
			e.valid = false
			continue
		}
		e.accept(event)
	}
	return e
}

func (e *evidence) accept(event qualificationStreamEvent) {
	if e == nil || !e.valid {
		return
	}
	switch event.Type {
	case "system":
		switch event.Subtype {
		case "init":
			if !validEvidenceToken(event.SessionID) || !validEvidenceToken(event.Model) ||
				(e.sessionID != "" && e.sessionID != event.SessionID) || (e.model != "" && e.model != event.Model) {
				e.valid = false
				return
			}
			e.sessionID, e.model = event.SessionID, event.Model
		case "permission_denied":
			if !validEvidenceToken(event.ToolUseID) || !validEvidenceToken(event.ToolName) {
				e.valid = false
				return
			}
			e.permissionDenials[event.ToolUseID] = event.ToolName
		}
	case "assistant":
		for _, block := range qualificationBlocks(event.Message) {
			if block.Type != "tool_use" {
				continue
			}
			if !validEvidenceToken(block.ID) || !validEvidenceToken(block.Name) {
				e.valid = false
				return
			}
			if _, duplicate := e.toolCalls[block.ID]; duplicate {
				e.valid = false
				return
			}
			call, ok := qualificationCall(block.Name, block.Input)
			if !ok {
				e.valid = false
				return
			}
			e.toolCalls[block.ID] = call
		}
	case "user":
		for _, block := range qualificationBlocks(event.Message) {
			if block.Type != "tool_result" {
				continue
			}
			if !validEvidenceToken(block.ToolUseID) {
				e.valid = false
				return
			}
			if _, exists := e.toolCalls[block.ToolUseID]; !exists {
				e.valid = false
				return
			}
			e.toolResults[block.ToolUseID] = !block.IsError
		}
	case "result":
		if e.success || event.Subtype != "success" || event.IsError || !validEvidenceToken(event.SessionID) {
			e.valid = false
			return
		}
		if e.sessionID != "" && e.sessionID != event.SessionID {
			e.valid = false
			return
		}
		e.success, e.result = true, event.Result
		if e.sessionID == "" {
			e.sessionID = event.SessionID
		}
	}
}

func qualificationBlocks(raw json.RawMessage) []qualificationContentBlock {
	if len(raw) == 0 {
		return nil
	}
	var message qualificationMessage
	if json.Unmarshal(raw, &message) != nil || len(message.Content) == 0 {
		return nil
	}
	var blocks []qualificationContentBlock
	if json.Unmarshal(message.Content, &blocks) != nil {
		return nil
	}
	return blocks
}

func qualificationCall(name string, raw json.RawMessage) (qualificationToolCall, bool) {
	var input struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
		Path     string `json:"path"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &input) != nil {
		return qualificationToolCall{}, false
	}
	path := firstQualificationValue(input.FilePath, input.Path)
	if hasControl(input.Command) || hasControl(path) || len(input.Command) > 1<<16 || len(path) > 1<<16 {
		return qualificationToolCall{}, false
	}
	return qualificationToolCall{Name: name, Command: input.Command, Path: path}, true
}

func firstQualificationValue(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func validEvidenceToken(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 4096 && !hasControl(value)
}

func (e evidence) nonce(n string) bool {
	return e.valid && e.success && n != "" && e.result == n
}
func (e evidence) exactModelSession(model string) bool {
	return e.valid && e.sessionID != "" && e.model == model
}
func (e evidence) successfulTool(names ...string) bool {
	if !e.valid {
		return false
	}
	for id, call := range e.toolCalls {
		if !e.toolResults[id] {
			continue
		}
		for _, want := range names {
			if call.Name == want {
				return true
			}
		}
	}
	return false
}
func (e evidence) deniedTool(tool, target string) bool {
	if !e.valid {
		return false
	}
	for id, call := range e.toolCalls {
		if call.Name != tool || e.permissionDenials[id] != tool {
			continue
		}
		if tool == "Bash" && call.Command == target {
			return true
		}
		if tool != "Bash" && filepath.Clean(call.Path) == filepath.Clean(target) {
			return true
		}
	}
	return false
}

func emptyChecks() []Check {
	checks := make([]Check, len(checkNames))
	for i, n := range checkNames {
		checks[i].Name = n
	}
	return checks
}
func set(r *Receipt, name string, ok bool, provenance, detail string, result runResult, err error) {
	for i := range r.Checks {
		if r.Checks[i].Name == name {
			r.Checks[i].Passed, r.Checks[i].Provenance, r.Checks[i].Detail = ok, provenance, detail
			r.Checks[i].EvidenceSHA256 = digest(append(append([]byte{}, result.output...), []byte(errorText(err))...))
			return
		}
	}
}
func passed(r Receipt, name string) bool {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Passed
		}
	}
	return false
}
func failAll(r *Receipt, evidence string, err error) {
	for i := range r.Checks {
		r.Checks[i].Provenance, r.Checks[i].Detail = "local_authoritative", evidence
		if err != nil {
			r.Checks[i].EvidenceSHA256 = digest([]byte(err.Error()))
		}
	}
}
func firstErr(a, b error) error {
	if a != nil {
		return a
	}
	return b
}
func digest(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
func nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("strong nonce generation: %w", err)
	}
	return "ntm-zai-" + hex.EncodeToString(b), nil
}
func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func hasControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
func cancellationTimeout(timeout time.Duration) time.Duration {
	if timeout > 2*time.Second {
		return 2 * time.Second
	}
	return timeout
}
func exitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	if err == nil {
		return 0
	}
	return -1
}

type limitedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
	mu       sync.Mutex
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.Buffer.Len()+n > b.limit {
		remaining := b.limit - b.Buffer.Len()
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		b.exceeded = true
		return n, nil
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}
