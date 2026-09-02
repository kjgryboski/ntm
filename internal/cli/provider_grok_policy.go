package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	providerGrokProbeOutputLimit = 16 << 10
	providerGrokProbeBinary      = "/grok"
)

// providerRuntimeProbeGrokBypassLock behaviorally attests the managed
// always-approve lock without giving the probe access to credentials or the
// network. Static inspect evidence is necessary but insufficient because Grok
// 1.0.13 reports the documented lock key as an unknown-field warning even
// while the headless execution path enforces it.
func providerRuntimeProbeGrokBypassLock(ctx context.Context, binary string) (result providerGrokBypassProbe, returnErr error) {
	result.ExitCode = -1
	if ctx == nil {
		return result, errors.New("Grok bypass-lock probe requires a context")
	}
	if runtime.GOOS != "linux" {
		return result, errors.New("Grok bypass-lock probe requires Linux no-network isolation")
	}
	if err := providerSecureRootPath("/etc/grok"); err != nil {
		return result, fmt.Errorf("Grok system policy path is not system-authoritative: %w", err)
	}

	bwrap, err := providerTrustedProbeExecutable("/usr/bin/bwrap")
	if err != nil {
		return result, fmt.Errorf("trusted Bubblewrap runtime unavailable: %w", err)
	}
	resolvedBinary, err := providerTrustedProbeExecutable(binary)
	if err != nil {
		return result, fmt.Errorf("trusted Grok runtime unavailable: %w", err)
	}
	if info, statErr := os.Stat("/etc/grok"); statErr != nil || !info.IsDir() {
		return result, errors.New("system Grok requirements directory is unavailable")
	}

	probeRoot, err := os.MkdirTemp("", "ntm-grok-bypass-probe-")
	if err != nil {
		return result, errors.New("create isolated Grok bypass-lock probe directory")
	}
	defer func() {
		if cleanupErr := os.RemoveAll(probeRoot); cleanupErr != nil && returnErr == nil {
			returnErr = errors.New("clean isolated Grok bypass-lock probe directory")
			result.Refused = false
		}
	}()

	args := providerGrokBypassProbeArgs(resolvedBinary)
	stdout := &providerCappedOutput{limit: providerGrokProbeOutputLimit}
	stderr := &providerCappedOutput{limit: providerGrokProbeOutputLimit}
	cmd := exec.CommandContext(ctx, bwrap, args...)
	cmd.Dir = probeRoot
	cmd.Env = []string{}
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.WaitDelay = time.Second
	runErr := cmd.Run()
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	transcript := strings.Join([]string{
		"ntm.grok-bypass-lock-probe.v1",
		resolvedBinary,
		strings.Join(args, "\x00"),
		strconv.Itoa(result.ExitCode),
		stdout.String(),
		stderr.String(),
	}, "\x00")
	result.SHA256 = sha256StringCLI(transcript)

	if ctx.Err() != nil {
		return result, errors.New("isolated Grok bypass-lock probe timed out or was canceled")
	}
	if stdout.exceeded || stderr.exceeded {
		return result, errors.New("isolated Grok bypass-lock probe output exceeded its limit")
	}
	if runErr == nil {
		return result, errors.New("Grok accepted always-approve inside the isolated bypass-lock probe")
	}
	output := strings.ToLower(stdout.String() + "\n" + stderr.String())
	for _, required := range []string{
		"always-approve disabled by managed policy",
		"disable_bypass_permissions_mode = true",
		"requirements.toml",
	} {
		if !strings.Contains(output, required) {
			return result, errors.New("Grok did not emit the exact managed bypass-lock refusal")
		}
	}
	result.Refused = true
	result.NetworkIsolated = true
	result.CredentialsIsolated = true
	return result, nil
}

func providerGrokBypassProbeArgs(resolvedBinary string) []string {
	grokArgs := []string{
		"--no-auto-update",
		"--always-approve",
		"--sandbox", "read-only",
		"--disable-web-search",
		"--no-subagents",
		"--no-memory",
		"--max-turns", "1",
		"--output-format", "json",
		"-p", "Reply with exactly NTM_POLICY_PROBE and do not call tools.",
	}
	args := []string{
		"--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
		"--ro-bind", "/usr", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--ro-bind", resolvedBinary, providerGrokProbeBinary,
		"--dir", "/etc",
		"--ro-bind", "/etc/grok", "/etc/grok",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--dir", "/grokhome",
		"--chdir", "/tmp",
		"--setenv", "GROK_HOME", "/grokhome",
		"--setenv", "TMPDIR", "/tmp",
		"--setenv", "PATH", "/usr/bin:/bin",
		providerGrokProbeBinary,
	}
	return append(args, grokArgs...)
}

func providerTrustedProbeExecutable(path string) (string, error) {
	return providerSystemAuthoritativeExecutable(strings.TrimSpace(path))
}
