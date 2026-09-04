package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestProviderGrokBypassProbeVectorIsNoNetworkAndCredentialIsolated(t *testing.T) {
	args := providerGrokBypassProbeArgs("/trusted/grok")
	joined := strings.Join(args, "\x00")
	for _, required := range []string{
		"--unshare-all", "--die-with-parent", "--clearenv",
		"--ro-bind\x00/etc/grok\x00/etc/grok",
		"--ro-bind\x00/trusted/grok\x00/grok",
		"--setenv\x00GROK_HOME\x00/grokhome",
		"--no-auto-update", "--always-approve", "--sandbox\x00strict",
		"--disable-web-search", "--no-subagents", "--no-memory",
		"Reply with exactly NTM_POLICY_PROBE and do not call tools.",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("isolated probe vector omitted %q: %q", required, joined)
		}
	}
	for _, prohibited := range []string{"XAI_API_KEY", "ZAI_API_KEY", "ANTHROPIC_AUTH_TOKEN", "--share-net"} {
		if strings.Contains(joined, prohibited) {
			t.Fatalf("isolated probe vector contains prohibited capability %q", prohibited)
		}
	}
}

func TestProviderTrustedProbeExecutableRejectsWritableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(path, []byte("not executable"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := providerTrustedProbeExecutable(path); err == nil {
		t.Fatal("group/world-writable probe runtime was trusted")
	}
}

func TestLiveProviderGrokBypassLockProbe(t *testing.T) {
	if os.Getenv("NTM_LIVE_GROK_POLICY_PROBE") != "1" {
		t.Skip("set NTM_LIVE_GROK_POLICY_PROBE=1 to authorize the local isolated policy probe")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the authoritative probe requires Linux Bubblewrap isolation")
	}
	binary := strings.TrimSpace(os.Getenv("NTM_LIVE_GROK_BINARY"))
	if binary == "" {
		var err error
		binary, err = exec.LookPath("grok")
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	probe, err := providerRuntimeProbeGrokBypassLock(ctx, binary)
	if err != nil || !probe.Refused || !probe.NetworkIsolated || !probe.CredentialsIsolated || probe.SHA256 == "" {
		t.Fatalf("probe=%+v err=%v", probe, err)
	}
}
