package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/spf13/cobra"
)

func TestProviderEnvironmentClockStepsFailClosed(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	for _, drift := range []time.Duration{-time.Hour, -3 * time.Second, 3 * time.Second, time.Hour} {
		var failure *providerEnvironmentError
		if err := validateProviderDispatchClock(start, start.Add(time.Minute+drift), time.Minute); !errors.As(err, &failure) || failure.reason != "clock_changed" {
			t.Fatalf("clock drift admitted: %v", err)
		}
	}
	if err := validateProviderDispatchClock(start, start.Add(time.Minute), time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestProviderEnvironmentVersionFailureIsSafe(t *testing.T) {
	_, err := providerRuntimeVersion(context.Background(), filepath.Join(t.TempDir(), "private-credential-like-name"))
	var failure *providerEnvironmentError
	if !errors.As(err, &failure) || failure.reason != "runtime_version_probe_failed" || strings.Contains(err.Error(), "private-") {
		t.Fatalf("unsafe/unclassified failure: %v", err)
	}
	_, hint := classifyRobotExecuteError(err)
	if strings.Contains(hint, "Retry the command") {
		t.Fatal("environment failure invited paid retry")
	}
}

func TestProviderEnvironmentStartFailureConsumesNoAttemptOrAssignment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native primary route")
	}
	t.Setenv("HOME", t.TempDir())
	prior := providerCampaignID
	defer func() { providerCampaignID = prior }()
	cmd := newProviderCampaignCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--id", "environment-prerequisite", "--limit", "1", "--authorization-sha256", strings.Repeat("a", 64)})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	providerCampaignID = "environment-prerequisite"
	root := t.TempDir()
	binary := filepath.Join(root, "nonexecutable")
	if err := os.WriteFile(binary, []byte("offline nonexecutable fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	hash, err := hashProviderSessionExecutable(binary)
	if err != nil {
		t.Fatal(err)
	}
	p := config.ProviderProfileConfig{Provider: "anthropic", AccountAlias: "offline", Model: "claude-fable-5", Endpoint: "https://api.anthropic.com", Runtime: "claude", CredentialClass: "oauth", BillingClass: "subscription", Entitlement: "primary_cli", Command: binary, RuntimeHome: root, RuntimeVersion: "test", RuntimeSHA256: hash, AutomationPolicy: primaryComparisonPolicy, ExactTargetOnly: true}
	p.ConfigSHA256 = p.CanonicalManifestSHA256()
	ledger := &providerNativeLedgerFake{}
	err = runPrimaryAssignment(&cobra.Command{}, providerAssignmentRequest{Profile: "offline", OperationID: "environment-start", Prompt: "never delivered", CWD: root, Timeout: time.Minute}, p, ledger)
	var failure *providerEnvironmentError
	if !errors.As(err, &failure) || len(ledger.ops) != 0 {
		t.Fatalf("failed prerequisite reached ledger: %v", err)
	}
	campaign, err := providerReadinessCampaign()
	if err != nil || campaign.Used != 0 {
		t.Fatalf("failed prerequisite spent attempt: %+v %v", campaign, err)
	}
}
