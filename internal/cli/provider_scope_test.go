package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/spf13/cobra"
)

func TestQualificationScopePreservesSignedFullResult(t *testing.T) {
	cmd := newProviderQualifyCmd()
	if err := cmd.Flags().Set("scope", "workspace"); err != nil {
		t.Fatal(err)
	}
	checks := []providerqualification.Check{}
	for _, name := range providerqualification.GrokRequiredChecks() {
		passed := false
		for _, required := range providerOperationRequiredChecks("xai_acp", providerOperationWorkspaceWrite) {
			passed = passed || name == required
		}
		checks = append(checks, providerqualification.Check{Name: name, Passed: passed, Provenance: "live", EvidenceSHA256: strings.Repeat("a", 64)})
	}
	now := time.Now().UTC()
	receipt := providerqualification.Receipt{Mode: providerqualification.ModeLive, Provider: "xai", Transport: "xai_acp", IdentitySHA256: strings.Repeat("b", 64), PolicySHA256: strings.Repeat("c", 64), RuntimeVersion: "test", RuntimeSHA256: strings.Repeat("d", 64), StartedAt: now.Add(-time.Minute), CompletedAt: now, DisposableRepoHash: strings.Repeat("e", 64), Checks: checks}
	if err := receipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := newProviderNativeTestSigner()(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatal(err)
	}
	before := receipt.ReceiptSHA256
	if err := providerQualificationScopeExit(cmd, receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Passed || receipt.ReceiptSHA256 != before {
		t.Fatal("scope rewrote signed full result")
	}
	if err := cmd.Flags().Set("scope", "full"); err != nil {
		t.Fatal(err)
	}
	if providerQualificationScopeExit(cmd, receipt) == nil {
		t.Fatal("partial receipt passed full scope")
	}
	if err := cmd.Flags().Set("scope", "workspace"); err != nil {
		t.Fatal(err)
	}
	receipt.Attestation = nil
	if providerQualificationScopeExit(cmd, receipt) == nil {
		t.Fatal("unsigned workspace passed")
	}
}

func TestQualificationScopeRejectsInvalidInputBeforeLoadingConfiguration(t *testing.T) {
	for _, constructor := range []func() *cobra.Command{newProviderQualifyCmd, newProviderPrimaryComparisonCmd} {
		cmd := constructor()
		if err := cmd.Flags().Set("scope", "typo"); err != nil {
			t.Fatal(err)
		}
		if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "scope") {
			t.Fatalf("invalid scope reached prerequisites: %v", err)
		}
	}
	_, hint := classifyRobotExecuteError(errors.Join(errors.New("qualification"), &providerQualificationExitError{}))
	if strings.Contains(hint, "Retry the command") {
		t.Fatal("paid retry advice survived")
	}
}
