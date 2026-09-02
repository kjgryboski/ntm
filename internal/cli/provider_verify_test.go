package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/provider"
)

type providerVerifierFake struct {
	manifest provider.VerificationManifest
	receipt  provider.VerificationReceipt
	err      error
}

func (f *providerVerifierFake) Verify(_ context.Context, manifest provider.VerificationManifest) (provider.VerificationReceipt, error) {
	f.manifest = manifest
	return f.receipt, f.err
}

func TestProviderVerifyWiresExactManifestAndReturnsReceipt(t *testing.T) {
	fake := &providerVerifierFake{receipt: provider.VerificationReceipt{SchemaVersion: "ntm.disposable-verifier.v2", DisposableWorktree: true, NetworkIsolated: true, CredentialsCleared: true, PIDNamespaceIsolated: true, CleanupVerified: true, Commands: []provider.CommandVerification{{ID: "go-test", ExitCode: 0, ProcessWaited: true, CleanupVerified: true}}}}
	deps := providerVerifyDependencies{newVerifier: func() (providerVerificationRunner, error) { return fake, nil }, sign: newProviderNativeTestSigner()}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	revision := strings.Repeat("a", 40)
	err := runProviderVerify(cmd, providerVerifyOptions{worktree: "/tmp/linked", revision: revision, commands: []string{"go-test"}}, deps)
	if err != nil || fake.manifest.Worktree != "/tmp/linked" || fake.manifest.Revision != revision || len(fake.manifest.CommandIDs) != 1 || !strings.Contains(output.String(), "passed for 1") {
		t.Fatalf("err=%v manifest=%+v output=%q", err, fake.manifest, output.String())
	}
}

func TestProviderVerifyFailsClosedAndRedactsVerifierError(t *testing.T) {
	fake := &providerVerifierFake{receipt: provider.VerificationReceipt{SchemaVersion: "ntm.disposable-verifier.v2"}, err: errors.New("secret path /tmp/private")}
	deps := providerVerifyDependencies{newVerifier: func() (providerVerificationRunner, error) { return fake, nil }, sign: newProviderNativeTestSigner()}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err := runProviderVerify(cmd, providerVerifyOptions{worktree: "/tmp/linked", revision: strings.Repeat("b", 40), commands: []string{"go-test"}}, deps)
	if err == nil || strings.Contains(output.String(), "private") || !strings.Contains(output.String(), "failed") {
		t.Fatalf("err=%v output=%q", err, output.String())
	}
}

func TestProviderVerifyRejectsIncompleteManifestBeforeFactory(t *testing.T) {
	called := false
	deps := providerVerifyDependencies{newVerifier: func() (providerVerificationRunner, error) { called = true; return nil, nil }, sign: newProviderNativeTestSigner()}
	if err := runProviderVerify(&cobra.Command{}, providerVerifyOptions{}, deps); err == nil || called {
		t.Fatalf("err=%v called=%t", err, called)
	}
}
