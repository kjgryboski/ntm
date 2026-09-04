package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

// providerOperationAuthorization is the shared production dispatch boundary.
// Doctor reports and route plans use the same operation vocabulary, but only
// this check authorizes a non-observe provider process to receive work.
type providerOperationAuthorization struct {
	Identity            provider.Identity
	Transport           string
	PolicySHA256        string
	RuntimeVersion      string
	RuntimeSHA256       string
	Operation           string
	QualificationDir    string
	MaxQualificationAge time.Duration
	TrustedSigner       providerattestation.KeyMetadata
}

type providerOperationAuthorizationDependencies struct {
	load func(string, string, string) (providerqualification.Receipt, string, error)
	now  func() time.Time
}

var providerOperationAuthorizationDeps = providerOperationAuthorizationDependencies{
	load: providerqualification.LoadLatestForTransport,
	now:  func() time.Time { return time.Now().UTC() },
}

func authorizeProviderOperation(input providerOperationAuthorization) (string, error) {
	return authorizeProviderOperationWithDependencies(input, providerOperationAuthorizationDeps)
}

func authorizeProviderOperationWithDependencies(input providerOperationAuthorization, deps providerOperationAuthorizationDependencies) (string, error) {
	operation := normalizeProviderOperation(input.Operation)
	if operation == providerOperationObserve {
		return "", nil
	}
	if !validProviderOperation(operation) || deps.load == nil || deps.now == nil || !input.Identity.Valid() || strings.TrimSpace(input.Transport) == "" || !validProviderNativeDigest(input.PolicySHA256) || strings.TrimSpace(input.RuntimeVersion) == "" || !validProviderNativeDigest(input.RuntimeSHA256) || input.MaxQualificationAge <= 0 {
		return "", errors.New("provider operation authorization input is incomplete")
	}
	if operation == providerOperationLifecycle {
		capability, ok := provider.CapabilityMatrix()[input.Transport]
		if !ok || !capability.LocalLifecycleSupported() {
			return "", errors.New("provider lifecycle dispatch requires structured local cancellation, process cleanup, and resume support")
		}
	}
	receipt, _, err := deps.load(input.QualificationDir, input.Identity.Hash(), input.Transport)
	if err != nil {
		return "", fmt.Errorf("%s dispatch requires a current signed live qualification: %w", operation, err)
	}
	if err := receipt.Validate(); err != nil {
		return "", fmt.Errorf("provider operation qualification is invalid: %w", err)
	}
	if receipt.Attestation == nil || receipt.Attestation.KeyMetadata != input.TrustedSigner {
		return "", errors.New("provider operation qualification was not signed by the currently trusted profile key")
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil || providerattestation.Verify(payload, *receipt.Attestation) != nil {
		return "", errors.New("provider operation qualification signature is invalid")
	}
	if receipt.Provider != input.Identity.Provider() || receipt.Transport != input.Transport || receipt.IdentitySHA256 != input.Identity.Hash() || receipt.PolicySHA256 != input.PolicySHA256 || !versionMatches(receipt.RuntimeVersion, input.RuntimeVersion) || receipt.RuntimeSHA256 != input.RuntimeSHA256 {
		return "", errors.New("provider operation qualification does not bind the exact provider, transport, identity, policy, runtime version, and runtime digest")
	}
	now := deps.now().UTC()
	if receipt.CompletedAt.After(now) || now.Sub(receipt.CompletedAt) > input.MaxQualificationAge {
		return "", errors.New("provider operation qualification is future-dated or stale")
	}
	checks := make(map[string]providerqualification.Check, len(receipt.Checks))
	for _, check := range receipt.Checks {
		checks[check.Name] = check
	}
	for _, name := range providerOperationRequiredChecks(input.Transport, operation) {
		if !providerqualification.AuthoritativePassedCheck(checks[name]) {
			return "", fmt.Errorf("provider operation %s is not promoted: signed check %s is absent, failed, or lacks authoritative evidence", operation, name)
		}
	}
	if identityCheck := checks[providerqualification.CheckIdentity]; identityCheck.Provenance != "live" {
		return "", errors.New("provider operation is not promoted without provider-live identity evidence")
	}
	if input.Transport == "zai_codex_runtime" && !qualificationModelIdentityVerified(receipt) {
		return "", errors.New("Z.ai Codex operation is not promoted without exact provider-served model evidence")
	}
	return receipt.ReceiptSHA256, nil
}

func providerOperationRequiredChecks(transport, operation string) []string {
	checks := []string{
		providerqualification.CheckIdentity,
		providerqualification.CheckSecretDenied,
		providerqualification.CheckPushDenied,
	}
	if operation == providerOperationWorkspaceWrite || operation == providerOperationLifecycle {
		checks = append(checks, providerqualification.CheckWorkspaceEdit, providerqualification.CheckTestCommand, providerqualification.CheckProcessCleanup)
		if transport == "zai_codex_runtime" {
			checks = append(checks, "capacity_accounting")
		}
	}
	if operation == providerOperationLifecycle {
		checks = append(checks, providerqualification.CheckCrashRecovery, providerqualification.CheckCancellation, providerqualification.CheckResume)
	}
	return checks
}
