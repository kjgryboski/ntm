package cli

import (
	"errors"

	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/spf13/cobra"
)

// Scope changes the requested command outcome, never the signed receipt or
// dispatch admission. A workspace result does not claim lifecycle support.
func providerQualificationScope(cmd *cobra.Command) string {
	if cmd != nil && cmd.Flags().Lookup("scope") != nil {
		scope, _ := cmd.Flags().GetString("scope")
		return scope
	}
	return "full"
}

func validateProviderQualificationScope(cmd *cobra.Command) error {
	scope := providerQualificationScope(cmd)
	if scope != "full" && scope != "workspace" {
		return errors.New("qualification scope must be full or workspace")
	}
	return nil
}

func providerQualificationScopePassed(cmd *cobra.Command, receipt providerqualification.Receipt) bool {
	if providerQualificationScope(cmd) == "full" {
		return receipt.Passed
	}
	if providerQualificationScope(cmd) != "workspace" || receipt.Mode != providerqualification.ModeLive || receipt.Validate() != nil || receipt.Attestation == nil {
		return false
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil || providerattestation.Verify(payload, *receipt.Attestation) != nil {
		return false
	}
	checks := map[string]providerqualification.Check{}
	for _, check := range receipt.Checks {
		checks[check.Name] = check
	}
	for _, name := range providerOperationRequiredChecks(receipt.Transport, providerOperationWorkspaceWrite) {
		if !providerqualification.AuthoritativePassedCheck(checks[name]) {
			return false
		}
	}
	return checks[providerqualification.CheckIdentity].Provenance == "live" && (receipt.Transport != "zai_codex_runtime" || qualificationModelIdentityVerified(receipt))
}

func providerQualificationScopeExit(cmd *cobra.Command, receipt providerqualification.Receipt) error {
	if providerQualificationScopePassed(cmd, receipt) {
		return nil
	}
	if IsJSONOutput() {
		return errJSONFailure
	}
	return &providerQualificationExitError{}
}

func (out providerQualificationRunOutput) withScope(cmd *cobra.Command) providerQualificationRunOutput {
	out.RequestedScope = providerQualificationScope(cmd)
	out.ScopePassed = providerQualificationScopePassed(cmd, out.Receipt)
	return out
}
