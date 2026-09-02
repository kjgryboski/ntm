package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
)

const providerVerificationSchema = "ntm.provider-verification-run.v1"

type providerVerifyOptions struct {
	worktree string
	revision string
	commands []string
}

type providerVerificationRunner interface {
	Verify(context.Context, provider.VerificationManifest) (provider.VerificationReceipt, error)
}

type providerVerifyDependencies struct {
	newVerifier func() (providerVerificationRunner, error)
	sign        func(context.Context, []byte) (providerattestation.SignatureMetadata, error)
}

var providerVerifyDeps = providerVerifyDependencies{newVerifier: func() (providerVerificationRunner, error) {
	catalog, err := provider.DefaultDisposableCommandCatalog()
	if err != nil {
		return nil, err
	}
	return provider.NewIsolatedVerifier(catalog)
}, sign: signProviderReceiptPayload}

type providerVerificationOutput struct {
	SchemaVersion string                                 `json:"schema_version"`
	Success       bool                                   `json:"success"`
	Receipt       provider.VerificationReceipt           `json:"receipt"`
	ErrorSHA256   string                                 `json:"error_sha256,omitempty"`
	Attestation   *providerattestation.SignatureMetadata `json:"attestation,omitempty"`
}

func newProviderVerifyCmd() *cobra.Command {
	opts := providerVerifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Run controller-owned tests in an isolated disposable worktree",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProviderVerify(cmd, opts, providerVerifyDeps)
		},
	}
	cmd.Flags().StringVar(&opts.worktree, "worktree", "", "Exact linked disposable worktree path (required)")
	cmd.Flags().StringVar(&opts.revision, "revision", "", "Exact current 40-64 character Git revision (required)")
	cmd.Flags().StringSliceVar(&opts.commands, "commands", nil, "Approved command IDs: go-test, go-vet, cargo-test")
	return cmd
}

func runProviderVerify(cmd *cobra.Command, opts providerVerifyOptions, deps providerVerifyDependencies) error {
	if strings.TrimSpace(opts.worktree) == "" || strings.TrimSpace(opts.revision) == "" || len(opts.commands) == 0 {
		return errors.New("provider verify requires --worktree, --revision, and at least one --commands ID")
	}
	if deps.newVerifier == nil || deps.sign == nil {
		return errors.New("provider verifier dependencies are incomplete")
	}
	verifier, err := deps.newVerifier()
	if err != nil || verifier == nil {
		return fmt.Errorf("initialize controller-owned isolated verifier: %w", err)
	}
	receipt, verifyErr := verifier.Verify(providerCommandContext(cmd), provider.VerificationManifest{
		Worktree: opts.worktree, Revision: opts.revision, CommandIDs: append([]string(nil), opts.commands...),
	})
	output := providerVerificationOutput{SchemaVersion: providerVerificationSchema, Success: verifyErr == nil, Receipt: receipt}
	if verifyErr != nil {
		output.ErrorSHA256 = safeErrorDigest(verifyErr)
	}
	payload, marshalErr := canonicalProviderVerificationOutput(output)
	if marshalErr != nil {
		return marshalErr
	}
	signature, signErr := deps.sign(providerCommandContext(cmd), payload)
	if signErr != nil || providerattestation.Verify(payload, signature) != nil {
		return errors.New("provider verification receipt could not be attested")
	}
	output.Attestation = &signature
	if IsJSONOutput() {
		if err := encodeIndentedJSON(cmd.OutOrStdout(), output); err != nil {
			return err
		}
		if verifyErr != nil {
			return errJSONFailure
		}
		return nil
	}
	if verifyErr != nil {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Provider verification failed. Receipt: %s\n", digestSafeJSON(receipt))
		return verifyErr
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Provider verification passed for %d approved command(s). Receipt: %s\n", len(receipt.Commands), digestSafeJSON(receipt))
	return err
}

func canonicalProviderVerificationOutput(output providerVerificationOutput) ([]byte, error) {
	output.Attestation = nil
	return json.Marshal(output)
}
