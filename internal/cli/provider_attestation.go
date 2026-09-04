package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

const providerReceiptAttestationKey = "ntm.provider.receipts.v1"
const providerReceiptPreflightDigest = "0000000000000000000000000000000000000000000000000000000000000000"

var providerReceiptAttestor = providerattestation.NewOSProtected()

func newProviderAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "attestation", Short: "Manage OS-protected provider receipt signing"}
	cmd.AddCommand(&cobra.Command{
		Use: "init", Short: "Explicitly initialize the OS-protected receipt signing key", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if providerReceiptAttestor == nil {
				return errors.New("provider receipt attestor is unavailable")
			}
			metadata, err := providerReceiptAttestor.EnsureKey(providerCommandContext(cmd), providerReceiptAttestationKey)
			if err != nil {
				return err
			}
			if IsJSONOutput() {
				return encodeIndentedJSON(cmd.OutOrStdout(), metadata)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Provider receipt signing initialized: key=%s protection=%s\n", metadata.KeyID, metadata.ProtectionEvidence)
			return err
		},
	})
	return cmd
}

func signProviderQualificationReceipt(ctx context.Context, receipt *providerqualification.Receipt) error {
	if receipt == nil || providerReceiptAttestor == nil {
		return errors.New("provider qualification receipt attestor is unavailable")
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		return err
	}
	signature, err := providerReceiptAttestor.Sign(ctx, providerReceiptAttestationKey, payload)
	if err != nil {
		return err
	}
	return receipt.AttachAttestation(signature)
}

// signProviderQualificationReceiptWith keeps receipt attachment identical for
// every transport while letting a profile bind signing to one immutable bridge.
func signProviderQualificationReceiptWith(ctx context.Context, receipt *providerqualification.Receipt, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) error {
	if receipt == nil || sign == nil {
		return errors.New("provider qualification receipt signer is unavailable")
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		return err
	}
	signature, err := sign(ctx, payload)
	if err != nil {
		return err
	}
	return receipt.AttachAttestation(signature)
}

// providerProfilePinnedSigner refuses ambient bridge selection.  Grok and
// Codex both use the same Windows TPM bridge contract, but each exact profile
// pins its executable content so receipt trust cannot silently drift.
func providerProfilePinnedSigner(profile config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
	if err := profile.VerifyCanonicalManifest(); err != nil {
		return nil, err
	}
	attestor, err := providerattestation.NewPinnedWindowsBridge(profile.CredentialBridgeCommand, profile.CredentialBridgeCommandSHA256)
	if err != nil || attestor == nil {
		return nil, providerattestation.ErrProtectionUnavailable
	}
	return func(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
		return attestor.Sign(ctx, providerReceiptAttestationKey, payload)
	}, nil
}

func providerGrokPinnedSigner(profile config.ProviderProfileConfig) (func(context.Context, []byte) (providerattestation.SignatureMetadata, error), error) {
	return providerProfilePinnedSigner(profile)
}

func signProviderReceiptPayload(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
	if providerReceiptAttestor == nil {
		return providerattestation.SignatureMetadata{}, errors.New("provider receipt attestor is unavailable")
	}
	return providerReceiptAttestor.Sign(ctx, providerReceiptAttestationKey, payload)
}

func preflightProviderReceiptSigner(ctx context.Context, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) error {
	_, err := preflightProviderReceiptSignerMetadata(ctx, sign)
	return err
}

func preflightProviderReceiptSignerMetadata(ctx context.Context, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) (providerattestation.SignatureMetadata, error) {
	return preflightProviderReceiptSignerMetadataFor(ctx, sign, false)
}

func preflightProviderGrokReceiptSignerMetadata(ctx context.Context, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) (providerattestation.SignatureMetadata, error) {
	return preflightProviderReceiptSignerMetadataFor(ctx, sign, true)
}

func preflightProviderReceiptSignerMetadataFor(ctx context.Context, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error), grokDiagnostics bool) (providerattestation.SignatureMetadata, error) {
	if sign == nil {
		return providerattestation.SignatureMetadata{}, errors.New("provider receipt attestor is unavailable")
	}
	payload, err := providerReceiptSignerPreflightPayloadFor(grokDiagnostics)
	if err != nil {
		return providerattestation.SignatureMetadata{}, err
	}
	signature, err := sign(ctx, payload)
	if err != nil {
		return providerattestation.SignatureMetadata{}, err
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return providerattestation.SignatureMetadata{}, errors.New("provider receipt attestation preflight verification failed")
	}
	return signature, nil
}

// providerReceiptSignerPreflightPayload exercises the exact binary-backed
// qualification envelope before any paid provider turn is admitted. A fixed
// string probe proves only key readability; this deliberately includes the
// runtime digest whose bridge-schema mismatch previously surfaced too late.
// The failed synthetic receipt is never stored and cannot promote a provider.
func providerReceiptSignerPreflightPayload() ([]byte, error) {
	return providerReceiptSignerPreflightPayloadFor(false)
}

// Grok exercises its diagnostic field through the real bridge before dispatch.
// The generic preflight remains unchanged for other provider transports.
func providerReceiptSignerPreflightPayloadFor(grokDiagnostics bool) ([]byte, error) {
	transport := "zai_codex_identity_preflight"
	names := providerqualification.CodexIdentityPreflightRequiredChecks()
	if grokDiagnostics {
		transport = "xai_acp"
		names = providerqualification.GrokRequiredChecks()
	}
	checks := make([]providerqualification.Check, 0, len(names))
	for _, name := range names {
		checks = append(checks, providerqualification.Check{Name: name, Provenance: "local_authoritative"})
	}
	if grokDiagnostics {
		checks[0].FailureReason = provider.ProtocolOther
	}
	fixedTime := time.Unix(1, 0).UTC()
	receipt := providerqualification.Receipt{
		Mode:               providerqualification.ModeLive,
		Provider:           "signer-preflight",
		Transport:          transport,
		IdentitySHA256:     providerReceiptPreflightDigest,
		PolicySHA256:       providerReceiptPreflightDigest,
		RuntimeVersion:     "schema-runtime-sha256-v1",
		RuntimeSHA256:      providerReceiptPreflightDigest,
		StartedAt:          fixedTime,
		CompletedAt:        fixedTime,
		DisposableRepoHash: providerReceiptPreflightDigest,
		Checks:             checks,
	}
	if err := receipt.Finalize(); err != nil {
		return nil, fmt.Errorf("build provider receipt signer preflight: %w", err)
	}
	return receipt.CanonicalPayload()
}
