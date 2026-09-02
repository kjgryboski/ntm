package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

const providerReceiptAttestationKey = "ntm.provider.receipts.v1"

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

func signProviderReceiptPayload(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
	if providerReceiptAttestor == nil {
		return providerattestation.SignatureMetadata{}, errors.New("provider receipt attestor is unavailable")
	}
	return providerReceiptAttestor.Sign(ctx, providerReceiptAttestationKey, payload)
}

func preflightProviderReceiptSigner(ctx context.Context, sign func(context.Context, []byte) (providerattestation.SignatureMetadata, error)) error {
	if sign == nil {
		return errors.New("provider receipt attestor is unavailable")
	}
	payload := []byte("ntm.provider-receipt-attestation-preflight.v1")
	signature, err := sign(ctx, payload)
	if err != nil {
		return err
	}
	if err := providerattestation.Verify(payload, signature); err != nil {
		return errors.New("provider receipt attestation preflight verification failed")
	}
	return nil
}
