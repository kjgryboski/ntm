//go:build windows

package providerattestation

import (
	"os"
	"testing"
	"time"
)

// This probe is deliberately opt-in: it creates one uniquely named,
// current-user TPM key and intentionally never deletes it. Operators can
// inspect the retained key after the test as activation evidence.
func TestTPMAttestationIntegrationRetainedKey(t *testing.T) {
	if os.Getenv("NTM_TPM_ATTESTATION_INTEGRATION") != "1" {
		t.Skip("set NTM_TPM_ATTESTATION_INTEGRATION=1 to create a retained TPM integration key")
	}
	attestor := NewOSProtected()
	name := "ntm.provider.integration." + time.Now().UTC().Format("20060102t150405.000000000z")
	metadata, err := attestor.EnsureKey(t.Context(), name)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Algorithm != AlgorithmECDSAP256SHA256 || metadata.ProtectionEvidence != ProtectionHardwareNoExportLocalController {
		t.Fatalf("unexpected TPM metadata: %+v", metadata)
	}
	payload := []byte("ntm TPM integration receipt v1")
	signature, err := attestor.Sign(t.Context(), name, payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(payload, signature); err != nil {
		t.Fatal(err)
	}
}
