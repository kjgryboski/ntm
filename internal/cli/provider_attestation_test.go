package cli

import (
	"encoding/json"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

func TestProviderReceiptSignerPreflightPayloadExercisesBinaryQualificationEnvelope(t *testing.T) {
	payload, err := providerReceiptSignerPreflightPayload()
	if err != nil {
		t.Fatal(err)
	}
	if err := providerattestation.ValidateBridgePayload(payload); err != nil {
		t.Fatalf("preflight payload rejected by bridge schema: %v", err)
	}
	var receipt providerqualification.Receipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatalf("preflight receipt invalid: %v", err)
	}
	if receipt.Transport != "zai_codex_identity_preflight" || receipt.RuntimeSHA256 != providerReceiptPreflightDigest || receipt.Passed {
		t.Fatalf("preflight envelope does not exercise the fail-closed runtime binding: %+v", receipt)
	}
}
