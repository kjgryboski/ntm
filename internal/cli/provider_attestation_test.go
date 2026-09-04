package cli

import (
	"encoding/json"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/provider"
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

func TestGrokReceiptSignerPreflightExercisesDiagnosticEnvelope(t *testing.T) {
	payload, err := providerReceiptSignerPreflightPayloadFor(true)
	if err != nil || providerattestation.ValidateBridgePayload(payload) != nil {
		t.Fatalf("Grok diagnostic preflight rejected: %v", err)
	}
	var receipt providerqualification.Receipt
	if json.Unmarshal(payload, &receipt) != nil || receipt.Validate() != nil || receipt.Passed || receipt.Transport != "xai_acp" || len(receipt.Checks) != 9 {
		t.Fatal("Grok preflight is not a valid failed nine-gate receipt")
	}
	if receipt.Checks[0].FailureReason != provider.ProtocolOther {
		t.Fatal("Grok preflight omitted the diagnostic field")
	}
}
