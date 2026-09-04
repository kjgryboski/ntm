package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

func TestQualificationDiagnosticsSurviveSignerFailure(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	payload, err := providerReceiptSignerPreflightPayloadFor(true)
	if err != nil {
		t.Fatal(err)
	}
	var receipt providerqualification.Receipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	var savedPath string
	err = signProviderQualificationReceiptWith(context.Background(), &receipt, func(context.Context, []byte) (providerattestation.SignatureMetadata, error) {
		paths, globErr := filepath.Glob(filepath.Join(os.Getenv("XDG_STATE_HOME"), "ntm", "provider-diagnostics", receipt.IdentitySHA256, "*.json"))
		if globErr != nil || len(paths) != 1 {
			t.Fatal("signer ran before durable diagnostics")
		}
		savedPath = paths[0]
		data, readErr := os.ReadFile(savedPath)
		if readErr != nil || !strings.Contains(string(data), "other_protocol_error") {
			t.Fatal("diagnostic unavailable at signing")
		}
		return providerattestation.SignatureMetadata{}, errors.New("simulated signer failure")
	})
	if err == nil || savedPath == "" || !strings.Contains(err.Error(), savedPath) || receipt.Attestation != nil {
		t.Fatal("signing failure lost diagnostics or attached a signature")
	}
	if _, _, err := providerqualification.LoadLatest("", receipt.IdentitySHA256); err == nil {
		t.Fatal("unsigned diagnostic promoted")
	}
}

func TestQualificationDoesNotSignWhenDiagnosticsCannotBeSaved(t *testing.T) {
	dir := t.TempDir()
	blocked := filepath.Join(dir, "file")
	if err := os.WriteFile(blocked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blocked)
	payload, err := providerReceiptSignerPreflightPayloadFor(true)
	if err != nil {
		t.Fatal(err)
	}
	var receipt providerqualification.Receipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatal(err)
	}
	err = signProviderQualificationReceiptWith(context.Background(), &receipt, func(context.Context, []byte) (providerattestation.SignatureMetadata, error) {
		t.Fatal("signer called after diagnostic storage failed")
		return providerattestation.SignatureMetadata{}, nil
	})
	if err == nil {
		t.Fatal("storage failure ignored")
	}
}

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
