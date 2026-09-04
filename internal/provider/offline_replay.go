package provider

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

//go:embed testdata/provider_conformance/*.json
var offlineConformanceFixtures embed.FS

// OfflineScenario is a redacted fixture consumed by the robot conformance
// command. It is embedded so the command stays credential-free and does not
// depend on a source checkout at runtime.
type OfflineScenario struct {
	ID              string                   `json:"id"`
	Transport       string                   `json:"transport"`
	WireFamily      string                   `json:"wire_family"`
	CapturedAt      time.Time                `json:"captured_at"`
	RuntimeVersion  string                   `json:"runtime_version"`
	ExpectedPass    bool                     `json:"expected_pass"`
	Requirements    RuntimeEventRequirements `json:"requirements"`
	Events          []WireEvent              `json:"events"`
	GoldenSignature OfflineGoldenSignature   `json:"golden_signature"`
}

// OfflineGoldenSignature authenticates a redacted fixture against the
// compiled test-laboratory trust anchor. The corresponding private key is not
// shipped. This signature protects offline golden provenance only; it is not
// evidence that a live provider produced the fixture.
type OfflineGoldenSignature struct {
	Algorithm     string `json:"algorithm"`
	KeyID         string `json:"key_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	SignatureHex  string `json:"signature"`
}

const offlineGoldenKeyID = "ntm-offline-fixture-ed25519-v1"

// Repository-controlled offline golden trust anchor. The one-time private key
// used to sign the reviewed fixtures is not stored in this repository.
const offlineGoldenPublicKeyHex = "ce970be88c9cf14c99ecb9c7b20f20408dfca25ad5321ad303bd53de427c0548"

type offlineScenarioPayload struct {
	ID             string                   `json:"id"`
	Transport      string                   `json:"transport"`
	WireFamily     string                   `json:"wire_family"`
	CapturedAt     time.Time                `json:"captured_at"`
	RuntimeVersion string                   `json:"runtime_version"`
	ExpectedPass   bool                     `json:"expected_pass"`
	Requirements   RuntimeEventRequirements `json:"requirements"`
	Events         []WireEvent              `json:"events"`
}

func (s OfflineScenario) signaturePayload() ([]byte, error) {
	return json.Marshal(offlineScenarioPayload{
		ID: s.ID, Transport: s.Transport, WireFamily: s.WireFamily,
		CapturedAt: s.CapturedAt, RuntimeVersion: s.RuntimeVersion,
		ExpectedPass: s.ExpectedPass, Requirements: s.Requirements, Events: s.Events,
	})
}

func (s OfflineScenario) VerifyGoldenSignature() error {
	if s.GoldenSignature.Algorithm != "ed25519" || s.GoldenSignature.KeyID != offlineGoldenKeyID {
		return errors.New("offline fixture has an untrusted signature algorithm or key id")
	}
	payload, err := s.signaturePayload()
	if err != nil {
		return fmt.Errorf("encode offline fixture signature payload: %w", err)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != s.GoldenSignature.PayloadSHA256 {
		return errors.New("offline fixture payload digest does not match its golden signature")
	}
	publicKey, err := hex.DecodeString(offlineGoldenPublicKeyHex)
	if err != nil {
		return errors.New("compiled offline fixture trust anchor is invalid")
	}
	signature, err := hex.DecodeString(s.GoldenSignature.SignatureHex)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return errors.New("offline fixture golden signature verification failed")
	}
	return nil
}

func LoadOfflineScenario(transport string) (OfflineScenario, bool, error) {
	name := ""
	switch transport {
	case "xai_acp":
		name = "grok_acp_happy.json"
	case "zai_codex_runtime":
		name = "zai_responses_happy.json"
	default:
		return OfflineScenario{}, false, nil
	}
	contents, err := offlineConformanceFixtures.ReadFile("testdata/provider_conformance/" + name)
	if err != nil {
		return OfflineScenario{}, false, err
	}
	var scenario OfflineScenario
	if err := json.Unmarshal(contents, &scenario); err != nil {
		return OfflineScenario{}, false, fmt.Errorf("decode embedded provider fixture %s: %w", name, err)
	}
	if scenario.ID == "" || scenario.Transport != transport || scenario.WireFamily == "" || scenario.CapturedAt.IsZero() {
		return OfflineScenario{}, false, fmt.Errorf("embedded provider fixture %s has incomplete provenance", name)
	}
	if err := scenario.VerifyGoldenSignature(); err != nil {
		return OfflineScenario{}, false, fmt.Errorf("verify embedded provider fixture %s: %w", name, err)
	}
	return scenario, true, nil
}

func (s OfflineScenario) Normalize() ([]RuntimeEvent, error) {
	return NormalizeWireEvents(s.WireFamily, s.Events)
}

// SignedEventModel returns the single public model recorded by the verified
// fixture. The caller must verify the golden signature before trusting it.
func (s OfflineScenario) SignedEventModel() (string, error) {
	events, err := s.Normalize()
	if err != nil {
		return "", err
	}
	model := ""
	for _, event := range events {
		if event.Type != EventModelObserved {
			continue
		}
		observed := strings.TrimSpace(event.Model)
		if observed == "" {
			return "", errors.New("offline fixture model observation is empty")
		}
		if model != "" && observed != model {
			return "", errors.New("offline fixture has conflicting model observations")
		}
		model = observed
	}
	if model == "" {
		return "", errors.New("offline fixture has no model observation")
	}
	return model, nil
}

func (s OfflineScenario) Validate(identity Identity) (EventContractReport, error) {
	events, err := s.Normalize()
	if err != nil {
		return EventContractReport{}, err
	}
	return ValidateRuntimeEventsForOperation(identity, events, s.Requirements), nil
}
