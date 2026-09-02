package cli

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
	"github.com/Dicklesworthstone/ntm/internal/state"
	"github.com/Dicklesworthstone/ntm/internal/zai"
)

type providerNativeAdmissionFake struct {
	decision                      ratelimit.Decision
	status                        ratelimit.CapacityStatus
	acquires, releases, successes int
	results                       []ratelimit.ErrorClass
}

func (f *providerNativeAdmissionFake) Acquire(provider.Identity) ratelimit.Decision {
	f.acquires++
	return f.decision
}
func (f *providerNativeAdmissionFake) Release(provider.Identity, ratelimit.Decision) { f.releases++ }
func (f *providerNativeAdmissionFake) RecordSuccess(provider.Identity) {
	f.successes++
}
func (f *providerNativeAdmissionFake) RecordResult(_ provider.Identity, class ratelimit.ErrorClass, _ time.Duration) ratelimit.Decision {
	f.results = append(f.results, class)
	return ratelimit.Decision{Reason: class, NoFailover: true}
}
func (f *providerNativeAdmissionFake) CapacityStatus() ratelimit.CapacityStatus { return f.status }

type providerNativeHTTPClientFake struct{}

func (providerNativeHTTPClientFake) Do(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected native HTTP call")
}

type providerNativeLedgerFake struct {
	mu  sync.Mutex
	ops map[string]*state.SendOperation
}

func (f *providerNativeLedgerFake) ClaimSendOperation(op *state.SendOperation) (*state.SendOperation, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ops == nil {
		f.ops = make(map[string]*state.SendOperation)
	}
	key := op.SessionName + "\x00" + op.OperationID
	if existing := f.ops[key]; existing != nil {
		copy := *existing
		return &copy, false, nil
	}
	copy := *op
	copy.Status = state.SendOperationInProgress
	f.ops[key] = &copy
	return &copy, true, nil
}

func (f *providerNativeLedgerFake) ReleaseSendOperation(operationID, sessionName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := sessionName + "\x00" + operationID
	if op := f.ops[key]; op != nil && op.Status == state.SendOperationInProgress {
		delete(f.ops, key)
	}
	return nil
}

func (f *providerNativeLedgerFake) CompleteSendOperation(operationID, sessionName, outcome string, completedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	op := f.ops[sessionName+"\x00"+operationID]
	if op == nil || op.Status != state.SendOperationInProgress {
		return errors.New("missing in-progress operation")
	}
	op.Status, op.OutcomeJSON = state.SendOperationCompleted, outcome
	op.CompletedAt = &completedAt
	return nil
}

func providerNativeProfile() config.ProviderProfileConfig {
	return config.ProviderProfileConfig{
		Provider: "zai", AccountAlias: "native", Model: "glm-test", Endpoint: zai.NativeChatCompletionsEndpoint,
		Runtime: "zai-api", RuntimeVersion: providerNativeAdapterVersion, CredentialClass: provider.CredentialClassAPIKey,
		BillingClass: provider.BillingClassAPIUsage, Entitlement: provider.EntitlementNativeAPI,
		ConfigSHA256: providerTestHash("native-zai-config"), AutomationPolicy: provider.NativeZAINoToolsPolicyName, ExactTargetOnly: true, ProbeRequired: true,
	}
}

func providerNativeDeps(profile config.ProviderProfileConfig, admission *providerNativeAdmissionFake) providerNativeRunDependencies {
	ledger := &providerNativeLedgerFake{}
	return providerNativeRunDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-native": profile}}
		},
		credential: &providerCredentialStoreFake{secret: []byte("native-only-test-key"), status: providercredential.Status{Backend: providercredential.BackendLinuxSecretTool, Available: true, Present: true, Evidence: providercredential.EvidenceOSProtectedProcessReadable}},
		newNonce:   func() (string, error) { return "NTM_ACK_0123456789abcdef0123456789abcdef", nil },
		sign:       newProviderNativeTestSigner(),
		recordTelemetry: func(_ context.Context, observation providertelemetry.Observation) (providertelemetry.Observation, error) {
			observation.SchemaVersion = providertelemetry.SchemaVersion
			observation.ID = "11111111111111111111111111111111"
			return observation, nil
		},
		client:    providerNativeHTTPClientFake{},
		admission: admission,
		openLedger: func() (providerNativeOperationLedger, func() error, error) {
			return ledger, func() error { return nil }, nil
		},
		now: func() time.Time { return time.Unix(1, 0).UTC() },
	}
}

type providerNativeAttestationStoreFake struct{ seed []byte }

func (s *providerNativeAttestationStoreFake) Get(context.Context, string) ([]byte, error) {
	if len(s.seed) == 0 {
		return nil, providercredential.ErrNotFound
	}
	return append([]byte(nil), s.seed...), nil
}
func (s *providerNativeAttestationStoreFake) Put(_ context.Context, _ string, value []byte) error {
	s.seed = append([]byte(nil), value...)
	return nil
}
func (s *providerNativeAttestationStoreFake) Status(context.Context, string) (providercredential.Status, error) {
	return providercredential.Status{Backend: providercredential.BackendLinuxSecretTool, Available: true, Present: len(s.seed) != 0, Evidence: providercredential.EvidenceOSProtectedProcessReadable}, nil
}

func newProviderNativeTestSigner() func(context.Context, []byte) (providerattestation.SignatureMetadata, error) {
	attestor, err := providerattestation.New(&providerNativeAttestationStoreFake{})
	if err != nil {
		panic(err)
	}
	if _, err := attestor.EnsureKey(context.Background(), "ntm.provider.receipts.v1"); err != nil {
		panic(err)
	}
	return func(ctx context.Context, payload []byte) (providerattestation.SignatureMetadata, error) {
		return attestor.Sign(ctx, "ntm.provider.receipts.v1", payload)
	}
}

func TestProviderNativeRunRequiresLiveOptIn(t *testing.T) {
	admission := &providerNativeAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	called := false
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		called = true
		return zai.NativeReceipt{}, nil
	}
	err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "sensitive prompt"}, deps)
	if err == nil || called || admission.acquires != 0 {
		t.Fatalf("err=%v called=%t admission=%+v", err, called, admission)
	}
}

func TestProviderNativeRunAcceptsOnlyExactBrokerCredential(t *testing.T) {
	admission := &providerNativeAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	store := &providerCredentialStoreFake{}
	deps.credential = store
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		t.Fatal("credential separation dispatched request")
		return zai.NativeReceipt{}, nil
	}
	err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "p", operationID: "native-credential", live: true}, deps)
	identity, identityErr := providerNativeProfile().Identity()
	if identityErr != nil {
		t.Fatal(identityErr)
	}
	if err == nil || store.getID != providerCredentialID(identity) || admission.acquires != 0 {
		t.Fatalf("err=%v requested=%q admission=%+v", err, store.getID, admission)
	}
}

func TestProviderNativeRunRequiresSignerBeforeCredentialOrDispatch(t *testing.T) {
	admission := &providerNativeAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	store := &providerCredentialStoreFake{secret: []byte("must-not-be-read")}
	deps.credential = store
	deps.sign = func(context.Context, []byte) (providerattestation.SignatureMetadata, error) {
		return providerattestation.SignatureMetadata{}, errors.New("signer unavailable")
	}
	called := false
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		called = true
		return zai.NativeReceipt{}, nil
	}
	err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "p", operationID: "native-no-signer", live: true}, deps)
	if err == nil || store.getID != "" || called || admission.acquires != 0 {
		t.Fatalf("err=%v credential=%q called=%t admission=%+v", err, store.getID, called, admission)
	}
}

func TestProviderNativeRunRedactsInputsAndRecordsSuccess(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	deps.run = func(_ context.Context, _ zai.NativeHTTPClient, request zai.NativeRequest) (zai.NativeReceipt, error) {
		identity, err := providerNativeProfile().Identity()
		if err != nil {
			t.Fatal(err)
		}
		expectedRequestID := providerNativeRequestID(providerNativeBindingHash(identity, "very sensitive prompt"), "native-success")
		if !request.ExplicitOptIn || request.AllowTools || request.Endpoint != zai.NativeChatCompletionsEndpoint || request.Model != "glm-test" || request.NativeAPIKey != "native-only-test-key" || !strings.Contains(request.Prompt, request.ExpectedNonce) || request.ExpectedRequestID != expectedRequestID {
			t.Fatalf("native request=%+v", request)
		}
		return zai.NativeReceipt{Model: "glm-test", NonceVerified: true, FinishReason: "stop", OutputSHA256: providerTestHash("output")}, nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err := runProviderNative(cmd, providerNativeRunOptions{profile: "zai-native", prompt: "very sensitive prompt", operationID: "native-success", live: true}, deps)
	if err != nil || admission.acquires != 1 || admission.releases != 1 || admission.successes != 1 || len(admission.results) != 0 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
	for _, secret := range []string{"very sensitive prompt", "native-only-test-key", "NTM_ACK_0123456789abcdef0123456789abcdef"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("output leaked %q: %q", secret, output.String())
		}
	}
}

func TestProviderNativeTelemetryFailureIsSignedAndDoesNotReplayProvider(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	runCalls := 0
	deps.run = func(_ context.Context, _ zai.NativeHTTPClient, request zai.NativeRequest) (zai.NativeReceipt, error) {
		runCalls++
		return zai.NativeReceipt{Model: request.Model, NonceVerified: true, FinishReason: "stop", StartedAt: time.Unix(1, 0).UTC(), CompletedAt: time.Unix(2, 0).UTC()}, nil
	}
	deps.recordTelemetry = func(context.Context, providertelemetry.Observation) (providertelemetry.Observation, error) {
		return providertelemetry.Observation{}, errors.New("telemetry store full")
	}
	opts := providerNativeRunOptions{profile: "zai-native", prompt: "one paid operation", operationID: "native-telemetry-failure", live: true}
	for i := 0; i < 2; i++ {
		cmd := &cobra.Command{}
		cmd.SetOut(&bytes.Buffer{})
		if err := runProviderNative(cmd, opts, deps); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	if runCalls != 1 {
		t.Fatalf("telemetry failure replayed provider %d times", runCalls)
	}
}

func TestProviderNativeRequestIDIsDeterministicAndBounded(t *testing.T) {
	identity, err := providerNativeProfile().Identity()
	if err != nil {
		t.Fatal(err)
	}
	first := providerNativeRequestID(providerNativeBindingHash(identity, "private prompt one"), "op-one")
	if second := providerNativeRequestID(providerNativeBindingHash(identity, "private prompt one"), "op-one"); first != second {
		t.Fatalf("request IDs not deterministic: %q != %q", first, second)
	}
	if changed := providerNativeRequestID(providerNativeBindingHash(identity, "private prompt two"), "op-one"); changed == first {
		t.Fatalf("request ID did not bind to operation content: %q", first)
	}
	if changed := providerNativeRequestID(providerNativeBindingHash(identity, "private prompt one"), "op-two"); changed == first {
		t.Fatalf("request ID did not bind to the exact operation: %q", first)
	}
	if len(first) != 64 || !strings.HasPrefix(first, "ntm-") || strings.Contains(first, "private") {
		t.Fatalf("request ID is not bounded non-secret correlation data: %q", first)
	}
}

func TestProviderDoctorNativeProbeRequestIDUsesPerProbeBinding(t *testing.T) {
	identity, err := providerNativeProfile().Identity()
	if err != nil {
		t.Fatal(err)
	}
	first := providerDoctorNativeProbeRequestID(identity, "NTM_ACK_0123456789abcdef0123456789abcdef")
	if duplicate := providerDoctorNativeProbeRequestID(identity, "NTM_ACK_0123456789abcdef0123456789abcdef"); first != duplicate {
		t.Fatalf("probe request IDs not deterministic for the same binding: %q != %q", first, duplicate)
	}
	if next := providerDoctorNativeProbeRequestID(identity, "NTM_ACK_fedcba9876543210fedcba9876543210"); first == next {
		t.Fatalf("probe request ID did not bind the per-probe nonce: %q", first)
	}
	if len(first) != 64 || !strings.HasPrefix(first, "ntm-") {
		t.Fatalf("probe request ID not valid for Z.ai: %q", first)
	}
}

func TestProviderNativeRunRecordsExactProviderFailureAndReleases(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		return zai.NativeReceipt{HTTPStatus: http.StatusUnauthorized, ErrorCode: "invalid_api_key"}, errors.New("provider response body must not be shown")
	}
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	err := runProviderNative(cmd, providerNativeRunOptions{profile: "zai-native", prompt: "private", operationID: "native-provider-failure", live: true}, deps)
	var exit *providerNativeRunExitError
	if !errors.As(err, &exit) || admission.releases != 1 || admission.successes != 0 || len(admission.results) != 1 || admission.results[0] != provider.ErrorAuthentication || strings.Contains(output.String(), "provider response body") {
		t.Fatalf("err=%v admission=%+v output=%q", err, admission, output.String())
	}
}

func TestProviderNativeRunDoesNotPoisonCircuitForLocalClientFailure(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		return zai.NativeReceipt{}, errors.New("local TLS failure with sensitive diagnostics")
	}
	var output bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&output)
	err := runProviderNative(cmd, providerNativeRunOptions{profile: "zai-native", prompt: "private", operationID: "native-local-failure", live: true}, deps)
	if err == nil || admission.releases != 1 || len(admission.results) != 0 || strings.Contains(output.String(), "sensitive diagnostics") {
		t.Fatalf("err=%v admission=%+v output=%q", err, admission, output.String())
	}
}

func TestProviderNativeRunDeniesBeforeDispatchAndRejectsAdapterDrift(t *testing.T) {
	t.Run("admission", func(t *testing.T) {
		admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Reason: provider.ErrorRateLimited, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
		deps := providerNativeDeps(providerNativeProfile(), admission)
		deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
			t.Fatal("denied admission dispatched provider")
			return zai.NativeReceipt{}, nil
		}
		err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "p", operationID: "native-admission", live: true}, deps)
		if err == nil || admission.acquires != 1 || admission.releases != 0 || admission.successes != 0 || len(admission.results) != 0 {
			t.Fatalf("err=%v admission=%+v", err, admission)
		}
	})
	t.Run("adapter drift", func(t *testing.T) {
		profile := providerNativeProfile()
		profile.RuntimeVersion = "zai-native-http-v0"
		admission := &providerNativeAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
		deps := providerNativeDeps(profile, admission)
		deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
			t.Fatal("drifted adapter dispatched provider")
			return zai.NativeReceipt{}, nil
		}
		err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "p", operationID: "native-drift", live: true}, deps)
		if err == nil || admission.acquires != 0 {
			t.Fatalf("err=%v admission=%+v", err, admission)
		}
	})
}

func TestProviderNativeRunReplaysCompletedOperationWithoutRedispatch(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	calls := 0
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		calls++
		return zai.NativeReceipt{Model: "glm-test", NonceVerified: true, FinishReason: "stop", OutputSHA256: providerTestHash("output")}, nil
	}
	opts := providerNativeRunOptions{profile: "zai-native", prompt: "private work", operationID: "native-replay", live: true}
	if err := runProviderNative(&cobra.Command{}, opts, deps); err != nil {
		t.Fatalf("initial run: %v", err)
	}
	var replay bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&replay)
	if err := runProviderNative(cmd, opts, deps); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if calls != 1 || admission.acquires != 1 || !strings.Contains(replay.String(), "native-replay (replayed)") {
		t.Fatalf("calls=%d admission=%+v output=%q", calls, admission, replay.String())
	}
}

func TestProviderNativeRunRejectsConflictAndOutcomeUnknownWithoutRedispatch(t *testing.T) {
	t.Run("binding conflict", func(t *testing.T) {
		admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
		deps := providerNativeDeps(providerNativeProfile(), admission)
		calls := 0
		deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
			calls++
			return zai.NativeReceipt{Model: "glm-test", NonceVerified: true, FinishReason: "stop"}, nil
		}
		if err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "first", operationID: "native-conflict", live: true}, deps); err != nil {
			t.Fatal(err)
		}
		err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "second", operationID: "native-conflict", live: true}, deps)
		if err == nil || calls != 1 || admission.acquires != 1 {
			t.Fatalf("err=%v calls=%d admission=%+v", err, calls, admission)
		}
	})
	t.Run("local outcome unknown", func(t *testing.T) {
		admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
		deps := providerNativeDeps(providerNativeProfile(), admission)
		calls := 0
		deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
			calls++
			return zai.NativeReceipt{}, errors.New("local connection closed")
		}
		opts := providerNativeRunOptions{profile: "zai-native", prompt: "private", operationID: "native-unknown", live: true}
		if err := runProviderNative(&cobra.Command{}, opts, deps); err == nil {
			t.Fatal("local failure unexpectedly succeeded")
		}
		if err := runProviderNative(&cobra.Command{}, opts, deps); err == nil || calls != 1 || admission.acquires != 1 {
			t.Fatalf("err=%v calls=%d admission=%+v", err, calls, admission)
		}
	})
	t.Run("HTTP 200 protocol outcome unknown", func(t *testing.T) {
		admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
		deps := providerNativeDeps(providerNativeProfile(), admission)
		calls := 0
		deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
			calls++
			return zai.NativeReceipt{HTTPStatus: http.StatusOK}, errors.New("invalid provider stream after dispatch")
		}
		opts := providerNativeRunOptions{profile: "zai-native", prompt: "private", operationID: "native-protocol-unknown", live: true}
		if err := runProviderNative(&cobra.Command{}, opts, deps); err == nil {
			t.Fatal("protocol failure unexpectedly succeeded")
		}
		if err := runProviderNative(&cobra.Command{}, opts, deps); err == nil || calls != 1 || admission.acquires != 1 || len(admission.results) != 0 {
			t.Fatalf("err=%v calls=%d admission=%+v", err, calls, admission)
		}
	})
}

func TestProviderNativeRunRejectsAdmissionThatPermitsFailover(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: false}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		t.Fatal("failover-capable admission dispatched provider")
		return zai.NativeReceipt{}, nil
	}
	err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "p", operationID: "native-no-failover", live: true}, deps)
	if err == nil || admission.acquires != 1 || admission.releases != 1 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
}

func TestProviderNativeRunRejectsCorruptCompletedReceiptWithoutRedispatch(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	ledger := &providerNativeLedgerFake{}
	deps.openLedger = func() (providerNativeOperationLedger, func() error, error) {
		return ledger, func() error { return nil }, nil
	}
	calls := 0
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		calls++
		return zai.NativeReceipt{Model: "glm-test", NonceVerified: true, FinishReason: "stop"}, nil
	}
	opts := providerNativeRunOptions{profile: "zai-native", prompt: "private", operationID: "native-corrupt", live: true}
	if err := runProviderNative(&cobra.Command{}, opts, deps); err != nil {
		t.Fatal(err)
	}
	ledger.mu.Lock()
	stored := ledger.ops[providerNativeOperationScope+"\x00native-corrupt"]
	stored.OutcomeJSON = strings.Replace(stored.OutcomeJSON, `"operation_id":"native-corrupt"`, `"operation_id":"different"`, 1)
	ledger.mu.Unlock()
	if err := runProviderNative(&cobra.Command{}, opts, deps); err == nil || calls != 1 || admission.acquires != 1 {
		t.Fatalf("err=%v calls=%d admission=%+v", err, calls, admission)
	}
}

func TestProviderNativeRunRequiresOperationIDForLiveDispatch(t *testing.T) {
	admission := &providerNativeAdmissionFake{status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		t.Fatal("missing operation ID dispatched")
		return zai.NativeReceipt{}, nil
	}
	err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: "p", live: true}, deps)
	if err == nil || admission.acquires != 0 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
}

func TestProviderNativeRunDurableReceiptRedactsPromptNonceAndCredential(t *testing.T) {
	admission := &providerNativeAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerNativeDeps(providerNativeProfile(), admission)
	ledger := &providerNativeLedgerFake{}
	deps.openLedger = func() (providerNativeOperationLedger, func() error, error) {
		return ledger, func() error { return nil }, nil
	}
	deps.run = func(context.Context, zai.NativeHTTPClient, zai.NativeRequest) (zai.NativeReceipt, error) {
		return zai.NativeReceipt{Model: "glm-test", NonceVerified: true, FinishReason: "stop"}, nil
	}
	const prompt = "very private durable prompt"
	const nonce = "NTM_ACK_0123456789abcdef0123456789abcdef"
	if err := runProviderNative(&cobra.Command{}, providerNativeRunOptions{profile: "zai-native", prompt: prompt, operationID: "native-redaction", live: true}, deps); err != nil {
		t.Fatal(err)
	}
	ledger.mu.Lock()
	stored := ledger.ops[providerNativeOperationScope+"\x00native-redaction"]
	ledger.mu.Unlock()
	if stored == nil || stored.Status != state.SendOperationCompleted {
		t.Fatalf("stored=%+v", stored)
	}
	for _, prohibited := range []string{prompt, nonce, "native-only-test-key"} {
		if strings.Contains(stored.OutcomeJSON, prohibited) {
			t.Fatalf("durable receipt leaked %q: %q", prohibited, stored.OutcomeJSON)
		}
	}
	if stored.PayloadSHA256 != sha256StringCLI(prompt) || stored.PayloadBytes != int64(len(prompt)) {
		t.Fatalf("unexpected payload metadata: %+v", stored)
	}
}
