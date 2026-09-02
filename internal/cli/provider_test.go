package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/Dicklesworthstone/ntm/internal/agent"
	"github.com/Dicklesworthstone/ntm/internal/config"
	"github.com/Dicklesworthstone/ntm/internal/grok"
	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
	"github.com/Dicklesworthstone/ntm/internal/providertelemetry"
	"github.com/Dicklesworthstone/ntm/internal/ratelimit"
)

func providerTestHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func TestProviderDoctorNonceSatisfiesGrokAcknowledgementContract(t *testing.T) {
	nonce, err := providerDoctorNonce()
	if err != nil || !grok.ValidNonce(nonce) {
		t.Fatalf("nonce=%q err=%v", nonce, err)
	}
}

func TestProviderCapabilitiesHumanOutputIncludesAuthorityScopes(t *testing.T) {
	cmd := newProviderCapabilitiesCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"COMPLETION_SCOPE", "CANCEL_SCOPE", "CLEANUP_SCOPE", "LAUNCH_CAPACITY", "REQUEST_CAPACITY", "LIVE_ERROR_FEEDBACK", "local_process_tree", "provider"} {
		if !strings.Contains(got, want) {
			t.Fatalf("capabilities output omitted %q: %s", want, got)
		}
	}
}

func TestProviderRuntimeVersionPinMatchesOnlyAnExactToken(t *testing.T) {
	if !versionMatches("grok 1.0.13", "1.0.13") || !versionMatches("2.1.252 (Claude Code)", "2.1.252") {
		t.Fatal("exact runtime version token did not match")
	}
	for _, pair := range [][2]string{{"grok 1.0.13", "1.0.1"}, {"2.1.252", "2.1"}, {"1.0.130", "1.0.13"}} {
		if versionMatches(pair[0], pair[1]) {
			t.Fatalf("runtime version %q matched non-exact pin %q", pair[0], pair[1])
		}
	}
}

func TestProviderQualificationRequiresExplicitLiveOptIn(t *testing.T) {
	called := false
	deps := providerQualificationDependencies{
		loadConfig: func() *config.Config { return &config.Config{} },
		lookPath:   func(string) (string, error) { return "/usr/bin/claude", nil },
		version:    func(context.Context, string) (string, error) { return "2.1.252", nil },
		lookupEnv:  func(string) (string, bool) { return "credential", true },
		run: func(context.Context, providerqualification.Options) providerqualification.Receipt {
			called = true
			return providerqualification.Receipt{}
		},
		store:     func(string, providerqualification.Receipt) (string, error) { return "", nil },
		sign:      func(context.Context, *providerqualification.Receipt) error { return nil },
		preflight: func(context.Context) error { return nil },
	}
	err := runProviderQualification(&cobra.Command{}, providerQualificationOptions{profile: "zai-qualified", timeout: time.Second, suiteTimeout: time.Second}, deps)
	if err == nil || called {
		t.Fatalf("live opt-in error=%v called=%v", err, called)
	}
}

func TestZAIAuthPresenceRejectsGenericAnthropicToken(t *testing.T) {
	identity, err := providerTestProfile().Identity()
	if err != nil {
		t.Fatal(err)
	}
	check := diagnoseProviderAuthPresence(identity, func(name string) (string, bool) {
		if name == "ANTHROPIC_AUTH_TOKEN" {
			return "generic-claude-token", true
		}
		return "", false
	})
	if check.Status != providerDoctorFail {
		t.Fatalf("generic Anthropic token crossed Z.ai credential boundary: %+v", check)
	}
}

func TestProviderDoctorPreservesLocalLifecycleAuthorityScope(t *testing.T) {
	capability := provider.CapabilityMatrix()["xai_headless_session"]
	check := diagnoseLifecycleAuthority(capability)
	if check.Status != providerDoctorWarn || !strings.Contains(check.Summary, "local_process_tree") || strings.Contains(check.Summary, "are provider-authoritative") {
		t.Fatalf("local lifecycle authority was overstated: %+v", check)
	}
}

func TestProviderDoctorReservesFullGoForProviderAuthoritativeLifecycle(t *testing.T) {
	capability := provider.OperationCapabilities{
		Cancellation: provider.EvidenceAuthoritative, CancellationAuthorityScope: provider.EvidenceAuthorityScopeProvider,
		Cleanup: provider.EvidenceAuthoritative, CleanupAuthorityScope: provider.EvidenceAuthorityScopeProvider,
	}
	if !providerLifecycleFullyAuthoritative(capability) || diagnoseLifecycleAuthority(capability).Status != providerDoctorPass {
		t.Fatal("provider-authoritative lifecycle did not satisfy the full-GO boundary")
	}
	capability.CleanupAuthorityScope = provider.EvidenceAuthorityScopeLocalClient
	if providerLifecycleFullyAuthoritative(capability) {
		t.Fatal("local-client cleanup was promoted to provider-authoritative lifecycle")
	}
}

func TestProviderDoctorDoesNotRequireZAICodingQualificationForProviderNativeTransport(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	result, checks := diagnoseQualification(identity, "xai_acp", providerTestHash("policy"), providerCommandOptions{}, providerDoctorDependencies{}, nil)
	if result.State != "not_required" || len(checks) != 1 || checks[0].Status != providerDoctorPass {
		t.Fatalf("provider-native qualification gate=%+v checks=%+v", result, checks)
	}
}

func TestGrokDoctorModelEvidenceConfirmedRejectsCatalogOnlyEvidence(t *testing.T) {
	for evidence, want := range map[string]bool{
		"completion_metadata":                             true,
		"provider_session_notification_plus_exact_launch": true,
		"session_config_option_plus_exact_launch":         true,
		"session_model_state_plus_exact_launch":           true,
		"provider_catalog_plus_exact_launch":              false,
		"":                                                false,
		"unrecognized":                                    false,
	} {
		if got := grokDoctorModelEvidenceConfirmed(evidence); got != want {
			t.Fatalf("grokDoctorModelEvidenceConfirmed(%q)=%v, want %v", evidence, got, want)
		}
	}
}

func TestProviderQualificationStoresFailedLiveReceiptWithoutPromoting(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	receipt := providerTestReceipt(t, identity, now)
	receipt.Checks[0].Passed = false
	if err := receipt.Finalize(); err != nil {
		t.Fatal(err)
	}
	stored := false
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	qualificationAdmission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	deps := providerQualificationDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-qualified": profile}}
		},
		lookPath: func(string) (string, error) { return "/usr/bin/claude", nil },
		version:  func(context.Context, string) (string, error) { return "2.1.252 (Claude Code)", nil },
		lookupEnv: func(name string) (string, bool) {
			if name == "ZAI_API_KEY" {
				return "never-serialize-this", true
			}
			return "", false
		},
		run: func(_ context.Context, got providerqualification.Options) providerqualification.Receipt {
			if !got.Live || got.Identity.Hash() != identity.Hash() || got.PolicySHA256 != providerqualification.QualificationPolicySHA256() {
				t.Fatalf("qualification options=%+v", got)
			}
			return receipt
		},
		store: func(_ string, got providerqualification.Receipt) (string, error) {
			stored = true
			if got.Passed {
				t.Fatal("failed receipt was promoted")
			}
			return "/redacted/failed-receipt.json", nil
		},
		sign:      func(context.Context, *providerqualification.Receipt) error { return nil },
		preflight: func(context.Context) error { return nil },
		admission: qualificationAdmission,
	}
	err = runProviderQualification(cmd, providerQualificationOptions{profile: "zai-qualified", live: true, timeout: time.Second, suiteTimeout: time.Minute}, deps)
	var exit *providerQualificationExitError
	if !errors.As(err, &exit) || !stored || qualificationAdmission.acquires != 1 || qualificationAdmission.releases != 1 || qualificationAdmission.successes != 0 || !strings.Contains(output.String(), "NO-GO") || strings.Contains(output.String(), "never-serialize-this") {
		t.Fatalf("err=%v stored=%v admission=%+v output=%q", err, stored, qualificationAdmission, output.String())
	}
}

type providerSessionAdmissionFake struct {
	decision                      ratelimit.Decision
	status                        ratelimit.CapacityStatus
	acquires, releases, successes int
}

func (f *providerSessionAdmissionFake) Acquire(provider.Identity) ratelimit.Decision {
	f.acquires++
	return f.decision
}
func (f *providerSessionAdmissionFake) Release(provider.Identity, ratelimit.Decision) { f.releases++ }
func (f *providerSessionAdmissionFake) RecordSuccess(provider.Identity)               { f.successes++ }
func (f *providerSessionAdmissionFake) CapacityStatus() ratelimit.CapacityStatus      { return f.status }

type providerSessionRunnerFake struct{}

func (providerSessionRunnerFake) Start(context.Context, grok.StartSpec) (grok.LifecycleProcess, error) {
	return nil, errors.New("unexpected real runner call")
}

func providerTestGrokProfile(policy string) config.ProviderProfileConfig {
	return config.ProviderProfileConfig{
		Provider: "xai", AccountAlias: "cached", Model: "grok-4.6", Endpoint: "https://api.x.ai/v1",
		Runtime: "grok", RuntimeVersion: "1.0.13", ConfigSHA256: providerTestHash("grok-config"),
		Command: "grok", AutomationPolicy: policy, ExactTargetOnly: true,
	}
}

func providerTestGrokInspection() providerGrokInspection {
	return providerGrokInspection{
		GrokVersion:                    "1.0.13",
		PermissionsLoaded:              true,
		PermissionSources:              []string{providerRequirementsPath() + " (system requirements)"},
		SystemRequirementsLayerPresent: true,
		SHA256:                         providerTestHash("inspect"),
	}
}

func providerTestGrokBypassProbe() providerGrokBypassProbe {
	return providerGrokBypassProbe{
		Refused: true, NetworkIsolated: true, CredentialsIsolated: true,
		ExitCode: 1, SHA256: providerTestHash("bypass-lock-probe"),
	}
}

func TestParseProviderRuntimeInspectGrokCurrentSchemaRequiresSystemEvidence(t *testing.T) {
	inspection, err := parseProviderRuntimeInspectGrok([]byte(`{
		"grokVersion":"1.0.13",
		"permissions":{"loaded":3,"sources":["/etc/grok/requirements.toml (system requirements)"],"managedSettingsPath":"/not-authority"},
		"configSources":{"layers":[{"role":"user"},{"role":"system-requirements"}]},
		"configWarnings":[]
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.PermissionsLoaded || !inspection.SystemRequirementsLayerPresent || !hasProviderSystemRequirementsSource(inspection.PermissionSources, "/etc/grok/requirements.toml") {
		t.Fatalf("current inspection did not retain system requirements evidence: %+v", inspection)
	}

	legacy, err := parseProviderRuntimeInspectGrok([]byte(`{
		"grokVersion":"1.0.12",
		"permissions":{"loaded":true,"sources":["/etc/grok/requirements.toml (system requirements)"]},
		"configSources":{"layers":[{"role":"system-requirements"}]}
	}`))
	if err != nil || !legacy.PermissionsLoaded {
		t.Fatalf("legacy boolean loaded shape was not accepted: inspection=%+v err=%v", legacy, err)
	}
	warning, err := parseProviderRuntimeInspectGrok([]byte(`{
		"grokVersion":"1.0.13",
		"permissions":{"loaded":1,"sources":["/etc/grok/requirements.toml (system requirements)"]},
		"configSources":{"layers":[{"role":"system-requirements"}]},
		"configWarnings":["unknown setting ui.disable_bypass_permissions_mode"]
	}`))
	if err != nil || !warning.BypassLockWarning {
		t.Fatalf("unrecognized bypass warning was not retained: inspection=%+v err=%v", warning, err)
	}
}

func TestProviderPolicyAcceptsInspectWarningOnlyWithIsolatedBehavioralRefusal(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	requirements, ok := agent.GrokSystemRequirementsForPolicy(profile.AutomationPolicy)
	if !ok {
		t.Fatal("missing compiled requirements")
	}
	deps := providerDoctorDependencies{
		readFile:  func(string) ([]byte, error) { return []byte(requirements.Contents), nil },
		stat:      func(string) (os.FileInfo, error) { return nil, nil },
		rootOwned: func(os.FileInfo) bool { return true },
		inspectGrok: func(context.Context, string, string) (providerGrokInspection, error) {
			inspection := providerTestGrokInspection()
			inspection.BypassLockWarning = true
			return inspection, nil
		},
		probeGrokBypassLock: func(context.Context, string) (providerGrokBypassProbe, error) {
			return providerTestGrokBypassProbe(), nil
		},
	}
	result, check := diagnoseProviderPolicy(context.Background(), "/repo", profile, identity, deps)
	if check.Status != providerDoctorPass || !result.BypassLockAuthoritative || result.RuntimeInspectionState != "managed_requirements_discovered_with_bypass_warning" || result.BypassLockProbeState != "always_approve_refused" {
		t.Fatalf("behaviorally enforced bypass lock was rejected: result=%+v check=%+v", result, check)
	}

	deps.probeGrokBypassLock = func(context.Context, string) (providerGrokBypassProbe, error) {
		probe := providerTestGrokBypassProbe()
		probe.Refused = false
		return probe, nil
	}
	result, check = diagnoseProviderPolicy(context.Background(), "/repo", profile, identity, deps)
	if check.Status != providerDoctorFail || result.BypassLockAuthoritative || result.BypassLockProbeState != "not_refused" {
		t.Fatalf("missing behavioral refusal was accepted: result=%+v check=%+v", result, check)
	}
}

func providerSessionTestDeps(t *testing.T, profile config.ProviderProfileConfig, admission *providerSessionAdmissionFake) providerSessionDependencies {
	t.Helper()
	requirements, ok := agent.GrokSystemRequirementsForPolicy(profile.AutomationPolicy)
	if !ok {
		t.Fatal("missing policy requirements")
	}
	signer := newProviderNativeTestSigner()
	return providerSessionDependencies{
		loadConfig: func() *config.Config {
			return &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"grok-qualified": profile}}
		},
		lookPath: func(string) (string, error) { return "/usr/bin/grok", nil },
		trustExecutable: func(path string) (string, error) {
			if path != "/usr/bin/grok" {
				t.Fatalf("unexpected Grok executable path %q", path)
			}
			return path, nil
		},
		version:   func(context.Context, string) (string, error) { return "grok 1.0.13", nil },
		readFile:  func(string) ([]byte, error) { return []byte(requirements.Contents), nil },
		stat:      func(string) (os.FileInfo, error) { return nil, nil },
		rootOwned: func(os.FileInfo) bool { return true },
		inspectGrok: func(context.Context, string, string) (providerGrokInspection, error) {
			return providerTestGrokInspection(), nil
		},
		probeGrokBypassLock: func(context.Context, string) (providerGrokBypassProbe, error) {
			return providerTestGrokBypassProbe(), nil
		},
		isLinkedWorktree: func(context.Context, string) (bool, error) { return true, nil },
		attestationPreflight: func(ctx context.Context) error {
			return providerSessionAttestationPreflightWithSigner(ctx, signer)
		},
		sign:       signer,
		hashBinary: func(string) (string, error) { return providerTestHash("grok-binary"), nil },
		recordTelemetry: func(_ context.Context, observation providertelemetry.Observation) (providertelemetry.Observation, error) {
			observation.SchemaVersion = providertelemetry.SchemaVersion
			observation.ID = "22222222222222222222222222222222"
			return observation, nil
		},
		runner: providerSessionRunnerFake{}, admission: admission,
		now: func() time.Time { return time.Unix(1_800_000_000, 0).UTC() },
	}
}

func TestProviderPolicyRequiresPinnedRuntimeDiscoveryOfManagedRequirements(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	requirements, ok := agent.GrokSystemRequirementsForPolicy(profile.AutomationPolicy)
	if !ok {
		t.Fatal("missing compiled requirements")
	}
	deps := providerDoctorDependencies{
		readFile:  func(string) ([]byte, error) { return []byte(requirements.Contents), nil },
		stat:      func(string) (os.FileInfo, error) { return nil, nil },
		rootOwned: func(os.FileInfo) bool { return true },
		inspectGrok: func(context.Context, string, string) (providerGrokInspection, error) {
			return providerTestGrokInspection(), nil
		},
		probeGrokBypassLock: func(context.Context, string) (providerGrokBypassProbe, error) {
			return providerTestGrokBypassProbe(), nil
		},
	}
	result, check := diagnoseProviderPolicy(context.Background(), "/repo", profile, identity, deps)
	if check.Status != providerDoctorPass || !result.BypassLockAuthoritative || result.RuntimeInspectionState != "managed_requirements_discovered" {
		t.Fatalf("runtime-attested policy result=%+v check=%+v", result, check)
	}

	deps.inspectGrok = func(context.Context, string, string) (providerGrokInspection, error) {
		inspection := providerTestGrokInspection()
		inspection.PermissionSources = []string{"/wrong/requirements.toml (system requirements)"}
		inspection.SHA256 = providerTestHash("wrong")
		return inspection, nil
	}
	result, check = diagnoseProviderPolicy(context.Background(), "/repo", profile, identity, deps)
	if check.Status != providerDoctorFail || result.BypassLockAuthoritative || result.RuntimeInspectionState != "managed_requirements_not_discovered" {
		t.Fatalf("mismatched runtime policy result=%+v check=%+v", result, check)
	}
}

func TestGrokACPDispatchRequiresLiveManagedPolicyAndPinnedRuntime(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	requirements, ok := agent.GrokSystemRequirementsForPolicy(profile.AutomationPolicy)
	if !ok {
		t.Fatal("missing compiled requirements")
	}
	versionCalls := 0
	deps := providerDoctorDependencies{
		lookPath: func(string) (string, error) { return "/user-path/grok", nil },
		trustExecutable: func(path string) (string, error) {
			if path != "/user-path/grok" {
				t.Fatalf("unexpected located runtime %q", path)
			}
			return "/verified/bin/grok", nil
		},
		version:   func(context.Context, string) (string, error) { versionCalls++; return "grok 1.0.13", nil },
		readFile:  func(string) ([]byte, error) { return []byte(requirements.Contents), nil },
		stat:      func(string) (os.FileInfo, error) { return nil, nil },
		rootOwned: func(os.FileInfo) bool { return true },
		inspectGrok: func(context.Context, string, string) (providerGrokInspection, error) {
			return providerTestGrokInspection(), nil
		},
		probeGrokBypassLock: func(context.Context, string) (providerGrokBypassProbe, error) {
			return providerTestGrokBypassProbe(), nil
		},
	}
	binary, err := verifyGrokACPDispatchAuthority(context.Background(), "/repo", profile, identity, deps)
	if err != nil || binary != "/verified/bin/grok" || versionCalls != 1 {
		t.Fatalf("binary=%q version_calls=%d err=%v", binary, versionCalls, err)
	}

	deps.inspectGrok = func(context.Context, string, string) (providerGrokInspection, error) {
		inspection := providerTestGrokInspection()
		inspection.PermissionsLoaded = false
		return inspection, nil
	}
	versionCalls = 0
	if _, err := verifyGrokACPDispatchAuthority(context.Background(), "/repo", profile, identity, deps); err == nil || versionCalls != 1 {
		t.Fatalf("runtime policy drift was not rejected after the pinned-version precheck: calls=%d err=%v", versionCalls, err)
	}

	deps.inspectGrok = func(context.Context, string, string) (providerGrokInspection, error) {
		return providerTestGrokInspection(), nil
	}
	deps.version = func(context.Context, string) (string, error) { return "grok 1.0.130", nil }
	if _, err := verifyGrokACPDispatchAuthority(context.Background(), "/repo", profile, identity, deps); err == nil {
		t.Fatal("runtime drift was accepted for Grok ACP dispatch")
	}

	deps.version = func(context.Context, string) (string, error) {
		versionCalls++
		return "grok 1.0.13", nil
	}
	deps.trustExecutable = func(string) (string, error) {
		return "", errors.New("user-owned runtime")
	}
	versionCalls = 0
	if _, err := verifyGrokACPDispatchAuthority(context.Background(), "/repo", profile, identity, deps); err == nil || versionCalls != 0 {
		t.Fatalf("untrusted executable reached version/policy attestation: calls=%d err=%v", versionCalls, err)
	}
}

func TestProviderSessionUsesSharedAdmissionAndReturnsOnlyHashedLineage(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	deps := providerSessionTestDeps(t, profile, admission)
	runCalls := 0
	deps.run = func(_ context.Context, _ grok.LifecycleRunner, request grok.SessionRequest) (grok.SessionReceipt, error) {
		runCalls++
		if request.ExpectedNonce == "" || !strings.Contains(request.Prompt, request.ExpectedNonce) || request.SessionID != "raw-parent-session" || request.Worktree != request.CWD || request.RuntimeVersion != profile.RuntimeVersion || request.PolicySHA256 == "" || request.ConfigSHA256 == "" || request.BinarySHA256 == "" {
			t.Fatalf("request=%+v", request)
		}
		joinedPolicy := strings.Join(request.PolicyArgs, "\n")
		if strings.Contains(joinedPolicy, "--sandbox=") || !strings.Contains(joinedPolicy, "--permission-mode=dontAsk") || !strings.Contains(joinedPolicy, "--deny=Edit") {
			t.Fatalf("lifecycle policy did not inherit the session sandbox while retaining rules: %#v", request.PolicyArgs)
		}
		return grok.SessionReceipt{
			Action: request.Action, Fork: request.Action == grok.SessionFork, LineageBound: true, ProviderAcknowledged: true, CompletionConfirmed: true,
			ParentSessionSHA256: providerTestHash("parent"), ChildSessionSHA256: providerTestHash("child"), NonceSHA256: providerTestHash("nonce"),
			CWDSHA256: sha256StringCLI(request.CWD), WorktreeSHA256: sha256StringCLI(request.Worktree), PolicySHA256: request.PolicySHA256, ConfigSHA256: request.ConfigSHA256, BinarySHA256: request.BinarySHA256,
		}, nil
	}
	cmd := &cobra.Command{}
	var output bytes.Buffer
	cmd.SetOut(&output)
	err := runProviderSession(cmd, grok.SessionFork, providerSessionOptions{profile: "grok-qualified", sessionID: "raw-parent-session", prompt: "sensitive prompt", cwd: t.TempDir(), timeout: time.Second}, deps)
	if err != nil || runCalls != 1 || admission.acquires != 1 || admission.releases != 1 || admission.successes != 1 {
		t.Fatalf("err=%v calls=%d admission=%+v", err, runCalls, admission)
	}
	if strings.Contains(output.String(), "raw-parent-session") || strings.Contains(output.String(), "sensitive prompt") {
		t.Fatalf("output leaked raw inputs: %q", output.String())
	}
}

func TestProviderSessionAttestationPreflightBlocksDispatchBeforeAdmission(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	admission := &providerSessionAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerSessionTestDeps(t, profile, admission)
	deps.attestationPreflight = func(context.Context) error { return errors.New("key unavailable") }
	deps.run = func(context.Context, grok.LifecycleRunner, grok.SessionRequest) (grok.SessionReceipt, error) {
		t.Fatal("attestation preflight dispatched Grok")
		return grok.SessionReceipt{}, nil
	}
	err := runProviderSession(&cobra.Command{}, grok.SessionResume, providerSessionOptions{profile: "grok-qualified", sessionID: "parent", prompt: "bounded", cwd: t.TempDir(), timeout: time.Second}, deps)
	if err == nil || admission.acquires != 0 || admission.releases != 0 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
}

func TestProviderSessionOutputSignatureBindsCompletedReceipt(t *testing.T) {
	output := providerSessionOutput{
		SchemaVersion: providerSessionSchema, Success: true, Dispatched: true, Profile: "grok-qualified", Transport: "xai_headless_session",
		IdentitySHA256: providerTestHash("identity"), Policy: agent.DefaultGrokAutomationPolicyName,
		PolicySHA256: providerTestHash("policy"), ConfigSHA256: providerTestHash("config"), BinarySHA256: providerTestHash("binary"), CWD_SHA256: providerTestHash("cwd"), WorktreeSHA256: providerTestHash("worktree"),
		Telemetry: providerTelemetryEvidence{State: providerTelemetryStateRecorded, ObservationID: "11111111111111111111111111111111", ObservationSHA256: providerTestHash("observation")},
		Receipt:   grok.SessionReceipt{Action: grok.SessionResume, CompletionConfirmed: true, ProviderAcknowledged: true, LineageBound: true, ParentSessionSHA256: providerTestHash("parent"), ChildSessionSHA256: providerTestHash("child"), NonceSHA256: providerTestHash("nonce"), CWDSHA256: providerTestHash("cwd"), WorktreeSHA256: providerTestHash("worktree"), PolicySHA256: providerTestHash("policy"), ConfigSHA256: providerTestHash("config"), BinarySHA256: providerTestHash("binary")},
	}
	if err := sealProviderSessionOutput(t.Context(), &output, newProviderNativeTestSigner()); err != nil || !validProviderSessionOutput(output) {
		t.Fatalf("sealed completed receipt valid=%v err=%v output=%+v", validProviderSessionOutput(output), err, output)
	}
	output.Receipt.ChildSessionSHA256 = providerTestHash("tampered-child")
	if validProviderSessionOutput(output) {
		t.Fatal("tampered completed session receipt was accepted")
	}
}

func TestProviderSessionRejectsAdmissionThatPermitsFailover(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: false},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	deps := providerSessionTestDeps(t, profile, admission)
	deps.run = func(context.Context, grok.LifecycleRunner, grok.SessionRequest) (grok.SessionReceipt, error) {
		t.Fatal("failover-capable admission dispatched Grok")
		return grok.SessionReceipt{}, nil
	}
	err := runProviderSession(&cobra.Command{}, grok.SessionResume, providerSessionOptions{profile: "grok-qualified", sessionID: "parent", prompt: "bounded", cwd: t.TempDir(), timeout: time.Second}, deps)
	if err == nil || admission.acquires != 1 || admission.releases != 1 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
}

func TestProviderWorkspaceSessionRejectsPrimaryCheckoutBeforeAdmission(t *testing.T) {
	profile := providerTestGrokProfile(agent.GrokWorkspaceWritePolicyName)
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	deps := providerSessionTestDeps(t, profile, admission)
	deps.isLinkedWorktree = func(context.Context, string) (bool, error) { return false, nil }
	deps.run = func(context.Context, grok.LifecycleRunner, grok.SessionRequest) (grok.SessionReceipt, error) {
		t.Fatal("workspace rejection dispatched provider")
		return grok.SessionReceipt{}, nil
	}
	err := runProviderSession(&cobra.Command{}, grok.SessionResume, providerSessionOptions{profile: "grok-qualified", sessionID: "parent", prompt: "work", cwd: t.TempDir(), timeout: time.Second}, deps)
	if err == nil || admission.acquires != 0 {
		t.Fatalf("err=%v admission=%+v", err, admission)
	}
}

func providerTestProfile() config.ProviderProfileConfig {
	return config.ProviderProfileConfig{
		Provider: "zai", AccountAlias: "qualification", Model: "glm-test", Endpoint: "https://api.z.ai/api/anthropic",
		Runtime: "claude-code", RuntimeVersion: "2.1.252", CredentialClass: provider.CredentialClassCodingPlan,
		BillingClass: provider.BillingClassCodingPlan, Entitlement: provider.EntitlementClaudeCompat,
		ConfigSHA256: providerTestHash("config"), Command: "claude", AutomationPolicy: provider.DefaultZAIAutomationPolicyName,
		ExactTargetOnly: true, ProbeRequired: true,
	}
}

func providerTestReceipt(t *testing.T, identity provider.Identity, at time.Time) providerqualification.Receipt {
	t.Helper()
	names := []string{
		"model_identity", "workspace_edit", "test_execution", "secret_access_denied", "push_denied",
		"crash_recovery", "cancellation", "session_resumption", "zero_residual_cleanup",
	}
	checks := make([]providerqualification.Check, 0, len(names))
	for _, name := range names {
		checks = append(checks, providerqualification.Check{Name: name, Passed: true, Provenance: "live", EvidenceSHA256: providerTestHash(name)})
	}
	receipt := providerqualification.Receipt{
		Provider: "zai", Transport: "zai_claude_runtime", IdentitySHA256: identity.Hash(), PolicySHA256: providerqualification.QualificationPolicySHA256(),
		RuntimeVersion: "2.1.252", StartedAt: at.Add(-time.Minute), CompletedAt: at,
		DisposableRepoHash: providerTestHash("repo"), Checks: checks,
	}
	if err := receipt.Finalize(); err != nil {
		t.Fatalf("Finalize() error: %v", err)
	}
	payload, err := receipt.CanonicalPayload()
	if err != nil {
		t.Fatalf("CanonicalPayload() error: %v", err)
	}
	signature, err := newProviderNativeTestSigner()(context.Background(), payload)
	if err != nil {
		t.Fatalf("sign test qualification receipt: %v", err)
	}
	if err := receipt.AttachAttestation(signature); err != nil {
		t.Fatalf("AttachAttestation() error: %v", err)
	}
	return receipt
}

func TestProviderDoctorRejectsUnsignedQualificationReceipt(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	receipt := providerTestReceipt(t, identity, now)
	receipt.Attestation = nil
	deps := providerTestDeps(t, now, receipt)
	result, checks := diagnoseQualification(identity, "zai_claude_runtime", providerqualification.QualificationPolicySHA256(), providerCommandOptions{qualificationAge: 24 * time.Hour}, deps, nil)
	if result.State != "unsigned" || len(checks) != 1 || checks[0].Status != providerDoctorFail {
		t.Fatalf("unsigned qualification was accepted: result=%+v checks=%+v", result, checks)
	}
}

func providerTestDeps(t *testing.T, now time.Time, receipt providerqualification.Receipt) providerDoctorDependencies {
	t.Helper()
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	return providerDoctorDependencies{
		now:      func() time.Time { return now },
		lookPath: func(string) (string, error) { return "/usr/bin/claude", nil },
		version:  func(context.Context, string) (string, error) { return "2.1.252 (Claude Code)", nil },
		lookupEnv: func(name string) (string, bool) {
			if name == "ZAI_API_KEY" {
				return "present-but-never-serialized", true
			}
			return "", false
		},
		readFile:  func(string) ([]byte, error) { return nil, fs.ErrNotExist },
		stat:      func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist },
		rootOwned: func(os.FileInfo) bool { return false },
		onlineProbe: func(context.Context, config.ProviderProfileConfig, provider.Identity) (providerDoctorLiveEvidence, error) {
			return providerDoctorLiveEvidence{ModelVerified: true, AuthVerified: true, SHA256: providerTestHash("live")}, nil
		},
		qualificationStore: func(_, identity string) (providerqualification.Receipt, string, error) {
			if receipt.IdentitySHA256 == "" || receipt.IdentitySHA256 != identity {
				return providerqualification.Receipt{}, "", fs.ErrNotExist
			}
			return receipt, "/redacted/receipt.json", nil
		},
		capacityStatus: func() ratelimit.CapacityStatus {
			return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared, SharedStorePath: "/redacted/capacity.json"}
		},
		capacitySnapshot: func(identity provider.Identity) ratelimit.AdmissionSnapshot {
			return ratelimit.AdmissionSnapshot{IdentityHash: identity.Hash(), Scope: provider.CapacityControlScopeLocalShared, Tokens: 1}
		},
		attestationPreflight: func(context.Context) (providerattestation.SignatureMetadata, error) {
			return providerattestation.SignatureMetadata{KeyMetadata: providerattestation.KeyMetadata{Algorithm: providerattestation.AlgorithmEd25519, ProtectionEvidence: providerattestation.ProtectionOSProcessRead}}, nil
		},
		admission: admission,
	}
}

func TestProviderDoctorCodexCapacityUsesSubscriptionControllerSnapshot(t *testing.T) {
	root := t.TempDir()
	profile := providerCodexProfile(root)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 2, 15, 0, 0, 0, time.UTC)
	fiveReset, weeklyReset := now.Add(5*time.Hour), now.Add(7*24*time.Hour)
	deps := providerDoctorDependencies{
		now: func() time.Time { return now },
		codexSubscriptionStatus: func() ratelimit.CapacityStatus {
			return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared, SharedStorePath: "/redacted/zai-coding-plan-capacity.json"}
		},
		codexSubscriptionSnapshot: func(got provider.Identity) ratelimit.SubscriptionCapacitySnapshot {
			if got.Hash() != identity.Hash() {
				t.Fatalf("snapshot identity=%s want %s", got.Hash(), identity.Hash())
			}
			return ratelimit.SubscriptionCapacitySnapshot{
				IdentityHash: identity.Hash(), SubscriptionScopeSHA256: strings.Repeat("b", 64),
				Exact:               ratelimit.AdmissionSnapshot{IdentityHash: identity.Hash(), Scope: provider.CapacityControlScopeLocalShared, Tokens: 0.5, Running: 1, ConsecutiveFailures: 2},
				FiveHourCreditsUsed: 1999.5, FiveHourCreditsLimit: 2000, FiveHourResetsAt: &fiveReset,
				WeeklyCreditsUsed: 10000, WeeklyCreditsLimit: 10000, WeeklyResetsAt: &weeklyReset,
				UnknownUsageReserved: true, LimitEvidence: "documented_zai_lite_floor_controller_local_estimate", ResetEvidence: "controller_local_rolling_window_estimate",
			}
		},
	}
	capacity, checks := diagnoseProviderCapacity(identity, deps, nil)
	if capacity.Subscription == nil || capacity.Subscription.ScopeSHA256 != strings.Repeat("b", 64) || capacity.Subscription.FiveHourCreditsUsed != 1999.5 || capacity.Subscription.WeeklyCreditsLimit != 10000 || !capacity.Subscription.UnknownUsageReserved || capacity.Subscription.FiveHourResetsAt == nil || !capacity.Subscription.FiveHourResetsAt.Equal(fiveReset) || capacity.Running != 1 || capacity.Tokens != 0.5 || capacity.ConsecutiveFailures != 2 {
		t.Fatalf("capacity=%+v", capacity)
	}
	if len(checks) != 1 || checks[0].ID != "capacity" || checks[0].Status != providerDoctorPass {
		t.Fatalf("capacity checks=%+v", checks)
	}
	encoded := string(mustJSON(t, capacity))
	for _, forbidden := range []string{"kevin", "api.z.ai", "ntm.zai.coding_plan"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("subscription capacity leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestProviderDoctorNeverDispatchesCodexOnlineProbeOutsideRunLane(t *testing.T) {
	root := t.TempDir()
	profile := providerCodexProfile(root)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	probeCalls := 0
	admission := &providerSessionAdmissionFake{decision: ratelimit.Decision{Allowed: true, NoFailover: true}, status: ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared}}
	deps := providerDoctorDependencies{
		now:      time.Now,
		lookPath: func(string) (string, error) { return profile.Command, nil },
		version:  func(context.Context, string) (string, error) { return "codex-cli 0.149.0", nil },
		lookupEnv: func(string) (string, bool) {
			return "", false
		},
		onlineProbe: func(context.Context, config.ProviderProfileConfig, provider.Identity) (providerDoctorLiveEvidence, error) {
			probeCalls++
			return providerDoctorLiveEvidence{ModelVerified: true, AuthVerified: true}, nil
		},
		qualificationStore: func(string, string) (providerqualification.Receipt, string, error) {
			return providerqualification.Receipt{}, "", fs.ErrNotExist
		},
		codexSubscriptionStatus: func() ratelimit.CapacityStatus {
			return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared, SharedStorePath: filepath.Join(root, "capacity.json")}
		},
		codexSubscriptionSnapshot: func(provider.Identity) ratelimit.SubscriptionCapacitySnapshot {
			return ratelimit.SubscriptionCapacitySnapshot{Exact: ratelimit.AdmissionSnapshot{IdentityHash: identity.Hash(), Scope: provider.CapacityControlScopeLocalShared}}
		},
		codexCredentialStatus: func(context.Context, config.ProviderProfileConfig) (providercredential.Status, error) {
			return providercredential.Status{Available: true, Present: true, Evidence: providercredential.EvidenceOSProtectedProcessReadable}, nil
		},
		codexAttestationPreflight: func(context.Context, config.ProviderProfileConfig) (providerattestation.SignatureMetadata, error) {
			return providerattestation.SignatureMetadata{KeyMetadata: providerattestation.KeyMetadata{Algorithm: providerattestation.AlgorithmEd25519, ProtectionEvidence: providerattestation.ProtectionOSProcessRead}}, nil
		},
		admission: admission,
	}
	report, err := buildProviderDoctorReport(context.Background(), &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-codex": profile}}, providerCommandOptions{profile: "zai-codex", online: true, timeout: time.Second, qualificationAge: time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 || admission.acquires != 0 || report.Readiness != providerReadinessNoGo || checkStatus(report.Checks, "model_entitlement") != providerDoctorFail {
		t.Fatalf("unsafe Codex doctor dispatch: calls=%d admission=%+v report=%+v", probeCalls, admission, report)
	}
}

func TestDiagnoseProviderReceiptAttestationReportsHardwareProtection(t *testing.T) {
	metadata := providerattestation.KeyMetadata{
		Algorithm:          providerattestation.AlgorithmECDSAP256SHA256,
		KeyID:              "ecdsa-p256:" + providerTestHash("public"),
		PublicKey:          "public-verification-material",
		PublicKeySHA256:    providerTestHash("public"),
		ProtectionEvidence: providerattestation.ProtectionHardwareNoExportLocalController,
	}
	check := diagnoseProviderReceiptAttestation(t.Context(), func(context.Context) (providerattestation.SignatureMetadata, error) {
		return providerattestation.SignatureMetadata{KeyMetadata: metadata}, nil
	})
	if check.Status != providerDoctorPass || check.Provenance != "hardware_local_controller" || !strings.Contains(check.Summary, "hardware-backed non-exportable") || check.Evidence != digestSafeJSON(metadata) {
		t.Fatalf("hardware attestation check=%+v", check)
	}
}

func TestProviderDoctorRequiresLiveProbeAndCurrentQualificationButDoesNotPromoteOpaqueZAIRequests(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	receipt := providerTestReceipt(t, identity, now.Add(-time.Hour))
	deps := providerTestDeps(t, now, receipt)
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "zai-qualified", online: true, timeout: time.Minute, qualificationAge: 24 * time.Hour}, deps)
	if err != nil {
		t.Fatalf("buildProviderDoctorReport() error: %v", err)
	}
	if report.Readiness != providerReadinessNoGo || report.Qualification.State != "current_pass" || report.Capacity.CircuitState != "closed" || checkStatus(report.Checks, "request_authority") != providerDoctorFail {
		t.Fatalf("report readiness=%s qualification=%s capacity=%s checks=%#v", report.Readiness, report.Qualification.State, report.Capacity.CircuitState, report.Checks)
	}
	for _, marshaled := range []string{string(mustJSON(t, report)), strings.Join(checkSummaries(report.Checks), " ")} {
		if strings.Contains(marshaled, "present-but-never-serialized") {
			t.Fatal("provider doctor serialized credential material")
		}
	}
}

func TestProviderDoctorBlocksGrokOnlineProbeUntilManagedPolicyIsAuthoritative(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	probeCalls := 0
	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	deps := providerDoctorDependencies{
		now:      func() time.Time { return now },
		lookPath: func(string) (string, error) { return "/usr/bin/grok", nil },
		version:  func(context.Context, string) (string, error) { return "grok 1.0.13", nil },
		lookupEnv: func(string) (string, bool) {
			return "", false
		},
		readFile:  func(string) ([]byte, error) { return nil, fs.ErrNotExist },
		stat:      func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist },
		rootOwned: func(os.FileInfo) bool { return false },
		onlineProbe: func(context.Context, config.ProviderProfileConfig, provider.Identity) (providerDoctorLiveEvidence, error) {
			probeCalls++
			return providerDoctorLiveEvidence{ModelVerified: true, AuthVerified: true, SHA256: providerTestHash("live")}, nil
		},
		capacityStatus: func() ratelimit.CapacityStatus {
			return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared, SharedStorePath: "/redacted/capacity.json"}
		},
		capacitySnapshot: func(provider.Identity) ratelimit.AdmissionSnapshot {
			return ratelimit.AdmissionSnapshot{IdentityHash: identity.Hash(), Scope: provider.CapacityControlScopeLocalShared, Tokens: 1}
		},
		admission: admission,
	}
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"grok-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "grok-qualified", online: true, timeout: time.Minute, qualificationAge: time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 0 || admission.acquires != 0 || report.Readiness != providerReadinessNoGo || checkStatus(report.Checks, "model_entitlement") != providerDoctorFail {
		t.Fatalf("unsafe Grok probe calls=%d admission=%+v readiness=%s checks=%+v", probeCalls, admission, report.Readiness, report.Checks)
	}
}

func TestProviderDoctorCanonicalizesGrokRuntimeBeforeOnlineDispatch(t *testing.T) {
	profile := providerTestGrokProfile(agent.DefaultGrokAutomationPolicyName)
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	requirements, ok := agent.GrokSystemRequirementsForPolicy(profile.AutomationPolicy)
	if !ok {
		t.Fatal("missing compiled requirements")
	}
	newDeps := func(admission *providerSessionAdmissionFake) providerDoctorDependencies {
		return providerDoctorDependencies{
			now:      time.Now,
			lookPath: func(string) (string, error) { return "/replaceable/grok", nil },
			trustExecutable: func(path string) (string, error) {
				if path != "/replaceable/grok" {
					t.Fatalf("unexpected located runtime %q", path)
				}
				return "/system/grok-1.0.13", nil
			},
			version: func(_ context.Context, path string) (string, error) {
				if path != "/system/grok-1.0.13" {
					t.Fatalf("version check re-entered untrusted runtime path %q", path)
				}
				return "grok 1.0.13", nil
			},
			lookupEnv: func(string) (string, bool) { return "", false },
			readFile:  func(string) ([]byte, error) { return []byte(requirements.Contents), nil },
			stat:      func(string) (os.FileInfo, error) { return nil, nil },
			rootOwned: func(os.FileInfo) bool { return true },
			inspectGrok: func(_ context.Context, path, _ string) (providerGrokInspection, error) {
				if path != "/system/grok-1.0.13" {
					t.Fatalf("runtime inspection re-entered untrusted path %q", path)
				}
				return providerTestGrokInspection(), nil
			},
			probeGrokBypassLock: func(_ context.Context, path string) (providerGrokBypassProbe, error) {
				if path != "/system/grok-1.0.13" {
					t.Fatalf("policy probe re-entered untrusted path %q", path)
				}
				return providerTestGrokBypassProbe(), nil
			},
			capacityStatus: func() ratelimit.CapacityStatus {
				return ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared, SharedStorePath: "/redacted/capacity.json"}
			},
			capacitySnapshot: func(provider.Identity) ratelimit.AdmissionSnapshot {
				return ratelimit.AdmissionSnapshot{IdentityHash: identity.Hash(), Scope: provider.CapacityControlScopeLocalShared, Tokens: 1}
			},
			attestationPreflight: func(context.Context) (providerattestation.SignatureMetadata, error) {
				return providerattestation.SignatureMetadata{KeyMetadata: providerattestation.KeyMetadata{Algorithm: providerattestation.AlgorithmEd25519, ProtectionEvidence: providerattestation.ProtectionOSProcessRead}}, nil
			},
			admission: admission,
		}
	}

	admission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	deps := newDeps(admission)
	onlineCalls := 0
	deps.onlineProbe = func(_ context.Context, got config.ProviderProfileConfig, _ provider.Identity) (providerDoctorLiveEvidence, error) {
		onlineCalls++
		if got.Command != "/system/grok-1.0.13" {
			t.Fatalf("online probe received non-canonical runtime %q", got.Command)
		}
		return providerDoctorLiveEvidence{ModelVerified: true, AuthVerified: true, SHA256: providerTestHash("live")}, nil
	}
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"grok-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "grok-qualified", online: true, timeout: time.Minute, qualificationAge: time.Hour}, deps)
	if err != nil || onlineCalls != 1 || report.Readiness != providerReadinessGoScoped {
		t.Fatalf("canonical doctor report=%+v calls=%d err=%v", report, onlineCalls, err)
	}

	blockedAdmission := &providerSessionAdmissionFake{
		decision: ratelimit.Decision{Allowed: true, NoFailover: true},
		status:   ratelimit.CapacityStatus{Scope: provider.CapacityControlScopeLocalShared},
	}
	blocked := newDeps(blockedAdmission)
	blocked.trustExecutable = func(string) (string, error) { return "", errors.New("user-writable runtime") }
	blockedCalls := 0
	blocked.onlineProbe = func(context.Context, config.ProviderProfileConfig, provider.Identity) (providerDoctorLiveEvidence, error) {
		blockedCalls++
		return providerDoctorLiveEvidence{}, nil
	}
	report, err = buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "grok-qualified", online: true, timeout: time.Minute, qualificationAge: time.Hour}, blocked)
	if err != nil || blockedCalls != 0 || blockedAdmission.acquires != 0 || report.Readiness != providerReadinessNoGo || checkStatus(report.Checks, "runtime") != providerDoctorFail {
		t.Fatalf("untrusted runtime was not blocked: report=%+v calls=%d admission=%+v err=%v", report, blockedCalls, blockedAdmission, err)
	}
}

func TestProviderDoctorOnlineProbeUsesExactIdentitySharedAdmission(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, err := profile.Identity()
	if err != nil {
		t.Fatal(err)
	}
	deps := providerTestDeps(t, now, providerTestReceipt(t, identity, now))
	admission := deps.admission.(*providerSessionAdmissionFake)
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "zai-qualified", online: true, timeout: time.Minute, qualificationAge: time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if report.Readiness != providerReadinessNoGo || checkStatus(report.Checks, "request_authority") != providerDoctorFail || admission.acquires != 1 || admission.releases != 1 || admission.successes != 1 {
		t.Fatalf("report=%s admission=%+v", report.Readiness, admission)
	}
}

func TestProviderDoctorOfflineNeverPromotesQualificationToModelEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, _ := profile.Identity()
	deps := providerTestDeps(t, now, providerTestReceipt(t, identity, now))
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "zai-qualified", timeout: time.Minute, qualificationAge: time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if report.Readiness != "NO_GO" || checkStatus(report.Checks, "model_entitlement") != providerDoctorUnavailable {
		t.Fatalf("offline report readiness=%s model=%s", report.Readiness, checkStatus(report.Checks, "model_entitlement"))
	}
}

func TestProviderDoctorFailedOnlineProbeIsNoGo(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, _ := profile.Identity()
	deps := providerTestDeps(t, now, providerTestReceipt(t, identity, now))
	deps.onlineProbe = func(context.Context, config.ProviderProfileConfig, provider.Identity) (providerDoctorLiveEvidence, error) {
		return providerDoctorLiveEvidence{}, errors.New("sensitive provider prose must be hashed")
	}
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "zai-qualified", online: true, timeout: time.Minute, qualificationAge: time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if report.Readiness != "NO_GO" || checkStatus(report.Checks, "model_entitlement") != providerDoctorFail {
		t.Fatalf("failed probe report readiness=%s model=%s", report.Readiness, checkStatus(report.Checks, "model_entitlement"))
	}
	if strings.Contains(string(mustJSON(t, report)), "sensitive provider prose") {
		t.Fatal("doctor serialized raw provider error")
	}
}

func TestProviderDoctorExpiredReceiptIsNoGo(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	profile := providerTestProfile()
	identity, _ := profile.Identity()
	deps := providerTestDeps(t, now, providerTestReceipt(t, identity, now.Add(-25*time.Hour)))
	cfg := &config.Config{ProviderProfiles: map[string]config.ProviderProfileConfig{"zai-qualified": profile}}
	report, err := buildProviderDoctorReport(context.Background(), cfg, providerCommandOptions{profile: "zai-qualified", online: true, timeout: time.Minute, qualificationAge: 24 * time.Hour}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if report.Qualification.State != "expired" || report.Readiness != "NO_GO" {
		t.Fatalf("expired report qualification=%s readiness=%s", report.Qualification.State, report.Readiness)
	}
}

func checkStatus(checks []providerDoctorCheck, id string) providerDoctorStatus {
	for _, check := range checks {
		if check.ID == id {
			return check.Status
		}
	}
	return ""
}

func checkSummaries(checks []providerDoctorCheck) []string {
	values := make([]string, 0, len(checks))
	for _, check := range checks {
		values = append(values, check.Summary+check.Evidence+check.Remediation)
	}
	return values
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := jsonMarshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

var jsonMarshal = func(value any) ([]byte, error) {
	return json.Marshal(value)
}
