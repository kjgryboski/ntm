package zai

// Structured Codex Responses execution. This file deliberately retains only
// hashes, counts, and reason-coded state from provider output. Prompts,
// transcripts, commands, paths, and bearer tokens never enter a receipt.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
	"github.com/Dicklesworthstone/ntm/internal/providerattestation"
	"github.com/Dicklesworthstone/ntm/internal/providercredential"
	"github.com/Dicklesworthstone/ntm/internal/providerqualification"
)

const (
	CodexRuntimeAdapterVersion = "zai-codex-exec-json-v1"
	defaultCodexOutputLimit    = 1 << 20
)

// CodexRunSpec is an execve-style, secret-free structured invocation. Env is
// filtered through an allowlist; API-key variables are always discarded.
type CodexRunSpec struct {
	Binary                        string
	BrokerCommand                 string
	CredentialBridgeCommand       string
	RuntimeHome                   string
	CWD                           string
	Prompt                        string
	ExpectedNonce                 string
	RequestedModel                string
	ParentSession                 string
	ConfigSHA256                  string
	BinarySHA256                  string
	BrokerCommandSHA256           string
	CredentialBridgeCommandSHA256 string
	PolicySHA256                  string
	RuntimeVersion                string
	WorkspaceWrite                bool
	Resume                        bool
	// ExpectedToolCommand is an optional qualification-only command. Its text
	// is never retained: the receipt records only its digest and whether the
	// exact structured command event completed with a non-zero exit status.
	ExpectedToolCommand string
	// ExpectedFileChange is an optional qualification-only workspace-relative
	// path. The receipt retains only its digest and whether one completed
	// file_change event named that exact path.
	ExpectedFileChange string
	// ManifestVerifier re-attests the exact CAAM config/catalog/descriptor and
	// executable pins at the last responsible moment before credential release
	// and again after execution. It closes the broad preflight-to-exec drift
	// window; callers must bind it to the same expectation as this run.
	ManifestVerifier func(context.Context) error
	// SessionObserver exposes the validated in-memory session id to a lifecycle
	// controller (for cancellation/resume qualification) without serializing it
	// into a receipt.
	SessionObserver  func(string)
	Runner           providerqualification.Runner
	CredentialBroker CodexCredentialBroker
	Env              []string
	OutputLimit      int
}

type CodexBrokerRequest struct {
	Command     string
	RuntimeHome string
	Env         []string
}

// CodexCredentialStatus queries the exact OS bridge without retrieving token
// material. Both the executable digest and nonce are checked before any status
// is accepted as evidence for this Coding Plan lane.
func CodexCredentialStatus(ctx context.Context, bridgeCommand, bridgeSHA256, credentialID string) (providercredential.Status, error) {
	var empty providercredential.Status
	if ctx == nil || strings.TrimSpace(credentialID) == "" || !filepath.IsAbs(bridgeCommand) || !validManifestDigest(bridgeSHA256) {
		return empty, errors.New("invalid Z.ai Codex credential status request")
	}
	if err := verifyCodexExecutablePin("credential bridge", bridgeCommand, bridgeSHA256); err != nil {
		return empty, err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return empty, errors.New("generate Z.ai Codex credential status nonce")
	}
	nonce := hex.EncodeToString(nonceBytes)
	input, err := json.Marshal(providerattestation.BridgeRequest{Operation: providerattestation.BridgeOperationCredentialStatus, CredentialID: credentialID, Nonce: nonce})
	if err != nil {
		return empty, errors.New("encode Z.ai Codex credential status request")
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(cctx, bridgeCommand)
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	output := &codexCappedBuffer{limit: 16 << 10}
	command.Stdout = output
	if err := command.Run(); err != nil || output.exceeded {
		return empty, errors.New("Z.ai Codex credential status bridge failed")
	}
	defer zeroCodexBytes(output.Bytes())
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	var response providerattestation.BridgeResponse
	if err := decoder.Decode(&response); err != nil {
		return empty, errors.New("invalid Z.ai Codex credential status response")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) || response.Error != "" || response.Nonce != nonce || response.Status == nil || response.Credential != "" || response.Metadata != nil || response.Signature != nil {
		return empty, errors.New("invalid Z.ai Codex credential status response")
	}
	if err := verifyCodexExecutablePin("credential bridge", bridgeCommand, bridgeSHA256); err != nil {
		return empty, err
	}
	return *response.Status, nil
}

// CodexCredentialBroker retrieves one profile-bound Coding Plan token. The
// token exists only long enough to construct the child environment and is
// zeroed immediately after the runner returns.
type CodexCredentialBroker interface {
	Credential(context.Context, CodexBrokerRequest) ([]byte, error)
}

type CodexCredentialBrokerFunc func(context.Context, CodexBrokerRequest) ([]byte, error)

func (f CodexCredentialBrokerFunc) Credential(ctx context.Context, request CodexBrokerRequest) ([]byte, error) {
	return f(ctx, request)
}

type LocalCodexCredentialBroker struct{}

type CodexUsage struct {
	InputTokens       int64 `json:"input_tokens"`
	CachedInputTokens int64 `json:"cached_input_tokens"`
	OutputTokens      int64 `json:"output_tokens"`
	TotalTokens       int64 `json:"total_tokens"`
}

type CodexCancellationReceipt struct {
	ProviderAcknowledged bool      `json:"provider_acknowledged"`
	LocalTermination     string    `json:"local_termination"`
	ResidualProcessIDs   []int     `json:"residual_process_ids"`
	ObservedAt           time.Time `json:"observed_at"`
}

// CodexRunReceipt is safe to persist and sign. ResolvedModel is populated only
// from a versioned structured event field, never from the requested config.
type CodexRunReceipt struct {
	AdapterVersion         string `json:"adapter_version"`
	Action                 string `json:"action"`
	RequestedModel         string `json:"requested_model"`
	ResolvedModel          string `json:"resolved_model"`
	ModelEvidence          string `json:"model_evidence"`
	ConfigSHA256           string `json:"config_sha256"`
	BinarySHA256           string `json:"binary_sha256"`
	BrokerCommandSHA256    string `json:"broker_command_sha256"`
	CredentialBridgeSHA256 string `json:"credential_bridge_sha256"`
	PolicySHA256           string `json:"policy_sha256"`
	RuntimeVersion         string `json:"runtime_version"`
	CWDSHA256              string `json:"cwd_sha256"`
	PromptSHA256           string `json:"prompt_sha256"`
	SessionIDSHA256        string `json:"session_id_sha256"`
	ParentSessionSHA256    string `json:"parent_session_sha256,omitempty"`
	NonceSHA256            string `json:"nonce_sha256"`
	OutputSHA256           string `json:"output_sha256"`
	EventStreamSHA256      string `json:"event_stream_sha256"`
	StderrSHA256           string `json:"stderr_sha256"`
	ToolEventsSHA256       string `json:"tool_events_sha256"`
	ToolEventCount         int    `json:"tool_event_count"`
	ExpectedToolSHA256     string `json:"expected_tool_sha256,omitempty"`
	ExpectedToolObserved   bool   `json:"expected_tool_observed"`
	ExpectedToolDenied     bool   `json:"expected_tool_denied"`
	ExpectedFileSHA256     string `json:"expected_file_sha256,omitempty"`
	ExpectedFileObserved   bool   `json:"expected_file_observed"`
	// ProviderHTTPStatus and ProviderErrorCode are captured only from
	// structured terminal error frames. They deliberately exclude provider
	// prose, which may contain sensitive or unbounded data.
	ProviderHTTPStatus  int                 `json:"provider_http_status,omitempty"`
	ProviderErrorCode   string              `json:"provider_error_code,omitempty"`
	ProviderErrorClass  provider.ErrorClass `json:"provider_error_class,omitempty"`
	Usage               CodexUsage          `json:"usage"`
	ExitCode            int                 `json:"exit_code"`
	StopReason          string              `json:"stop_reason"`
	ProviderStarted     bool                `json:"provider_started"`
	ProcessStarted      bool                `json:"process_started"`
	OutcomeKnown        bool                `json:"outcome_known"`
	CompletionConfirmed bool                `json:"completion_confirmed"`
	NonceVerified       bool                `json:"nonce_verified"`
	ModelVerified       bool                `json:"model_verified"`
	LineageVerified     bool                `json:"lineage_verified"`
	// ZeroResiduals is scoped to the continuously observed local process tree;
	// it is not a claim about provider-side work or an unobserved escaped PID.
	ZeroResiduals            bool                              `json:"zero_residuals"`
	Cancellation             CodexCancellationReceipt          `json:"cancellation"`
	RuntimeEvents            []provider.RuntimeEvent           `json:"runtime_events"`
	RuntimeEventRequirements provider.RuntimeEventRequirements `json:"runtime_event_requirements"`
	RuntimeEventContract     provider.EventContractReport      `json:"runtime_event_contract"`
	StartedAt                time.Time                         `json:"started_at"`
	CompletedAt              time.Time                         `json:"completed_at"`
}

func RunCodexStructured(ctx context.Context, spec CodexRunSpec) (CodexRunReceipt, error) {
	receipt := newCodexRunReceipt(spec)
	if err := validateCodexRunSpec(ctx, spec); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, err
	}
	if err := validateCodexAuthBoundary(spec.RuntimeHome); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, err
	}
	if err := verifyCodexExecutablePins(spec); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, err
	}
	if err := spec.ManifestVerifier(ctx); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, errors.New("Codex manifest changed before credential release")
	}
	broker := spec.CredentialBroker
	if broker == nil {
		broker = LocalCodexCredentialBroker{}
	}
	brokerEnv := append([]string(nil), spec.Env...)
	brokerEnv = append(brokerEnv, "NTM_WINDOWS_PROVIDER_BRIDGE="+spec.CredentialBridgeCommand)
	credential, err := broker.Credential(ctx, CodexBrokerRequest{Command: spec.BrokerCommand, RuntimeHome: spec.RuntimeHome, Env: brokerEnv})
	if err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, err
	}
	defer zeroCodexBytes(credential)
	if err := verifyCodexExecutablePins(spec); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, err
	}
	if err := spec.ManifestVerifier(ctx); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, errors.New("Codex manifest changed before process launch")
	}
	runner := spec.Runner
	if runner == nil {
		runner = providerqualification.LocalRunner{}
	}
	limit := spec.OutputLimit
	if limit <= 0 {
		limit = defaultCodexOutputLimit
	}
	transmitted := strings.TrimSpace(spec.Prompt) + "\n\nWhen finished, return this exact acknowledgement token as the final response and no other final text: " + spec.ExpectedNonce
	outcome, runErr := runner.Run(ctx, providerqualification.Invocation{
		Binary:      spec.Binary,
		Args:        codexStructuredArgs(spec),
		Env:         structuredCodexEnvironment(spec.Env, spec.RuntimeHome, credential),
		Dir:         spec.CWD,
		Stdin:       []byte(transmitted),
		OutputLimit: limit,
	})
	receipt.ExitCode = outcome.ExitCode
	receipt.ProcessStarted = outcome.ProcessStarted
	receipt.EventStreamSHA256 = digestCodex(outcome.Stdout)
	receipt.StderrSHA256 = digestCodex(outcome.Stderr)
	receipt.Cancellation = codexCancellationReceipt(ctx, outcome)
	receipt.ZeroResiduals = outcome.ResidualCheckPerformed && outcome.ProcessTreeTerminated && len(outcome.ResidualProcessIDs) == 0
	if err := validateCodexAuthBoundary(spec.RuntimeHome); err != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, errors.New("Codex auth boundary changed during execution")
	}
	if outcome.OutputTruncated {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, errors.New("structured Codex event stream was truncated")
	}
	postCtx, postCancel := context.WithTimeout(context.Background(), 5*time.Second)
	postManifestErr := spec.ManifestVerifier(postCtx)
	postCancel()
	if postManifestErr != nil {
		receipt.CompletedAt = time.Now().UTC()
		return receipt, errors.New("Codex manifest changed during execution")
	}
	parsed, parseErr := parseCodexEvents(outcome.Stdout, spec.ExpectedNonce, spec.ParentSession, spec.Resume, spec.ExpectedToolCommand, spec.ExpectedFileChange)
	applyCodexParsed(&receipt, parsed, spec)
	if parsed.sessionID != "" && spec.SessionObserver != nil {
		spec.SessionObserver(parsed.sessionID)
	}
	receipt.CompletedAt = time.Now().UTC()
	if parseErr != nil {
		return receipt, parseErr
	}
	if runErr != nil {
		return receipt, runErr
	}
	if !receipt.CompletionConfirmed || !receipt.NonceVerified || !receipt.ModelVerified || receipt.SessionIDSHA256 == "" || (spec.Resume && !receipt.LineageVerified) || (spec.ExpectedToolCommand != "" && (!receipt.ExpectedToolObserved || !receipt.ExpectedToolDenied)) || (spec.ExpectedFileChange != "" && !receipt.ExpectedFileObserved) {
		return receipt, errors.New("structured Codex receipt is incomplete")
	}
	return receipt, nil
}

func newCodexRunReceipt(spec CodexRunSpec) CodexRunReceipt {
	action := "start"
	if spec.Resume {
		action = "resume"
	}
	receipt := CodexRunReceipt{
		AdapterVersion:         CodexRuntimeAdapterVersion,
		Action:                 action,
		RequestedModel:         strings.TrimSpace(spec.RequestedModel),
		ConfigSHA256:           strings.TrimSpace(spec.ConfigSHA256),
		BinarySHA256:           strings.TrimSpace(spec.BinarySHA256),
		BrokerCommandSHA256:    strings.TrimSpace(spec.BrokerCommandSHA256),
		CredentialBridgeSHA256: strings.TrimSpace(spec.CredentialBridgeCommandSHA256),
		PolicySHA256:           strings.TrimSpace(spec.PolicySHA256),
		RuntimeVersion:         strings.TrimSpace(spec.RuntimeVersion),
		CWDSHA256:              digestCodex([]byte(filepath.Clean(spec.CWD))),
		PromptSHA256:           digestCodex([]byte(strings.TrimSpace(spec.Prompt))),
		NonceSHA256:            digestCodex([]byte(spec.ExpectedNonce)),
		OutputSHA256:           digestCodex(nil),
		ToolEventsSHA256:       digestCodex(nil),
		Cancellation: CodexCancellationReceipt{
			LocalTermination:   "not_started",
			ResidualProcessIDs: []int{},
			ObservedAt:         time.Now().UTC(),
		},
		StartedAt: time.Now().UTC(),
	}
	if spec.ExpectedToolCommand != "" {
		receipt.ExpectedToolSHA256 = digestCodex([]byte(spec.ExpectedToolCommand))
	}
	if spec.ExpectedFileChange != "" {
		receipt.ExpectedFileSHA256 = digestCodex([]byte(spec.ExpectedFileChange))
	}
	return receipt
}

func validateCodexRunSpec(ctx context.Context, spec CodexRunSpec) error {
	if ctx == nil {
		return errors.New("structured Codex run requires a context")
	}
	for name, value := range map[string]string{"binary": spec.Binary, "broker_command": spec.BrokerCommand, "credential_bridge_command": spec.CredentialBridgeCommand, "runtime_home": spec.RuntimeHome, "cwd": spec.CWD} {
		if !filepath.IsAbs(value) || strings.TrimSpace(value) != value || hasControl(value) {
			return fmt.Errorf("structured Codex %s must be an absolute literal path", name)
		}
	}
	if strings.TrimSpace(spec.Prompt) == "" || strings.TrimSpace(spec.ExpectedNonce) == "" || strings.TrimSpace(spec.RequestedModel) == "" {
		return errors.New("structured Codex run requires prompt, nonce, and requested model")
	}
	if spec.ExpectedToolCommand != "" && (strings.TrimSpace(spec.ExpectedToolCommand) != spec.ExpectedToolCommand || hasControl(spec.ExpectedToolCommand) || len(spec.ExpectedToolCommand) > 4096) {
		return errors.New("structured Codex expected tool command is invalid")
	}
	if spec.ExpectedFileChange != "" && (!validCodexRelativePath(spec.ExpectedFileChange) || len(spec.ExpectedFileChange) > 4096) {
		return errors.New("structured Codex expected file change is invalid")
	}
	if spec.ManifestVerifier == nil {
		return errors.New("structured Codex run requires a manifest verifier")
	}
	for name, value := range map[string]string{"binary": spec.BinarySHA256, "broker": spec.BrokerCommandSHA256, "credential_bridge": spec.CredentialBridgeCommandSHA256} {
		if !validManifestDigest(value) {
			return fmt.Errorf("structured Codex %s SHA-256 pin is invalid", name)
		}
	}
	if spec.Resume && !validCodexSessionID(spec.ParentSession) {
		return errors.New("structured Codex resume requires an exact parent session")
	}
	if !spec.Resume && strings.TrimSpace(spec.ParentSession) != "" {
		return errors.New("structured Codex start must not name a parent session")
	}
	return nil
}

func verifyCodexExecutablePins(spec CodexRunSpec) error {
	for _, item := range []struct {
		name, path, expected string
	}{
		{name: "runtime", path: spec.Binary, expected: spec.BinarySHA256},
		{name: "credential broker", path: spec.BrokerCommand, expected: spec.BrokerCommandSHA256},
		{name: "credential bridge", path: spec.CredentialBridgeCommand, expected: spec.CredentialBridgeCommandSHA256},
	} {
		if err := verifyCodexExecutablePin(item.name, item.path, item.expected); err != nil {
			return err
		}
	}
	return nil
}

func verifyCodexExecutablePin(name, path, expected string) error {
	contents, err := regularExecutable(path)
	if err != nil {
		return fmt.Errorf("structured Codex %s executable is unsafe", name)
	}
	sum := sha256.Sum256(contents)
	if hex.EncodeToString(sum[:]) != expected {
		return fmt.Errorf("structured Codex %s executable digest mismatch", name)
	}
	return nil
}

func (LocalCodexCredentialBroker) Credential(ctx context.Context, request CodexBrokerRequest) ([]byte, error) {
	if ctx == nil || !filepath.IsAbs(request.Command) || filepath.Base(filepath.Clean(request.RuntimeHome)) != ".codex" {
		return nil, errors.New("invalid Z.ai Codex broker request")
	}
	profileDir := filepath.Dir(filepath.Clean(request.RuntimeHome))
	baseDir := filepath.Dir(profileDir)
	profileName := filepath.Base(profileDir)
	if profileName == "." || profileName == string(filepath.Separator) || baseDir == profileDir {
		return nil, errors.New("invalid Z.ai Codex broker profile boundary")
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(cctx, request.Command, "zai-codex", "broker-token", "--profile", profileName, "--base", baseDir)
	command.Dir = request.RuntimeHome
	command.Env = minimalStructuredCodexEnvironment(request.Env, request.RuntimeHome)
	stdout := &codexCappedBuffer{limit: 16 << 10}
	stderr := &codexCappedBuffer{limit: 16 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil || stdout.exceeded || stderr.exceeded {
		zeroCodexBytes(stdout.Bytes())
		zeroCodexBytes(stderr.Bytes())
		return nil, errors.New("Z.ai Codex OS credential broker failed")
	}
	secret := append([]byte(nil), stdout.Bytes()...)
	zeroCodexBytes(stdout.Bytes())
	zeroCodexBytes(stderr.Bytes())
	if len(secret) < 8 || len(secret) > 16<<10 || len(bytes.TrimSpace(secret)) != len(secret) || bytes.IndexByte(secret, 0) >= 0 {
		zeroCodexBytes(secret)
		return nil, errors.New("Z.ai Codex OS credential broker returned invalid material")
	}
	return secret, nil
}

type codexCappedBuffer struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *codexCappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := b.limit - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.Buffer.Write(p[:remaining])
		} else {
			_, _ = b.Buffer.Write(p)
		}
	}
	if original > remaining {
		b.exceeded = true
	}
	return original, nil
}

func zeroCodexBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func codexStructuredArgs(spec CodexRunSpec) []string {
	permissionProfile := CodexObservePermissionProfile
	if spec.WorkspaceWrite {
		permissionProfile = CodexWorkspaceWritePermissionProfile
	}
	args := []string{"exec", "--strict-config", "--json", "-c", `default_permissions="` + permissionProfile + `"`, "-C", spec.CWD}
	if spec.Resume {
		return append(args, "resume", spec.ParentSession, "-")
	}
	args = append(args, "--model", spec.RequestedModel)
	return append(args, "-")
}

func validCodexSessionID(value string) bool {
	if len(value) != 36 || strings.TrimSpace(value) != value {
		return false
	}
	for index, r := range value {
		switch index {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return false
			}
		}
	}
	return true
}

func minimalStructuredCodexEnvironment(source []string, runtimeHome string) []string {
	if source == nil {
		source = os.Environ()
	}
	allowed := map[string]bool{
		"PATH": true, "HOME": true, "USERPROFILE": true, "SystemRoot": true,
		"WINDIR": true, "TMP": true, "TEMP": true, "TMPDIR": true,
		"LANG": true, "LC_ALL": true, "TERM": true,
		"NTM_WINDOWS_PROVIDER_BRIDGE": true,
	}
	values := map[string]string{}
	for _, item := range source {
		key, value, ok := strings.Cut(item, "=")
		if ok && allowed[key] {
			values[key] = value
		}
	}
	values["CODEX_HOME"] = runtimeHome
	// Z.ai's supported Codex configuration points model_catalog_json at
	// ~/.codex/models.json. Keep HOME at the isolated CAAM profile root while
	// CODEX_HOME names its private .codex directory; neither can resolve the
	// user's ordinary OpenAI Codex home.
	profileHome := filepath.Dir(filepath.Clean(runtimeHome))
	values["HOME"] = profileHome
	values["USERPROFILE"] = profileHome
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+values[key])
	}
	return env
}

func structuredCodexEnvironment(source []string, runtimeHome string, credential []byte) []string {
	minimal := minimalStructuredCodexEnvironment(source, runtimeHome)
	env := make([]string, 0, len(minimal)+1)
	for _, item := range minimal {
		key, _, _ := strings.Cut(item, "=")
		if key != "NTM_WINDOWS_PROVIDER_BRIDGE" {
			env = append(env, item)
		}
	}
	env = append(env, "ZAI_API_KEY="+string(credential))
	sort.Strings(env)
	return env
}

type codexParsed struct {
	sessionID          string
	model              string
	modelEvidence      string
	finalText          string
	toolDigest         string
	toolCount          int
	runtimeToolEvents  []provider.RuntimeEvent
	usage              CodexUsage
	stopReason         string
	providerStarted    bool
	outcomeKnown       bool
	complete           bool
	nonce              bool
	lineage            bool
	turnStarted        bool
	terminal           bool
	agentMessageSeen   bool
	expectedToolSeen   bool
	expectedToolDeny   bool
	expectedFileSeen   bool
	providerHTTPStatus int
	providerErrorCode  string
	itemIDs            map[string]bool
	startedToolIDs     map[string]string
	earlyToolIDs       map[string]string
}

var codexToolItemTypes = map[string]bool{
	"command_execution": true,
	"file_change":       true,
	"mcp_tool_call":     true,
	"web_search":        true,
	"tool_call":         true,
}

func validCodexTerminalToolStatus(itemType, status string, present bool) bool {
	switch itemType {
	case "command_execution":
		return present && (status == "completed" || status == "failed" || status == "declined")
	case "file_change", "mcp_tool_call", "web_search", "tool_call":
		// Preserve the existing narrow lane for every other tool type. The
		// observed compatibility gap is specific to terminal command failures;
		// other capabilities must not broaden implicitly.
		return present && status == "completed"
	default:
		return false
	}
}

func parseCodexEvents(raw []byte, nonce, parent string, resume bool, expectedCommand ...string) (codexParsed, error) {
	parsed := codexParsed{toolDigest: digestCodex(nil), itemIDs: map[string]bool{}, startedToolIDs: map[string]string{}, earlyToolIDs: map[string]string{}}
	wantCommand, wantFile := "", ""
	if len(expectedCommand) > 0 {
		wantCommand = expectedCommand[0]
	}
	if len(expectedCommand) > 1 {
		wantFile = expectedCommand[1]
	}
	toolHasher := sha256.New()
	linesSeen := 0
	for _, rawLine := range bytes.Split(raw, []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		linesSeen++
		if parsed.terminal {
			return parsed, errors.New("Codex emitted events after a terminal turn event")
		}
		var event map[string]json.RawMessage
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.UseNumber()
		if err := decoder.Decode(&event); err != nil {
			return parsed, errors.New("malformed Codex JSON event")
		}
		var extra any
		if err := decoder.Decode(&extra); err == nil {
			return parsed, errors.New("Codex JSON event contains trailing data")
		} else if !errors.Is(err, io.EOF) {
			return parsed, errors.New("Codex JSON event contains malformed trailing data")
		}
		typ, ok := rawJSONString(event["type"])
		if !ok || typ == "" {
			return parsed, errors.New("Codex JSON event has no type")
		}
		if typ != "turn.completed" {
			if err := rejectPrematureCodexServerModel(event, typ); err != nil {
				return parsed, err
			}
		}
		switch typ {
		case "thread.started":
			if linesSeen != 1 {
				return parsed, errors.New("Codex thread.started was not the first event")
			}
			sessionID, ok := rawJSONString(event["thread_id"])
			if !ok || !validCodexSessionID(sessionID) {
				return parsed, errors.New("Codex thread.started has no valid thread id")
			}
			if parsed.sessionID != "" && parsed.sessionID != sessionID {
				return parsed, errors.New("Codex structured events contain conflicting thread ids")
			}
			parsed.sessionID = sessionID
			parsed.providerStarted = true
		case "turn.started":
			if !parsed.providerStarted || parsed.turnStarted {
				return parsed, errors.New("Codex turn.started ordering is invalid")
			}
			parsed.turnStarted = true
		case "item.started":
			if !parsed.turnStarted {
				return parsed, errors.New("Codex item.started preceded turn.started")
			}
			item, err := rawJSONObject(event["item"])
			if err != nil {
				return parsed, errors.New("Codex item.started has no item object")
			}
			itemType, _ := rawJSONString(item["type"])
			itemID, ok := rawJSONString(item["id"])
			if !ok || itemID == "" || hasControl(itemID) || parsed.startedToolIDs[itemID] != "" {
				return parsed, errors.New("Codex item.started has an invalid or duplicate item id")
			}
			if codexToolItemTypes[itemType] {
				toolRef := parsed.earlyToolIDs[itemID]
				if toolRef == "" {
					toolRef = fmt.Sprintf("tool-%06d", len(parsed.startedToolIDs)+1)
				}
				parsed.startedToolIDs[itemID] = toolRef
				parsed.runtimeToolEvents = append(parsed.runtimeToolEvents, provider.RuntimeEvent{Type: provider.EventToolRequested, Tool: toolRef})
			}
		case "item.completed":
			if !parsed.turnStarted {
				return parsed, errors.New("Codex item.completed preceded turn.started")
			}
			item, err := rawJSONObject(event["item"])
			if err != nil {
				return parsed, errors.New("Codex item.completed has no item object")
			}
			itemType, _ := rawJSONString(item["type"])
			itemID, ok := rawJSONString(item["id"])
			if !ok || itemID == "" || hasControl(itemID) || parsed.itemIDs[itemID] {
				return parsed, errors.New("Codex item.completed has an invalid or duplicate item id")
			}
			parsed.itemIDs[itemID] = true
			switch {
			case itemType == "agent_message":
				if parsed.agentMessageSeen {
					return parsed, errors.New("Codex emitted more than one final agent message")
				}
				text, ok := rawJSONString(item["text"])
				if !ok {
					return parsed, errors.New("Codex agent_message has no text")
				}
				parsed.finalText = text
				parsed.nonce = strings.TrimSpace(text) == nonce
				parsed.agentMessageSeen = true
			case codexToolItemTypes[itemType]:
				status, statusPresent := rawJSONString(item["status"])
				if !validCodexTerminalToolStatus(itemType, status, statusPresent) {
					return parsed, errors.New("Codex tool item lacks a valid terminal status")
				}
				if itemType == "command_execution" && wantCommand != "" {
					command, _ := rawJSONString(item["command"])
					if command == wantCommand {
						if parsed.expectedToolSeen {
							return parsed, errors.New("Codex emitted the expected tool command more than once")
						}
						parsed.expectedToolSeen = true
						exitCode, exitPresent, exitErr := signedJSONInt(item["exit_code"])
						if exitErr != nil {
							return parsed, errors.New("Codex expected tool command has inconsistent terminal evidence")
						}
						switch status {
						case "declined":
							if exitPresent {
								return parsed, errors.New("Codex declined expected tool command unexpectedly has an exit status")
							}
							parsed.expectedToolDeny = true
						case "failed":
							if !exitPresent || exitCode == 0 {
								return parsed, errors.New("Codex failed expected tool command lacks a nonzero exit status")
							}
							parsed.expectedToolDeny = true
						case "completed":
							if !exitPresent {
								return parsed, errors.New("Codex completed expected tool command lacks an exit status")
							}
							parsed.expectedToolDeny = exitCode != 0
						}
					}
				}
				if itemType == "file_change" && status == "completed" && wantFile != "" {
					matched, err := codexFileChangeMatches(item["changes"], wantFile)
					if err != nil {
						return parsed, err
					}
					if matched {
						if parsed.expectedFileSeen {
							return parsed, errors.New("Codex emitted the expected file change more than once")
						}
						parsed.expectedFileSeen = true
					}
				}
				_, _ = toolHasher.Write(line)
				_, _ = toolHasher.Write([]byte{'\n'})
				parsed.toolCount++
				toolRef := parsed.startedToolIDs[itemID]
				if toolRef == "" {
					// Keep the observed completion rather than inventing a preceding
					// request. The shared contract will reject this stream.
					toolRef = fmt.Sprintf("unmatched-tool-%06d", parsed.toolCount)
					parsed.earlyToolIDs[itemID] = toolRef
				}
				parsed.runtimeToolEvents = append(parsed.runtimeToolEvents, provider.RuntimeEvent{Type: provider.EventToolCompleted, Tool: toolRef})
			}
		case "turn.completed":
			if parsed.complete || !parsed.turnStarted {
				return parsed, errors.New("Codex emitted duplicate turn.completed events")
			}
			parsed.complete = true
			parsed.terminal = true
			parsed.outcomeKnown = true
			parsed.stopReason = "turn.completed"
			if stop, ok := rawJSONString(event["stop_reason"]); ok && stop != "" {
				parsed.stopReason = stop
			}
			if _, present := event["server_model_conflict"]; present {
				return parsed, errors.New("Codex terminal server_model_conflict is not valid provider evidence")
			}
			if err := recordCodexServerModel(&parsed, event); err != nil {
				return parsed, err
			}
			usage, err := rawJSONObjectOptional(event["usage"])
			if err != nil {
				return parsed, errors.New("Codex turn.completed usage is invalid")
			}
			parsed.usage, err = parseCodexUsage(usage)
			if err != nil {
				return parsed, err
			}
		case "turn.failed", "error":
			if err := recordCodexProviderError(&parsed, event); err != nil {
				return parsed, err
			}
			parsed.outcomeKnown = true
			parsed.terminal = true
			return parsed, errors.New("Codex reported a structured provider failure")
		}
	}
	if linesSeen == 0 {
		return parsed, errors.New("Codex emitted no structured events")
	}
	parsed.toolDigest = hex.EncodeToString(toolHasher.Sum(nil))
	if parsed.sessionID == "" {
		return parsed, errors.New("Codex structured output is missing thread.started")
	}
	if resume {
		parsed.lineage = parsed.sessionID == parent
	}
	if !parsed.complete {
		return parsed, errors.New("Codex structured output is missing turn.completed")
	}
	if !parsed.nonce {
		return parsed, errors.New("Codex final agent message did not exactly echo the nonce")
	}
	if parsed.model == "" || parsed.modelEvidence == "" {
		return parsed, errors.New("Codex structured output lacks resolved-model evidence")
	}
	if resume && !parsed.lineage {
		return parsed, errors.New("Codex resume did not preserve the exact session id")
	}
	return parsed, nil
}

// recordCodexProviderError preserves only structured status/code evidence so
// capacity control can distinguish an entitlement block from a retryable
// outage. It never derives classifications from provider error prose.
func recordCodexProviderError(parsed *codexParsed, event map[string]json.RawMessage) error {
	if parsed == nil {
		return errors.New("Codex provider error parser is unavailable")
	}
	for _, name := range []string{"http_status", "status_code"} {
		if raw, present := event[name]; present {
			status, _, err := signedJSONInt(raw)
			if err != nil || status < 100 || status > 599 {
				return errors.New("Codex provider error has an invalid HTTP status")
			}
			if parsed.providerHTTPStatus != 0 && parsed.providerHTTPStatus != int(status) {
				return errors.New("Codex provider error has conflicting HTTP statuses")
			}
			parsed.providerHTTPStatus = int(status)
		}
	}
	code, present := rawJSONString(event["code"])
	if !present {
		if nested, err := rawJSONObjectOptional(event["error"]); err != nil {
			return errors.New("Codex provider error object is invalid")
		} else if nested != nil {
			code, present = rawJSONString(nested["code"])
		}
	}
	if present {
		code = strings.TrimSpace(code)
		if code == "" || len(code) > 128 || hasControl(code) {
			return errors.New("Codex provider error code is invalid")
		}
		parsed.providerErrorCode = code
	}
	return nil
}

func codexFileChangeMatches(raw json.RawMessage, expected string) (bool, error) {
	var changes []struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if len(raw) == 0 || decoder.Decode(&changes) != nil || len(changes) == 0 {
		return false, errors.New("Codex file_change has invalid changes")
	}
	matched := false
	for _, change := range changes {
		if !validCodexRelativePath(change.Path) || (change.Kind != "add" && change.Kind != "update" && change.Kind != "delete") {
			return false, errors.New("Codex file_change contains an invalid change")
		}
		if filepath.Clean(change.Path) == filepath.Clean(expected) {
			if matched || change.Kind == "delete" {
				return false, errors.New("Codex expected file_change is ambiguous")
			}
			matched = true
		}
	}
	return matched, nil
}

func validCodexRelativePath(value string) bool {
	if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value || filepath.IsAbs(value) || hasControl(value) {
		return false
	}
	clean := filepath.Clean(value)
	return clean != "." && clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

// A provider model is authoritative only when the server attests it on the
// terminal completion event. Requested/configured model fields are deliberately
// ignored: they are inputs to Codex, not evidence of upstream resolution.
func recordCodexServerModel(parsed *codexParsed, event map[string]json.RawMessage) error {
	raw, present := event["server_model"]
	if !present {
		return nil
	}
	model, ok := rawJSONString(raw)
	if !ok || model == "" {
		return errors.New("Codex terminal server_model is invalid")
	}
	if !validCanonicalCodexServerModel(model) {
		return errors.New("Codex terminal server_model is invalid")
	}
	if parsed.model != "" && parsed.model != model {
		return errors.New("Codex structured events contain conflicting server models")
	}
	parsed.model = model
	parsed.modelEvidence = "turn.completed.server_model"
	return nil
}

func validCanonicalCodexServerModel(model string) bool {
	if model != strings.TrimSpace(model) || hasControl(model) {
		return false
	}
	return model == "glm-5.3" || model == "glm-5.3-flash"
}

func rejectPrematureCodexServerModel(event map[string]json.RawMessage, eventType string) error {
	if _, present := event["server_model"]; present {
		return fmt.Errorf("Codex %s emitted server_model before terminal completion", eventType)
	}
	return nil
}

func rawJSONString(value json.RawMessage) (string, bool) {
	if len(value) == 0 {
		return "", false
	}
	var decoded string
	if json.Unmarshal(value, &decoded) != nil {
		return "", false
	}
	return decoded, true
}

func rawJSONObject(value json.RawMessage) (map[string]json.RawMessage, error) {
	if len(value) == 0 {
		return nil, errors.New("object is missing")
	}
	var decoded map[string]json.RawMessage
	if json.Unmarshal(value, &decoded) != nil || decoded == nil {
		return nil, errors.New("value is not an object")
	}
	return decoded, nil
}

func rawJSONObjectOptional(value json.RawMessage) (map[string]json.RawMessage, error) {
	if len(value) == 0 || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
		return map[string]json.RawMessage{}, nil
	}
	return rawJSONObject(value)
}

func parseCodexUsage(raw map[string]json.RawMessage) (CodexUsage, error) {
	usage := CodexUsage{}
	fields := []struct {
		name string
		dest *int64
	}{
		{"input_tokens", &usage.InputTokens},
		{"cached_input_tokens", &usage.CachedInputTokens},
		{"output_tokens", &usage.OutputTokens},
		{"total_tokens", &usage.TotalTokens},
	}
	for _, field := range fields {
		value, ok, err := nonnegativeJSONInt(raw[field.name])
		if err != nil {
			return CodexUsage{}, fmt.Errorf("Codex usage %s is invalid", field.name)
		}
		if ok {
			*field.dest = value
		}
	}
	if usage.TotalTokens == 0 {
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens
	}
	return usage, nil
}

func nonnegativeJSONInt(raw json.RawMessage) (int64, bool, error) {
	if len(raw) == 0 {
		return 0, false, nil
	}
	value, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil || value < 0 {
		return 0, false, errors.New("not a nonnegative integer")
	}
	return value, true, nil
}

func signedJSONInt(raw json.RawMessage) (int64, bool, error) {
	if len(raw) == 0 {
		return 0, false, nil
	}
	value, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil {
		return 0, false, errors.New("not an integer")
	}
	return value, true, nil
}

func applyCodexParsed(receipt *CodexRunReceipt, parsed codexParsed, spec CodexRunSpec) {
	if receipt == nil {
		return
	}
	if parsed.sessionID != "" {
		receipt.SessionIDSHA256 = digestCodex([]byte(parsed.sessionID))
	}
	if spec.Resume {
		receipt.ParentSessionSHA256 = digestCodex([]byte(spec.ParentSession))
	}
	receipt.ResolvedModel = parsed.model
	receipt.ModelEvidence = parsed.modelEvidence
	receipt.ModelVerified = parsed.model != "" && parsed.model == spec.RequestedModel
	receipt.LineageVerified = !spec.Resume || parsed.lineage
	receipt.OutputSHA256 = digestCodex([]byte(parsed.finalText))
	receipt.ToolEventsSHA256 = parsed.toolDigest
	receipt.ToolEventCount = parsed.toolCount
	receipt.ExpectedToolObserved = parsed.expectedToolSeen
	receipt.ExpectedToolDenied = parsed.expectedToolDeny
	receipt.ExpectedFileObserved = parsed.expectedFileSeen
	receipt.ProviderHTTPStatus = parsed.providerHTTPStatus
	receipt.ProviderErrorCode = parsed.providerErrorCode
	if parsed.providerHTTPStatus != 0 || parsed.providerErrorCode != "" {
		receipt.ProviderErrorClass = provider.ClassifyProviderError(parsed.providerHTTPStatus, parsed.providerErrorCode)
	}
	receipt.Usage = parsed.usage
	receipt.StopReason = parsed.stopReason
	receipt.ProviderStarted = parsed.providerStarted
	receipt.OutcomeKnown = parsed.outcomeKnown
	receipt.CompletionConfirmed = parsed.complete
	receipt.NonceVerified = parsed.nonce
	receipt.RuntimeEventRequirements = provider.RuntimeEventRequirements{ToolLifecycle: spec.WorkspaceWrite}
	receipt.RuntimeEvents = provider.NormalizeTerminalRuntimeObservation(provider.TerminalRuntimeObservation{
		SessionRef: receipt.SessionIDSHA256, Model: receipt.ResolvedModel,
		Accepted: receipt.ProviderStarted, ObservedToolEvents: parsed.runtimeToolEvents,
		Completed:     receipt.CompletionConfirmed,
		UsageObserved: receipt.CompletionConfirmed && receipt.Usage.InputTokens+receipt.Usage.CachedInputTokens+receipt.Usage.OutputTokens > 0,
		InputTokens:   receipt.Usage.InputTokens + receipt.Usage.CachedInputTokens, OutputTokens: receipt.Usage.OutputTokens,
		CleanupObserved:   receipt.ProcessStarted && receipt.Cancellation.ResidualProcessIDs != nil,
		ResidualProcesses: len(receipt.Cancellation.ResidualProcessIDs),
	})
	receipt.RuntimeEventContract = provider.ValidateRuntimeEventsForModel(spec.RequestedModel, receipt.RuntimeEvents, receipt.RuntimeEventRequirements)
}

func codexCancellationReceipt(ctx context.Context, outcome providerqualification.Outcome) CodexCancellationReceipt {
	receipt := CodexCancellationReceipt{
		ProviderAcknowledged: false,
		LocalTermination:     "cleanup_not_observed_process_exited",
		ResidualProcessIDs:   append([]int{}, outcome.ResidualProcessIDs...),
		ObservedAt:           time.Now().UTC(),
	}
	if ctx != nil && ctx.Err() != nil {
		switch {
		case outcome.ProcessTreeTerminated && len(outcome.ResidualProcessIDs) == 0:
			receipt.LocalTermination = "observed_tree_terminated_verified"
		case len(outcome.ResidualProcessIDs) > 0:
			receipt.LocalTermination = "residual_processes_detected"
		default:
			receipt.LocalTermination = "termination_unverified"
		}
	}
	return receipt
}

func digestCodex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
