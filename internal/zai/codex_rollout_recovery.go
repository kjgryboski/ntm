package zai

// Fail-closed extraction of the small evidence subset needed to recover one
// conservative Coding Plan capacity reservation. This parser never treats a
// configured/requested model as provider identity evidence.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxCodexRecoveryRolloutBytes = 16 << 20

type CodexRolloutRecoveryEvidence struct {
	RolloutSHA256  string
	SessionSHA256  string
	TurnSHA256     string
	NonceSHA256    string
	CWDSHA256      string
	InputTokens    int64
	CachedTokens   int64
	OutputTokens   int64
	CompletedAt    time.Time
	RuntimeVersion string
}

type codexRecoveryRolloutLine struct {
	Timestamp time.Time       `json:"timestamp"`
	Ordinal   int64           `json:"ordinal"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// ReadCodexRolloutRecoveryEvidence accepts only a regular rollout beneath the
// exact isolated runtime's sessions directory and returns hashes plus token
// counts. Agent/user text never leaves this function.
func ReadCodexRolloutRecoveryEvidence(path, runtimeHome, expectedVersion string) (CodexRolloutRecoveryEvidence, error) {
	var evidence CodexRolloutRecoveryEvidence
	if !filepath.IsAbs(path) || !filepath.IsAbs(runtimeHome) || strings.TrimSpace(path) != path || strings.TrimSpace(runtimeHome) != runtimeHome || strings.TrimSpace(expectedVersion) == "" {
		return evidence, errors.New("Codex recovery rollout paths and version must be exact")
	}
	sessionsRoot, err := filepath.EvalSymlinks(filepath.Join(runtimeHome, "sessions"))
	if err != nil {
		return evidence, errors.New("Codex recovery sessions root is unavailable")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return evidence, errors.New("Codex recovery rollout is unavailable")
	}
	relative, err := filepath.Rel(sessionsRoot, resolved)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return evidence, errors.New("Codex recovery rollout is outside the isolated sessions root")
	}
	info, err := os.Lstat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxCodexRecoveryRolloutBytes || strings.ToLower(filepath.Ext(resolved)) != ".jsonl" {
		return evidence, errors.New("Codex recovery rollout is not a bounded regular JSONL file")
	}
	raw, err := os.ReadFile(resolved)
	if err != nil || len(raw) == 0 || len(raw) > maxCodexRecoveryRolloutBytes {
		return evidence, errors.New("read bounded Codex recovery rollout")
	}
	digest := sha256.Sum256(raw)
	evidence.RolloutSHA256 = hex.EncodeToString(digest[:])

	var sessionID, turnID, nonce, cwd string
	var sessionSeen, taskStarted, taskCompleted, usageSeen bool
	var previousTimestamp time.Time
	var lineCount int64
	for _, rawLine := range bytes.Split(raw, []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		if taskCompleted {
			return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery rollout contains data after task completion")
		}
		var envelope codexRecoveryRolloutLine
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&envelope); err != nil || envelope.Ordinal != lineCount || envelope.Timestamp.IsZero() || (!previousTimestamp.IsZero() && envelope.Timestamp.Before(previousTimestamp)) || strings.TrimSpace(envelope.Type) == "" {
			return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery rollout envelope is invalid")
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery rollout line contains trailing data")
		}
		previousTimestamp = envelope.Timestamp
		lineCount++

		switch envelope.Type {
		case "session_meta":
			if sessionSeen || lineCount != 1 {
				return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery session metadata ordering is invalid")
			}
			payload, err := rawJSONObject(envelope.Payload)
			if err != nil {
				return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery session metadata is invalid")
			}
			id, idOK := rawJSONString(payload["id"])
			duplicateID, duplicateOK := rawJSONString(payload["session_id"])
			providerName, providerOK := rawJSONString(payload["model_provider"])
			originator, originatorOK := rawJSONString(payload["originator"])
			source, sourceOK := rawJSONString(payload["source"])
			version, versionOK := rawJSONString(payload["cli_version"])
			cwd, _ = rawJSONString(payload["cwd"])
			if !idOK || !duplicateOK || id != duplicateID || !validCodexSessionID(id) || !providerOK || providerName != "zai" || !originatorOK || originator != "codex_exec" || !sourceOK || source != "exec" || !versionOK || version != expectedVersion || !filepath.IsAbs(cwd) {
				return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery session identity is invalid")
			}
			sessionID, evidence.RuntimeVersion, sessionSeen = id, version, true
		case "event_msg":
			payload, err := rawJSONObject(envelope.Payload)
			if err != nil {
				return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery event payload is invalid")
			}
			eventType, ok := rawJSONString(payload["type"])
			if !ok {
				return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery event type is invalid")
			}
			switch eventType {
			case "task_started":
				observedTurn, ok := rawJSONString(payload["turn_id"])
				if !sessionSeen || taskStarted || !ok || !validCodexSessionID(observedTurn) {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery task start is invalid")
				}
				turnID, taskStarted = observedTurn, true
			case "token_count":
				info, err := rawJSONObject(payload["info"])
				if err != nil {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery token event is invalid")
				}
				usage, err := rawJSONObject(info["total_token_usage"])
				if err != nil {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery total usage is invalid")
				}
				input, inputOK, inputErr := nonnegativeJSONInt(usage["input_tokens"])
				cached, cachedOK, cachedErr := nonnegativeJSONInt(usage["cached_input_tokens"])
				output, outputOK, outputErr := nonnegativeJSONInt(usage["output_tokens"])
				if inputErr != nil || cachedErr != nil || outputErr != nil || !inputOK || !cachedOK || !outputOK || cached > input || !validPositiveCodexRecoveryTokenTotal(input, cached, output) {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery token usage is invalid")
				}
				if usageSeen && (input < evidence.InputTokens || cached < evidence.CachedTokens || output < evidence.OutputTokens) {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery cumulative usage regressed")
				}
				evidence.InputTokens, evidence.CachedTokens, evidence.OutputTokens, usageSeen = input, cached, output, true
			case "task_complete":
				observedTurn, turnOK := rawJSONString(payload["turn_id"])
				final, finalOK := rawJSONString(payload["last_agent_message"])
				started, startedOK, startedErr := nonnegativeJSONInt(payload["started_at"])
				completed, completedOK, completedErr := nonnegativeJSONInt(payload["completed_at"])
				if !taskStarted || !usageSeen || taskCompleted || !turnOK || observedTurn != turnID || !finalOK || !validCodexRecoveryNonce(final) || startedErr != nil || completedErr != nil || !startedOK || !completedOK || completed < started {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery task completion is invalid")
				}
				evidence.CompletedAt = time.Unix(completed, 0).UTC()
				if delta := envelope.Timestamp.Sub(evidence.CompletedAt); delta < -5*time.Second || delta > 5*time.Second {
					return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery completion clocks disagree")
				}
				nonce, taskCompleted = final, true
			}
		}
	}
	if !sessionSeen || !taskStarted || !usageSeen || !taskCompleted || lineCount < 4 {
		return CodexRolloutRecoveryEvidence{}, errors.New("Codex recovery rollout is incomplete")
	}
	evidence.SessionSHA256 = digestCodex([]byte(sessionID))
	evidence.TurnSHA256 = digestCodex([]byte(turnID))
	evidence.NonceSHA256 = digestCodex([]byte(nonce))
	evidence.CWDSHA256 = digestCodex([]byte(filepath.Clean(cwd)))
	return evidence, nil
}

func validCodexRecoveryNonce(value string) bool {
	if len(value) != len("NTM_ACK_")+32 || !strings.HasPrefix(value, "NTM_ACK_") {
		return false
	}
	for _, char := range value[len("NTM_ACK_"):] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func (e CodexRolloutRecoveryEvidence) Validate() error {
	for name, value := range map[string]string{"rollout": e.RolloutSHA256, "session": e.SessionSHA256, "turn": e.TurnSHA256, "nonce": e.NonceSHA256, "cwd": e.CWDSHA256} {
		if !validManifestDigest(value) {
			return fmt.Errorf("Codex recovery %s digest is invalid", name)
		}
	}
	if e.CompletedAt.IsZero() || strings.TrimSpace(e.RuntimeVersion) == "" || !validPositiveCodexRecoveryTokenTotal(e.InputTokens, e.CachedTokens, e.OutputTokens) {
		return errors.New("Codex recovery evidence is incomplete")
	}
	return nil
}

func validPositiveCodexRecoveryTokenTotal(input, cached, output int64) bool {
	if input < 0 || cached < 0 || output < 0 {
		return false
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if input > maxInt64-cached {
		return false
	}
	total := input + cached
	return total <= maxInt64-output && total+output > 0
}
