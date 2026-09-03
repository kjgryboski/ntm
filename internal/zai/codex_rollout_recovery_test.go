package zai

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeCodexRecoveryRollout(t *testing.T, mutate func([]map[string]any)) (string, string) {
	t.Helper()
	runtimeHome := filepath.Join(t.TempDir(), ".codex")
	sessions := filepath.Join(runtimeHome, "sessions", "2026", "09", "03")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 3, 16, 53, 49, 0, time.UTC)
	nonce := "NTM_ACK_0123456789abcdef0123456789abcdef"
	lines := []map[string]any{
		{"timestamp": base.Format(time.RFC3339Nano), "ordinal": 0, "type": "session_meta", "payload": map[string]any{"id": codexTestSession, "session_id": codexTestSession, "model_provider": "zai", "originator": "codex_exec", "source": "exec", "cli_version": "0.153.0", "cwd": "/workspace"}},
		{"timestamp": base.Add(time.Second).Format(time.RFC3339Nano), "ordinal": 1, "type": "event_msg", "payload": map[string]any{"type": "task_started", "turn_id": codexTestOtherSession}},
		{"timestamp": base.Add(2 * time.Second).Format(time.RFC3339Nano), "ordinal": 2, "type": "event_msg", "payload": map[string]any{"type": "token_count", "info": map[string]any{"total_token_usage": map[string]any{"input_tokens": 100, "cached_input_tokens": 20, "output_tokens": 5}}}},
		{"timestamp": base.Add(3 * time.Second).Format(time.RFC3339Nano), "ordinal": 3, "type": "event_msg", "payload": map[string]any{"type": "task_complete", "turn_id": codexTestOtherSession, "last_agent_message": nonce, "started_at": base.Add(time.Second).Unix(), "completed_at": base.Add(3 * time.Second).Unix()}},
	}
	if mutate != nil {
		mutate(lines)
	}
	var raw strings.Builder
	for _, line := range lines {
		encoded, err := json.Marshal(line)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(encoded)
		raw.WriteByte('\n')
	}
	path := filepath.Join(sessions, "rollout-test.jsonl")
	if err := os.WriteFile(path, []byte(raw.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, runtimeHome
}

func TestReadCodexRolloutRecoveryEvidence(t *testing.T) {
	path, runtimeHome := writeCodexRecoveryRollout(t, nil)
	evidence, err := ReadCodexRolloutRecoveryEvidence(path, runtimeHome, "0.153.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.Validate(); err != nil {
		t.Fatal(err)
	}
	if evidence.InputTokens != 100 || evidence.CachedTokens != 20 || evidence.OutputTokens != 5 || evidence.SessionSHA256 != digestCodex([]byte(codexTestSession)) || evidence.NonceSHA256 != digestCodex([]byte("NTM_ACK_0123456789abcdef0123456789abcdef")) || evidence.RuntimeVersion != "0.153.0" {
		t.Fatalf("evidence=%+v", evidence)
	}
}

func TestReadCodexRolloutRecoveryEvidenceFailsClosed(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]map[string]any)
	}{
		{name: "wrong_provider", mutate: func(lines []map[string]any) { lines[0]["payload"].(map[string]any)["model_provider"] = "openai" }},
		{name: "wrong_version", mutate: func(lines []map[string]any) { lines[0]["payload"].(map[string]any)["cli_version"] = "0.152.0" }},
		{name: "bad_nonce", mutate: func(lines []map[string]any) { lines[3]["payload"].(map[string]any)["last_agent_message"] = "done" }},
		{name: "regressed_ordinal", mutate: func(lines []map[string]any) { lines[2]["ordinal"] = 1 }},
		{name: "missing_usage", mutate: func(lines []map[string]any) { lines[2]["type"] = "world_state" }},
		{name: "clock_mismatch", mutate: func(lines []map[string]any) {
			lines[3]["timestamp"] = time.Date(2026, 9, 3, 17, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
		}},
		{name: "token_overflow", mutate: func(lines []map[string]any) {
			usage := lines[2]["payload"].(map[string]any)["info"].(map[string]any)["total_token_usage"].(map[string]any)
			usage["input_tokens"], usage["cached_input_tokens"], usage["output_tokens"] = int64(^uint64(0)>>1), int64(^uint64(0)>>1), int64(1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path, runtimeHome := writeCodexRecoveryRollout(t, test.mutate)
			if _, err := ReadCodexRolloutRecoveryEvidence(path, runtimeHome, "0.153.0"); err == nil {
				t.Fatal("malformed rollout was accepted")
			}
		})
	}
}

func TestReadCodexRolloutRecoveryEvidenceRejectsPathOutsideRuntime(t *testing.T) {
	path, _ := writeCodexRecoveryRollout(t, nil)
	otherRuntime := filepath.Join(t.TempDir(), ".codex")
	if err := os.MkdirAll(filepath.Join(otherRuntime, "sessions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCodexRolloutRecoveryEvidence(path, otherRuntime, "0.153.0"); err == nil {
		t.Fatal("rollout outside runtime was accepted")
	}
}
