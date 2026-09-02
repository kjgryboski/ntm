package adapters

import (
	"context"
	"errors"
	"testing"
)

type fakeCAAMQuotaRunner struct {
	available bool
	payload   string
	err       error
}

func (r *fakeCAAMQuotaRunner) Available(context.Context) bool { return r.available }

func (r *fakeCAAMQuotaRunner) Limits(context.Context) ([]byte, error) {
	return []byte(r.payload), r.err
}

func TestCAAMQuotaAdapterNormalizesProfiles(t *testing.T) {
	runner := &fakeCAAMQuotaRunner{
		available: true,
		payload: `[
  {"provider":"codex","profile_name":"codex-one","usage":{"primary_window":{"utilization":0.76,"used_percent":76,"resets_at":"2026-09-07T14:29:04Z"}}},
  {"provider":"codex","profile_name":"codex-two","usage":{"primary_window":{"used_percent":97}}},
  {"provider":"claude","profile_name":"claude-one","usage":{"error":"unauthorized: token expired or invalid"}}
]`,
	}
	adapter := newCAAMQuotaAdapterWithRunner(runner)
	batch, err := adapter.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !adapter.Available(context.Background()) {
		t.Fatal("Available() = false, want true")
	}
	if batch.Quota == nil || !batch.Quota.Available {
		t.Fatalf("quota = %#v, want available", batch.Quota)
	}
	if got := len(batch.Quota.Accounts); got != 3 {
		t.Fatalf("account count = %d, want 3", got)
	}
	if got := *batch.Quota.Accounts[0].UsagePercent; got != 76 {
		t.Fatalf("first usage = %v, want 76", got)
	}
	if got := batch.Quota.Accounts[0].ResetAt; got != "2026-09-07T14:29:04Z" {
		t.Fatalf("first reset = %q", got)
	}
	if got := batch.Quota.Accounts[1].Status; got != "critical" {
		t.Fatalf("second status = %q, want critical", got)
	}
	if got := batch.Quota.Accounts[2].ReasonCode; got != ReasonQuotaUnavailable {
		t.Fatalf("third reason = %q, want %q", got, ReasonQuotaUnavailable)
	}
	if batch.Quota.Accounts[2].UsagePercent != nil {
		t.Fatalf("expired account usage = %v, want nil", batch.Quota.Accounts[2].UsagePercent)
	}
	if got := batch.Quota.Summary.TotalAccounts; got != 3 {
		t.Fatalf("summary total = %d, want 3", got)
	}
}

func TestCAAMQuotaAdapterUsesUtilizationFallbackAndClamps(t *testing.T) {
	runner := &fakeCAAMQuotaRunner{
		available: true,
		payload:   `[{"provider":"codex","profile_name":"one","usage":{"primary_window":{"utilization":1.5}}}]`,
	}
	batch, err := newCAAMQuotaAdapterWithRunner(runner).Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if got := *batch.Quota.Accounts[0].UsagePercent; got != 100 {
		t.Fatalf("usage = %v, want 100", got)
	}
	if got := batch.Quota.Accounts[0].Status; got != "exceeded" {
		t.Fatalf("status = %q, want exceeded", got)
	}
}

func TestCAAMQuotaAdapterFailsClosedOnCommandError(t *testing.T) {
	wantErr := errors.New("provider unavailable")
	runner := &fakeCAAMQuotaRunner{available: true, err: wantErr}
	adapter := newCAAMQuotaAdapterWithRunner(runner)
	batch, err := adapter.Collect(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Collect() error = %v, want %v", err, wantErr)
	}
	if batch.Quota.Available {
		t.Fatal("quota available after command error")
	}
	if adapter.LastError() == nil {
		t.Fatal("LastError() = nil")
	}
}

func TestCAAMQuotaAdapterRejectsEmptyAndMalformedPayloads(t *testing.T) {
	for name, payload := range map[string]string{
		"empty":     `[]`,
		"malformed": `{`,
	} {
		t.Run(name, func(t *testing.T) {
			runner := &fakeCAAMQuotaRunner{available: true, payload: payload}
			batch, err := newCAAMQuotaAdapterWithRunner(runner).Collect(context.Background())
			if err == nil {
				t.Fatal("Collect() error = nil")
			}
			if batch.Quota.Available {
				t.Fatal("quota available for invalid payload")
			}
		})
	}
}
