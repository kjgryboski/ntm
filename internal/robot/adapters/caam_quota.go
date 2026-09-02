package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/tools"
)

const (
	defaultCAAMQuotaOutputLimit = 2 * 1024 * 1024
	defaultCAAMQuotaTimeout     = 15 * time.Second
)

type caamQuotaRunner interface {
	Available(context.Context) bool
	Limits(context.Context) ([]byte, error)
}

type caamQuotaCommand struct {
	binary  string
	timeout time.Duration
}

func (r *caamQuotaCommand) Available(ctx context.Context) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	_, err := exec.LookPath(r.binary)
	return err == nil
}

func (r *caamQuotaCommand) Limits(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = defaultCAAMQuotaTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.binary, "limits", "--format", "json")
	cmd.WaitDelay = time.Second
	stdout := tools.NewLimitedBuffer(defaultCAAMQuotaOutputLimit)
	stderr := tools.NewLimitedBuffer(64 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("caam limits failed: %w", err)
	}
	return append([]byte(nil), stdout.Bytes()...), nil
}

type caamLimitWindow struct {
	Utilization *float64 `json:"utilization"`
	UsedPercent *float64 `json:"used_percent"`
	ResetsAt    string   `json:"resets_at"`
}

type caamLimitUsage struct {
	Provider        string           `json:"provider"`
	ProfileName     string           `json:"profile_name"`
	Error           string           `json:"error"`
	PrimaryWindow   *caamLimitWindow `json:"primary_window"`
	SecondaryWindow *caamLimitWindow `json:"secondary_window"`
}

type caamLimitRecord struct {
	Provider    string         `json:"provider"`
	ProfileName string         `json:"profile_name"`
	Usage       caamLimitUsage `json:"usage"`
}

// CAAMQuotaAdapter turns CAAM's per-profile limit report into NTM's durable
// quota projection. CAAM owns provider authentication and profile isolation;
// NTM only consumes its secret-free JSON surface.
type CAAMQuotaAdapter struct {
	runner  caamQuotaRunner
	lastErr error
}

// NewCAAMQuotaAdapter constructs the live CAAM quota adapter.
func NewCAAMQuotaAdapter() *CAAMQuotaAdapter {
	return &CAAMQuotaAdapter{
		runner: &caamQuotaCommand{
			binary:  "caam",
			timeout: defaultCAAMQuotaTimeout,
		},
	}
}

func newCAAMQuotaAdapterWithRunner(runner caamQuotaRunner) *CAAMQuotaAdapter {
	return &CAAMQuotaAdapter{runner: runner}
}

// Name returns the adapter identifier.
func (a *CAAMQuotaAdapter) Name() string {
	return "caam_quota"
}

// Available reports whether CAAM can be resolved without querying providers.
func (a *CAAMQuotaAdapter) Available(ctx context.Context) bool {
	return a != nil && a.runner != nil && a.runner.Available(ctx)
}

// Collect fetches one bounded, non-interactive CAAM limits snapshot.
func (a *CAAMQuotaAdapter) Collect(ctx context.Context) (*SignalBatch, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now().UTC()
	section := &QuotaSection{Accounts: []AccountQuota{}}
	batch := &SignalBatch{
		Source:      a.Name(),
		CollectedAt: now,
		Quota:       section,
	}
	if a == nil || a.runner == nil {
		return batch, fmt.Errorf("caam quota runner is not configured")
	}

	payload, err := a.runner.Limits(ctx)
	if err != nil {
		section.Reason = "caam limits unavailable"
		a.lastErr = err
		return batch, err
	}
	var records []caamLimitRecord
	if err := json.Unmarshal(payload, &records); err != nil {
		section.Reason = "caam limits returned invalid JSON"
		a.lastErr = fmt.Errorf("decode caam limits: %w", err)
		return batch, a.lastErr
	}
	if len(records) == 0 {
		section.Reason = "caam limits returned no profiles"
		a.lastErr = fmt.Errorf("caam limits returned no profiles")
		return batch, a.lastErr
	}

	for _, record := range records {
		provider := strings.ToLower(strings.TrimSpace(firstNonEmptyQuotaValue(record.Provider, record.Usage.Provider)))
		profile := strings.TrimSpace(firstNonEmptyQuotaValue(record.ProfileName, record.Usage.ProfileName))
		if provider == "" || profile == "" {
			continue
		}

		account := AccountQuota{
			ID:         profile,
			Provider:   provider,
			Status:     "ok",
			ReasonCode: ReasonQuotaOK,
		}
		if strings.TrimSpace(record.Usage.Error) != "" {
			account.Status = "critical"
			account.ReasonCode = ReasonQuotaUnavailable
		} else if usedPercent, resetAt, ok := caamUsedPercent(record.Usage); ok {
			account.UsagePercent = &usedPercent
			account.ResetAt = resetAt
			switch {
			case usedPercent >= 100:
				account.Status = "exceeded"
				account.ReasonCode = ReasonQuotaExceededTokens
			case usedPercent >= 95:
				account.Status = "critical"
				account.ReasonCode = ReasonQuotaCriticalTokens
			case usedPercent >= 80:
				account.Status = "warning"
				account.ReasonCode = ReasonQuotaWarningTokens
			}
		} else {
			account.Status = "warning"
			account.ReasonCode = ReasonQuotaUnavailable
		}
		section.Accounts = append(section.Accounts, account)
	}

	if len(section.Accounts) == 0 {
		section.Reason = "caam limits contained no usable profiles"
		a.lastErr = fmt.Errorf("caam limits contained no usable profiles")
		return batch, a.lastErr
	}
	section.Available = true
	section.Summary = summarizeAccountQuota(section.Accounts)
	a.lastErr = nil
	return batch, nil
}

// LastError returns the most recent collection failure.
func (a *CAAMQuotaAdapter) LastError() error {
	if a == nil {
		return nil
	}
	return a.lastErr
}

func caamUsedPercent(usage caamLimitUsage) (float64, string, bool) {
	var used float64
	var resetAt string
	found := false
	for _, window := range []*caamLimitWindow{usage.PrimaryWindow, usage.SecondaryWindow} {
		if window == nil {
			continue
		}
		candidate, ok := caamWindowUsedPercent(window)
		if !ok {
			continue
		}
		if !found || candidate > used {
			used = candidate
			resetAt = strings.TrimSpace(window.ResetsAt)
			found = true
		}
	}
	return used, resetAt, found
}

func caamWindowUsedPercent(window *caamLimitWindow) (float64, bool) {
	if window == nil {
		return 0, false
	}
	if window.UsedPercent != nil {
		return clampQuotaPercent(*window.UsedPercent), true
	}
	if window.Utilization != nil {
		return clampQuotaPercent(*window.Utilization * 100), true
	}
	return 0, false
}

func clampQuotaPercent(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func summarizeAccountQuota(accounts []AccountQuota) *QuotaSummary {
	summary := &QuotaSummary{TotalAccounts: len(accounts)}
	for _, account := range accounts {
		switch account.Status {
		case "ok":
			summary.HealthyAccounts++
		case "warning", "critical":
			summary.WarningAccounts++
		case "exceeded":
			summary.ExceededAccounts++
		}
		if account.ResetAt != "" && (summary.NextReset == "" || account.ResetAt < summary.NextReset) {
			summary.NextReset = account.ResetAt
		}
	}
	return summary
}

func firstNonEmptyQuotaValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
