package cli

import (
	"time"
)

// Closed reasons contain no runtime output, arguments, paths or credentials.
type providerEnvironmentError struct{ reason string }

func (e *providerEnvironmentError) Error() string {
	return "provider environment prerequisite failed: " + e.reason
}

// Compare wall time with Go's monotonic elapsed time immediately before spending
// an experiment attempt. A clock step invalidates earlier freshness checks.
func checkProviderDispatchClock(started time.Time) error {
	now := time.Now()
	return validateProviderDispatchClock(started.Round(0), now.Round(0), now.Sub(started))
}

func validateProviderDispatchClock(started, now time.Time, elapsed time.Duration) error {
	drift := now.Sub(started) - elapsed
	if started.IsZero() || now.IsZero() || elapsed < 0 || drift < -2*time.Second || drift > 2*time.Second {
		return &providerEnvironmentError{reason: "clock_changed"}
	}
	return nil
}
