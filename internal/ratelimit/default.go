package ratelimit

import (
	"os"
	"path/filepath"
	"sync"
)

var (
	defaultAdmissionOnce sync.Once
	defaultAdmission     *AdmissionController
)

// DefaultAdmissionController is the process-wide provider admission boundary.
// State remains isolated by the complete provider identity tuple; callers must
// not create a fresh controller per request because that would reset tokens,
// backoff, and circuit state.
func DefaultAdmissionController() *AdmissionController {
	defaultAdmissionOnce.Do(func() {
		storePath := defaultSharedAdmissionStorePath()
		controller, err := NewSharedAdmissionController(DefaultAdmissionConfig(), storePath, nil, nil)
		if err != nil {
			sharedErr := err
			// The fallback remains visible through CapacityStatus. Do not panic:
			// NTM can still operate safely with an explicit local-only receipt.
			controller, err = NewAdmissionController(DefaultAdmissionConfig(), nil, nil)
			if err != nil {
				panic(err)
			}
			controller.fallbackReason = "shared admission store unavailable: " + sharedErr.Error()
		}
		defaultAdmission = controller
	})
	return defaultAdmission
}

func defaultSharedAdmissionStorePath() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, "ntm", "provider-capacity.json")
}
