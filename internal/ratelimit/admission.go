package ratelimit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sync"
	"time"

	"github.com/Dicklesworthstone/ntm/internal/provider"
)

// ErrorClass is shared with provider conformance so every launch boundary
// applies the same exact Z.ai taxonomy. Only transient categories are retried.
type ErrorClass = provider.ErrorClass

const (
	ErrorRateLimited         = provider.ErrorRateLimited
	ErrorOverloaded          = provider.ErrorOverloaded
	ErrorLongPeriodQuota     = provider.ErrorLongPeriodQuota
	ErrorPlanExpired         = provider.ErrorPlanExpired
	ErrorUnsupportedModel    = provider.ErrorUnsupportedModel
	ErrorUsageRestricted     = provider.ErrorUsageRestricted
	ErrorInsufficientBalance = provider.ErrorInsufficientBalance
	ErrorAuthentication      = provider.ErrorAuthentication
	ErrorIdentityMismatch    = provider.ErrorIdentityMismatch
	ErrorUnknown             = provider.ErrorUnknown
)

// ClassifyProviderError performs exact classification from HTTP status and a
// normalized provider error code. Z.ai business codes are evaluated before an
// HTTP status because a 429 can represent a non-retryable long-period quota or
// account/policy condition. It intentionally does not guess from prose.
func ClassifyProviderError(httpStatus int, code string) ErrorClass {
	return provider.ClassifyProviderError(httpStatus, code)
}

// AdmissionConfig is an identity-local capacity policy. Token refill is
// expressed as tokens per second. MaxConcurrent and TokenCapacity must be
// positive; a zero retry-after uses exponential backoff with full jitter.
type AdmissionConfig struct {
	MaxConcurrent    int
	TokenCapacity    float64
	TokensPerSecond  float64
	BaseBackoff      time.Duration
	MaxBackoff       time.Duration
	CircuitThreshold int
	CircuitOpenFor   time.Duration
	// LeaseTTL bounds an admitted operation in the shared store.  A process
	// that dies before Release cannot permanently consume capacity.
	LeaseTTL time.Duration
}

func DefaultAdmissionConfig() AdmissionConfig {
	return AdmissionConfig{
		MaxConcurrent:    1,
		TokenCapacity:    1,
		TokensPerSecond:  1.0 / 30.0,
		BaseBackoff:      5 * time.Second,
		MaxBackoff:       5 * time.Minute,
		CircuitThreshold: 3,
		CircuitOpenFor:   1 * time.Minute,
		LeaseTTL:         15 * time.Minute,
	}
}

func (c AdmissionConfig) validate() error {
	if c.MaxConcurrent < 1 || c.TokenCapacity <= 0 || c.TokensPerSecond <= 0 {
		return fmt.Errorf("admission capacity values must be positive")
	}
	if c.BaseBackoff <= 0 || c.MaxBackoff < c.BaseBackoff || c.CircuitThreshold < 1 || c.CircuitOpenFor <= 0 || c.LeaseTTL <= 0 {
		return fmt.Errorf("admission backoff and circuit values are invalid")
	}
	return nil
}

// Decision is the complete, non-failover admission result. RetryAt is set for
// a temporary denial; permanent provider errors have RetryAt=nil.
type Decision struct {
	Allowed    bool
	Reason     ErrorClass
	RetryAt    *time.Time
	NoFailover bool
	// leaseID is an opaque, controller-issued capability. Callers cannot forge
	// or serialize it; they must return the exact Decision to Release so
	// concurrent operations for one identity cannot release each other's lease.
	leaseID string
}

type admissionState struct {
	running             int
	tokens              float64
	lastRefill          time.Time
	consecutiveFailures int
	nextRetry           time.Time
	circuitOpenUntil    time.Time
	halfOpenInFlight    bool
	terminalReason      ErrorClass
	leases              map[string]admissionLease
}

// AdmissionController isolates budgets by provider.Identity.CapacityScope.
// It intentionally has no fallback target or provider-selection API.
type AdmissionController struct {
	mu         sync.Mutex
	config     AdmissionConfig
	now        func() time.Time
	rand       func() float64
	states     map[provider.CapacityScope]*admissionState
	shared     *LocalSharedStore
	ownerPID   int32
	ownerID    string
	leaseSeq   uint64
	leaseStops map[string]chan struct{}
	// fallbackReason is populated only after a configured local shared store
	// fails. It makes degraded process-local operation explicit to callers.
	fallbackReason string
}

// NewAdmissionController uses injected clock/random functions when supplied;
// they make retry and circuit behavior deterministic in tests. randFn must
// return a value in [0,1); values outside that range are clamped defensively.
func NewAdmissionController(config AdmissionConfig, now func() time.Time, randFn func() float64) (*AdmissionController, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	if randFn == nil {
		randFn = func() float64 { return 0.5 }
	}
	ownerID, err := newAdmissionOwnerID()
	if err != nil {
		return nil, err
	}
	return &AdmissionController{config: config, now: now, rand: randFn, states: make(map[provider.CapacityScope]*admissionState), ownerPID: int32(os.Getpid()), ownerID: ownerID, leaseStops: make(map[string]chan struct{})}, nil
}

// NewSharedAdmissionController coordinates exact-identity admission state
// across local NTM processes. A store failure remains visible through
// CapacityStatus, but new acquisitions fail closed instead of silently using
// process-local capacity.
func NewSharedAdmissionController(config AdmissionConfig, storePath string, now func() time.Time, randFn func() float64) (*AdmissionController, error) {
	controller, err := NewAdmissionController(config, now, randFn)
	if err != nil {
		return nil, err
	}
	store, err := NewLocalSharedStore(storePath)
	if err != nil {
		return nil, err
	}
	controller.shared = store
	return controller, nil
}

// CapacityStatus is the truth-bearing admission coordination descriptor.
// LocalShared never means fleet-wide capacity control.
type CapacityStatus struct {
	Scope           provider.CapacityControlScope `json:"scope"`
	SharedStorePath string                        `json:"shared_store_path,omitempty"`
	FallbackReason  string                        `json:"fallback_reason,omitempty"`
}

// AdmissionSnapshot is a non-secret observation of one exact provider
// identity's admission state. It deliberately exposes no endpoint, account
// alias, credential, or store contents; callers bind it to Identity.Hash().
type AdmissionSnapshot struct {
	IdentityHash        string                        `json:"identity_hash"`
	Scope               provider.CapacityControlScope `json:"scope"`
	Running             int                           `json:"running"`
	Tokens              float64                       `json:"tokens"`
	ConsecutiveFailures int                           `json:"consecutive_failures"`
	NextRetry           *time.Time                    `json:"next_retry,omitempty"`
	CircuitOpenUntil    *time.Time                    `json:"circuit_open_until,omitempty"`
	TerminalReason      ErrorClass                    `json:"terminal_reason,omitempty"`
	HalfOpenInFlight    bool                          `json:"half_open_in_flight"`
	FallbackReason      string                        `json:"fallback_reason,omitempty"`
}

func (c *AdmissionController) CapacityStatus() CapacityStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shared != nil && c.fallbackReason == "" {
		return CapacityStatus{Scope: provider.CapacityControlScopeLocalShared, SharedStorePath: c.shared.path}
	}
	return CapacityStatus{Scope: provider.CapacityControlScopeProcessLocal, FallbackReason: c.fallbackReason}
}

// Snapshot reads one identity's state without changing token, retry, or
// circuit values. Invalid identities return a reason-coded empty snapshot.
func (c *AdmissionController) Snapshot(identity provider.Identity) AdmissionSnapshot {
	snapshot := AdmissionSnapshot{IdentityHash: identity.Hash(), Scope: c.CapacityStatus().Scope}
	if !validIdentity(identity) {
		snapshot.TerminalReason = ErrorIdentityMismatch
		return snapshot
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	snapshot.Scope = provider.CapacityControlScopeProcessLocal
	snapshot.FallbackReason = c.fallbackReason
	var state admissionState
	if c.shared != nil && c.fallbackReason == "" {
		stored, ok, err := c.shared.snapshot(identity.CapacityScope(), c.now())
		if err == nil {
			snapshot.Scope = provider.CapacityControlScopeLocalShared
			if !ok {
				return snapshot
			}
			state = stored
		} else {
			c.fallbackReason = err.Error()
			snapshot.FallbackReason = c.fallbackReason
			state = admissionState{}
		}
	} else if local := c.states[identity.CapacityScope()]; local != nil {
		state = *local
	}
	snapshot.Running, snapshot.Tokens = state.running, state.tokens
	snapshot.ConsecutiveFailures, snapshot.TerminalReason = state.consecutiveFailures, state.terminalReason
	snapshot.HalfOpenInFlight = state.halfOpenInFlight
	if !state.nextRetry.IsZero() {
		value := state.nextRetry.UTC()
		snapshot.NextRetry = &value
	}
	if !state.circuitOpenUntil.IsZero() {
		value := state.circuitOpenUntil.UTC()
		snapshot.CircuitOpenUntil = &value
	}
	return snapshot
}

func (c *AdmissionController) withState(scope provider.CapacityScope, now time.Time, fn func(*admissionState)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shared != nil && c.fallbackReason == "" {
		if err := c.shared.withState(scope, now, c.config.TokenCapacity, c.config.LeaseTTL, fn); err == nil {
			return
		} else {
			c.fallbackReason = err.Error()
		}
	}
	fn(c.stateLocked(scope, now))
}

// withAcquireState is the dispatch-safe variant of withState. Controllers
// intentionally created without a shared store retain their process-local
// behavior. Once a shared store is configured, however, an unavailable shared
// transaction must never spend local tokens or create a local lease: callers
// use a successful acquisition as authority to contact the exact provider.
func (c *AdmissionController) withAcquireState(scope provider.CapacityScope, now time.Time, fn func(*admissionState)) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shared != nil {
		if c.fallbackReason != "" {
			return false
		}
		if err := c.shared.withState(scope, now, c.config.TokenCapacity, c.config.LeaseTTL, fn); err != nil {
			c.fallbackReason = err.Error()
			return false
		}
		return true
	}
	fn(c.stateLocked(scope, now))
	return true
}

// Acquire consumes one identity-local concurrency slot and token. A successful
// acquire must be paired with Release. This method never retries or selects a
// different identity on the caller's behalf.
func (c *AdmissionController) Acquire(identity provider.Identity) Decision {
	if !validIdentity(identity) {
		return Decision{Reason: ErrorIdentityMismatch, NoFailover: true}
	}
	scope := identity.CapacityScope()
	now := c.now()
	var decision Decision
	var leaseID string
	acquiredState := c.withAcquireState(scope, now, func(state *admissionState) {
		c.reclaimLocalExpiredLeases(state, now)
		c.refillLocked(state, now)
		if state.terminalReason != "" {
			decision = Decision{Reason: state.terminalReason, NoFailover: true}
			return
		}
		if !state.circuitOpenUntil.IsZero() && now.Before(state.circuitOpenUntil) {
			decision = retryDecision(ErrorOverloaded, state.circuitOpenUntil)
			return
		}
		if !state.nextRetry.IsZero() && now.Before(state.nextRetry) {
			decision = retryDecision(ErrorRateLimited, state.nextRetry)
			return
		}
		if !state.circuitOpenUntil.IsZero() && state.halfOpenInFlight {
			decision = retryDecision(ErrorOverloaded, now.Add(c.config.BaseBackoff))
			return
		}
		if state.running >= c.config.MaxConcurrent {
			decision = Decision{Reason: ErrorRateLimited, NoFailover: true}
			return
		}
		if state.tokens < 1 {
			wait := time.Duration(math.Ceil((1 - state.tokens) / c.config.TokensPerSecond * float64(time.Second)))
			decision = retryDecision(ErrorRateLimited, now.Add(wait))
			return
		}
		if !state.circuitOpenUntil.IsZero() {
			state.halfOpenInFlight = true
		}
		leaseID = c.newLeaseID()
		if state.leases == nil {
			state.leases = make(map[string]admissionLease)
		}
		state.leases[leaseID] = admissionLease{OwnerPID: c.ownerPID, OwnerID: c.ownerID, OperationID: leaseID, ExpiresAt: now.Add(c.config.LeaseTTL)}
		state.running = len(state.leases)
		state.tokens--
		decision = Decision{Allowed: true, NoFailover: true, leaseID: leaseID}
	})
	if !acquiredState {
		return Decision{Reason: ErrorUnknown, NoFailover: true}
	}
	if decision.Allowed {
		c.startLeaseRenewal(scope, leaseID)
	}
	return decision
}

// Release returns only the exact concurrency lease represented by decision.
// Tokens represent actual request admission and are deliberately not refunded
// after a process starts. A denied, forged, stale, or cross-controller decision
// is a no-op.
func (c *AdmissionController) Release(identity provider.Identity, decision Decision) {
	if !validIdentity(identity) || !decision.Allowed || decision.leaseID == "" {
		return
	}
	scope := identity.CapacityScope()
	c.withState(scope, c.now(), func(state *admissionState) {
		c.reclaimLocalExpiredLeases(state, c.now())
		lease, ok := state.leases[decision.leaseID]
		if !ok || lease.OwnerID != c.ownerID || lease.OperationID != decision.leaseID {
			return
		}
		if stop := c.leaseStops[decision.leaseID]; stop != nil {
			close(stop)
			delete(c.leaseStops, decision.leaseID)
		}
		delete(state.leases, decision.leaseID)
		state.running = len(state.leases)
	})
}

// RecordResult records the outcome of one acquired request. retryAfter is
// authoritative when supplied for a rate limit; otherwise exponential backoff
// uses full jitter. Permanent failures never create a retry schedule.
func (c *AdmissionController) RecordResult(identity provider.Identity, class ErrorClass, retryAfter time.Duration) Decision {
	if !validIdentity(identity) {
		return Decision{Reason: ErrorIdentityMismatch, NoFailover: true}
	}
	scope := identity.CapacityScope()
	now := c.now()
	var decision Decision
	c.withState(scope, now, func(state *admissionState) {
		if class == "" {
			class = ErrorUnknown
		}
		// Only an explicitly classified rate limit or temporary overload may retry.
		// Long-period quota, plan/balance, policy, model, identity, and auth errors
		// require deliberate operator remediation under the same identity.
		if class != ErrorRateLimited && class != ErrorOverloaded {
			state.terminalReason = class
			state.consecutiveFailures = 0
			state.nextRetry = time.Time{}
			state.circuitOpenUntil = time.Time{}
			state.halfOpenInFlight = false
			decision = Decision{Reason: class, NoFailover: true}
			return
		}

		state.consecutiveFailures++
		state.halfOpenInFlight = false
		if retryAfter > 0 && class == ErrorRateLimited {
			state.nextRetry = now.Add(retryAfter)
		} else {
			state.nextRetry = now.Add(c.jitteredBackoffLocked(state.consecutiveFailures))
		}
		if state.consecutiveFailures >= c.config.CircuitThreshold {
			state.circuitOpenUntil = now.Add(c.config.CircuitOpenFor)
			if state.nextRetry.After(state.circuitOpenUntil) {
				state.circuitOpenUntil = state.nextRetry
			}
		}
		decision = retryDecision(class, state.nextRetry)
	})
	return decision
}

// RecordSuccess closes a half-open circuit and clears transient backoff only
// for this exact identity scope. Permanent provider classifications require an
// explicit Reset so a stray or misattributed success cannot reopen the lane.
func (c *AdmissionController) RecordSuccess(identity provider.Identity) {
	if !validIdentity(identity) {
		return
	}
	c.withState(identity.CapacityScope(), c.now(), func(state *admissionState) {
		state.consecutiveFailures = 0
		state.nextRetry = time.Time{}
		state.circuitOpenUntil = time.Time{}
		state.halfOpenInFlight = false
	})
}

// Reset clears result-driven blocks for one exact identity after an operator
// has remediated its quota, plan, policy, model, or credentials. It never
// releases a running slot or refunds tokens; callers still pair Acquire with
// Release.
func (c *AdmissionController) Reset(identity provider.Identity) {
	if !validIdentity(identity) {
		return
	}
	c.withState(identity.CapacityScope(), c.now(), func(state *admissionState) {
		state.terminalReason = ""
		state.consecutiveFailures = 0
		state.nextRetry = time.Time{}
		state.circuitOpenUntil = time.Time{}
		state.halfOpenInFlight = false
	})
}

func validIdentity(identity provider.Identity) bool {
	// Identity values are normally created by provider.NewIdentity. The zero
	// value remains constructible by callers, so reject it before it can merge
	// unrelated work into the shared "provider:" capacity scope.
	return identity.Hash() != ""
}

func (c *AdmissionController) stateLocked(scope provider.CapacityScope, now time.Time) *admissionState {
	if state := c.states[scope]; state != nil {
		return state
	}
	state := &admissionState{tokens: c.config.TokenCapacity, lastRefill: now, leases: make(map[string]admissionLease)}
	c.states[scope] = state
	return state
}

func newAdmissionOwnerID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate admission owner id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func (c *AdmissionController) newLeaseID() string {
	c.leaseSeq++
	return fmt.Sprintf("%s-%d", c.ownerID, c.leaseSeq)
}

// reclaimLocalExpiredLeases gives process-local operation the same bounded
// lease semantics as the shared store. PID liveness is intentionally a
// shared-store concern; a live controller owns its own in-memory leases.
func (c *AdmissionController) reclaimLocalExpiredLeases(state *admissionState, now time.Time) {
	if state.leases == nil {
		state.leases = make(map[string]admissionLease)
		return
	}
	// Process-local leases are owned by this controller and live until Release.
	// They must not expire merely because a legitimate operation outlasted its
	// original TTL. Cross-process recovery is handled by the shared store,
	// where heartbeats renew active leases and dead owners are reclaimed.
	state.running = len(state.leases)
}

func (c *AdmissionController) startLeaseRenewal(scope provider.CapacityScope, leaseID string) {
	if leaseID == "" {
		return
	}
	interval := c.config.LeaseTTL / 3
	if interval < 10*time.Millisecond {
		interval = 10 * time.Millisecond
	}
	stop := make(chan struct{})
	c.mu.Lock()
	// A controller-owned lease ID is unique. This guard also ensures a future
	// API change cannot accidentally start two renewers for the same lease.
	if _, exists := c.leaseStops[leaseID]; exists {
		c.mu.Unlock()
		return
	}
	c.leaseStops[leaseID] = stop
	shared := c.shared != nil && c.fallbackReason == ""
	c.mu.Unlock()
	if !shared {
		return
	}
	go c.renewLeaseLoop(scope, leaseID, stop, interval)
}

func (c *AdmissionController) renewLeaseLoop(scope provider.CapacityScope, leaseID string, stop <-chan struct{}, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer c.forgetLeaseRenewer(leaseID, stop)
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			if !c.renewLease(scope, leaseID) {
				return
			}
		}
	}
}

func (c *AdmissionController) forgetLeaseRenewer(leaseID string, stop <-chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	current, ok := c.leaseStops[leaseID]
	if ok && (<-chan struct{})(current) == stop {
		delete(c.leaseStops, leaseID)
	}
}

// renewLease extends only a lease still owned by this controller. If shared
// storage is unavailable it leaves the visible process-local fallback in
// place; it never recreates a lease that recovery already reclaimed.
func (c *AdmissionController) renewLease(scope provider.CapacityScope, leaseID string) bool {
	if leaseID == "" {
		return false
	}
	now := c.now()
	renewed := false
	c.withState(scope, now, func(state *admissionState) {
		lease, ok := state.leases[leaseID]
		if !ok || lease.OwnerID != c.ownerID || lease.OwnerPID != c.ownerPID {
			return
		}
		lease.ExpiresAt = now.Add(c.config.LeaseTTL)
		state.leases[leaseID] = lease
		state.running = len(state.leases)
		renewed = true
	})
	return renewed
}

func (c *AdmissionController) refillLocked(state *admissionState, now time.Time) {
	if now.Before(state.lastRefill) {
		return
	}
	state.tokens = math.Min(c.config.TokenCapacity, state.tokens+now.Sub(state.lastRefill).Seconds()*c.config.TokensPerSecond)
	state.lastRefill = now
}

func (c *AdmissionController) jitteredBackoffLocked(failures int) time.Duration {
	capDelay := c.config.BaseBackoff
	for i := 1; i < failures && capDelay < c.config.MaxBackoff; i++ {
		if capDelay > c.config.MaxBackoff/2 {
			capDelay = c.config.MaxBackoff
			break
		}
		capDelay *= 2
	}
	r := c.rand()
	if r < 0 {
		r = 0
	} else if r >= 1 {
		r = math.Nextafter(1, 0)
	}
	return time.Duration(r * float64(capDelay))
}

func retryDecision(reason ErrorClass, retryAt time.Time) Decision {
	retryAt = retryAt.UTC()
	return Decision{Reason: reason, RetryAt: &retryAt, NoFailover: true}
}
