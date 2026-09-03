package ratelimit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
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
	subscriptionUsage   []subscriptionUsageEvent
}

type subscriptionUsageEvent struct {
	LeaseID    string    `json:"lease_id"`
	ObservedAt time.Time `json:"observed_at"`
	Credits    float64   `json:"credits"`
	Reconciled bool      `json:"reconciled"`
	// Conservative means the request completed with provider token usage but
	// without provider-resolved model evidence. Credits are then charged at
	// the highest supported Coding Plan rate without claiming model identity.
	Conservative bool `json:"conservative,omitempty"`
	// RecoveryAuthorizationSHA256 binds an explicit, signed owner
	// authorization to a legacy unbound accounting repair. It is never model
	// identity or automatic operation-to-usage evidence.
	RecoveryAuthorizationSHA256 string `json:"recovery_authorization_sha256,omitempty"`
	OperationBindingSHA256      string `json:"operation_binding_sha256,omitempty"`
	NonceSHA256                 string `json:"nonce_sha256,omitempty"`
	// Unknown records that a dispatched request could not be reconciled to
	// provider-resolved model and token evidence. Its conservative reservation
	// deliberately prevents additional spend in the same subscription scope.
	Unknown bool `json:"unknown"`
}

// SubscriptionAdmissionConfig applies one exact-identity controller together
// with a separate shared Coding Plan entitlement budget. Window credits are
// consumed at admission, never refunded after dispatch.
type SubscriptionAdmissionConfig struct {
	Exact                AdmissionConfig
	MaxConcurrent        int
	FiveHourCreditLimit  float64
	WeeklyCreditLimit    float64
	AdmissionReservation float64
	FiveHourWindow       time.Duration
	WeeklyWindow         time.Duration
}

func DefaultSubscriptionAdmissionConfig() SubscriptionAdmissionConfig {
	return SubscriptionAdmissionConfig{
		Exact: DefaultAdmissionConfig(), MaxConcurrent: 1,
		FiveHourCreditLimit: 2000, WeeklyCreditLimit: 10000, AdmissionReservation: 0.01,
		FiveHourWindow: 5 * time.Hour, WeeklyWindow: 7 * 24 * time.Hour,
	}
}

func (c SubscriptionAdmissionConfig) validate() error {
	if err := c.Exact.validate(); err != nil {
		return err
	}
	if c.MaxConcurrent < 1 || c.FiveHourCreditLimit <= 0 || c.WeeklyCreditLimit <= 0 || c.AdmissionReservation <= 0 || c.FiveHourWindow <= 0 || c.WeeklyWindow <= 0 {
		return errors.New("subscription admission window values must be positive")
	}
	return nil
}

// SubscriptionDecision is the paired exact-identity and entitlement lease.
// Callers must release the same value; NoFailover is always true because the
// scope cannot choose another provider, account, or billing entitlement.
type SubscriptionDecision struct {
	Allowed    bool
	Reason     ErrorClass
	RetryAt    *time.Time
	NoFailover bool
	exact      Decision
	plan       Decision
}

// SubscriptionCapacitySnapshot exposes non-secret window use/reset evidence.
type SubscriptionCapacitySnapshot struct {
	IdentityHash             string                        `json:"identity_hash"`
	SubscriptionScopeSHA256  string                        `json:"subscription_scope_sha256"`
	Exact                    AdmissionSnapshot             `json:"exact"`
	PlanRunning              int                           `json:"plan_running"`
	PlanMaxConcurrent        int                           `json:"plan_max_concurrent"`
	AdmissionReservation     float64                       `json:"admission_reservation"`
	FiveHourCreditsUsed      float64                       `json:"five_hour_credits_used"`
	FiveHourCreditsLimit     float64                       `json:"five_hour_credits_limit"`
	FiveHourResetsAt         *time.Time                    `json:"five_hour_resets_at,omitempty"`
	WeeklyCreditsUsed        float64                       `json:"weekly_credits_used"`
	WeeklyCreditsLimit       float64                       `json:"weekly_credits_limit"`
	WeeklyResetsAt           *time.Time                    `json:"weekly_resets_at,omitempty"`
	Scope                    provider.CapacityControlScope `json:"scope"`
	FallbackReason           string                        `json:"fallback_reason,omitempty"`
	LimitEvidence            string                        `json:"limit_evidence,omitempty"`
	ResetEvidence            string                        `json:"reset_evidence,omitempty"`
	UnknownUsageReserved     bool                          `json:"unknown_usage_reserved"`
	ConservativeUsage        bool                          `json:"conservative_usage_recorded"`
	LegacyRecoveryAuthorized bool                          `json:"legacy_owner_authorized_recovery"`
}

// TokenUsage contains provider-reported token counts. Callers must pass a
// provider-resolved model to RecordUsage; requested model names are rejected.
type TokenUsage struct {
	InputTokens       int64
	CachedInputTokens int64
	OutputTokens      int64
}

// SubscriptionAdmissionController preserves the existing AdmissionController
// API while requiring a paired plan lease for callers that opt into it.
type SubscriptionAdmissionController struct {
	exact  *AdmissionController
	plan   *AdmissionController
	config SubscriptionAdmissionConfig
}

func NewSubscriptionAdmissionController(config SubscriptionAdmissionConfig, storePath string, now func() time.Time, randFn func() float64) (*SubscriptionAdmissionController, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	var exact, plan *AdmissionController
	var err error
	if storePath != "" {
		exact, err = NewSharedAdmissionController(config.Exact, storePath, now, randFn)
		if err != nil {
			return nil, err
		}
		plan, err = NewSharedAdmissionController(config.Exact, storePath, now, randFn)
		if err != nil {
			return nil, err
		}
	} else {
		exact, err = NewAdmissionController(config.Exact, now, randFn)
		if err != nil {
			return nil, err
		}
		plan, err = NewAdmissionController(config.Exact, now, randFn)
		if err != nil {
			return nil, err
		}
	}
	return &SubscriptionAdmissionController{exact: exact, plan: plan, config: config}, nil
}

func (c *SubscriptionAdmissionController) Acquire(identity provider.Identity) SubscriptionDecision {
	if c == nil || c.exact == nil || c.plan == nil || !validIdentity(identity) || identity.SubscriptionCapacityScope() == "" {
		return SubscriptionDecision{Reason: ErrorIdentityMismatch, NoFailover: true}
	}
	exact := c.exact.Acquire(identity)
	if !exact.Allowed {
		return SubscriptionDecision{Reason: exact.Reason, RetryAt: exact.RetryAt, NoFailover: true}
	}
	plan := c.acquirePlan(identity.SubscriptionCapacityScope())
	if !plan.Allowed {
		c.exact.Release(identity, exact)
		return SubscriptionDecision{Reason: plan.Reason, RetryAt: plan.RetryAt, NoFailover: true}
	}
	return SubscriptionDecision{Allowed: true, NoFailover: true, exact: exact, plan: plan}
}

func (c *SubscriptionAdmissionController) Release(identity provider.Identity, decision SubscriptionDecision) {
	if c == nil || !decision.Allowed || !validIdentity(identity) {
		return
	}
	c.plan.releaseScope(identity.SubscriptionCapacityScope(), decision.plan)
	c.exact.Release(identity, decision.exact)
}

// CapacityStatus reports shared only when both exact and subscription plan
// controllers can coordinate through their local durable store.
func (c *SubscriptionAdmissionController) CapacityStatus() CapacityStatus {
	if c == nil || c.exact == nil || c.plan == nil {
		return CapacityStatus{Scope: provider.CapacityControlScopeProcessLocal, FallbackReason: "subscription admission controller is unavailable"}
	}
	exact, plan := c.exact.CapacityStatus(), c.plan.CapacityStatus()
	if exact.Scope == provider.CapacityControlScopeLocalShared && plan.Scope == provider.CapacityControlScopeLocalShared {
		return exact
	}
	reason := exact.FallbackReason
	if reason == "" {
		reason = plan.FallbackReason
	}
	return CapacityStatus{Scope: provider.CapacityControlScopeProcessLocal, FallbackReason: reason}
}

// RecordSuccess mirrors the existing admission boundary for integrations that
// only need to clear transient controller-local state after a verified run.
func (c *SubscriptionAdmissionController) RecordSuccess(identity provider.Identity) {
	if c == nil || !validIdentity(identity) {
		return
	}
	c.exact.RecordSuccess(identity)
	c.plan.recordSuccessScope(identity.SubscriptionCapacityScope())
}

// BindReservation attaches controller-owned operation and nonce digests
// before provider dispatch. Future recovery can then require an exact link
// instead of relying on a legacy timestamp coincidence.
func (c *SubscriptionAdmissionController) BindReservation(identity provider.Identity, decision SubscriptionDecision, operationBindingSHA256, nonceSHA256 string) error {
	if c == nil || c.plan == nil || !decision.Allowed || !validIdentity(identity) || decision.plan.leaseID == "" || !validSubscriptionEvidenceDigest(operationBindingSHA256) || !validSubscriptionEvidenceDigest(nonceSHA256) {
		return errors.New("invalid subscription reservation binding")
	}
	updated := false
	if !c.plan.withAuthoritativeState(identity.SubscriptionCapacityScope(), c.plan.now(), func(state *admissionState) {
		for index := range state.subscriptionUsage {
			event := &state.subscriptionUsage[index]
			if event.LeaseID != decision.plan.leaseID {
				continue
			}
			if event.Reconciled || event.Unknown || event.OperationBindingSHA256 != "" || event.NonceSHA256 != "" {
				return
			}
			event.OperationBindingSHA256 = operationBindingSHA256
			event.NonceSHA256 = nonceSHA256
			updated = true
			return
		}
	}) {
		return errors.New("shared subscription reservation binding is unavailable")
	}
	if !updated {
		return errors.New("subscription reservation binding was not applied")
	}
	return nil
}

// RecordUsage replaces one small admission reservation with provider-reported
// Coding Plan credit usage. resolvedModel must come from the provider receipt,
// never a configured/requested model. observedAt is retained only as a
// controller-local rolling-window estimate.
func (c *SubscriptionAdmissionController) RecordUsage(identity provider.Identity, decision SubscriptionDecision, resolvedModel string, usage TokenUsage, observedAt time.Time) error {
	credits, err := ZAICodingPlanCredits(resolvedModel, usage, observedAt)
	if err != nil {
		return err
	}
	return c.recordUsageCredits(identity, decision, credits, observedAt, false)
}

// RecordConservativeUsage reconciles a completed request whose token usage is
// provider-reported but whose resolved model is unavailable. It charges the
// larger supported Coding Plan rate and does not establish model identity.
func (c *SubscriptionAdmissionController) RecordConservativeUsage(identity provider.Identity, decision SubscriptionDecision, usage TokenUsage, observedAt time.Time) error {
	if _, valid := positiveTokenUsageTotal(usage); !valid {
		return errors.New("invalid conservative subscription usage")
	}
	full, fullErr := ZAICodingPlanCredits("glm-5.3", usage, observedAt)
	flash, flashErr := ZAICodingPlanCredits("glm-5.3-flash", usage, observedAt)
	if fullErr != nil || flashErr != nil {
		return errors.New("calculate conservative subscription usage")
	}
	return c.recordUsageCredits(identity, decision, math.Max(full, flash), observedAt, true)
}

func (c *SubscriptionAdmissionController) recordUsageCredits(identity provider.Identity, decision SubscriptionDecision, credits float64, observedAt time.Time, conservative bool) error {
	if c == nil || c.plan == nil || !decision.Allowed || !validIdentity(identity) || decision.plan.leaseID == "" || observedAt.IsZero() || math.IsNaN(credits) || math.IsInf(credits, 0) || credits < 0 {
		return errors.New("invalid subscription usage reconciliation")
	}
	scope := identity.SubscriptionCapacityScope()
	updated := false
	if !c.plan.withAuthoritativeState(scope, c.plan.now(), func(state *admissionState) {
		for index := range state.subscriptionUsage {
			event := &state.subscriptionUsage[index]
			if event.LeaseID != decision.plan.leaseID {
				continue
			}
			if event.Reconciled {
				return
			}
			event.Credits, event.ObservedAt, event.Reconciled, event.Conservative = credits, observedAt.UTC(), true, conservative
			updated = true
			return
		}
	}) {
		return errors.New("shared subscription usage reconciliation is unavailable")
	}
	if !updated {
		return errors.New("subscription usage reservation is unavailable or already reconciled")
	}
	return nil
}

// CancelReservation removes the small controller-local credit reservation for
// an admitted operation that is authoritatively known not to have started the
// provider process. Callers must not use it after ProcessStarted becomes true;
// dispatched operations require RecordUsage or RecordUnknownUsage instead.
func (c *SubscriptionAdmissionController) CancelReservation(identity provider.Identity, decision SubscriptionDecision) error {
	if c == nil || c.plan == nil || !decision.Allowed || !validIdentity(identity) || decision.plan.leaseID == "" {
		return errors.New("invalid subscription reservation cancellation")
	}
	scope := identity.SubscriptionCapacityScope()
	removed := false
	if !c.plan.withAuthoritativeState(scope, c.plan.now(), func(state *admissionState) {
		for index := range state.subscriptionUsage {
			event := state.subscriptionUsage[index]
			if event.LeaseID != decision.plan.leaseID || event.Reconciled {
				continue
			}
			state.subscriptionUsage = append(state.subscriptionUsage[:index], state.subscriptionUsage[index+1:]...)
			removed = true
			return
		}
	}) {
		return errors.New("shared subscription reservation cancellation is unavailable")
	}
	if !removed {
		return errors.New("subscription usage reservation is unavailable or already reconciled")
	}
	return nil
}

// RecordUnknownUsage replaces an admission reservation after a request was
// dispatched but cannot be authoritatively reconciled. It reserves the full
// documented weekly limit for that exact subscription scope. This deliberately
// fails closed: a later operation cannot spend the plan on the strength of the
// tiny normal admission reservation alone. The rolling window is explicit in
// Snapshot, so this is a conservative local estimate rather than a claim about
// the provider's authoritative remaining quota.
func (c *SubscriptionAdmissionController) RecordUnknownUsage(identity provider.Identity, decision SubscriptionDecision) error {
	if c == nil || c.plan == nil || !decision.Allowed || !validIdentity(identity) || decision.plan.leaseID == "" {
		return errors.New("invalid unknown subscription usage reservation")
	}
	scope := identity.SubscriptionCapacityScope()
	updated := false
	if !c.plan.withAuthoritativeState(scope, c.plan.now(), func(state *admissionState) {
		pruneSubscriptionUsage(state, c.plan.now(), c.config.WeeklyWindow)
		for index := range state.subscriptionUsage {
			event := &state.subscriptionUsage[index]
			if event.LeaseID != decision.plan.leaseID {
				continue
			}
			if event.Reconciled {
				return
			}
			// One or more unknown operations fail the whole subscription scope
			// closed, but never multiply the documented weekly ceiling. Existing
			// reconciled usage and other admission reservations count toward it.
			var otherCredits float64
			for otherIndex, other := range state.subscriptionUsage {
				if otherIndex != index {
					otherCredits += other.Credits
				}
			}
			event.Credits = c.config.WeeklyCreditLimit - otherCredits
			if event.Credits < 0 {
				event.Credits = 0
			}
			event.ObservedAt = c.plan.now().UTC()
			event.Reconciled = true
			event.Unknown = true
			updated = true
			return
		}
	}) {
		return errors.New("shared unknown subscription usage reservation is unavailable")
	}
	if !updated {
		return errors.New("subscription usage reservation is unavailable or already reconciled")
	}
	return nil
}

// ApplyLegacyUnknownUsageAuthorization replaces one recent full-week unknown
// reservation after a signed owner authorization has already been persisted.
// Legacy state has no cryptographic operation-to-reservation link, so this is
// intentionally not automatic evidence recovery and never establishes model
// identity.
func (c *SubscriptionAdmissionController) ApplyLegacyUnknownUsageAuthorization(identity provider.Identity, usage TokenUsage, completedAt time.Time, authorizationSHA256 string) (float64, error) {
	totalTokens, validUsage := positiveTokenUsageTotal(usage)
	if c == nil || c.plan == nil || !validIdentity(identity) || completedAt.IsZero() || !validUsage || !validSubscriptionEvidenceDigest(authorizationSHA256) {
		return 0, errors.New("invalid unknown subscription usage recovery")
	}
	now := c.plan.now().UTC()
	completedAt = completedAt.UTC()
	if completedAt.After(now.Add(time.Minute)) || now.Sub(completedAt) > c.config.WeeklyWindow {
		return 0, errors.New("unknown subscription usage recovery timestamp is outside the active window")
	}
	// This legacy recovery format is not trusted to preserve every future
	// token category's billing semantics. Charge every reported token at the
	// most expensive supported GLM-5.3 output rate.
	worstCase := TokenUsage{OutputTokens: totalTokens}
	credits, creditErr := ZAICodingPlanCredits("glm-5.3", worstCase, completedAt)
	if creditErr != nil {
		return 0, errors.New("calculate recovered subscription usage")
	}
	updated := false
	if !c.plan.withAuthoritativeState(identity.SubscriptionCapacityScope(), now, func(state *admissionState) {
		pruneSubscriptionUsage(state, now, c.config.WeeklyWindow)
		unknownCount, candidate := 0, -1
		for index, event := range state.subscriptionUsage {
			if !event.Unknown {
				continue
			}
			unknownCount++
			if event.Reconciled && event.OperationBindingSHA256 == "" && event.NonceSHA256 == "" && !event.ObservedAt.Before(completedAt) && event.ObservedAt.Sub(completedAt) <= 15*time.Minute {
				candidate = index
			}
		}
		if unknownCount != 1 || candidate < 0 {
			return
		}
		var fiveHourOther, weeklyOther float64
		for index, other := range state.subscriptionUsage {
			if index == candidate {
				continue
			}
			if other.ObservedAt.After(now.Add(-c.config.WeeklyWindow)) {
				weeklyOther += other.Credits
			}
			if other.ObservedAt.After(now.Add(-c.config.FiveHourWindow)) {
				fiveHourOther += other.Credits
			}
		}
		if weeklyOther+credits > c.config.WeeklyCreditLimit || (completedAt.After(now.Add(-c.config.FiveHourWindow)) && fiveHourOther+credits > c.config.FiveHourCreditLimit) {
			return
		}
		event := &state.subscriptionUsage[candidate]
		event.Credits = credits
		event.ObservedAt = completedAt
		event.Conservative = true
		event.Unknown = false
		event.RecoveryAuthorizationSHA256 = authorizationSHA256
		updated = true
	}) {
		return 0, errors.New("shared unknown subscription usage recovery is unavailable")
	}
	if !updated {
		return 0, errors.New("exactly one matching unknown subscription reservation is required")
	}
	return credits, nil
}

func validSubscriptionEvidenceDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func positiveTokenUsageTotal(usage TokenUsage) (int64, bool) {
	if usage.InputTokens < 0 || usage.CachedInputTokens < 0 || usage.OutputTokens < 0 {
		return 0, false
	}
	const maxInt64 = int64(^uint64(0) >> 1)
	if usage.InputTokens > maxInt64-usage.CachedInputTokens {
		return 0, false
	}
	total := usage.InputTokens + usage.CachedInputTokens
	if total > maxInt64-usage.OutputTokens {
		return 0, false
	}
	total += usage.OutputTokens
	return total, total > 0
}

var zaiSingapore = time.FixedZone("Asia/Singapore", 8*60*60)

// ZAICodingPlanCredits implements the documented Coding Plan credit formula.
// Lite-floor limits and off-peak scheduling are estimates; the provider's
// resolved model is required so a transparent model remap is charged correctly.
func ZAICodingPlanCredits(resolvedModel string, usage TokenUsage, observedAt time.Time) (float64, error) {
	if observedAt.IsZero() || usage.InputTokens < 0 || usage.CachedInputTokens < 0 || usage.OutputTokens < 0 {
		return 0, errors.New("invalid Z.ai Coding Plan usage")
	}
	var inputRate, cachedRate, outputRate float64
	switch resolvedModel {
	case "glm-5.3":
		inputRate, cachedRate, outputRate = 6.9, 1.7, 24
	case "glm-5.3-flash":
		inputRate, cachedRate, outputRate = 2.3, 0.56, 8
	default:
		return 0, errors.New("provider-resolved model is not eligible for Z.ai Coding Plan credit accounting")
	}
	credits := (float64(usage.InputTokens)*inputRate + float64(usage.CachedInputTokens)*cachedRate + float64(usage.OutputTokens)*outputRate) / 10000
	local := observedAt.In(zaiSingapore)
	if local.Weekday() < time.Monday || local.Weekday() > time.Friday || local.Hour() < 14 || local.Hour() >= 18 {
		credits *= 0.5
	}
	return credits, nil
}

func (c *SubscriptionAdmissionController) acquirePlan(scope provider.CapacityScope) Decision {
	now := c.plan.now()
	var decision Decision
	var leaseID string
	if !c.plan.withAcquireState(scope, now, func(state *admissionState) {
		c.plan.reclaimLocalExpiredLeases(state, now)
		if state.terminalReason != "" {
			decision = Decision{Reason: state.terminalReason, NoFailover: true}
			return
		}
		pruneSubscriptionUsage(state, now, c.config.WeeklyWindow)
		fiveUsed, fiveReset := subscriptionUsageTotal(state.subscriptionUsage, now, c.config.FiveHourWindow)
		weeklyUsed, weeklyReset := subscriptionUsageTotal(state.subscriptionUsage, now, c.config.WeeklyWindow)
		if state.running >= c.config.MaxConcurrent {
			decision = Decision{Reason: ErrorRateLimited, NoFailover: true}
			return
		}
		if fiveUsed+c.config.AdmissionReservation > c.config.FiveHourCreditLimit {
			decision = retryDecision(ErrorLongPeriodQuota, fiveReset)
			return
		}
		if weeklyUsed+c.config.AdmissionReservation > c.config.WeeklyCreditLimit {
			decision = retryDecision(ErrorLongPeriodQuota, weeklyReset)
			return
		}
		leaseID = c.plan.newLeaseID()
		if state.leases == nil {
			state.leases = make(map[string]admissionLease)
		}
		state.leases[leaseID] = admissionLease{OwnerPID: c.plan.ownerPID, OwnerID: c.plan.ownerID, OperationID: leaseID, ExpiresAt: now.Add(c.plan.config.LeaseTTL)}
		state.running = len(state.leases)
		state.subscriptionUsage = append(state.subscriptionUsage, subscriptionUsageEvent{LeaseID: leaseID, ObservedAt: now.UTC(), Credits: c.config.AdmissionReservation})
		decision = Decision{Allowed: true, NoFailover: true, leaseID: leaseID}
	}) {
		return Decision{Reason: ErrorUnknown, NoFailover: true}
	}
	if decision.Allowed {
		c.plan.startLeaseRenewal(scope, leaseID)
	}
	return decision
}

func pruneSubscriptionUsage(state *admissionState, now time.Time, width time.Duration) {
	cutoff := now.Add(-width)
	kept := state.subscriptionUsage[:0]
	for _, event := range state.subscriptionUsage {
		if !event.ObservedAt.After(cutoff) {
			continue
		}
		kept = append(kept, event)
	}
	state.subscriptionUsage = kept
}

func subscriptionUsageTotal(events []subscriptionUsageEvent, now time.Time, width time.Duration) (float64, time.Time) {
	cutoff := now.Add(-width)
	var total float64
	var earliest time.Time
	for _, event := range events {
		if !event.ObservedAt.After(cutoff) {
			continue
		}
		total += event.Credits
		if earliest.IsZero() || event.ObservedAt.Before(earliest) {
			earliest = event.ObservedAt
		}
	}
	if earliest.IsZero() {
		return total, now.UTC()
	}
	return total, earliest.Add(width).UTC()
}

func (c *SubscriptionAdmissionController) Snapshot(identity provider.Identity) SubscriptionCapacitySnapshot {
	if c == nil || c.exact == nil || c.plan == nil {
		return SubscriptionCapacitySnapshot{IdentityHash: identity.Hash(), Scope: provider.CapacityControlScopeProcessLocal, FallbackReason: "subscription admission controller is unavailable"}
	}
	snapshot := SubscriptionCapacitySnapshot{
		Exact:                c.exact.Snapshot(identity),
		IdentityHash:         identity.Hash(),
		Scope:                c.exact.CapacityStatus().Scope,
		PlanMaxConcurrent:    c.config.MaxConcurrent,
		AdmissionReservation: c.config.AdmissionReservation,
		FiveHourCreditsLimit: c.config.FiveHourCreditLimit,
		WeeklyCreditsLimit:   c.config.WeeklyCreditLimit,
		LimitEvidence:        "documented_zai_lite_floor_controller_local_estimate",
		ResetEvidence:        "controller_local_rolling_window_estimate",
	}
	if !validIdentity(identity) {
		return snapshot
	}
	scope := identity.SubscriptionCapacityScope()
	snapshot.SubscriptionScopeSHA256 = strings.TrimPrefix(scope.String(), "subscription:")
	state, ok, err := c.plan.subscriptionState(scope)
	if err != nil {
		snapshot.Scope, snapshot.FallbackReason = provider.CapacityControlScopeProcessLocal, err.Error()
		return snapshot
	}
	if !ok {
		return snapshot
	}
	now := c.plan.now()
	pruneSubscriptionUsage(&state, now, c.config.WeeklyWindow)
	fiveUsed, fiveReset := subscriptionUsageTotal(state.subscriptionUsage, now, c.config.FiveHourWindow)
	weeklyUsed, weeklyReset := subscriptionUsageTotal(state.subscriptionUsage, now, c.config.WeeklyWindow)
	snapshot.PlanRunning, snapshot.FiveHourCreditsUsed, snapshot.WeeklyCreditsUsed = state.running, fiveUsed, weeklyUsed
	snapshot.FiveHourResetsAt, snapshot.WeeklyResetsAt = &fiveReset, &weeklyReset
	for _, event := range state.subscriptionUsage {
		if event.Unknown {
			snapshot.UnknownUsageReserved = true
		}
		if event.Conservative {
			snapshot.ConservativeUsage = true
		}
		if event.RecoveryAuthorizationSHA256 != "" {
			snapshot.LegacyRecoveryAuthorized = true
		}
	}
	return snapshot
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
	return c.withAuthoritativeState(scope, now, fn)
}

// withAuthoritativeState permits local state only when this controller was
// deliberately created without a shared store. A configured store that cannot
// be transacted is a fail-closed condition: reconciliation must not create a
// divergent process-local accounting record after another process admitted the
// same subscription.
func (c *AdmissionController) withAuthoritativeState(scope provider.CapacityScope, now time.Time, fn func(*admissionState)) bool {
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
	c.releaseScope(identity.CapacityScope(), decision)
}

func (c *AdmissionController) releaseScope(scope provider.CapacityScope, decision Decision) {
	if c == nil || scope == "" || !decision.Allowed || decision.leaseID == "" {
		return
	}
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

func (c *AdmissionController) subscriptionState(scope provider.CapacityScope) (admissionState, bool, error) {
	if c == nil || scope == "" {
		return admissionState{}, false, errors.New("subscription capacity scope is unavailable")
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.shared != nil && c.fallbackReason == "" {
		state, ok, err := c.shared.snapshot(scope, now)
		if err != nil {
			c.fallbackReason = err.Error()
			return admissionState{}, false, err
		}
		return state, ok, nil
	}
	state := c.states[scope]
	if state == nil {
		return admissionState{}, false, nil
	}
	return *state, true, nil
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
	c.recordSuccessScope(identity.CapacityScope())
}

func (c *AdmissionController) recordSuccessScope(scope provider.CapacityScope) {
	if c == nil || scope == "" {
		return
	}
	c.withState(scope, c.now(), func(state *admissionState) {
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
