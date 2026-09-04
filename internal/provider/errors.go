package provider

// ProtocolObservation contains only controller-selected labels and counters.
// Redacted must be applied at persistence boundaries, including for test runners.
// No request IDs, session IDs, parameters, or provider error text are retained.
type ProtocolObservation struct {
	Method            string                `json:"method"`
	RequestIDKind     string                `json:"request_id_kind"`
	SessionMatch      string                `json:"session_match"`
	Stage             string                `json:"stage"`
	Reason            ProtocolFailureReason `json:"reason,omitempty"`
	ToolEvents        int                   `json:"tool_events"`
	ToolRequests      int                   `json:"tool_requests"`
	ToolCompletions   int                   `json:"tool_completions"`
	PermissionDenials int                   `json:"permission_denials"`
}

func (o ProtocolObservation) Redacted() ProtocolObservation {
	// Reviewed ACP client methods and Grok 1.0.13 notifications. Recognition
	// for diagnostics never implies permission to execute a reverse request.
	switch o.Method {
	case "session/update", "session/request_permission", "fs/read_text_file", "fs/write_text_file",
		"terminal/create", "terminal/output", "terminal/release", "terminal/wait_for_exit", "terminal/kill",
		"x.ai/announcements/update", "x.ai/git/worktree/status", "x.ai/git_head_changed",
		"x.ai/mcp/init_progress", "x.ai/mcp/server_status", "x.ai/mcp/servers_updated", "x.ai/mcp/tools_changed",
		"x.ai/mcp_initialized", "x.ai/models/update", "x.ai/queue/changed", "x.ai/session/models/update",
		"x.ai/session/prompt_complete", "x.ai/session_notification", "x.ai/sessions/changed", "x.ai/settings/update",
		"_x.ai/announcements/update", "_x.ai/git/worktree/status", "_x.ai/git_head_changed",
		"_x.ai/mcp/init_progress", "_x.ai/mcp/server_status", "_x.ai/mcp/servers_updated", "_x.ai/mcp/tools_changed",
		"_x.ai/mcp_initialized", "_x.ai/models/update", "_x.ai/queue/changed", "_x.ai/session/models/update",
		"_x.ai/session/prompt_complete", "_x.ai/session_notification", "_x.ai/sessions/changed", "_x.ai/settings/update", "absent":
	default:
		o.Method = "unknown"
	}
	switch o.RequestIDKind {
	case "absent", "null", "present":
	default:
		o.RequestIDKind = "unobserved"
	}
	switch o.SessionMatch {
	case "absent", "match", "mismatch", "unbound", "malformed":
	default:
		o.SessionMatch = "unobserved"
	}
	switch o.Stage {
	case "request_validation", "process_start", "initialize", "auth_method_selection", "authenticate", "session_new",
		"prompt_write", "prompt_response", "completion_metadata", "post_response_updates", "completion_validation":
	default:
		o.Stage = "unobserved"
	}
	if !o.Reason.Valid() {
		o.Reason = ProtocolOther
	}
	o.ToolEvents = max(0, o.ToolEvents)
	o.ToolRequests = max(0, o.ToolRequests)
	o.ToolCompletions = max(0, o.ToolCompletions)
	o.PermissionDenials = max(0, o.PermissionDenials)
	return o
}

// ProtocolFailureReason is a closed controller-owned diagnostic vocabulary.
// It never contains method names, session IDs, payload fragments, or error text.
type ProtocolFailureReason string

const (
	ProtocolUnknownMethod          ProtocolFailureReason = "unknown_method"
	ProtocolUnexpectedRequest      ProtocolFailureReason = "unexpected_request"
	ProtocolMalformedMessage       ProtocolFailureReason = "malformed_message"
	ProtocolInvalidVersion         ProtocolFailureReason = "invalid_protocol_version"
	ProtocolResponseIDMismatch     ProtocolFailureReason = "response_id_mismatch"
	ProtocolMissingResult          ProtocolFailureReason = "missing_result"
	ProtocolMalformedEnvelope      ProtocolFailureReason = "malformed_envelope"
	ProtocolEnvelopeMethodMismatch ProtocolFailureReason = "envelope_method_mismatch"
	ProtocolMalformedSessionUpdate ProtocolFailureReason = "malformed_session_update"
	ProtocolSessionMismatch        ProtocolFailureReason = "session_mismatch"
	ProtocolInvalidToolLifecycle   ProtocolFailureReason = "invalid_tool_lifecycle"
	ProtocolInvalidResult          ProtocolFailureReason = "invalid_result"
	ProtocolStreamClosed           ProtocolFailureReason = "stream_closed"
	ProtocolStreamRead             ProtocolFailureReason = "stream_read_failed"
	ProtocolOther                  ProtocolFailureReason = "other_protocol_error"
)

// Valid permits omission on successful runs and older receipts, but rejects
// arbitrary strings rather than treating provider text as a diagnostic label.
func (r ProtocolFailureReason) Valid() bool {
	switch r {
	case "", ProtocolUnknownMethod, ProtocolUnexpectedRequest, ProtocolMalformedMessage,
		ProtocolInvalidVersion, ProtocolResponseIDMismatch, ProtocolMissingResult,
		ProtocolMalformedEnvelope, ProtocolEnvelopeMethodMismatch, ProtocolMalformedSessionUpdate,
		ProtocolSessionMismatch, ProtocolInvalidToolLifecycle, ProtocolInvalidResult,
		ProtocolStreamClosed, ProtocolStreamRead, ProtocolOther:
		return true
	default:
		return false
	}
}

// ErrorClass is an exact, provider-neutral classification of a response. It
// intentionally never infers state from provider prose. The Z.ai business
// codes are kept here so conformance and admission use one taxonomy without a
// package dependency cycle.
type ErrorClass string

const (
	ErrorRateLimited         ErrorClass = "rate_limited"
	ErrorOverloaded          ErrorClass = "overloaded"
	ErrorLongPeriodQuota     ErrorClass = "long_period_quota"
	ErrorPlanExpired         ErrorClass = "plan_expired"
	ErrorUnsupportedModel    ErrorClass = "unsupported_model"
	ErrorUsageRestricted     ErrorClass = "usage_policy_restricted"
	ErrorInsufficientBalance ErrorClass = "insufficient_balance"
	ErrorAuthentication      ErrorClass = "authentication"
	ErrorIdentityMismatch    ErrorClass = "identity_mismatch"
	ErrorUnknown             ErrorClass = "unknown"
)

// ClassifyProviderError performs exact classification from an HTTP status and
// normalized provider code. Business codes take precedence because a 429 may
// represent a permanent quota, plan, account, or policy condition.
func ClassifyProviderError(httpStatus int, code string) ErrorClass {
	switch code {
	case "1302", "rate_limit", "rate_limit_exceeded", "too_many_requests":
		return ErrorRateLimited
	case "1305", "overloaded", "server_overloaded", "service_unavailable":
		return ErrorOverloaded
	case "1308", "1310", "1316", "1317", "1318", "1319", "1320", "1321":
		return ErrorLongPeriodQuota
	case "1309", "1314", "plan_expired", "subscription_expired":
		return ErrorPlanExpired
	case "1311", "1211", "1212", "unsupported_model", "model_not_found", "invalid_model":
		return ErrorUnsupportedModel
	case "1301", "1313", "1315", "1220":
		return ErrorUsageRestricted
	case "1113":
		return ErrorInsufficientBalance
	case "1000", "1001", "1003", "1005", "authentication_failed", "invalid_api_key", "unauthorized":
		return ErrorAuthentication
	case "identity_mismatch":
		return ErrorIdentityMismatch
	}
	switch httpStatus {
	case 429:
		return ErrorRateLimited
	case 401, 403:
		return ErrorAuthentication
	case 503, 529:
		return ErrorOverloaded
	}
	return ErrorUnknown
}

// RequiredZAIErrorClasses are the distinct Z.ai outcomes a qualified Z.ai
// fixture must exercise. Unknown is intentionally excluded: it denotes an
// unclassified response, rather than an expected provider outcome.
func RequiredZAIErrorClasses() []ErrorClass {
	return []ErrorClass{
		ErrorRateLimited,
		ErrorOverloaded,
		ErrorLongPeriodQuota,
		ErrorPlanExpired,
		ErrorUnsupportedModel,
		ErrorUsageRestricted,
		ErrorInsufficientBalance,
		ErrorAuthentication,
	}
}
