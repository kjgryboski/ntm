package provider

// EvidenceGrade states the strongest evidence a transport can produce for an
// operation. "submission" proves NTM handed work to the transport, not that a
// provider executed it. Callers must not promote a lower grade to a higher one.
type EvidenceGrade string

const (
	EvidenceUnavailable   EvidenceGrade = "unavailable"
	EvidenceSubmission    EvidenceGrade = "submission"
	EvidenceAuthoritative EvidenceGrade = "authoritative"
)

// EvidenceAuthorityScope identifies who can substantiate an operation at the
// declared evidence grade. A provider scope means the provider/runtime emitted
// the acknowledgement; agent_acp means the local Grok ACP agent acknowledged
// the exact protocol transition, not that xAI cloud inference was stopped.
// A local_process_tree scope proves only local process control and must never
// be read as provider-side cancellation.
type EvidenceAuthorityScope string

const (
	EvidenceAuthorityScopeUnavailable      EvidenceAuthorityScope = "unavailable"
	EvidenceAuthorityScopeProvider         EvidenceAuthorityScope = "provider"
	EvidenceAuthorityScopeAgentACP         EvidenceAuthorityScope = "agent_acp"
	EvidenceAuthorityScopeLocalProcessTree EvidenceAuthorityScope = "local_process_tree"
	EvidenceAuthorityScopeLocalClient      EvidenceAuthorityScope = "local_client"
)

// CapacityControlScope states where admission/circuit state is coordinated.
// ProcessLocal must never be presented as a fleet-wide quota or provider
// reservation.
type CapacityControlScope string

const (
	CapacityControlScopeUnavailable CapacityControlScope = "unavailable"
	// CapacityControlScopeLocalShared means cooperating local NTM processes
	// share a crash-tolerant lease/circuit store. It is not a fleet service.
	CapacityControlScopeLocalShared  CapacityControlScope = "local_shared"
	CapacityControlScopeProcessLocal CapacityControlScope = "process_local"
)

// OperationCapabilities is a machine-readable, transport-level contract.
// IdentityProbeRequired means a launch cannot be admitted merely because the
// executable starts; the provider/model boundary must be proven independently.
type OperationCapabilities struct {
	// IdentityEvidence is the strongest evidence for the complete immutable
	// tuple (provider, account, model, endpoint, runtime, config hash). It is
	// intentionally separate from a model probe: a probe can qualify a model
	// without proving an opaque runtime still honors every configured setting.
	IdentityEvidence           IdentityEvidenceGrade  `json:"identity_evidence"`
	CapacityControlScope       CapacityControlScope   `json:"capacity_control_scope"`
	Launch                     EvidenceGrade          `json:"launch"`
	Delivery                   EvidenceGrade          `json:"delivery"`
	Completion                 EvidenceGrade          `json:"completion"`
	CompletionAuthorityScope   EvidenceAuthorityScope `json:"completion_authority_scope"`
	Cancellation               EvidenceGrade          `json:"cancellation"`
	CancellationAuthorityScope EvidenceAuthorityScope `json:"cancellation_authority_scope"`
	Resume                     EvidenceGrade          `json:"resume"`
	Cleanup                    EvidenceGrade          `json:"cleanup"`
	CleanupAuthorityScope      EvidenceAuthorityScope `json:"cleanup_authority_scope"`
	IdentityProbeRequired      bool                   `json:"identity_probe_required"`
	// LaunchCapacityControl covers admission of the provider process itself.
	// RequestCapacityControl and LiveErrorFeedback apply to actual model API
	// calls; an opaque TUI launch must never be promoted to request control.
	LaunchCapacityControl  EvidenceGrade `json:"launch_capacity_control"`
	RequestCapacityControl EvidenceGrade `json:"request_capacity_control"`
	LiveErrorFeedback      EvidenceGrade `json:"live_error_feedback"`
}

// CapabilityMatrix is a static declaration of transport evidence, not an
// assertion that a local account has been qualified. The key is a transport
// identifier intentionally separate from a provider profile/config surface.
func CapabilityMatrix() map[string]OperationCapabilities {
	return map[string]OperationCapabilities{
		// xAI ACP cancellation is authoritative only at the Grok ACP-agent
		// boundary: NTM writes session/cancel and requires the original
		// session/prompt response to say stopReason=cancelled. That does not
		// establish that an already accepted xAI cloud inference was stopped.
		"xai_acp": {
			IdentityEvidence:     IdentityEvidenceProfileAttested,
			CapacityControlScope: CapacityControlScopeLocalShared,
			Launch:               EvidenceAuthoritative, Delivery: EvidenceAuthoritative,
			Completion: EvidenceAuthoritative, CompletionAuthorityScope: EvidenceAuthorityScopeProvider,
			Cancellation: EvidenceAuthoritative, CancellationAuthorityScope: EvidenceAuthorityScopeAgentACP,
			Resume: EvidenceUnavailable, Cleanup: EvidenceAuthoritative, CleanupAuthorityScope: EvidenceAuthorityScopeLocalProcessTree,
			LaunchCapacityControl: EvidenceAuthoritative, RequestCapacityControl: EvidenceAuthoritative,
			LiveErrorFeedback: EvidenceUnavailable,
		},
		// Native Grok headless sessions return a nonce-bound structured result
		// and session lineage. Resume/fork is authoritative at that boundary.
		// Cancellation is provider-unavailable; its local process-tree receipt
		// must not be mistaken for provider acknowledgement. Cleanup is
		// authoritative only for that locally observed process tree.
		"xai_headless_session": {
			IdentityEvidence:     IdentityEvidenceProfileAttested,
			CapacityControlScope: CapacityControlScopeLocalShared,
			Launch:               EvidenceAuthoritative, Delivery: EvidenceAuthoritative,
			Completion: EvidenceAuthoritative, CompletionAuthorityScope: EvidenceAuthorityScopeProvider,
			Cancellation: EvidenceAuthoritative, CancellationAuthorityScope: EvidenceAuthorityScopeLocalProcessTree,
			Resume: EvidenceAuthoritative, Cleanup: EvidenceAuthoritative, CleanupAuthorityScope: EvidenceAuthorityScopeLocalProcessTree,
			LaunchCapacityControl: EvidenceAuthoritative, RequestCapacityControl: EvidenceAuthoritative,
			LiveErrorFeedback: EvidenceUnavailable,
		},
		// A Grok terminal pane can prove composer-ready keystroke submission;
		// output scraping is not an authoritative provider completion/cancel
		// receipt.
		"xai_grok_tui": {
			IdentityEvidence:     IdentityEvidenceProfileAttested,
			CapacityControlScope: CapacityControlScopeLocalShared,
			Launch:               EvidenceSubmission, Delivery: EvidenceSubmission,
			Completion: EvidenceUnavailable, CompletionAuthorityScope: EvidenceAuthorityScopeUnavailable,
			Cancellation: EvidenceUnavailable, CancellationAuthorityScope: EvidenceAuthorityScopeUnavailable,
			Resume: EvidenceUnavailable, Cleanup: EvidenceSubmission, CleanupAuthorityScope: EvidenceAuthorityScopeLocalClient,
			LaunchCapacityControl: EvidenceUnavailable, RequestCapacityControl: EvidenceUnavailable,
			LiveErrorFeedback: EvidenceUnavailable,
		},
		// Z.ai can use the Claude runtime, so an explicit endpoint/model probe
		// is mandatory before treating a process as a Z.ai lane. The runtime
		// alone has no authority to establish that provider identity.
		"zai_claude_runtime": {
			IdentityEvidence:     IdentityEvidenceProfileAttested,
			CapacityControlScope: CapacityControlScopeLocalShared,
			Launch:               EvidenceSubmission, Delivery: EvidenceSubmission,
			Completion: EvidenceUnavailable, CompletionAuthorityScope: EvidenceAuthorityScopeUnavailable,
			Cancellation: EvidenceUnavailable, CancellationAuthorityScope: EvidenceAuthorityScopeUnavailable,
			Resume: EvidenceUnavailable, Cleanup: EvidenceSubmission, CleanupAuthorityScope: EvidenceAuthorityScopeLocalClient,
			IdentityProbeRequired: true,
			LaunchCapacityControl: EvidenceAuthoritative, RequestCapacityControl: EvidenceUnavailable,
			LiveErrorFeedback: EvidenceUnavailable,
		},
		// Z.ai Coding Plan via the official Codex Responses endpoint is the
		// primary structured Z.ai coding lane. Its potential authority is
		// realized only after the exact identity has a signed live qualification;
		// this static declaration is never a local promotion receipt.
		"zai_codex_runtime": {
			IdentityEvidence:           IdentityEvidenceProfileAttested,
			CapacityControlScope:       CapacityControlScopeLocalShared,
			Launch:                     EvidenceAuthoritative,
			Delivery:                   EvidenceAuthoritative,
			Completion:                 EvidenceAuthoritative,
			CompletionAuthorityScope:   EvidenceAuthorityScopeProvider,
			Cancellation:               EvidenceAuthoritative,
			CancellationAuthorityScope: EvidenceAuthorityScopeLocalProcessTree,
			Resume:                     EvidenceAuthoritative,
			Cleanup:                    EvidenceAuthoritative,
			CleanupAuthorityScope:      EvidenceAuthorityScopeLocalProcessTree,
			IdentityProbeRequired:      true,
			LaunchCapacityControl:      EvidenceAuthoritative,
			RequestCapacityControl:     EvidenceAuthoritative,
			LiveErrorFeedback:          EvidenceUnavailable,
		},
		// Native Z.ai API requests emit structured completion, usage, and error
		// records. Cancellation and resume remain unavailable until their own
		// authoritative provider receipts exist; local cleanup is submission-only.
		"zai_native_api": {
			IdentityEvidence:           IdentityEvidenceRuntimeVerified,
			CapacityControlScope:       CapacityControlScopeLocalShared,
			Launch:                     EvidenceAuthoritative,
			Delivery:                   EvidenceAuthoritative,
			Completion:                 EvidenceAuthoritative,
			CompletionAuthorityScope:   EvidenceAuthorityScopeProvider,
			Cancellation:               EvidenceUnavailable,
			CancellationAuthorityScope: EvidenceAuthorityScopeUnavailable,
			Resume:                     EvidenceUnavailable,
			Cleanup:                    EvidenceSubmission,
			CleanupAuthorityScope:      EvidenceAuthorityScopeLocalClient,
			IdentityProbeRequired:      true,
			LaunchCapacityControl:      EvidenceAuthoritative,
			RequestCapacityControl:     EvidenceAuthoritative,
			LiveErrorFeedback:          EvidenceAuthoritative,
		},
	}
}
