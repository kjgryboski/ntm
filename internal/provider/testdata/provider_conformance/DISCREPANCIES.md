# Known conformance divergences

## DISC-001: Fixture replay is not a live model-attestation receipt

- Reference: ACP and Responses transports can emit live provider/runtime data.
- NTM: embedded fixtures replay only redacted scalar protocol metadata.
- Impact: replay proves parser and lifecycle-contract behavior, never account
  entitlement, current routing, cloud cancellation, or availability.
- Resolution: ACCEPTED — live qualification remains a separate promotion gate.
- Tests affected: `TestSharedProviderRuntimeContractReplaysRedactedWireFixtures`.
- Review date: 2026-09-03.
