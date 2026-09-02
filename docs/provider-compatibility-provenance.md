# Provider compatibility provenance

This document separates replayable compatibility evidence from live provider
evidence. A fixture confirms that NTM still understands a documented or
previously observed wire shape. It does not confirm current account access,
model entitlement, quota, policy enforcement, or provider-side cancellation.

## Evidence classes

| Class | What it proves | What it does not prove |
| --- | --- | --- |
| Redacted fixture replay | Parser and receipt compatibility for the listed shape | A live vendor interaction or account entitlement |
| Local runtime inspection | A particular local executable/configuration observation | A request reached the provider |
| Live nonce-bound receipt | A particular request/model/transport acknowledgement | Broader availability or future behavior |
| Provider-authoritative lifecycle receipt | Vendor acknowledgement for the documented lifecycle operation | Unrelated provider operations |

Telemetry observations only record normalized identity and policy hashes,
adapter/model/runtime identifiers, scalar latency/token/cost facts, normalized
error/quota/circuit state, and fixture version. They never carry raw prompts,
outputs, paths, or credentials.

## Fixture coverage

| Provider lane | Fixture version | Covered shape | Provenance | Known gap |
| --- | --- | --- | --- | --- |
| Grok native ACP | `grok-acp-1.0.13-v1` | Redacted post-completion economics/drift record | Synthetic replay fixture derived from the NTM receipt schema | Does not replay an ACP transcript, authenticate, or establish cloud cancellation |
| Z.ai native HTTP | `zai-native-v4-v1` | Redacted structured chat-completion economics/drift record | Synthetic replay fixture derived from the native receipt schema | Does not establish key entitlement, API availability, cancellation, or resume |
| Z.ai Claude-compatible runtime | none | Not replayable at per-request protocol level | Intentionally opaque compatibility lane | Must remain NO_GO for request-level authority unless a structured provider contract is qualified |

The fixtures live under `internal/cli/testdata/provider_telemetry/` and are
loaded by focused replay tests. Their identity/policy values are fixed hashes,
not hashes of local users, accounts, prompts, keys, or repositories.

## Drift and discrepancy policy

`ntm provider telemetry` is read-only and defaults to the create-only execution
store; `--store <existing-directory>` selects another exact store. It compares
the latest observation's fixture version with an optional expected version and
computes fixture age. `drifted` means those exact version identifiers differ;
`stale` means the latest compatible observation is older than the selected age
bound. Neither result is a live health claim.

When a live observation disagrees with a fixture, preserve both facts: record a
new create-only observation with the new fixture/runtime/model identifiers,
mark the expected fixture version as drifted, and require a reviewed fixture
update plus a fresh live qualification before promoting readiness. Never edit
or replace the old observation to make the discrepancy disappear.

## Operational boundaries

- Grok ACP cancellation may be acknowledged by the local ACP agent; that is
  narrower than confirmation that cloud inference stopped.
- Z.ai native chat supplies structured request/model/usage/finish evidence, but
  no documented native chat cancellation, resume, or fork receipt is assumed.
- Native-tools qualification observes cancellation of an in-flight local HTTP
  request context and cleanup of the local Bubblewrap process. It does not
  promote either observation to a provider-side acknowledgement, and its
  disposable qualification repository is intentionally retained as evidence.
- Z.ai Coding Plan credentials and a general native API credential remain
  separate authorization classes. The Coding Plan endpoint is not evidence of
  authorization for an NTM-native API lane.
