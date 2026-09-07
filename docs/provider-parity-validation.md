# Managed provider validation

Workspace admission and lifecycle evidence are separate. An ordinary assignment
requires current signed identity, edit, verification, denial and cleanup checks
for its exact profile, runtime and policy. Successful completion additionally
requires the exact runtime terminal event, independent workspace verification,
cleanup and the appropriate local capacity release. Local cancellation does not
establish remote generation termination or resume support.

Readiness discovers task evidence in the ledger beside the selected configuration.
When comparing profiles from different configurations, query each owning ledger
and retain each report's provenance. An empty candidate ledger does not erase a
verified task in the normal ledger; combine only matching exact identity hashes.

## Dispatch audit

| Entry point | Owning boundary |
| --- | --- |
| Primary compare and ordinary spawn/assign/send | Exact primary profile, signed workspace admission for ordinary work, shared control ledger and campaign |
| Grok ordinary assignments | `prepareGrokACPDispatch`, qualified scope, shared control ledger and campaign |
| Direct robot Grok ACP | Same profile/qualification preparation, explicit campaign reservation before robot dispatch |
| Grok qualification and headless sessions | Budgeted production runners; each qualification dispatch consumes an attempt |
| Z.ai Codex run and qualification | Existing capacity/identity/receipt boundary and budgeted structured runner |
| Native API run and tool qualification | Existing admission and durable operation boundary; every HTTP generation round reserves a campaign attempt |
| Older online doctor probes | Existing exact identity/local admission checks plus campaign reservation; doctor output grants no qualification |
| Opaque Z.ai Claude-compatible qualification and doctor | Live dispatch denied because individual Coding Plan requests cannot be accounted for; cannot substitute for the blocked structured lane |
| Guarded restart | Verified original terminal state, cleanup and local release; distinct operation ID and ordinary dispatch admission |
| Raw tmux pane controls | Outside managed qualification; rejected when presented as campaign-controlled work |

This does not turn arbitrary manually launched CLI processes into managed work.
Campaign state is independent of `--config`; an alternate operation ledger cannot
reset its ceiling. Unknown operations cannot be replayed. A new campaign requires
its own explicit scope and authorization record; never use one to silently refund
or replay an exhausted campaign.

## Saved task evidence and lifecycle contract

`provider evidence --profile NAME --operation ID --require completion` checks a
saved task through the same pinned-signer and exact-binding status owner used by
readiness. Use `--require local-cancellation` for an observed canceled task or
`--require guarded-restart --restart-of PARENT_ID` to verify both parent and child.
The parent must have the same exact identity, a verified terminal result, cleanup
and local capacity release; a restart digest alone is insufficient. The child
must independently complete workspace verification. Unknown or incompletely
finalized controllers fail acceptance even when a signed runtime result exists.

`--output ABSOLUTE_NEW_FILE` saves a redacted result before returning a failed
acceptance verdict. Existing files are never replaced. This is a local observation
of the signed ledger, not a new signature or dispatch authorization. The original
signed receipt remains the authority; rerun this read-only command to repair an
export rather than replaying generation. Local elapsed time is measured from the
ledger timestamps and is separate from billed runtime. Human intervention is
reported as unmeasured unless recorded separately by the pilot owner.

`provider evidence --contract` describes the common lifecycle acceptance rules.
Controller restart preserves uncertain ownership and usage. It cannot replay or
take over an operation based on PID death or age. Subprocess crash tests cover
all four provider routes after reservation, dispatch, signing, receipt persistence
and forced controller death. These demonstrate quarantine, not automatic recovery.
The common assignment workflow implements Grok ACP resume with provider-specific
session persistence and identity-bound predecessor evidence. Successful coding
after resume requires its own live evidence. Local cancellation and fresh restart do not establish remote
generation termination or final billing settlement.

For a bounded operational pilot, record the exact binary, fixture, account/model,
qualification expiry, campaign limit and intended task duration before dispatch.
Check local startup and compiled verifier prerequisites first. Preserve failed
attempts, original tests and all exhausted campaigns. Compare completion, local
elapsed time, recorded human interventions and local capacity release through
`provider evidence`; keep blocked providers in the denominator as not attempted.

## Credential refresh

`provider credential refresh-snapshot --profile NAME --source-home DIRECTORY`
previews an already refreshed account-owner snapshot. Add `--apply` to activate
after validation, preserving a private backup. This command neither switches an
active account nor rotates OAuth tokens from disposable runtime homes.

Codex refresh requires matching nonempty account IDs. Claude's opaque credentials
require unchanged refresh-token lineage and subscription type. Rotated opaque
tokens require fresh identity binding; an account label alone cannot justify
reuse. These checks are local profile attestation, not provider-authoritative
account proof. Expired Claude snapshots remain blocked. Configuration and signed
qualification records are not rewritten by refresh; readiness still checks pins,
policy and qualification expiry before subsequent work.

## Representative acceptance

Prepare an independent linked fixture with
`provider acceptance --scenario order-total --directory ABSOLUTE_NEW_DIRECTORY`.
Use its `acceptance.json` prompt through ordinary provider controls. The baseline
contains deliberate parsing and totaling defects across two source files; tests
cover whitespace, invalid quantities, unknown products, duplicate products,
negative prices, empty input and the complete import flow. Keep the original test
and module hashes unchanged. Require edits to both sources and passing independent
verification. Prepare and run each admitted provider sequentially under a declared
attempt ceiling.

## Offline prerequisites and evidence compatibility

The native `make build` target now binds the actual Go toolchain root and runs
the compiled broker fixture against the resulting executable. Missing Linux,
native architecture, Bubblewrap, or compiled-binary prerequisites fail this
verification instead of silently skipping it. `install` and `install-user`
depend on this verified build. Distribution cross-builds are not local workspace
qualification and still require verification on the destination machine.

A trimpath build must bind `internal/provider.verifierBuildGoRoot` to its actual
Go toolchain root. Broker preparation now initializes the isolated verifier before
generation. Before a live attempt, run the compiled broker fixture against the
actual candidate (`NTM_PROVIDER_BROKER_BINARY`) and load the controlled catalog in
the pinned Codex runtime (`NTM_PRIMARY_CODEX_OFFLINE_BINARY`). Recheck hashes and
readiness after building. A status read validates historical receipts against the
installed verifier; it does not retroactively claim that the historical live run
used the new controller binary.

## Repeatable scanner review

Run the complete installed Go AST rulepack with a native ast-grep executable and
retain its complete JSON array. Summary counts cannot serve as a finding baseline.
`provider scan-review` accepts `--input`, `--root`, `--scanner-sha256`, and
`--rules-sha256`. After individual review, use `--write-baseline NEW_FILE` and
`--reviewed-input-sha256` for the exact input. Subsequent runs use `--baseline` and
fail for new occurrences, changed source contents, or scanner/rule drift. Findings
are bound to rule, location, matched text digest and full source digest. Raw
scanner severity remains unchanged. Keep heuristic findings and their individual
dispositions alongside the AST baseline; a green baseline comparison is not a
claim that the raw scanner is green.

## Z.ai reconciliation

`provider codex reconciliation-plan --profile NAME` reads the uncertain capacity
scope and emits the settlement and bounded-headroom evidence requirements. It
never changes accounting or grants admission. Aggregate quota and model-usage
totals do not bind an older request or establish its remaining cost. An explicit
legacy unbound accounting exception is a different operation and must not be
presented as authoritative settlement. Preserve the strict served-model preflight
until the required admission evidence is available.

## One readiness and acceptance view

`provider readiness --profile NAME` supports the exact Codex, Claude, Grok and
Z.ai profiles. Repeat `--profile` to compare them. Use `--cwd ABSOLUTE_WORKSPACE`
for Grok policy discovery in the intended workspace. Optional repeated
`--operation PROFILE=OPERATION_ID` adds explicit existing task references. The
view also discovers up to 64 recent references bound to each exact identity in
the selected local ledger, verifies them through the status owner, and reports
truncation or unverifiable references. It makes no generation calls. Use the ordinary global `--campaign-id` to inspect that
budget alongside the profiles without consuming an attempt.

The shared response separates workspace evidence, credential freshness, local
admission blockers, qualification expiry, and task observations. The state
`ready_for_dispatch_checks` means local prerequisites passed; the read surface
always returns `dispatch_authorized=false`. Actual dispatch owns the final
credential, exact target, policy, qualification, capacity and campaign checks.
Offline Grok authentication stays explicitly unverified. Missing, stale and
unsupported capabilities are never inferred from ordinary CLI usability.

The acceptance matrix retains the source and digest for each passed, failed,
unsupported or untested observation. Qualification checks include their expiry;
historical task results do not renew it. Ordinary task completion, local
cancellation, guarded fresh restart, provider session resume, remote generation
termination and billing settlement remain distinct. A later failed task does
not erase an independently successful earlier task. `capability_summary` contains
one row per capability and indexes every contributing observation in `checks`.
Its passed state means demonstrated at least once; admission remains independent.
The same row also reports `failed_observations`, `latest_dated_states` and
`latest_observed_at`. Human output labels the aggregate as historical and shows
the failure count and latest dated result. Dates, rather than selection order,
determine recency; conflicting states at the same timestamp are both retained.
Undated observations remain in the counts and references but cannot establish
recency. These summaries cover only the inspected history; truncation and
unverifiable references remain visible and no summary grants dispatch authority.

Use `--task-timeout 180s` to compare the intended duration with the earliest known
credential or qualification expiry in `usable_until`. A task ending at or after
that expiry fails the duration check. Dispatch enforces its qualification window;
primary tasks are bounded to five minutes and require a Claude credential snapshot
valid beyond the five-minute freshness margin. Unknown provider authentication
and historical task success cannot extend those windows.

## Assignment previews and task comparisons

`provider preview` is an alias of the existing read-only readiness command.
Use `--profile NAME` repeatedly, `--require workspace_edit,test_execution,local_cancellation`
for the needed capabilities and `--task-timeout 180s` for the intended duration.
The default requirements cover identity, editing, tests, permission denial and
cleanup. Admission and freshness are mandatory even if fewer capabilities are
requested. Unknown/duplicate requirements fail before profile inspection.

Each lane's `assignment_preview` explains eligibility. Expired admission,
insufficient duration, missing capability evidence, incomplete history and a
latest dated failure of ordinary work or a requested capability prevent preview eligibility. It does not
select a winner, launch a task, reserve capacity, or enable automatic fallback.
Actual assignment continues through the existing exact provider adapter and
its fresh admission checks.

`task_statistics` counts verified completions, failures, cancellations and
unresolved observations separately. Mean local elapsed seconds covers only
measured completed/failed attempts in the inspected history. These are descriptive
samples, not a representative provider ranking. Billing cost remains unavailable;
human interventions remain unrecorded unless an external acceptance record
actually measured them. Local slots, attempts and billed usage stay separate.

## Request usage evidence imports

`provider codex import-usage-evidence --profile NAME --operation-id ID --template`
prints a local ledger-bound template. Provider account/request digests, source
digest, usage and timestamps remain empty until actual evidence is supplied.
To retain a review, provide absolute `--evidence-file`, `--source-file` and a new
`--output` path. Inputs must be regular files no larger than one MiB. The strict
record rejects unknown/duplicate/case-ambiguous keys, mismatched local references,
changed source bytes, absent provider reference digests, nonterminal states,
wrong units, negative/missing usage and incomplete settlement windows.

The importer hashes the supplied source without retaining its text. It reports
consistency against the selected local profile and operation; it cannot prove
that the selected profile owns a legacy operation or authenticate a provider
account/request merely because the record says so. Even a valid record remains
`external_source_review_required` with `provider_association=unverified_source_claim`.
No import changes accounting, releases unknown usage, grants admission or creates
a qualification. Original-request settlement does not cover other outstanding
requests or an entire account.

`provider codex settle-reviewed-usage --profile NAME --operation-id ID
--evidence-file FILE --source-file FILE --review-file FILE` verifies a separate
pinned-owner signed source review. The review must bind the exact source bytes,
evidence, identity, request/account references, operation binding and reservation
nonce. Its authentication and request-association statements are the reviewer's
attestation, not a provider signature. The importer cannot create that authority.
Only `--apply` settles the exact matching reservation under the shared store lock.
Duplicate identical settlement is idempotent; conflicting settlement, active
leases and legacy reservations without a matching binding/nonce are refused.
Neither a successful preview nor local settlement grants qualification. The
original unbound Z.ai reservation still needs an authoritative request association.

## Credential continuity findings

The canonical primary profile manifest includes runtime home, account alias,
runtime/model/policy and broker selections; it excludes credential contents.
The existing refresh path already preserves identity for an unchanged Codex
account ID or an unchanged Claude refresh-token lineage, while enforcing a
fresh subscription snapshot. The refreshed Claude profiles use different homes,
so their identities differ. A rotated opaque Claude token fails the existing
continuity test; local account-owner metadata can support a fresh binding but
does not authenticate the replacement token's provider account.

`provider credential refresh-snapshot --verify-account` supports rotated Claude
tokens when `--account-binding-file` and `--account-binding-sha256` pin the
original reviewed binding for the exact profile and runtime. It sends the fresh
token only to Claude's fixed authenticated profile endpoint, refuses redirects,
and requires the returned account and subscription to match. No generation is
requested. Diagnostics contain no response body, account UUID or token. Apply
preserves a private backup and checks the destination has not changed before
replacement. Runtime home, identity and qualification remain unchanged; neither
credential refresh nor account verification extends qualification expiry.

## Grok session capability inspection

The pinned Grok 1.0.13 runtime (SHA-256
`edf79521581bb5e6b95abef848491a6a742e860da3e237ebe86a280d30dce4c1`)
advertised session loading, resume and close in a valid protocol-1 initialization
on September 6, 2026. The inspection used an empty credential-free home, sent
only `initialize`, created no session and made no generation calls. The process
was reaped. These are advertised capabilities, not successful lifecycle tests.

Shared `resume --provider-profile NAME --operation-id CHILD --parent-session
PREDECESSOR --cwd WORKTREE --prompt TEXT --timeout DURATION` uses the completed
predecessor operation ID for Grok ACP. Its signed session, exact identity/runtime,
workspace verification and cleanup must pass before an immutable successor claim
is created. A second owner cannot fork that predecessor after controller restart.
Uncertain claims remain quarantined. The runtime must advertise and acknowledge
`session/resume`; mismatched sessions and replayed history are rejected before a
new prompt. `provider session close --profile NAME --operation-id CLOSE
--parent-operation PREDECESSOR --cwd WORKTREE` uses the same ownership path and
requires advertised close. It sends no generation prompt and cannot dispatch to
another provider. Each turn has a distinct signed receipt and operation binding.
An acknowledged, identity-bound cancellation with observed cleanup and capacity
release can authorize close, but cannot authorize another resumed coding turn.
The pinned Grok response must report `x.ai/closeOutcome=closed`; empty,
`notResident`, and `superseded` responses do not establish a successful close.

`provider evidence --require session-resume --restart-of PREDECESSOR` requires a
verified next-turn completion linked to its verified predecessor. Implemented or
advertised capabilities remain untested until actual evidence is recorded. A
live two-turn exercise must still establish permission boundaries and capacity
release; offline fixtures do not establish live provider readiness.

On September 6, the reliability campaign completed the common order importer
through Grok and Claude in approximately 50 and 31 seconds respectively, including
controller overhead. Both completion-evidence checks passed and original tests
remained unchanged. Claude's existing home first moved from expired to eligible
through one authenticated same-account refresh, without rewriting qualification.
The second Grok turn acknowledged the original session but produced no tool or
assistant events before its 180-second deadline. Its signed cancellation was
acknowledged, local cleanup observed zero residuals, and local capacity released.
This is failed resumed coding, not a successful two-turn acceptance. Both Grok
attempts and the single Claude attempt are spent; billing cost remains unknown.
The earlier campaign-route rejection occurred before any operation was dispatched.
The subsequent close-only operation timed out during initialization, before
authentication or a generation prompt. Its signed diagnostic records that stage
and observed local cleanup. Provider session closure remains unproven, and its
successor claim remains held; neither elapsed time nor local cleanup authorizes
another owner to reuse the session.

ACP distinguishes [resume](https://agentclientprotocol.com/announcements/session-resume-stabilized)
from [close](https://agentclientprotocol.com/announcements/session-close-stabilized).
An advertised method or a successful fresh restart cannot establish either
provider session cleanup or remote generation termination.

## Explicit qualification scope and environmental failures

`provider qualify --scope workspace` and `provider compare --scope workspace`
return success when the signed authoritative workspace subset passes. The default
`--scope full` still requires the full suite. JSON includes `requested_scope` and
`scope_passed` beside the unchanged signed receipt; a six-gate workspace success
never rewrites its full nine-gate result. Workspace scope cannot be combined with
identity-only or headless-lineage qualification. A qualification failure directs
the operator to saved evidence, not to an automatic paid retry.

Runtime version-probe failures are reported as closed environmental reasons,
without process output or credential-bearing paths. A canceled prerequisite
cannot start a local provider process. Primary terminal diagnostics distinguish
`environment_start_failed` from a provider runtime error. Managed assignment
preparation compares wall-clock change with monotonic elapsed time before spending
an attempt; an unexplained clock step requires fresh prerequisites. Startup
failure does not establish cleanup, completion, remote termination, or settlement.

Capacity has three separate dimensions: local process slots, durable experiment
dispatch attempts, and provider billing usage. Runtime adapters may make several
provider requests inside one experiment attempt; native API tool rounds reserve
one attempt per HTTP generation request. Campaign limits are not billing limits,
and releasing a local process slot never settles unknown provider charges.

`provider codex reconciliation-plan --profile NAME --operation-id ID` includes
the original local operation reference and timestamp, plus concrete evidence
fields and acquisition sources. A local operation binding hash cannot by itself
prove the provider request/account association. Obtain that association, terminal
usage/units and settlement coverage from an account-owner export or provider
support. The current aggregate endpoints alone do not establish that association.

## Safe Codex runtime failure diagnostics

Both qualification and ordinary assignments preserve the first runtime error's
event category and closed message hint, plus counts of known exec event types.
Unknown event names and all error text, arguments, paths and credentials are
discarded. The unsigned observation is saved before cleanup/signing; the ordinary
assignment also binds these fields into its signed outcome. Unsigned diagnostics
never qualify a provider. Optional fields leave historical signed hashes intact.
Grok ordinary receipts also carry the redacted protocol observation, including
broker-rejected-call counts even without a qualification audit file. The counter
records rejected tool calls; it does not identify the protected resource or prove
that every permission boundary was exercised.

Codex baseline `b194851` discarded structured error information and retryability
in its exec formatter. The corrected fork emits optional closed error categories
and `will_retry`; the NTM adapter retains only known categories and a boolean
retry observation. It discards nested details and unknown values. Older producers
still report unavailable/unknown. A retry notification is not terminal; a later
terminal failure always ends retrying. Message hints remain separate from error
codes, and neither field authorizes another paid attempt.

The September 6 corrected-runtime qualification recorded `unauthorized` with
`not_retrying`, before any tool event. Only local cleanup passed (one of nine
checks); no ordinary Codex task followed. This identifies an authorization
failure, not a demonstrated tool-registration failure. The new runtime hash was
`4765e0e3e4792b8de5cf9781ecaad5bee6f385545b6eddbe24b052ed4eda7cf1`.
It used the already verified official 0.153.0 tool host, pinned independently:
the local tool-host rebuild could not download its V8 150.4.0 archive (HTTP 404).
The account home and model were unchanged, and this result does not qualify the
new profile or authorize an automatic retry after credential changes.

The common diagnostic projection also preserves tool counters, startup warnings
and model-conflict observations for ordinary assignments. `event_after_terminal`
is an accepted diagnostic failure category, so that failure cannot prevent saving
the observation. Regression fixtures cover nested/flat errors, malformed shapes,
unknown text, credential redaction, first-error retention, invalid counters and
pre-signing storage without readiness promotion. Another paid Codex attempt still
requires new authorization and a relevant change or diagnostic evidence.

## Operator actions and conditional attempts

`provider readiness` / `provider preview` includes an `operator` projection in
JSON and plain-language next actions in the existing display. Workspace evidence,
credential expiry, lifecycle evidence and current admission remain separate.
`attempt_ceiling_remaining` is the campaign's unused ceiling. `authorized_attempts`
is zero for a missing or exhausted campaign and null when positive unused slots
have conditions the controller cannot evaluate. Inspect the bound authorization
before dispatch. Bind a conditional slot with `provider campaign --id ID
--slot N --slot-purpose workspace --slot-identity-sha256 IDENTITY_SHA
--authorization-sha256 AUTHORIZATION_SHA`. The immutable condition is checked in
the same transaction as attempt reservation, survives restart and cannot be
overwritten. `qualification` and `resume` are also supported purposes. Only the
qualified managed workspace routes emit `workspace`; generic experiments and
qualification retries cannot spend that slot. Existing ceilings without bound
conditions still require review of their original authorization.

The September 6 resolution inspection authenticated the owner's newer Codex o08
snapshot against the fixed usage endpoint and verified the original account.
The older isolated snapshot returned 401 despite a future claimed expiry. The
existing refresh command preserved a private backup and the same runtime identity.
One newly scoped qualification then returned `usageLimitExceeded`, not retrying,
before tools. The same account's authenticated usage response confirmed the weekly
window at 100%, `allowed=false`. The conditional ordinary task remains unspent.

`provider credential quota --profile EXACT_CODEX_PROFILE` performs a fixed,
authenticated usage GET using that profile's token and account header, verifies
the returned account, and emits only a hashed account, observation time, decision
and reset time. No generation, token refresh, credit reset or attempt reservation
occurs. Redirects, missing authority, invalid windows and unreviewed additional
model buckets fail closed. Primary Codex qualification performs this check before
claiming its experiment or spending the campaign slot. Ordinary Codex work checks
before claiming a new operation; completed receipt replay does not require quota.
An available observation is not a guarantee of capacity at a later instant.

## Grok execution-stage observations

For pinned Grok 1.0.13, the controller snapshots the existing unified log inode
and offset immediately before writing the prompt. Before cleanup and signing it
extracts only `prompt received`, `shell.prompt.queued`,
`shell.handle_prompt.start`, and `shell.turn.inference_start` counts for the
selected session and the receiving process. `shell.turn.inference_retry` adds
sampler retry counts, HTTP retry counts, and the latest closed error category,
attempt and configured retry limit. Other messages and context stay private,
including retry reason text, endpoint URLs and sampler request identifiers.
Logs absent, malformed or over the four MiB budget remain explicitly
unavailable or incomplete. The matching terminal ACP response is separate.

The producer contracts are in grok-build revision
`bb7f39d5858cbf5e00de639367f59debbdcb0138`, `acp_agent.rs`,
`acp_session_impl/prompt_queue.rs` and `acp_session_impl/turn.rs`.
Inference start precedes sampler submission: it does not prove a network request
reached xAI. These diagnostics neither establish remote cancellation nor grant
qualification. Missing execution fields retain the canonical form of historical
signed receipts. Tests distinguish receipt, queue, dispatch and inference, reject
other processes and unbound history, and check historical serialization.

Sampler-internal retries do not increment `inference_start`. The retained
September 7 resumed turn reported seven `http` retries (attempts 1 through 7,
configured limit 15) before cancellation, despite only one inference-start
marker. This is transport-failure evidence, not proof of a silent deadlock or
remote acceptance. The producer is `acp_session_impl/sampling_events.rs`;
the closed category vocabulary is `xai-grok-sampler/src/events.rs` at the same
pinned revision. Retrospective log analysis remains unsigned supporting evidence;
existing receipts are never rewritten to add these fields. Zero retry fields
are omitted to preserve both pre-execution and execution-era signed bytes.

The isolated Grok environment now pins `GROK_MAX_RETRIES=0`, overriding ambient
and model retry defaults through the reviewed sampler's existing setting. It also
pins `GROK_DOOM_LOOP_RECOVERY=0` and `GROK_TURN_TRANSIENT_RETRY=0`: those independent
resampling layers do not consult the sampler's transport retry limit. Controller
campaign attempts remain separately counted. These settings do not bound every
request made by other runtime subsystems or by the underlying HTTP library,
prove remote acceptance, or measure billable usage. The controller deadline and
campaign ceiling still apply. Changing this pin requires a reviewed policy change.

The local source patch for grok-build preserves a closed `transport_cause=...`
marker across the sampler's non-Clone HTTP error conversion, which otherwise loses
the underlying source chain. NTM accepts only its exact category vocabulary from
the bound session/process retry or terminal inference-failure event. Older runtime
prose remains `unknown`; no substring interpretation of endpoint URLs or payloads
grants a cause. Categories are diagnostic observations, never admission evidence.
The source patch requires a separately pinned runtime qualification before it can
replace the installed provider runtime. No existing receipt is rewritten.

The retained September 7 broker regression establishes a host-clock reversal:
the successful `go-vet` command's completion precedes its start by about 66 ms.
Full safe audit receipts now survive a failed test's cleanup in test output.
Timestamp-order validation remains strict. A rerun on a stable clock does not
erase that failure or demonstrate that host-clock stability has been repaired.
The noisy-pane test now waits for the static marker and for actual window activity
to advance beyond its first observation instead of assuming a fixed sleep suffices.

## Clock correction evidence

The earlier v2 command receipts carried a one-based sequence and start/end
elapsed nanoseconds measured from one process-local monotonic origin. UTC remains
unchanged. The optional timing object survives JSON serialization, while its absence
preserves historical receipt bytes. Deterministic tests step the wall clock forward
and backward without altering monotonic ordering. These fields are diagnostic only:
the existing UTC bounds, signed identity, manifest, command, isolation, process wait
and cleanup checks still apply.

A September 7 recurrence recorded go-vet taking 2.258825362 seconds by monotonic
time while UTC moved backward 330.271693 milliseconds. That failed qualification
evidence remains rejected. Neither successful commands nor a later green rerun
authorize relabeling it. The observed host had Windows Time stopped and Linux NTP
reporting an approximately -2.56 second offset; competing clock correction is an
investigation hypothesis, not an established attribution to a particular service.

New broker audit v2 and verifier receipt v3 now implement the execution-timing
contract. The broker mints one random domain and retains a process-local monotonic
origin with a five-minute maximum deadline. Its context carries that exact clock
into verification. Ordered tool spans must share the header's domain and deadline;
verification must fit inside its tool event, and consecutive command spans must
fit inside verification and their controller-approved timeouts. The signed outer
qualification continues to bind the exact profile, process, manifest and evidence.
These fields are controller evidence, never provider-supplied duration claims.

UTC observations must still lie inside the trusted qualification interval, and
receipt freshness, signature expiry and identity admission retain their UTC checks.
Historical audit v1/verifier v2 evidence continues to require ordered UTC. Adding
new timing fields to an old schema, missing a domain, crossing domains, overlapping
events or commands, exceeding a deadline, and moving outside UTC bounds all fail.
No old receipt is rewritten or promoted. Deterministic serialized-audit fixtures
cover forward/backward wall corrections and these rejection cases. See Go's
[monotonic clock contract](https://pkg.go.dev/time#hdr-Monotonic_Clocks): serialization
does not preserve a live Go clock; only one controller may interpret its domain.

The September 7 host repair started Windows Time and produced three successful
forced synchronization cycles, followed by 150 seconds with no backward samples
on Windows. The simultaneous WSL observation still had five backward samples
(largest observed reversal approximately 573 ms). The guest clock-source experiment
is pending; host repair alone does not clear the live qualification clock gate.

## Historical Z.ai reservations without nonces

`TestZaiSupportResponseFixturesPreserveOriginalReservation` runs synthetic support
responses through `provider codex import-usage-evidence`: sufficient for source
review, missing final usage, unknown outstanding liability, incomplete cutoff,
a later operation, a different local account, and complete-account-window evidence.
It verifies that rejected responses still persist digest-bound review reasons and
that every original reservation remains byte-for-byte unchanged. A different but
well-formed provider account/request claim deliberately remains **unverified**:
structural validation cannot authenticate the source or prove its association.
Complete-window evidence needs a separately reviewed migration; the current
request-only importer does not reinterpret it or clear nonce-less reservations.

## One-command comparison across configurations

Use `provider readiness --profile first,second --profile-config first=/absolute/first.toml
--profile-config second=/absolute/second.toml --json` to inspect profiles whose
evidence lives in different configuration-specific ledgers. Bind every selected
profile exactly once. Duplicate, unknown, relative or incomplete bindings fail
before inspection; there is no implicit fallback to another ledger.

Each profile uses the same executable's existing readiness command in a separate
process, sequentially, with a one-minute deadline and 8 MiB output ceiling. This
preserves configuration isolation without swapping the controller's environment.
The combined observation validates the exact profile identity, configuration hash
before/after inspection, and ledger path. Each lane includes `source` with the
configuration path/hash, ledger path and observation time. Existing signed receipt
observations, individual capabilities, qualification expiry, account/model/runtime
identity and capacity remain intact. Configuration hashes describe the selected
global file; normal project policy overlays still apply. This is a current local
observation, not a signed portable authorization or an atomic cross-ledger snapshot.
It grants no dispatch, renews no evidence, and performs no generation or quota poll.
When a campaign is selected, the same campaign ID is inspected in each selected
configuration's campaign store; purpose and external authorization still apply.

## Resolving the historical reservation

The existing reconciliation plan now spells out the missing historical evidence.
Exact nonce settlement cannot accept the original nonce-less reservation. Do not
manufacture a nonce, rewrite its identity, or infer provider correlation from a
nearby timestamp. Obtain either authenticated original request correlation and
terminal charge/units/settlement coverage, or authoritative coverage of every
request and outstanding liability in the affected account/window. Preserve the
source and review its digest before applying an atomic migration.
Current aggregate quota, local reset estimates and an unsigned support claim do
not satisfy that requirement. This plan makes no ledger mutation or admission grant.

`provider codex settle-reviewed-usage --profile NAME --operation-id ORIGINAL
--inspect-legacy-reservations` exposes fingerprints of local nonce-less rows. A
fingerprint includes the exact identity and persisted row; it supplies no provider
association. The pinned owner reviewer must sign a source-review v2 record with
that `legacy_reservation_sha256`, an empty `nonce_sha256`, and
`legacy_association=exact_local_reservation_associated_with_authenticated_original_request`.
The existing authenticated source, provider account/request, original operation,
terminal charge and settlement-coverage checks remain mandatory.

Supply `--evidence-file`, `--source-file` and `--review-file` to preview against the
current authoritative store, then `--apply` to commit. Both use the same transaction
engine as contemporary nonce settlement. Migration requires exactly one unknown
row, the unchanged reviewed fingerprint, no active plan leases, and no conflicting
prior recovery. It preserves the absent nonce and original binding, storing separate
settlement provenance. A repeated identical review survives restart without charging
twice; changed review, binding or charge fails. Storage failure does not fall back to
local accounting. Offline tests exercise the CLI with signed synthetic evidence and
independent controllers contending on the actual shared file transaction.

This migration handles an authenticated original request only. Complete-window
evidence without exact request association still needs a separately reviewed contract.
Accounting settlement does not mark the old task complete, prove served-model
identity, authorize a qualification or spend the reserved strict preflight.

## Repeatable scanner disposition checks

`go run ./scripts/provider-scan-review --root ABSOLUTE_PROJECT_ROOT
--review REVIEW.csv --review-sha256 SHA --findings CURRENT.csv
--findings-sha256 SHA --raw RAW_REPORT --raw-sha256 SHA` verifies pinned artifacts
and matches every current finding to a reviewed disposition on exact source bytes.
Both CSV files use the existing seven-column schema:
`severity,rule,file,line,source_sha256,disposition,reason`.
The raw report must now be a complete ast-grep JSON array. The checker derives
every normalized finding directly from that pinned report and current source.
The current CSV is optional; if provided, it must equal the raw report's complete
multiset, including duplicates. `--normalize` emits that complete CSV for review
without granting a verdict. Summary JSON and capped text reports are rejected
because they cannot establish extraction completeness. This closes the supplied
CSV omission gap, but covers only that ast-grep report: UBS's separate heuristics
and summary totals still require their own raw review. The output identifies this
scope explicitly. It rejects an empty inventory, changed source, new/changed locations or
rules, extra duplicates, invalid dispositions, changed artifact hashes and paths
outside the source root. It never edits reports, changes severity or grants
provider readiness. Success means the reviewed inventory matches, not that the
raw scanner passed. A raw report with no findings should use its own clean result.
