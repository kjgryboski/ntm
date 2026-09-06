# Managed provider validation

Workspace admission and lifecycle evidence are separate. An ordinary assignment
requires current signed identity, edit, verification, denial and cleanup checks
for its exact profile, runtime and policy. Successful completion additionally
requires the exact runtime terminal event, independent workspace verification,
cleanup and the appropriate local capacity release. Local cancellation does not
establish remote generation termination or resume support.

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
The common assignment workflow does not implement provider session resume. Adding
that capability requires provider-specific session persistence and identity-bound
protocol evidence. Local cancellation and fresh restart do not establish remote
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
requests or an entire account. Authoritative source verification and atomic
reconciliation remain separate work once genuine evidence is available.

## Credential continuity findings

The canonical primary profile manifest includes runtime home, account alias,
runtime/model/policy and broker selections; it excludes credential contents.
The existing refresh path already preserves identity for an unchanged Codex
account ID or an unchanged Claude refresh-token lineage, while enforcing a
fresh subscription snapshot. The refreshed Claude profiles use different homes,
so their identities differ. A rotated opaque Claude token fails the existing
continuity test; local account-owner metadata can support a fresh binding but
does not authenticate the replacement token's provider account.

Separating stable account identity from credential leases therefore needs an
authenticated account-binding observation tied to each replacement token, plus
an explicit runtime-state migration policy. Keep qualification and credential
expiry separate, but do not extend the 24-hour qualification window or transfer
evidence across runtime homes simply because account aliases match. The current
investigation does not relax these rules.

## Grok session capability inspection

The pinned Grok 1.0.13 runtime (SHA-256
`edf79521581bb5e6b95abef848491a6a742e860da3e237ebe86a280d30dce4c1`)
advertised session loading, resume and close in a valid protocol-1 initialization
on September 6, 2026. The inspection used an empty credential-free home, sent
only `initialize`, created no session and made no generation calls. The process
was reaped. These are advertised capabilities, not successful lifecycle tests.

The shared controls still do not implement persistent-session resume. Connecting
it requires a durable checkpoint bound to the exact identity, runtime, workspace
and session; exclusive ownership across controllers; and a distinct ledger
operation for each resumed turn. Unknown outcomes must remain quarantined.
Qualification must prove a second turn uses the original session, preserves the
permission boundary and releases local capacity. It must test refused or missing
sessions and controller interruption without duplicate work.

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

Source baseline: Codex fork commit `b194851`, `codex-rs/exec/src/exec_events.rs`
and `event_processor_with_jsonl_output.rs`. Its `ThreadErrorEvent` contains only
`message`; the formatter discards structured error information and retryability.
Consequently this adapter explicitly reports `error_code=unavailable` and
`retryability=unknown`, even if an unreviewed event supplies extra fields. Message
hints match fixed strings in `codex-rs/protocol/src/error.rs`; they are not provider
error codes or permission to retry. Runtime failures remain fail-closed.

The common diagnostic projection also preserves tool counters, startup warnings
and model-conflict observations for ordinary assignments. `event_after_terminal`
is an accepted diagnostic failure category, so that failure cannot prevent saving
the observation. Regression fixtures cover nested/flat errors, malformed shapes,
unknown text, credential redaction, first-error retention, invalid counters and
pre-signing storage without readiness promotion. Another paid Codex attempt still
requires new authorization and a relevant change or diagnostic evidence.
