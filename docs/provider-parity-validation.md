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
