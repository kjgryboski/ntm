# NTM - Named Tmux Manager

<div align="center">
  <img src="ntm_dashboard.webp" alt="NTM dashboard">
</div>

<div align="center">

![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.26.5+-00ADD8.svg)
![License](https://img.shields.io/badge/License-MIT%2BOpenAI%2FAnthropic%20Rider-blue.svg)
![Release](https://img.shields.io/github/v/release/Dicklesworthstone/ntm?include_prereleases)

</div>

NTM turns `tmux` into a local control plane for multi-agent software development.
It combines session orchestration, graph-aware work triage, safety policy and approvals,
Agent Mail coordination, durable state capture, machine-readable robot surfaces, and a
local REST/WebSocket API in one Go binary.

<div align="center">

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ntm/main/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

</div>

## TL;DR

### The Problem

Running several coding agents in parallel is easy to start and annoying to sustain.
Plain `tmux` gives you panes, but it does not give you durable coordination, work
selection, safety policy, approvals, history, replayable automation surfaces, or a
shared control model that both humans and agents can use.

### The Solution

NTM gives you a single local system for:

- spawning labeled multi-agent sessions in `tmux`
- sending work, interrupts, and follow-ups across panes
- triaging what to do next with `br` and `bv`
- coordinating agents with Agent Mail, file reservations, and assignments
- protecting dangerous operations with policy, approvals, and guards
- exposing the whole system through `--robot-*`, REST, SSE, WebSocket, and OpenAPI
- capturing state with checkpoints, timelines, audit trails, and pipeline state

### Why NTM

| Area | What NTM provides | Typical commands |
| --- | --- | --- |
| Session orchestration | Spawn, label, inspect, zoom, dashboard, palette | `ntm spawn`, `ntm dashboard`, `ntm palette` |
| Work intelligence | Graph-aware triage, next-step selection, impact analysis, assignment | `ntm work triage`, `ntm work next`, `ntm assign` |
| Coordination | Human overseer mail, inbox views, file reservations, worktrees | `ntm mail`, `ntm locks`, `ntm worktrees` |
| Safety | Destructive-command protection, policy editing, approval workflows | `ntm safety`, `ntm policy`, `ntm approve`, `ntm guards` |
| Durable operations | Checkpoints, timelines, audit logs, saved sessions, pipelines | `ntm checkpoint`, `ntm timeline`, `ntm audit`, `ntm pipeline` |
| Automation surfaces | Robot JSON, REST API, SSE/WebSocket streams, OpenAPI | `ntm --robot-snapshot`, `ntm serve`, `ntm openapi generate` |

## Quick Start

### Requirements

NTM is a pure Go project, but the runtime experience is intentionally integration-heavy.

- Required: `tmux`
- Required for agent spawning: whichever CLIs you want to run, typically Claude Code, Codex, Antigravity CLI, or Grok Build (Gemini CLI is supported as legacy)
- Optional but powerful: `br`, `bv`, Agent Mail, `cass`, `dcg`, `pt`
- Sanity check everything with `ntm deps -v`

### First Session

```bash
# Install
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ntm/main/install.sh?$(date +%s)" | bash -s -- --easy-mode

# Enable shell integration
eval "$(ntm shell zsh)"

# Verify tools and integrations
ntm deps -v

# Scaffold a project directory
ntm quick api --template=go

# Launch a mixed swarm
ntm spawn api --cc=2 --cod=1 --agy=1

# Open the live operator surfaces
ntm dashboard api
ntm palette api

# Dispatch work
ntm send api --cc "Map the auth layer and propose a refactor plan."

# If the repo uses br/bv, inspect the work graph
ntm work triage --format=markdown

# Save a recoverable checkpoint
ntm checkpoint save api -m "before auth refactor"

# Expose local APIs for dashboards, scripts, and agents
ntm serve --port 7337
ntm --robot-snapshot
```

## Core Workflows

### 1. Multi-Agent Session Orchestration

NTM is built around named `tmux` sessions with explicit agent panes and a user pane.
It handles session naming, pane layout, agent startup, labels, and inspection so you
can treat a swarm like a manageable unit instead of a pile of terminals.

```bash
ntm quick payments --template=go
ntm spawn payments --cc=3 --cod=2 --agy=1
ntm add payments --cc=1
ntm list
ntm status payments
ntm view payments
ntm zoom payments 3
ntm attach payments
```

#### Grok Build

NTM recognizes the official xAI Grok Build CLI as the canonical `grok` agent
type. Install it using [xAI's current instructions](https://docs.x.ai/build/overview),
then authenticate without putting credentials in NTM configuration:

```bash
curl -fsSL https://x.ai/cli/install.sh | bash
grok login                   # browser authentication
grok login --device-auth     # SSH/headless alternative
ntm deps -v
```

A bare spec delegates model selection to Grok Build. Use `grok models` to inspect
the models available to the authenticated account, then pass an exact model ID
only when an override is needed:

```bash
ntm spawn research --grok=1
ntm spawn research --grok=1:MODEL_ID
ntm spawn research --grok=1:MODEL_ID:EFFORT
ntm --robot-spawn=research --spawn-grok=1
ntm --robot-spawn=research --spawn-grok=1 --spawn-wait --timeout=30s
ntm --robot-spawn=research --spawn-grok=1 --spawn-wait --spawn-assign-work --strategy=dependency-aware
```

Provider-native automation uses Grok's ACP JSON-RPC transport as the primary
automation path rather than screen scraping. One-shot runs launch
`grok --no-auto-update --sandbox=read-only --permission-mode=dontAsk <allow/deny rules> [--model EXACT_MODEL] agent stdio`,
apply the named `grok-readonly-ci` policy, and return a nonce-bound receipt
containing provider session/completion metadata plus redacted hashes and cleanup
evidence. Exact-identity admission applies a separate, cross-process local shared
concurrency/token budget, backoff, and circuit state to each exact provider,
account, model, endpoint, runtime, credential class, billing class, entitlement,
and config tuple, and never changes provider on denial. The default observe
policy is deliberately read/search-only. The separately named workspace policy
runs only in a linked disposable worktree, uses the strict sandbox, permits
edits, and denies provider-run shell/web operations, credential-path reads,
pushes, destructive commands, and approval bypasses. Model-edited tests are
never executed inside the credential-bearing provider process.

Bind each ACP run to an exact non-secret provider profile. The `command` field
is the executable path passed directly to the operating system, not a shell
command, and optional CLI model/binary flags are assertions rather than
overrides:

```toml
[provider_profiles.xai-grok-primary]
provider = "xai"
account_alias = "kevin"
model = "YOUR_EXACT_GROK_MODEL"
endpoint = "https://api.x.ai/v1"
runtime = "grok"
config_sha256 = "YOUR_64_CHARACTER_LOWERCASE_REDACTED_CONFIG_SHA256"
command = "/usr/local/libexec/ntm/grok-1.0.13"
automation_policy = "grok-readonly-ci"
exact_target_only = true
```

```bash
ntm --robot-grok-acp-run --provider-profile=xai-grok-primary --msg='Inspect the repository and report the relevant files and findings.'
ntm --robot-grok-acp-run --provider-profile=xai-grok-primary --msg-file=/tmp/prompt.txt --provider-model=MODEL_ID --op-id=audit-42
ntm --robot-grok-acp-receipt=audit-42
ntm --robot-provider-conformance --provider-profile=xai-grok-primary --provider-transport=xai_acp
ntm --robot-provider-capabilities
```

The receipt is successful only when Grok reports structured completion and the
assistant stream echoes the generated nonce exactly. It records only hashes,
counts, provider session/model/usage metadata when supplied by ACP, and local
exit/cleanup evidence when observable. When the caller cancels an accepted
prompt, NTM sends the ACP `session/cancel` notification and accepts cancellation
only when that exact original `session/prompt` response returns
`stopReason=cancelled`. This is authoritative at the local Grok ACP-agent
boundary, not proof that xAI stopped cloud inference. Local process-tree
termination, residual-PID inspection, and reaping are recorded separately. A
missing cancellation acknowledgement remains `DISPATCH_UNKNOWN`, not an
invitation to replay blindly. NTM never serializes the prompt, nonce,
credentials, raw output, or raw tool arguments in the receipt. Automated ACP starts with a minimal environment that
explicitly removes `XAI_API_KEY` and all proxy variables (proxy URLs may embed
credentials), then authenticates only with the local Grok CLI's `cached_token`;
it fails with `GROK_ACP_CACHED_AUTH_UNAVAILABLE` when no cached login is offered.
An exported API key is never an automated fallback.

Exact Grok model identity is confirmed only by completion metadata or an xAI
structured notification bound to the returned provider session and the exact
selected model. A provider model catalog proves availability only, so it is
retained as transport observation but cannot make a robot operation succeed.

An identity is **runtime-attested** only for fields the structured provider
protocol actually returns in the receipt (for example, a Grok ACP session ID,
completion status, or model observation). The remaining fields in a configured
profile are **profile-attested**: NTM hashes and binds the operator-supplied
tuple, but does not claim the opaque provider runtime independently proved
them.

Operation IDs are durable and binding-sensitive. The binding covers the exact
provider identity, logical prompt hash, working-directory hash, canonical
executable-path hash, and compiled policy digest; the receipt separately hashes the exact
nonce-bound packet. This allows a normal retry with an omitted/generated nonce
to replay the recorded safe outcome without another provider call. Conflicting reuse returns
`IDEMPOTENCY_CONFLICT`; an abandoned in-progress operation remains
outcome-unknown and is never taken over automatically. Use
`--robot-grok-acp-receipt=OPERATION_ID` to inspect it without dispatch.

Interactive Grok panes remain a compatibility path. Their default launch also
uses `--no-auto-update`, the `read-only` sandbox, and the `grok-readonly-ci`
allow/deny policy; it does not grant broad approval. Panes participate in readiness waits, exact-pane prompt
delivery and assignment, interrupt-with-message, restart, and restore-time
relaunch. For stronger spawn evidence, combine `--spawn-wait` with
`--spawn-assign-work` so the spawn response does not succeed until NTM has
observed an authenticated empty composer. Assignment dispatch performs its own
fresh safety observation even when `--spawn-wait` is omitted.

xAI does not publish a passive TUI-readiness protocol. NTM therefore recognizes
the bordered composer and live working chrome observed in authenticated Grok
Build sessions and fails closed when that evidence is absent. A welcome banner,
login/device-auth screen, modal, error, rate limit, bare shell, pre-filled
composer, or active turn does not satisfy the spawn readiness gate. Readiness
receipts include a stable `ready_reason`: `READY` or a reason-coded `UNREADY_*`
state such as `UNREADY_AUTHENTICATION_REQUIRED`, `UNREADY_ACTIVE_TURN`,
`UNREADY_RATE_LIMITED`, `UNREADY_COMPOSER_MISSING`, or
`UNREADY_PROVIDER_CHROME_MISSING`. Detection receives the actual tmux pane
width so wrapped narrow panes do not silently lose the live tail needed for a
safe decision. UI changes in a future Grok release may cause a bounded readiness
timeout until NTM's redacted fixture matrix and capture patterns are updated.
Persona injection remains unsupported because Grok Build does not expose a
system-prompt launch surface.

#### Z.ai provider profiles

Z.ai is an explicit provider lane, not a broad `claude`/`cc` target. Use an
exact configured profile with the provider, account alias, model, endpoint,
runtime, and redacted configuration digest bound into one immutable identity:

```bash
ntm --robot-spawn=research --spawn-zai=2 --provider-profile=zai-team-model
ntm --robot-provider-conformance --provider-profile=zai-team-model --provider-transport=zai_claude_runtime
ntm --robot-provider-capabilities
```

```toml
[provider_profiles.zai-team-model]
provider = "zai"
account_alias = "team"
model = "glm-5.3-flash"
endpoint = "https://api.z.ai/api/anthropic"
runtime = "claude-code"
runtime_version = "YOUR_REVIEWED_CLAUDE_CODE_VERSION"
credential_class = "coding_plan"
billing_class = "coding_plan"
entitlement = "claude_compatible"
config_sha256 = "YOUR_64_CHARACTER_LOWERCASE_REDACTED_CONFIG_SHA256"
command = "claude"
automation_policy = "zai-readonly-ci"
exact_target_only = true
probe_required = true
model_probe_state = "unprobed"
model_probe_receipt_sha256 = ""
```

The separately billed native lanes use a different identity and OS-brokered
API credential. The no-tool profile is:

```toml
[provider_profiles.zai-native-no-tools]
provider = "zai"
account_alias = "team-api"
model = "glm-5.3"
endpoint = "https://api.z.ai/api/paas/v4/chat/completions"
runtime = "zai-api"
runtime_version = "zai-native-http-v1"
credential_class = "api_key"
billing_class = "api_usage"
entitlement = "native_api"
config_sha256 = "YOUR_64_CHARACTER_LOWERCASE_REDACTED_CONFIG_SHA256"
command = ""
automation_policy = "zai-native-no-tools-v1"
exact_target_only = true
probe_required = true
```

For controller-owned coding tools, use the same immutable native identity
fields with `automation_policy = "zai-native-tools-v1"`. That policy exposes
only bounded list/read/write operations in a linked disposable worktree and a
fixed isolated verification manifest; it never exposes an arbitrary provider
shell, credential paths, network access, or Git push.

For the Claude-compatible Z.ai lane, the selected profile must use the official
`https://api.z.ai/api/anthropic` endpoint and `claude-code` runtime. Its
`command` is an executable only: NTM generates the exact endpoint/model and
restricted policy (`--restricted`, `--safe-mode`, strict MCP, no slash
commands/Chrome, and only `Read,Glob,Grep,WebSearch`; Bash/Edit/write tools
are denied). Before any tmux mutation, production launch runs a fresh zero-tool,
no-session-persistence Claude stream-JSON probe. It must return the nonce in a
successful result for the same session whose initialization names the exact
model; otherwise launch is NO-GO. The probe requires the explicitly Z.ai-scoped
`ZAI_API_KEY`; a generic `ANTHROPIC_AUTH_TOKEN` is never forwarded. The provider
child receives only a canonical `ANTHROPIC_AUTH_TOKEN` mapped from that key plus
a minimal runtime environment; it
does not inherit unrelated xAI, AWS, GitHub, or other credentials. The tmux
server must also have inherited `ZAI_API_KEY`: the compiled
pane command fails with `NTM_ZAI_AUTH_REQUIRED` when it did not, and NTM does
not claim that a profile or preflight proves tmux credential delivery.

The profile identity remains profile-attested; the provider-capability receipt exposes
only safe identity hashes and probe state—never commands, endpoints, API keys,
or raw configuration. It also advertises the offline fake-runtime conformance
harness, which exercises launch, nonce delivery, cancellation semantics,
recovery, resumption, rate-limit classification, and cleanup against redacted
fixtures. That harness makes no provider or network call and is not a live
qualification receipt.

Current Z.ai Coding Plan documentation explicitly lists GLM-5.3 and
GLM-5.3-Flash for all plan tiers and names `glm-5.3-flash` as a Claude Code
model identifier. Documentation availability is still not account/plan
entitlement. If the local Claude client cannot emit session-scoped exact-model
evidence, production Z.ai launch remains NO-GO while dry-run/profile identity
discovery stays available.

Capability discovery never calls a configured profile “launchable”: xAI
profiles report `operation_evidence_required`, while Z.ai profiles report
`live_probe_required`. A successful Z.ai preflight is recorded as
`live_verified` only in that spawn operation and its bound pane metadata; a
similarly named value written into configuration remains a diagnostic claim,
not qualification evidence.

Capacity evidence is transport-specific. Native Grok ACP calls are governed per
exact identity by a cross-process local shared concurrency lease, token bucket,
backoff, and circuit state. The Z.ai preflight and first authorized pane launch share one exact-
identity admission, and structured live preflight errors update the same
rate-limit/overload/permanent-error circuit. For the resulting Claude-compatible
TUI, NTM still cannot
observe or govern the runtime's individual model calls or live business-error
responses. The capability matrix therefore reports Z.ai request-capacity control
and TUI live error feedback as `unavailable`; the complete Z.ai taxonomy is
exercised by the offline conformance harness, while exact structured errors
seen during live preflight are classified without guessing from prose. NTM
never silently fails over to a different provider identity.

`--robot-provider-conformance` is deliberately synthetic and offline. It is a
fixture-backed adapter contract check, not live-provider qualification. For an
opt-in no-write live Grok ACP check, run
`NTM_LIVE_GROK_ACP=1 NTM_LIVE_GROK_MODEL=grok-4.6 go test -tags=integration ./internal/grok -run '^TestLiveACPReadOnlyRoundTrip$' -count=1 -v`
only in an authenticated Grok environment you are authorized to use.

#### Provider readiness, policy ownership, and live qualification

An exact provider identity is immutable and non-secret. It binds the provider,
account alias, model, normalized HTTPS endpoint, runtime, credential class,
billing class, entitlement, and the SHA-256 of a redacted configuration
manifest. The resulting identity hash is the admission, circuit, receipt, and
qualification boundary. A profile is therefore not interchangeable with a
runtime executable, and NTM never changes identity or fails over when
admission is denied. Profile-attested identity is a safe boundary, not proof
that an opaque provider runtime currently honors every configured field.

Grok has exactly two built-in unattended policies:

- `grok-readonly-ci` is the observe policy: read/search only, read-only
  sandbox, fail-closed `dontAsk`, and no `Bash(*)` or edits.
- `grok-workspace-write-ci` is the narrowly reviewed edit policy for a
  disposable linked Git worktree. It uses xAI's `strict` sandbox, permits
  edits, and denies provider-run shell commands, web tools, pushes,
  destructive commands, approval bypasses, and credential-path reads. NTM
  rejects this policy unless the working directory is a linked disposable
  worktree. Executing model-edited tests is controller-owned and requires a
  separate OS-isolated verifier; a permission allowlist alone is not a
  credential or network boundary.

The Grok requirements document is a system-owned bypass lock, not a
per-project setting. An administrator/root process must install it once; the
installer never overwrites a different existing document and verifies both
digest and system-authoritative ownership. Every live attestation revalidates
the requirements file and its full root-owned, non-writable parent path before
Grok inspects or Bubblewrap binds it:

```bash
ntm provider policy requirements --policy=grok-readonly-ci --install --confirm
# or, when the reviewed workspace-write envelope is needed:
ntm provider policy requirements --policy=grok-workspace-write-ci --install --confirm
```

Unattended Grok also requires a canonical system-authoritative executable rather
than a user-updatable PATH entry. After reviewing the installed vendor binary,
an administrator can place the pinned version at the path named by the profile:

```bash
sudo install -D -o root -g root -m 0755 "$(readlink -f "$(command -v grok)")" /usr/local/libexec/ntm/grok-1.0.13
```

NTM fails closed if that file or any parent directory is not root-owned and
non-writable by unprivileged users. Updating Grok therefore requires an explicit
reviewed replacement and a matching `runtime_version` update.

Policy attestation requires more than parsing `grok inspect`. NTM verifies the
root-owned digest and exact system-requirements source/layer, then canonicalizes
the version-pinned Grok executable and requires both it and every parent
directory to be root-owned and non-writable by unprivileged users. It starts
that same system-authoritative binary inside a credential-free Bubblewrap
namespace with no network and requests `--always-approve`. Automation is admitted only when the
runtime emits the exact managed-policy refusal. This behavioral check also
handles Grok 1.0.13's inspect-schema warning for the documented bypass-lock key
without either ignoring the warning or making a provider request.

Run `ntm provider doctor --profile=PROFILE` for the read-only report, or add
`--online` for one bounded, no-tool identity/model probe. Doctor checks the
exact identity, pinned runtime, authorization presence, managed-policy digest
and ownership, local shared capacity/circuit state, lifecycle evidence, and,
for each Z.ai coding lane, a stored signed qualification receipt for that
transport and policy.
The online probe and offline conformance harness are not coding qualification;
for provider-native no-tool transports, the online probe is instead one of the
capability-scoped readiness gates.

Doctor reserves `GO` for a transport whose cancellation and cleanup are both
acknowledged authoritatively by the provider. `GO_SCOPED` means every required
gate for the declared operation scope passed, but lifecycle control is local or
unavailable; doctor deliberately exits non-zero so automation cannot mistake
that narrower result for Claude/Codex-equivalent lifecycle authority.
The Claude-compatible Z.ai pane transport cannot earn either `GO` state: its
opaque runtime exposes neither per-request capacity/circuit enforcement nor
structured live error feedback. A successful pane preflight or coding
qualification is evidence for those bounded checks only, never a claim that
NTM governs the pane's individual provider requests.

Native Grok ACP is the receipt-bearing one-shot route. For native headless
lineage operations, use `ntm provider session resume` or `ntm provider session
fork` with an exact Grok profile, `--session-id`, `--prompt`, and (when using
the write policy) a linked disposable worktree. These commands additionally
require a root-owned matching requirements document, a canonical
system-authoritative Grok executable, a reviewed runtime-version pin with no
drift, and the cross-process local shared capacity store. They emit
signed nonce-bound receipts that bind identity, policy, configuration and
binary hashes, worktree/working-directory hashes, admission, action,
child-session lineage, and redacted telemetry without echoing the provider
session ID or preserving the prompt. Cancellation and cleanup are authoritative
only for the locally observed process tree; they are not provider-side
cancellation acknowledgements. Arbitrary provider output, raw tool arguments,
credentials, and opaque runtime settings are not authoritative evidence.

Grok sessions retain the sandbox recorded when the parent was created, so a
resume or fork omits only the per-invocation sandbox selector while preserving
every compiled allow/deny rule from the root-owned policy. Model identity stays
fail-closed: for the reviewed Grok CLI `1.0.13`, NTM binds the selectable
`grok-4.6` alias to the exact `grok-4.6-build` token emitted by the
`streaming-json` completion's singleton `modelUsage` record. Unknown runtime
versions and model pairs require strict equality and must be requalified; no
prefix or family matching is accepted.

The local shared store coordinates concurrency, token budget, backoff, and
circuits across cooperating local NTM processes, keyed by exact identity. It
is not a fleet-wide quota service; if it falls back to process-local state,
doctor reports that degradation and native headless session resume/fork is
refused.

Z.ai has two separate authorization lanes. The Claude-compatible Coding Plan
lane uses only the deliberately Z.ai-scoped `ZAI_API_KEY`, remapped to the
Claude-compatible child token. A native Z.ai API profile is a different
immutable credential/billing/entitlement identity. Its separately authorized
key is provisioned with `ntm provider credential set --profile=PROFILE --stdin`
and read only from the OS credential broker; native execution does not fall
back to environment variables. Coding Plan credentials are not accepted for
the native lane. Native API structured completion, usage, and error records do
not confer provider-side cancellation or resume evidence.

Initialize receipt signing explicitly before any live native request or Grok
session operation:

```bash
ntm provider attestation init
```

On Linux, native Z.ai API credentials use the Secret Service directly, not a
`secret-tool` subprocess. NTM resolves the `default` collection for each
operation and refuses to use an unset alias, the ephemeral `session`
collection, a locked collection, a prompt, or ambiguous matching items. It
never creates/unlocks a collection or changes an alias. Establish and unlock a
password-protected persistent collection through the owner’s desktop/PAM
keyring flow before running `ntm provider credential set --stdin`; NTM will
otherwise fail closed.

On Windows, the current-user TPM path uses a Microsoft Platform Crypto Provider
P-256 signing key with no export policy and signing-only usage. Receipt
verification proves the signature and its declared local-controller evidence;
it is **not** remotely verifiable TPM provenance. NTM does not emit a TPM quote,
attestation certificate chain, or remote hardware proof. A same-Windows-user
process permitted to launch the bridge can request the bridge’s narrow allowed
operations, so non-exportability does not make the bridge an authorization
boundary against that user.

WSL may opt into that Windows current-user store only when direct persistent
Secret Service access is unavailable. Build the helper from the reviewed source
with the current Windows NTM checkout, then set an explicit WSL-visible path:

```powershell
# Windows PowerShell, from the NTM checkout
go build -trimpath -o "$env:USERPROFILE\.local\bin\ntm-provider-bridge.exe" .\cmd\ntm-provider-bridge
.\ntm.exe provider credential set --profile=zai-native-no-tools --stdin
.\ntm.exe provider attestation init
```

```bash
# WSL: only after the Windows profile above is configured and the helper exists
export NTM_WINDOWS_PROVIDER_BRIDGE=/mnt/c/Users/YOU/.local/bin/ntm-provider-bridge.exe
ntm provider credential status --profile=zai-native-no-tools
ntm provider attestation init
```

The bridge is invoked directly, never through a shell. It accepts only one
nonce-bound JSON request and permits WSL only to read credential status or one
credential; WSL provisioning and removal remain fail-closed. Windows also
allows those bridge reads only for exact configured Z.ai native-API profiles
whose identity has `provider=zai`, native-API entitlement, API-key credential
class, API-usage billing class, and `exact_target_only=true`. It is an
allowlist, not caller authentication. No generic credential, Coding Plan key,
or arbitrary profile can be requested through the bridge.

Receipt signing has a fixed bridge allowlist: the attestation preflight and
canonical receipt schemas `ntm.provider-native-run.v2`,
`ntm.provider-qualification.v1`, and `ntm.provider-session.v2`. The bridge
will not sign arbitrary payloads. Non-Windows receipts use an OS-protected,
process-readable Ed25519 seed; Windows TPM receipts use ECDSA P-256. Neither
receipt type upgrades local evidence into provider-side cancellation, provider
resume, or remotely attested hardware provenance.

The native no-tool API lane is an explicit single-request operation, not a
substitute for Claude-compatible coding qualification. After configuring a
separate native API entitlement, invoke it only with an explicit durable
operation identifier:

```bash
ntm provider run --profile=zai-native-no-tools --operation-id=YOUR_UNIQUE_OPERATION_ID --prompt='bounded no-tool task' --live
```

Its redacted receipt binds the operation, exact identity, and request outcome.
NTM derives a non-secret `request_id` from that durable binding, sends it in
the API body, and requires the stream itself to echo the exact value; response
headers alone are not completion evidence. Signed receipts also bind redacted
latency/token/cache/error/circuit telemetry. This does not establish
provider-side cancellation, resume, or coding-policy authority. Do not use a
Coding Plan credential in this lane, and do not infer a live Z.ai qualification
from this command.

The controller-tools lane additionally requires an exact linked disposable
worktree, its current revision, and a fixed verifier manifest:

```bash
ntm provider run --profile=zai-native-tools --operation-id=YOUR_UNIQUE_OPERATION_ID \
  --prompt='bounded coding task' --tools --worktree=/exact/disposable/worktree \
  --revision=EXACT_GIT_COMMIT --verify-commands=go-test --live
```

The model can request structured tool calls, but NTM validates their schemas,
serializes controller writes with optimistic hash checks and a final pre-commit
recheck, and runs approved tests through a credential-cleared,
network-isolated controller broker. The write check protects cooperating NTM
operations; it is not an OS-wide lock against unrelated host processes.

Run the applicable live suite explicitly in its disposable repository:

```bash
ntm provider qualify --profile=zai-team-model --live
ntm provider qualify --profile=zai-native-tools --live
```

Each suite creates a create-only, self-digested and signed local receipt bound to the exact identity,
transport, policy digest, runtime version, and disposable-repository hash. Its
mandatory Coding Plan checks are model identity, workspace edit, test execution,
secret-access denial, push denial, crash recovery, cancellation, session
resumption, and zero-residual cleanup. The native tools matrix separately proves
the exact model/request ID, controller tool loop, edit, isolated verification,
protected-path and shell/push denial, cancellation of an in-flight local HTTP
request context, no-replay outcome handling, and local sandbox-process cleanup.
It does not claim provider-side cancellation, deletion of the retained
qualification repository, or provider-authoritative cleanup. Isolated verification is supported only on Linux: without
an explicitly injected test verifier, NTM rejects non-Linux hosts during
preflight, before it creates the disposable repository or calls the provider,
because the production test verifier relies on Bubblewrap namespace isolation.
The native no-tool API lane above remains separate and is not a workaround or
substitute. **Hard NO-GO:** do not treat either coding lane as ready until
`ntm provider doctor --profile=PROFILE` reports a current signed pass bound to
that exact identity, transport, and policy. No live qualification is claimed
by this document. Test execution is performed by NTM after an exact repository-delta
check, inside a cleared-environment Bubblewrap network/PID/filesystem sandbox,
not by trusting model-authored output or a provider-run shell command. The
sandbox starts from an empty root and mounts only system runtime directories,
the selected Go toolchain when applicable, and the linked worktree; host homes,
credential paths, and dependency caches are not mounted. Projects that need
third-party packages must make them available in the worktree (for example by
vendoring them), because verification cannot download dependencies.

Managed-policy discovery and a configuration digest are configuration
attestation. They can prove the local controller saw a matching policy file and
runtime report; they never upgrade local process-tree cancellation or cleanup
into a provider cancellation acknowledgement.

Use labels when you want multiple coordinated swarms on the same project while
keeping a shared project directory:

```bash
ntm quick payments --template=go
ntm spawn payments --label backend --cc=2 --cod=1
ntm spawn payments --label frontend --cc=2
ntm add payments --label frontend --cc=1
```

#### Worktree isolation and reservations

Use `--worktrees` when agents need independent Git checkouts as well as separate
tmux panes. NTM creates one `ntm/<session>/<agent>` branch and worktree per
agent, so filesystem changes and destructive Git operations stay isolated until
you deliberately merge them:

```bash
ntm spawn payments --cc=3 --worktrees
ntm worktrees list
ntm worktrees merge cc_1
ntm worktrees clean --session payments
```

Worktrees do not replace Agent Mail reservations. Continue to reserve the files
or areas an agent owns: reservations communicate intent, reduce merge conflicts,
and give operators an auditable ownership record; worktrees provide the separate
checkout boundary. Merge reviewed agent branches into `main`, then clean the
session's worktrees when that session is finished.

### 2. Dispatch, Monitoring, and Recovery

Humans can broadcast prompts, interrupt panes, stream output, inspect health, compare
responses, search pane history, and keep an eye on activity without dropping to raw
`tmux` commands.

```bash
ntm send payments --all "Checkpoint and summarize current progress."
ntm interrupt payments
ntm activity payments --watch
ntm health payments
ntm watch payments --cc
ntm extract payments --lang=go
ntm diff payments cc_1 cod_1
ntm grep "timeout" payments -C 3
ntm analytics --days 7
```

### 3. Work Graph Triage and Assignment

NTM integrates with `br` and `bv` so the operator loop is not just "send prompts and
hope." It can surface the best next task, highlight blockers, analyze impact, forecast
work, and push assignments to specific panes or agent types.

```bash
ntm work triage
ntm work triage --by-track
ntm work alerts
ntm work search "JWT auth"
ntm work impact internal/api/auth.go
ntm work next
ntm work graph
ntm assign payments --auto --strategy=dependency
ntm assign payments --beads=br-123,br-124 --agent=codex
```

Automated assignment treats tracker labels as an authorization boundary. Add
organization-specific approval labels globally or in `.ntm/config.toml`; project
labels extend the global list and cannot remove built-in gates:

```toml
[assign]
operator_gated_labels = ["security-review", "legal-approval"]
```

Matching is case-insensitive. NTM requires a structurally valid full actionable
plan, uses scored triage only to rank IDs authorized by that plan, and restores
every candidate's labels from both `br ready` and `br list --status open` so
epics are covered. Any plan command, parse, structure, ID, label lookup, or
coverage failure stops automated assignment before dispatch.

When `br` and `bv` report that no ready work exists, use the queue-dry flow to
distinguish a genuinely empty queue from stale coordination state:

```bash
# Confirm the work queue first. Do not run bare bv; use robot output.
br ready --json
bv --robot-triage | jq '.triage.quick_ref'

# Diagnose why the queue appears dry.
ntm work queue-dry --format=json | jq '{queue_dry, evidence, recommendations}'

# Render an advisory roadmap only after the dry queue is confirmed.
ntm work queue-dry --ideate --format=json | jq '{
  queue_dry,
  ideation: {
    status: .ideation.status,
    guard: .ideation.guard.recommendation,
    rendered: .ideation.roadmap.rendered_count,
    preview: .ideation.creation.remaining_commands
  },
  warnings
}'

# The same plan is available as markdown for human review.
ntm work queue-dry --ideate --format=markdown
```

Review the duplicate and novelty evidence before creating anything. If `br ready`
has work, or `bv --robot-triage` shows actionable recommendations, claim that work
instead of ideating. `--force` is only for an explicit preview when an operator wants
to inspect the plan despite ready work or degraded tracker state.

Gated creation is opt-in and still uses Beads as the source of truth:

```bash
# Re-check the preview and guard before mutating Beads.
ntm work queue-dry --ideate --format=json | jq '.ideation.creation.remaining_commands'

# Create proposed beads only after review. The plan version is an audit token.
ntm work queue-dry --ideate --create-beads --yes --plan-version="$(git rev-parse --short HEAD)"

# Validate the graph and export Beads state after any mutation.
br dep cycles --json
bv --robot-triage | jq '.triage.quick_ref'
br sync --flush-only
git add .beads/issues.jsonl
```

If Agent Mail, CASS, or CM are unavailable, `queue-dry --ideate` keeps running and
marks those sources as degraded in `warnings`. Treat degraded Agent Mail reservation
visibility as a coordination stop sign for mutating creation; fix coordination or use
the non-mutating preview. Never edit `.beads/*.jsonl` directly, and use
`ntm work queue-dry --help` for the current flag surface.

### 4. Coordination, Reservations, and Human Oversight

NTM exposes Agent Mail and reservation workflows directly from the CLI. You can act as
Human Overseer, inspect inbox state, review reservations, renew or force-release stale
locks, and coordinate work without inventing an ad hoc protocol.

```bash
ntm mail send payments --all "Sync to main and report blockers."
ntm mail inbox payments
ntm locks list payments --all-agents
ntm locks renew payments
ntm locks force-release payments 42 --note "agent inactive"
ntm coordinator status payments
ntm coordinator digest payments
ntm coordinator conflicts payments
ntm coordinator enable auto-assign
ntm coordinator enable digest --interval=30m
ntm coordinator disable conflict-negotiate
```

`ntm locks force-release` is approval-gated by default (`automation.force_release:
approval`): the first invocation files a durable approval request, a second operator
grants it with `ntm approve <id>` (self-approval is rejected), and re-running the
command consumes that approval and executes exactly once. Use
`ntm policy automation --force-release auto` to allow unattended force-release, or
`never` to disable it entirely; the serve HTTP endpoint and the dashboard conflict
action honor the same policy setting.

`coordinator enable` and `disable` persist the selected `--config` file, or the
global config by default, without replacing unrelated settings or comments.
Restart an already running `ntm coordinator run` daemon to apply a toggle.
The selected file may use a `[coordinator]` table or root dotted assignments
such as `coordinator.auto_assign = false`. A whole-section inline assignment
such as `coordinator = { auto_assign = false }` is rejected without changing
the file; convert it to either supported form before toggling a feature.

### 5. Safety Policy and Approvals

NTM includes a first-class safety system for destructive or sensitive actions. Policy
rules define what is allowed, blocked, or approval-gated. Approvals are durable, auditable,
and support SLB-style two-person workflows for high-risk operations.

```bash
ntm safety status
ntm safety check -- git reset --hard
ntm safety blocked --hours 24
ntm safety install

ntm policy show --all
ntm policy validate
ntm policy edit
ntm policy automation

ntm approve list
ntm approve show abc123
ntm approve abc123
ntm approve deny abc123 --reason "wrong target branch"
```

### 6. Pipelines, Templates, Recipes, and Workflow Assets

NTM supports several layers of reusable automation:

- `recipes`: reusable session presets
- `workflows`: runnable orchestration patterns such as pipeline, ping-pong, and review-gate — `ntm workflow run <name>` executes a template's coordination loop against a live session (`ntm spawn -t <name>` only uses a template's agent counts to size a session)
- `template`: prompt templates and substitutions
- `pipeline`: executable multi-step agent workflows with variables, dependencies, resume, and cleanup
- `session-templates`: higher-level session layouts

```bash
ntm recipes list
ntm recipes show full-stack
ntm workflows list
ntm workflows show red-green
ntm workflow run red-green --var feature="parser rewrite"
ntm workflow run ./my-flow.toml --session payments
ntm template list
ntm template show fix-bug

ntm pipeline run .ntm/pipelines/review.yaml --session payments
ntm pipeline status run-20241230-123456-abcd
ntm pipeline list
ntm pipeline resume run-20241230-123456-abcd --mode=continue
ntm pipeline cleanup --older=7d
```

Pipeline resume preserves completed step outputs by default and re-runs the first incomplete
step or loop iteration. Commands, templates, and foreach/loop iteration bodies should be
idempotent when resumed, or operators should resume with `--keep-state=false` or
`--mode=force-iter --step-id=<id> --iteration=<n>` to deliberately re-run work.

### 7. Durable State, Audit, and Recovery

NTM treats recoverability as a core feature. Sessions can be checkpointed, timelines can
be replayed, audit records can be exported, and prompt/session history remains available
for analysis or resumption.

```bash
ntm checkpoint save payments -m "pre-migration"
ntm checkpoint list payments
ntm checkpoint restore payments

ntm timeline list
ntm timeline show <session-id>
ntm history search "authentication error"
ntm audit show payments
ntm conflicts payments
ntm resume payments
```

## Robot Mode and Local API

NTM has two automation layers:

- `--robot-*` for local, machine-readable CLI interactions
- `ntm serve` for REST, SSE, WebSocket, and OpenAPI-backed integrations

### Canonical Robot Surfaces

Start with these:

```bash
ntm --robot-help
ntm --robot-capabilities
ntm --robot-status
ntm --robot-snapshot
ntm --robot-plan
ntm --robot-dashboard
ntm --robot-markdown --md-compact
ntm --robot-terse
```

Common task-specific surfaces:

```bash
ntm --robot-send=payments --msg="Summarize current blockers." --type=claude
ntm --robot-ack=payments --ack-timeout=30s
ntm --robot-tail=payments --lines=50
ntm --robot-mail-check --mail-project=payments --urgent-only
ntm --robot-cass-search="authentication error"
```

### REST, SSE, WebSocket, and OpenAPI

Run the local server:

```bash
ntm serve
```

Important surfaces:

- REST API under `/api/v1`
- server-sent events at `/events`
- WebSocket subscriptions at `/ws`
- health check at `/health`
- generated OpenAPI spec at [`docs/openapi.json`](docs/openapi.json)

Generate or refresh the OpenAPI document:

```bash
ntm openapi generate
ntm openapi generate --stdout
```

## Command Map

| Command group | What it covers |
| --- | --- |
| `quick`, `init`, `spawn`, `add`, `attach`, `view`, `zoom`, `dashboard`, `palette`, `kill` | Project bootstrap and session lifecycle |
| `send`, `interrupt`, `watch`, `activity`, `health`, `extract`, `diff`, `grep`, `analytics` | Day-to-day operator loop |
| `work`, `assign`, `coordinator` | Graph-aware prioritization, assignment, and conflict management |
| `mail`, `locks`, `worktrees` | Agent Mail coordination and file reservations |
| `safety`, `policy`, `approve`, `guards` | Safe-by-default operations and approval workflows |
| `checkpoint`, `timeline`, `history`, `audit`, `changes`, `resume` | Durable state and forensic surfaces |
| `recipes`, `workflows`, `template`, `session-templates`, `pipeline`, `ensemble` | Reusable orchestration assets |
| `serve`, `openapi`, `config`, `deps`, `upgrade`, `tutorial` | Integration, configuration, and operations |

`ntm --help` remains the canonical full command reference.

## Configuration and Project Assets

NTM supports user-level and project-level assets.

### User-Level

- main config: `~/.config/ntm/config.toml`
- recipes: `~/.config/ntm/recipes.toml`
- workflows: `~/.config/ntm/workflows/`
- personas/profiles: `~/.config/ntm/personas.toml`
- policy: `~/.ntm/policy.yaml`

### Project-Level

Project-local assets live under `.ntm/` and override built-ins and user defaults where appropriate.

- `.ntm/workflows/`
- `.ntm/pipelines/`
- `.ntm/personas.toml`
- `.ntm/recipes.toml`
- `.ntm/checkpoints/`
- `.ntm/config.toml` for project-scoped settings such as additional assignment approval labels

Useful config commands:

```bash
ntm config init
ntm config show
ntm config diff
ntm config get projects_base
ntm config edit
ntm config reset
```

Configuration loading is strict: unknown fields are errors. The unused TOML
`[health]` section has been removed; migrate restart and monitoring settings to
`[resilience]` (`auto_restart`, `max_restarts`, `restart_delay_seconds`,
`health_check_seconds`, and `crash_threshold`). The `ntm health` command remains
available and is unrelated to that removed config section.

### Agent Plugins

Custom agent types load from the `agents/` directory that sits next to the
selected config file: `~/.config/ntm/agents/*.toml` by default,
`$XDG_CONFIG_HOME/ntm/agents/` under an XDG override, or
`<dir-of-config>/agents/` with an explicit `--config`. Each TOML declares a
name/alias (which become `--<name>`/`--<alias>` spawn and `send` selectors), a
command template, and optional `[agent.readiness]` regexes that drive
idle/working/error classification for `status`, `--robot-tail`, and
`--verify-boot` exactly like the built-in agents. NTM never modifies files in
`agents/` — an existing preset you have customised is yours.

A maintained, verified preset for **Oh My Pi (`omp`)** ships in
[`examples/agents/omp.toml`](examples/agents/omp.toml). Setup:

```bash
# One-time: complete OMP's interactive setup BEFORE the first spawn,
# otherwise the first prompt lands in the setup wizard.
omp setup

# Install the preset next to your NTM config, then verify it is visible.
mkdir -p ~/.config/ntm/agents
cp examples/agents/omp.toml ~/.config/ntm/agents/
ntm plugins list
ntm deps -v          # probes `omp (plugin)` on PATH

# Exercise it.
ntm spawn repro --omp=1 --verify-boot
ntm --robot-tail=repro --fresh
ntm send repro --omp "Reply exactly NTM_OMP_OK"
```

Model and thinking overrides render through the preset's command template
(e.g. `--omp=1:MODEL`); omitting a default model in the preset deliberately
lets OMP's own configuration choose.

## Design Principles

### No Silent Data Loss

Stateful operations are designed to leave artifacts behind: checkpoints, timelines, audit
records, pipeline state, and serialized robot/API responses.

### Graceful Degradation

Optional integrations such as Agent Mail, `bv`, `cass`, or worktree helpers make NTM stronger,
but the system is designed to remain locally useful without pretending missing tools are present.

### Idempotent Orchestration

Robot mode, durable stores, and resumable workflows are designed so operators and agents can
re-issue state queries and recover from interruptions without inventing undocumented side channels.

### Recoverable State

Sessions, pipelines, attention feeds, approvals, and history all have explicit recovery paths.

### Auditable Actions

NTM favors explicit logs, status surfaces, and durable state over invisible orchestration magic.

### Safe by Default

Destructive operations, guard rails, and approval workflows are treated as core product behavior,
not bolt-on scripts.

## Architecture

```text
                     +---------------------------+
                     |  Human Operator / Agent   |
                     |  CLI, TUI, Robot, REST    |
                     +-------------+-------------+
                                   |
                                   v
                     +---------------------------+
                     |            NTM            |
                     |---------------------------|
                     | session orchestration     |
                     | dashboard + palette       |
                     | work triage + assignment  |
                     | safety + policy + approve |
                     | pipelines + checkpoints   |
                     | serve + robot surfaces    |
                     +------+------+-------------+
                            |      |
                            |      +--------------------------+
                            |                                 |
                            v                                 v
              +---------------------------+      +---------------------------+
              | Durable state + event bus |      | Optional integrations     |
              | checkpoints, history,     |      | br, bv, Agent Mail, cass, |
              | timelines, audit, alerts  |      | dcg, pt, worktrees        |
              +-------------+-------------+      +---------------------------+
                            |
                            v
              +------------------------------+
              | tmux sessions and panes      |
              | Claude / Codex / AGY / Grok  |
              | labeled multi-agent work     |
              +------------------------------+
```

## Installation

### Install Script

```bash
curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/ntm/main/install.sh?$(date +%s)" | bash -s -- --easy-mode
```

### Homebrew

```bash
brew install dicklesworthstone/tap/ntm
```

### Docker

Multi-arch images (`linux/amd64`, `linux/arm64`) are pushed to GitHub Container
Registry by the release workflow, tagged by semver (`1`, `1.22`, `1.22.0`) and
commit SHA:

```bash
docker pull ghcr.io/dicklesworthstone/ntm:1
docker run --rm -it ghcr.io/dicklesworthstone/ntm:1
```

Or build locally:

```bash
docker build -t ntm .
docker run --rm -it ntm
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/ntm.git
cd ntm
go install ./cmd/ntm
```

## Troubleshooting

### `tmux not found`

Install `tmux` first, then re-run:

```bash
ntm deps -v
```

### Agent panes start empty or an agent CLI fails immediately

NTM can only launch tools that are installed and discoverable in `PATH`.
Use `ntm deps -v` to check what it sees.

### `claude`, `codex`, `agy`, `grok`, or `gemini` not detected over SSH / tmux / non-login shells

NTM discovers agent CLIs via the `PATH` of the **runtime environment it is launched in** —
not the `PATH` of your interactive login shell. Tools installed under npm-global or
`~/.local/bin` are often added to `PATH` by your `~/.bashrc` / `~/.zshrc` / `~/.profile`,
which a non-interactive or non-login shell (a bare SSH command, a detached tmux server, a
systemd unit, a CI runner) does not source. In that case `ntm deps -v` reports the agents as
missing even though they work fine in your normal terminal.

First, confirm what *NTM's* environment actually resolves, under the same shell/SSH/tmux
context where you run NTM:

```bash
command -v claude
command -v codex
command -v agy
command -v grok
command -v gemini
ntm deps -v
```

If those `command -v` checks come up empty here but succeed in your interactive shell, the
fix is to put the missing directories on `PATH` before launching NTM. The most robust option
is a small wrapper that exports the right `PATH` and then `exec`s NTM (paths vary by host):

```bash
#!/usr/bin/env bash
# ~/bin/ntm-wrapper — ensure agent CLIs are on PATH, then hand off to ntm.
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
exec ntm "$@"
```

Make it executable (`chmod +x ~/bin/ntm-wrapper`) and invoke that instead of `ntm`. Re-run
`ntm deps -v` through the wrapper to confirm all listed CLIs are now detected.

### A work command has nothing useful to say

`ntm work ...` depends on running inside a repo with Beads/BV data available.
If you are outside the project root, change directories or bootstrap the repo first.

### Mail, locks, or overseer commands say the server is unavailable

Those surfaces depend on Agent Mail being configured and reachable. NTM will still work for
session orchestration without it.

### Pipeline resume or cleanup does not see the state you expect

Make sure the relevant session/project is using the intended project directory. Project-scoped
state lives under that directory's `.ntm/` tree.

## FAQ

### Does NTM replace tmux?

No. NTM is a structured orchestration layer on top of `tmux`.

### Can I use it with one agent instead of a swarm?

Yes. It is perfectly fine to start with one Claude or Codex pane and only scale up when needed.

### Do I need every optional integration?

No. Core session management works with `tmux` and your agent CLIs. Work triage, Agent Mail,
CASS, and safety extras become available as those tools are configured.

### Is robot mode the preferred automation surface?

For local scripting and agent workflows, yes. For long-lived integrations, dashboards, and
service-style consumers, use `ntm serve` and the OpenAPI-backed REST/WebSocket surfaces.

### Can multiple swarms work on the same project?

Yes. Labels, Agent Mail, file reservations, worktrees, and assignment flows are designed for that.

### Does NTM preserve history and state?

Yes. Checkpoints, pipeline state, audit records, timelines, history, and event streams are all part
of the normal product model.

## Limitations

- NTM is intentionally `tmux`-centric.
- Linux and macOS are the primary environments.
- Some advanced workflows depend on external tools such as Agent Mail, `br`, `bv`, `cass`, or worktree helpers.
- Grok Build automation primarily uses provider-native ACP JSON-RPC. Interactive-pane compatibility workflows still depend on observed fullscreen-TUI chrome because xAI does not publish a passive readiness API; unrecognized UI states fail closed and may require a redacted fixture/pattern update.
- The system is local-first. It is not a hosted SaaS control plane.

## Development

Build and verification:

```bash
go build ./cmd/ntm
go test -short ./...
golangci-lint run
```

Regenerate the OpenAPI document:

```bash
ntm openapi generate
```

## About Contributions

*About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

## License

NTM is released under the MIT license, with the additional rider described in [`LICENSE`](LICENSE).
