# Provider conformance fixture provenance

These fixtures are hand-authored redacted protocol-shape records, dated
2026-09-03. They contain no credentials, prompts, outputs, repository paths,
or provider response bodies.

`grok_acp_happy.json` maps documented Grok ACP lifecycle frame names to the
shared NTM event contract. `zai_responses_happy.json` maps a Responses-style
stream for the Z.ai Codex endpoint. They are embedded in the binary and replayed
by `--robot-provider-conformance` for their respective transports.

Each JSON fixture includes an Ed25519 signature over its canonical metadata and
ordered redacted wire events. NTM verifies it against the compiled
`ntm-offline-fixture-ed25519-v1` public test anchor before replay. The private
test key is not shipped. This authenticates the reviewed golden file only and
does not imply that a live provider signed or served it. The model inside a
fixture is checked as part of the signed replay but never qualifies the model
configured in a selected local profile.

To update: capture only scalar frame metadata from a reviewed live receipt,
redact it, update this provenance with source/version/date, run focused tests,
and review the fixture diff. No fixture can establish live entitlement.
