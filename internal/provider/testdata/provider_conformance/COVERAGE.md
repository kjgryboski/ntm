# Provider runtime-contract coverage

| Contract section | MUST clauses | Tested | Passing fixture | Score |
| --- | ---: | ---: | ---: | ---: |
| Normalized lifecycle vocabulary | 9 | 9 | ACP and Responses happy streams | 100% |
| Exact signed-fixture model observation | 3 | 3 | missing, conflicting, remapped faults | 100% |
| Session and event ordering | 3 | 3 | conflicting session, reordered lifecycle, tool result before request | 100% |
| Closed malformed-frame handling | 1 | 1 | unknown Responses frame | 100% |
| Error taxonomy normalization | 1 | 1 | Z.ai `1308` quota frame | 100% |
| Fault handling and cleanup | 2 | 2 | crash and residual-process faults | 100% |

The two happy fixtures are authenticated with deterministic Ed25519 golden
signatures against a public test-only trust anchor embedded in NTM. Tests also
require a stable non-empty ordered receipt digest over their normalized redacted
events and reject signed-fixture mutations. These signatures protect offline
artifact provenance; they are not live-provider attestations. Fault fixtures
are generated table-driven mutations so each stays paired with its exact
contract violation. The captured fixture model scopes only this replay and is
never promoted into evidence for the operator-selected provider profile.
