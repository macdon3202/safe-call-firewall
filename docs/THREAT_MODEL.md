# Threat model

| Threat | Control | Result on uncertainty |
|---|---|---|
| SSRF / caller-selected source | closed chain-to-origin catalog | input reverts |
| Source substitution | exact returned safeTxHash binding | `UNRESOLVED` |
| Self-authored evidence | contract fetches the official record directly | caller prose is ignored |
| Prompt injection in decoded metadata | hostile-data prompt boundary, closed schema and enums | review or unresolved |
| Partial MultiSend analysis | recursive leaf requirement and exact call count | `REVIEW_REQUIRED` |
| Validator disagreement | exact comparative agreement; no majority-field merge | `UNRESOLVED` |
| Malformed model output | exact keys, types, bounds, digest and calls checks | `UNRESOLVED` |
| Dangerous execution shape | deterministic delegatecall/admin/value/call-count rules | `BLOCKED` |
| Duplicate assessment | replay key set atomically with certificate | full revert |
| Privileged deployer | no owner state, constructor arguments or admin methods | no privilege exists |
| UI optimism | accept only finalized successful leader execution, then read contract | error shown; no success claim |

## Out of scope

The contract does not prove signer identity or intent, off-chain authorization,
token valuation, downstream contract correctness, future execution, or economic
safety. Safe Transaction Service is authoritative only for the indexed record it
returns within its published service scope.

