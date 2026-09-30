# SafeCall Firewall V2.2 — end-to-end audit

## Release identity

- Contract: [`0x32dA611016AFA6F256fE9F158E3383AF4EfB6716`](https://explorer-studio.genlayer.com/address/0x32dA611016AFA6F256fE9F158E3383AF4EfB6716)
- Public version: `SAFE_CALL_FIREWALL_V2_2`
- Architecture: `ATOMIC_BOUND_SOURCE_CALL_GRAPH_CERTIFICATE`
- Runtime roles: none; any wallet may submit a distinct tuple.
- Final authoritative count after this audit: 3 certificates.

## Live consequential paths

| Claim | Transaction | Finality | Authoritative result |
|---|---|---|---|
| Bounded approval happy path | [`0xde8d…0b6f`](https://explorer-studio.genlayer.com/tx/0xde8d83c01aafc7c2af13310f1a4ca5da858c015ea2585d66294f61f607720b6f) | FINALIZED / MAJORITY_AGREE / SUCCESS | certificate #1 `CLEAR / POLICY_CHECKS_SATISFIED` |
| Admin mutation blocked | [`0xbd9f…01d2`](https://explorer-studio.genlayer.com/tx/0xbd9fc2ad0b981c5b99a919c74a07b35d3d44bc804eb8d234ef93a4e4806801d2) | FINALIZED / MAJORITY_AGREE / SUCCESS | certificate #2 `BLOCKED / ADMIN_MUTATION_BLOCKED` |
| Official source record absent | [`0xff64…6e16`](https://explorer-studio.genlayer.com/tx/0xff64acd1b68a3ca966080dcfe785aeecb5132786b62274ae08a0529df9ae6e16) | FINALIZED / MAJORITY_AGREE / SUCCESS | certificate #3 `UNRESOLVED / SOURCE_NOT_VERIFIED` |

Wallet A created #1. Wallet B created #2 and #3. Neither is the deployment
wallet; this proves the write path is permissionless in live execution.

## Rejected paths and rollback

Each row captured the complete config and every existing certificate before and
after execution. Equality was required; an error badge alone was not accepted.

| Attack | Transaction | Result | State proof |
|---|---|---|---|
| Duplicate tuple replay | [`0x9bbb…876b`](https://explorer-studio.genlayer.com/tx/0x9bbb7a4a82e1315082eabd09aab10312945e57822cb8b7af75bacb2a394c876b) | FINALIZED / AGREE / ERROR | config and all three certificates exactly unchanged |
| Unsupported chain | [`0x72bf…6d42`](https://explorer-studio.genlayer.com/tx/0x72bfa4392992730f095e5f48b8f38d2f17924cdbec1178ce9ba7d4d96db16d42) | FINALIZED / AGREE / ERROR | pre-state equals post-state |
| Malformed hash | [`0xe283…de4b`](https://explorer-studio.genlayer.com/tx/0xe283a7d35115eb4a6969cf3ad8e5a34b6f9ec9821746771819893d2ceaa3de4b) | FINALIZED / AGREE / ERROR | pre-state equals post-state |
| Unknown policy | [`0xb43f…6bf5`](https://explorer-studio.genlayer.com/tx/0xb43f82de62387b597107993990e611543133cd393b732940a6979d6d2b326bf5) | FINALIZED / AGREE / ERROR | pre-state equals post-state |

## Consensus-conflict proof

Two real predecessor runs reached FINALIZED `MAJORITY_DISAGREE` and created no
certificate. They exposed an overly strict comparator and led to V2.2's explicit
semantic-equivalence boundary. They are retained as negative evidence rather
than relabeled as successful verdicts:

- [`0x690d…ae33`](https://explorer-studio.genlayer.com/tx/0x690de312303c9f6511a525d9aa52114a3fba0a8e3767f8a396a1c812d76eae33)
- [`0x1ea5…7698`](https://explorer-studio.genlayer.com/tx/0x1ea53b3fa871798d38ddff8f84b8a9f98a8a2ed6f5cbf6d0b71d21e8ddcd7698)

The production UI transaction reducer separately tests that disagreement is a
failure and can never become a success notice.

## UI-to-contract reconciliation

The production-mode frontend was run with the exact V2.2 address and read
certificates directly from StudioNet:

| UI action | Visible authoritative state |
|---|---|
| Load ID 1 | `CLEAR`, `approve`, zero blocked/review/unknown leaves, exact commitments |
| Load ID 2 | `BLOCKED`, `ADMIN_MUTATION_BLOCKED`, `addOwnerWithThreshold` |
| Load ID 3 | `UNRESOLVED`, `SOURCE_NOT_VERIFIED`, no decoded leaves |
| Load ID 999 | prior certificate cleared; `NO DATA` plus read error |

The UI showed count 3 and the exact active contract link. Browser console had no
warning or error. Transaction-state tests cover hash normalization, FINALIZED
leader error, majority disagreement, missing affirmative consensus, successful
leader execution and both list/object receipt shapes.

## Local adversarial matrix

The GenVM contract suite additionally covers delegatecall, native value cap,
admin mutation, a blocked nested leaf hidden behind top-level clear, unlimited
approval, incomplete decoding, wrong binding, unavailable source, prompt
injection, malformed model schema, malformed nested calls, consensus exception,
replay and invalid inputs. These are local GenVM execution tests and are not
misrepresented as extra live transactions.

## Evidence boundary

Safe Transaction Service is authoritative for the indexed record it returns.
This audit does not prove signer intent, economic safety, token value, or future
execution. Browser verification proves live readback and rendering; signing was
performed by the two auxiliary wallets through the same public contract method
using the GenLayer SDK, not by an injected wallet inside the test browser.
