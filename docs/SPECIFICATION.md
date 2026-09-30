# SafeCall Firewall specification

## Decision question

For one exact Safe transaction record returned by an official, contract-selected
Safe Transaction Service endpoint, does the fully decoded call tree satisfy one
of the contract's closed risk policies?

The answer is an immutable certificate with one of four states:

- `CLEAR`: every decoded leaf is accounted for and deterministic policy checks pass.
- `REVIEW_REQUIRED`: the record is bound, but decoding is incomplete, contains an
  unknown leaf, or includes an unlimited approval.
- `BLOCKED`: a deterministic prohibited condition is present, such as delegatecall,
  an administrative mutation, excessive native value, or excessive call count.
- `UNRESOLVED`: the official source, exact transaction binding, validator schema,
  or validator consensus could not be verified.

Only `CLEAR` is positive, and it means policy compliance within this evidence
boundary—not economic safety or permission to execute.

## Atomic write path

`analyze_safe_transaction(chain_key, safe_tx_hash, policy_id)` performs the whole
decision in one write:

1. Reject unsupported chains, malformed hashes, unknown policies, and replayed
   `(chain, safeTxHash, policy)` tuples before any state change.
2. Construct the official Safe service URL internally; callers cannot supply a URL.
3. Fetch one exact record and bind the returned `safeTxHash`, Safe address, nonce,
   target, value, operation, execution status, and confirmation requirement.
4. Recursively classify the decoded call graph under validator comparative consensus.
5. Require exact agreement for all consequential fields and canonical digests.
6. Apply a deterministic risk lattice and store one immutable certificate.

The V2 certificate commits the exact source URL, selected closed policy, source
envelope, decoded payload, canonical leaf-call graph, deterministic outcome and
requesting wallet. It also stores independently derived blocked, review and
unknown leaf counters. These counters are computed by contract code from the
post-consensus canonical graph; they are not trusted model assertions.

There are no administrative writes, constructor allowlists, or deployer-only paths.

## Fixed policies

| Policy | Native value cap | Leaf-call cap | Admin mutation |
|---|---:|---:|---|
| `STRICT_NO_ADMIN` | 0 wei | 8 | blocked |
| `ROUTINE_OPERATIONS` | 1 ETH | 12 | blocked |
| `TREASURY_REVIEW` | 100 ETH | 20 | blocked |

Unlimited approvals always require review. Delegatecall is always blocked.

## Public API

- Write: `analyze_safe_transaction(chain_key, safe_tx_hash, policy_id) -> id`
- View: `get_assessment(id) -> certificate`
- View: `get_policy(policy_id) -> canonical policy + digest`
- View: `get_source_config(chain_key) -> fixed authority configuration + digest`
- View: `get_config() -> version, architecture, count, chains, policies`
