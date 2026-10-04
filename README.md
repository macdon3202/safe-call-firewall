# SafeCall Firewall

SafeCall Firewall is a permissionless GenLayer dApp that turns an official Safe
Transaction Service record into an immutable, policy-scoped call-graph risk
certificate.

Anyone can analyze a transaction. The deployer has no runtime authority and the
contract has no constructor arguments or wallet allowlist.

Active StudioNet V2.2 deployment: [`0x32dA611016AFA6F256fE9F158E3383AF4EfB6716`](https://explorer-studio.genlayer.com/address/0x32dA611016AFA6F256fE9F158E3383AF4EfB6716).
The repository release is `SAFE_CALL_FIREWALL_V2_2`. Verify this exact value via
public `get_config()` before running live evidence.

Live frontend: [safe-call-firewall.pages.dev](https://safe-call-firewall.pages.dev/).

Reviewer update: [`REVIEW_RESPONSE.md`](REVIEW_RESPONSE.md) documents the
transaction-bound post-write readback fix and concurrent-submission coverage.

The production frontend is pinned to this exact V2.2 address and rejects a
contract-version mismatch before submitting a write.

## Proof boundary

The contract establishes whether the exact Safe service record is fully decoded
and satisfies one closed policy. It does not prove economic safety, off-chain
authorization, signer intent, or future execution.

## Architecture

```text
contract-built Safe service URL
→ exact transaction envelope + decoded tree
→ recursive validator classification
→ deterministic risk lattice
→ source/policy/call-graph commitments
→ immutable replay-protected certificate
```

## Verify

```bash
python -m pytest -q
python -X utf8 -m genvm_linter.cli check contracts/safe_call_firewall.py
cd frontend
npm test
npm run build
```

The local suite currently covers happy, failure, review/conflict, adversarial input,
schema corruption, consensus failure, replay rollback, transaction-finality handling,
and a non-deployer wallet caller. See [test matrix](docs/TEST_MATRIX.md),
[specification](docs/SPECIFICATION.md), [threat model](docs/THREAT_MODEL.md), and
[end-to-end audit](docs/E2E_AUDIT.md).

## Deploy and live evidence

Deploy the exact reviewed source with no constructor arguments. The deploying wallet
has no post-deployment authority. Execute live paths from two auxiliary wallets and
record only finalized successful transactions plus contract readback in
[the evidence ledger](docs/LIVE_EVIDENCE.md). Any reviewer can repeat the same write
with their own wallet and a distinct supported Safe transaction hash.

The reviewed V2.2 source is deployed on StudioNet. Finalized happy-path,
blocked, unresolved, validation-failure, replay-rollback, and conflict history
are linked from [the end-to-end audit](docs/E2E_AUDIT.md).
