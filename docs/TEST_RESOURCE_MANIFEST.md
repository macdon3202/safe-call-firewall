# Test resource manifest

Live resources must be exact Safe transaction hashes fetched from a fixed
contract-owned chain catalog. For each candidate record: chain ID, official
service endpoint, safeTxHash, Safe address, nonce, executed/pending status,
decoded leaf count, mutability, expected branch, and epistemic limitation.

Historical executed records are preferred for stable read-only fixtures.
Pending records are mutable and require a fresh digest/readback at assessment.
Local mocked payloads are synthetic and never represented as live evidence.

The Safe service proves the indexed/proposed transaction record in its own
scope. It does not prove that signers authorized it off-chain or that it will
execute successfully.

## Reviewed StudioNet live fixtures

Recorded before running the GenLayer writes on 2026-09-30.

| ID | Chain / authoritative endpoint | Exact resource | Observed stable facts | Expected branch | Limitation |
|---|---|---|---|---|---|
| `SAFE-SEP-APPROVE-1` | Sepolia / `safe-transaction-sepolia.safe.global` | `0x736a2748f27f55f951ae97072a5520e4a8b9e14a3a01344794243b530d44be12` | Safe `0x86D4…e9F`; nonce 3; executed successfully; decoded `approve`; amount 1; operation CALL | `CLEAR` under `ROUTINE_OPERATIONS` | Establishes only the indexed transaction and closed-policy result; not economic safety or signer intent. |
| `SAFE-SEP-ADD-OWNER` | Sepolia / `safe-transaction-sepolia.safe.global` | `0x763db1b49ce2055ab91f1fd19e5e1423a53ed4845ca4f0d18fd479074ec5adcb` | Same Safe; nonce 4; executed successfully; decoded `addOwnerWithThreshold`; operation CALL | `BLOCKED` under `STRICT_NO_ADMIN` | Establishes a deterministic admin-mutation branch; not whether the historic change was legitimate. |

Both are historical executed records (2025-01-16), not mutable pending proposals.
The contract still refetches and digest-binds the exact record during consensus.

| `SAFE-SEP-NOT-FOUND` | Sepolia / same official origin | `0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` | Deliberately nonexistent identifier; expected official response is non-200 | `UNRESOLVED` | Synthetic negative locator used only to prove fail-closed behavior; it is not presented as a real Safe transaction. |
