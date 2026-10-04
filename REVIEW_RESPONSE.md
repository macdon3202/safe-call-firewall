# SafeCall Firewall — reviewer response

## Issue addressed

The previous frontend waited for transaction A and then read the global
`assessment_count`. If transaction B finalized before A's post-write readback,
the counter could point at B's certificate.

## Deterministic transaction-to-certificate binding

`analyze_safe_transaction(...)` already returns the newly created assessment
ID. The corrected frontend now:

1. waits for the submitted transaction to finalize with consensus agreement and
   successful leader execution;
2. extracts the positive integer ID from that transaction's leader return
   payload (`leader_receipt.result.payload.readable`);
3. reads `get_assessment(returned_id)` directly;
4. fails closed unless the record matches the returned ID, connected requester,
   submitted chain, exact Safe transaction hash, and selected policy.

The global counter is read only afterward to refresh the aggregate UI statistic.
It is never used to select the post-write certificate.

## Focused regression coverage

[`frontend/transactions.test.mjs`](frontend/transactions.test.mjs) includes:

- extraction of the ID from the real StudioNet receipt shape;
- a concurrent-submission regression where transaction A returns ID 7 while
  the global count has advanced to 8, proving A still reads ID 7;
- rejection of a mismatched certificate tuple;
- fail-closed behavior when a finalized receipt lacks a valid returned ID.

Verification results:

- frontend transaction tests: **11 passing**;
- production frontend build: **passing**;
- contract tests: **26 passing**;
- GenLayer lint and contract validation: **passing**.

## Scope and deployment

This is a frontend readback correction. The deployed V2.2 contract already
returns the exact assessment ID, so no contract redeployment or migration is
required.

- [Live frontend](https://safe-call-firewall.pages.dev/)
- [Repository](https://github.com/macdon3202/safe-call-firewall)
- [V2.2 contract](https://explorer-studio.genlayer.com/address/0x32dA611016AFA6F256fE9F158E3383AF4EfB6716)
- [Transaction demonstrating leader return value `1`](https://explorer-studio.genlayer.com/tx/0xde8d83c01aafc7c2af13310f1a4ca5da858c015ea2585d66294f61f607720b6f)
