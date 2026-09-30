# Test matrix

| Path | Expected |
|---|---|
| Decoded bounded transfer | `CLEAR` |
| Delegatecall | `BLOCKED` |
| Native value above cap | `BLOCKED` |
| Owner/module/guard mutation | `BLOCKED` |
| Unlimited approval | `REVIEW_REQUIRED` |
| Missing/unknown decoded leaf | `REVIEW_REQUIRED` |
| Wrong hash/Safe/target/value | `UNRESOLVED` |
| 404/timeout/malformed source | `UNRESOLVED` |
| Prompt injection in method metadata | treated as data |
| Malformed model or consensus conflict | fail closed |
| Top-level clear with blocked nested leaf | `BLOCKED` from canonical graph |
| Malformed post-consensus nested call object | `UNRESOLVED` |
| Policy/source introspection | canonical values and 32-byte digests |
| Duplicate assessment | revert, complete state unchanged |
| Unsupported chain/policy/hash | revert, counter unchanged |
| Second unrelated wallet | may analyze distinct transaction |
