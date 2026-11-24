# Security roadmap (advanced capabilities)

Nothing on this page is deployed. Experimental code lives in `src/experimental/`,
is excluded from the published package, and must not be activated in any
Sentient client until it has been independently reviewed and the founder has
explicitly authorized deployment. A new protocol will always get a new protocol
identifier, explicit version negotiation and downgrade protection. It will never
silently replace `sentient-hybrid-v1`.

| # | Capability | Gap today | Basis we intend to build on | Status |
|---|---|---|---|---|
| 1 | Independent identity-key verification | Keys come from the server directory unverified | Published "safety number" designs (iterated hash of identity keys, out-of-band comparison or QR) | **Experimental code** (`identity-verification.ts`): fingerprint and comparison code, 6 tests. Not reviewed, not wired into any client. |
| 2 | Key-change detection | No pinning of a contact's device set | Trust-on-first-use pins with explicit change events | **Experimental code** (same module): pure state machine, tests. |
| 3 | Cryptographic sender authentication (1:1) | hybrid-v1 has no sender signature | Reuse the deployed hybrid Ed25519 + ML-DSA-65 framing (already used by business and group) to sign hybrid-v1 payloads under a **new** protocol id | Design only. Needs a key-registration path for signing keys per device, a negotiation rule, and old-client compatibility. |
| 4 | Authenticated initial key agreement | Ephemeral-static KEM only | PQXDH (Signal, 2023) as a reference design; formal analyses of PQXDH published 2023-2024 | Research. Not implemented. |
| 5 | Forward secrecy and post-compromise security (classical) | Static recipient keys | Double Ratchet specification (Signal) | Research. Not implemented. |
| 6 | Post-quantum ratcheting | None | Sparse Post-Quantum Ratchet (SPQR) and the "Triple Ratchet" composition published by Signal in 2025, and the academic work it builds on | Research. Not implemented. |
| 7 | Secure multi-device sessions | Fan-out to the server-listed devices | Per-device sessions (Sesame-style session management) combined with 1 and 2 | Research. |
| 8 | Out-of-order and offline handling | N/A (no ratchet state) | Skipped-message-key handling with bounds, as in the Double Ratchet spec | Depends on 5. |
| 9 | Replay and downgrade protection | Server-assigned ordering; version string only | Signed version advertisement per device; refuse lower versions once a peer has advertised a higher one | Design only. |
| 10 | Session lifecycle | N/A | Explicit session reset and key-deletion events | Depends on 5 and 6. |

## Why items 4-10 are not implemented in this release

A ratcheting messaging protocol is a large state machine whose security
depends on details: header encryption, skipped-key bounds, state rollback on
failure, multi-device fan-out and negotiation. Code written quickly, and
validated only by its author's own tests, is not a responsible basis for
claims of forward secrecy or post-compromise security. We will build these
components separately and versioned, with state-machine tests, fuzzing and
test vectors, then seek independent review before any deployment.

## Licensing constraints

- **libsignal is AGPL-3.0.** None of its code is copied, vendored, translated
  or adapted here, and none will be. Contributors must not submit such code.
- Specifications: Signal publishes the X3DH, Double Ratchet, PQXDH and Sesame
  specifications as documents. The specification texts carry their own
  dedication and licence statements, which must be read for each document
  before use. Using a published specification does not automatically grant
  rights to any patents that might cover it. Before implementing items 4-7 we
  will review each specification's stated terms and look for relevant patents,
  and record the result here. Until then those items remain research.
- Primitives: we will use only maintained, permissively licensed
  implementations (currently the MIT-licensed `@noble/*`).
