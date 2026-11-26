# Security roadmap (advanced capabilities)

Nothing on this page is active for Sentient users. The code lives in `src/experimental/`,
is published as `@sentient012/security/session/*` since 0.2.0, and must not be activated in any
Sentient client until it has been independently reviewed and the founder has
explicitly authorized deployment. A new protocol will always get a new protocol
identifier, explicit version negotiation and downgrade protection. It will never
silently replace `sentient-hybrid-v1`.

| # | Capability | Status (see docs/experimental/PROTOCOLS-EXPERIMENTAL.md) |
|---|---|---|
| 1 | Independent identity-key verification | **Experimental code + tests**: comparison codes, QR-bound verification |
| 2 | Key-change detection | **Experimental code + tests**: pins, device-list classification |
| 3 | Cryptographic sender authentication (1:1) | **Experimental code + tests**: pqxdh (identity DH + hybrid-signed initial message) and the ratchet AEAD |
| 4 | Authenticated initial key agreement | **Experimental code + tests**: sentient-pqxdh-v0 (PQXDH structure, hybrid-signed prekeys) |
| 5 | Forward secrecy and post-compromise security (classical) | **Experimental code + tests**: Double Ratchet per specification |
| 6 | Post-quantum ratcheting | **Experimental code + tests**: sparse ML-KEM epoch ratchet + KDF_HYBRID (SPQR-inspired, not SPQR-compatible) |
| 7 | Secure multi-device sessions | **Experimental code + tests**: signed device lists. Per-device session fan-out is left to the app |
| 8 | Out-of-order and offline handling | **Experimental code + tests**: bounded skipped keys, randomized reordering tests |
| 9 | Replay and downgrade protection | **Experimental code + tests**: signed capabilities, upgrade pinning, replay tests |
| 10 | Session lifecycle | **Partial**: state serialization and mutex. No reset or recovery UX |
| 11 | Group FS within an epoch | **Experimental code + tests**: per-sender chains. MLS not adopted |

None of this is reviewed, formally verified or deployed.

## Why these are experimental, not stable

The implementations exist and are tested, but tests written by the implementer are not evidence of security. Independent review, a formal model and real-device measurements are required before any production use (docs/experimental/PROTOCOLS-EXPERIMENTAL.md section 6).

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
