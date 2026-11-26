# Security architecture and roadmap

## In Sentient 4.2.0

| Capability | How | Module |
|---|---|---|
| Authenticated initial key agreement, post-quantum | PQXDH-style X25519 + ML-KEM-768, hybrid-signed prekeys and initial message | `session/pqxdh` |
| Forward secrecy and post-compromise security | Double Ratchet, plus sparse ML-KEM-768 epochs (inspired by SPQR, not SPQR-compatible) | `session/ratchet` |
| Cryptographic sender authentication (1:1) | Identity DH, hybrid-signed initial message, ratchet AEAD | `session/pqxdh`, `session/ratchet` |
| Identity verification and key-change detection | Pinned identities, safety numbers, QR verification | `session/identity-verification` |
| Secure multi-device | Signed, versioned device lists; new devices approved by a known device | `session/device-list` |
| Replay and downgrade protection | Signed capabilities, per-account upgrade pins | `session/negotiation` |
| Out-of-order and offline delivery | Bounded skipped keys, retained post-quantum epochs | `session/ratchet` |
| Group forward secrecy within an epoch | Per-sender chains, signed messages | `session/group-sender-keys` |
| Business device authorization | Signed organization rosters | `session/business-roster` |
| Mutual call authentication | Call keys bound to device identities, checked by both sides | `call` (+ app and Terminal) |
| Key transparency | Append-only log, RFC 9162 proofs, hybrid-signed tree heads, owner monitoring | `session/transparency` |
| Account recovery and encrypted backups | Two 20-digit recovery keys, account-bound backup key wrapping | `recovery/keys` |

New protocols always get a new protocol identifier, explicit version
negotiation and downgrade protection; Sentient 4.2.0 keeps `sentient-hybrid-v1`
only to talk to devices still on Sentient 4.1.0.

## Next

- **Transparency gossip and monitoring**: clients comparing tree heads, and an
  independent log monitor, so a server that shows different clients different
  logs is detected.
- **MLS (RFC 9420)** for large groups, once a maintained, permissively licensed
  implementation with post-quantum ciphersuites is available.
- **A formal model** (for example ProVerif or Tamarin) of the key agreement and
  the epoch ratchet, and interoperability vectors from a second implementation.
- **Performance** measurements on low-end Android devices.

## Licensing constraints

- **libsignal is AGPL-3.0.** None of its code is copied, vendored, translated
  or adapted here, and none will be. Contributors must not submit such code.
- Specifications: Signal publishes the X3DH, Double Ratchet, PQXDH and Sesame
  specifications as documents placed in the public domain; this package follows
  their published pseudocode. Using a published specification does not by itself
  grant rights to any patents that might cover it; no professional patent search
  has been done.
- Primitives: we use only maintained, permissively licensed implementations
  (currently the MIT-licensed `@noble/*`).
