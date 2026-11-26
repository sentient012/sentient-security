# @sentient012/security

The cryptographic protocol implementations used by the Sentient apps and the
Sentient Business Terminal, published for independent inspection under the
Apache License 2.0.

> **Audit status: not independently audited.** This code has automated tests,
> including byte-for-byte parity vectors against the deployed implementations,
> but no qualified third party has assessed it. Please review it and report
> what you find (see [SECURITY.md](SECURITY.md)).

## What is here

| Subpath | What it implements | Status in Sentient |
|---|---|---|
| `hybrid-v1` | `sentient-hybrid-v1` consumer direct messages and attachment descriptors: per-message hybrid X25519 + ML-KEM-768, HKDF-SHA-256, XChaCha20-Poly1305 | Deployed |
| `business`, `business/conversation-keys` | `sentient-business-*-v1`: conversation-key epochs, hybrid-sealed key wraps, Ed25519 + ML-DSA-65 signatures, key commitments, organization access key, attachment and scanner seals | Deployed |
| `group`, `group/keys` | `sentient-group-*-v1`: group-key epochs, signed wraps and messages, backward key chain | Deployed |
| `call`, `call/frame-web` | `sentient-call-hybrid-v1` authenticated hybrid post-quantum call handshake; browser frame encryption byte-compatible with libwebrtc's frame cryptor | Deployed (optional layer on top of WebRTC DTLS-SRTP) |
| `recovery`, `recovery/keyring`, `recovery/passkey` | Android key-history recovery object (v2), keyring file (v1), recovery-key codec, passkey PRF wrapper | Deployed (Android) |
| `recovery/keys` (0.3.0) | Recovery v2: two 20-digit recovery keys, HKDF-derived server token and backup wrap key, account-bound encrypted backups | Implemented and tested; used by Sentient 4.2.0 (awaiting mobile distribution); not independently reviewed |
| `notification-preview` | Decryption for notification previews (also bundled for iOS JavaScriptCore) | Deployed |
| `kem`, `sig`, `encoding`, `random` | Shared hybrid seal, hybrid signatures, canonical encodings, CSPRNG tokens and PINs | Deployed |
| `testing` | Deterministic **test-only** random stream | Tests only |
| `session/pqxdh`, `session/ratchet`, `session/negotiation`, `session/device-list`, `session/group-sender-keys`, `session/identity-verification`, `session/business-roster` (0.3.0), `session/transparency` (0.4.0) | The 4.2.0 session protocols: PQXDH-style hybrid key agreement, Double Ratchet with a sparse ML-KEM-768 epoch ratchet (SPQR-inspired, not SPQR), downgrade pins, signed device lists, group sender keys, safety-number-style codes, signed Business Terminal organization rosters, a key transparency log (RFC 9162 Merkle tree, hybrid-signed tree heads) | **Implemented and tested; NOT independently reviewed; off by default in every Sentient release** (since 0.2.0; source in `src/experimental/`) |

The `session/*` subpaths are published so that reviewers and the Sentient apps
use one implementation. Publishing is not activation: no Sentient release sends
or accepts these protocols until an independent review is complete and the
founder authorizes it. See [ROADMAP.md](ROADMAP.md).

Read [THREAT_MODEL.md](THREAT_MODEL.md) before relying on any of this. In
particular, `sentient-hybrid-v1` does **not** authenticate senders
cryptographically and does **not** provide forward secrecy. Every protocol here
trusts Sentient's server for the public keys it hands out.

## Install

```sh
npm install --save-exact @sentient012/security
```

ESM only, with TypeScript declarations. Runtime dependencies: `@noble/ciphers`,
`@noble/curves`, `@noble/hashes`, `@noble/post-quantum` and `@scure/base`, all
pinned to exact versions. React Native apps must install a `crypto.getRandomValues`
polyfill backed by the OS CSPRNG (for example `react-native-get-random-values`)
before first use.

## Verify it yourself

```sh
npm ci
npm test            # build + all unit, negative and legacy-parity tests
npm run verify:pack # inspect exactly what would be published
```

[TESTING.md](TESTING.md) explains the parity vectors: they were captured by
running the unmodified deployed source with a public deterministic seed, and
this package must reproduce them byte for byte.

## What reviewing this package does NOT cover

Sentient's server-side controls are not in this repository: database
row-level security, contact pairing and authorization rules, rate limits,
device enrollment, revocation, platform attestation policy, push delivery and
TURN. Neither is the mobile apps' platform key storage. Reviewing this package
is a review of the cryptographic protocol code only. It is not an audit of
Sentient's production service.

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
