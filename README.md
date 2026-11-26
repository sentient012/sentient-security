# @sentient012/security

The cryptographic core of [Sentient](https://getsentient.io): the protocol code
that the Sentient app (iOS and Android), the Sentient Business Terminal and
Sentient's supporting services run. It is published under the Apache License 2.0
so anyone can read, test and report on exactly the code Sentient ships.

The Sentient app and the Business Terminal install this package at an exact
version and import it directly; guard tests in those codebases fail if a second
copy of any protocol appears. Installing the package yourself does not change
anything in anyone's Sentient app: protections reach users through Sentient app
releases.

## What Sentient 4.2.0 uses it for

| Protection in Sentient 4.2.0 | Implemented in this package | Implemented in the app, Terminal or backend |
|---|---|---|
| **One-to-one messages**: post-quantum key agreement and ratcheting between devices | `session/pqxdh` (PQXDH-style X25519 + ML-KEM-768 key agreement, hybrid-signed prekeys), `session/ratchet` (Double Ratchet with sparse ML-KEM-768 epochs), `session/negotiation` (protocol selection, no downgrade after an upgrade) | Per-device session engine, encrypted on-device session store, prekey directory and delivery |
| **Device verification**: safety numbers, QR verification, key-change warnings | `session/identity-verification` | Contact security screen, pinned identities |
| **Multi-device**: an account's devices are listed and signed by its own devices | `session/device-list` | New-device approval, enforcement before every send and receive |
| **Groups**: per-sender chains, signed messages | `session/group-sender-keys`, `group`, `group/keys` | Hand-offs over pairwise sessions, membership authorization |
| **Business Terminal**: end-to-end encrypted business conversations; only devices the organization approved receive keys | `business`, `business/conversation-keys`, `session/business-roster` | Terminal key storage (non-extractable WebCrypto key), device approval, organization access key with audited compliance reads |
| **Calls**: post-quantum handshake and encrypted audio frames, with both sides' call keys verified against their device identities | `call`, `call/frame-web` | Call key bindings, roster checks for business calls, ringing and delivery |
| **Key transparency**: every published identity, device list, roster and call-key binding is in an append-only log with signed tree heads | `session/transparency` (RFC 9162 tree, inclusion and consistency proofs, signed heads) | The log and its service, first-trust proofs, owner monitoring |
| **Account recovery**: two 20-digit recovery keys | `recovery/keys` | Recovery screens, device approval, server-side hash only |
| **Encrypted backups** of message history | `recovery/keys` (backup key wrapping) | Automatic client-side encrypted backups |
| **Notification previews** decrypted on the device | `notification-preview` | iOS notification extension, Android previews |
| **Compatibility with Sentient 4.1.0** | `hybrid-v1`, `recovery`, `recovery/keyring`, `recovery/passkey` | Used only to talk to and restore from older app versions |
| Shared building blocks | `kem`, `sig`, `encoding`, `random` | — |

`testing` is a deterministic random stream for tests only.

Server-side authorization (database row-level security, contact and pairing
rules, rate limits), device enrollment and platform attestation, revocation,
push delivery, TURN relays and the apps' platform key storage are part of
Sentient but live in the app, Terminal and backend codebases, not in this
package.

Some modules keep the directory name `src/experimental/` and protocol ids that
end in `-v0-experimental` (for example `sentient-tr-v0-experimental`). These are
fixed wire identifiers kept for compatibility; Sentient 4.2.0 uses these
protocols in production.

## Read before relying on it

[THREAT_MODEL.md](THREAT_MODEL.md) states what each protocol guarantees and what
it does not, [PROTOCOLS.md](PROTOCOLS.md) is the byte-level specification, and
[docs/session-protocols.md](docs/session-protocols.md) describes the 4.2.0
session, device-list, roster and transparency protocols. Important limits in
brief: first contact is trust on first use until keys are verified; the
post-quantum ratchet is inspired by Signal's SPQR but is not SPQR; the
transparency log does not yet detect a server that shows different clients
different logs.

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
this package must reproduce them byte for byte. [RESEARCHERS.md](RESEARCHERS.md)
is a starting point for reviewing the code; report findings privately as
described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE) and
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
