# Threat model and known limitations

This document states what each protocol in this package is designed to
guarantee, what it assumes, and what it does **not** guarantee. If you find a
property claimed here that the code does not provide, that is a vulnerability
and we want the report (see [SECURITY.md](SECURITY.md)).

## Parties and trust

- **Endpoints**: the Sentient mobile app (iOS, Android) and the Business
  Terminal (browser). Private keys exist only on endpoints.
- **Sentient's server** (Supabase Postgres, Realtime, Edge Functions) stores
  ciphertext, wrapped keys, public keys and routing metadata, and enforces
  authorization (who may message whom, group membership, business routing).
- **Network attacker**: sees and modifies traffic. TLS protects client-server
  traffic. That protection is not part of this package.

**Key directory trust.** In every protocol here, endpoints obtain other
parties' public keys from Sentient's server, and none of them verifies those
keys independently today: there are no deployed safety numbers and no key
transparency. A server that is malicious or compromised can therefore insert
its own device keys and read or forge traffic for affected conversations. The
protocols below protect against a server that *stores* data but does not
actively substitute keys. Experimental verification building blocks are
described in [ROADMAP.md](ROADMAP.md). They are not deployed.

## sentient-hybrid-v1 (consumer direct messages)

Guaranteed, if the server returned genuine keys:
- Confidentiality of each message to the listed recipient devices, as long as
  either X25519 or ML-KEM-768 is secure. The KEM combiner is concatenate-then-HKDF,
  with the transcript as salt and AEAD associated data.
- Integrity and binding: the ciphertext is bound to thread id, sender and
  receiver user ids, and the recipient device, credential and user ids.

Not guaranteed:
- **Sender authentication.** There is no sender signature. Anyone who holds a
  recipient's public keys can produce a valid envelope naming any sender. The
  only sender check is the server's insert policy. `test/negative.test.mjs`
  demonstrates this.
- **Forward secrecy and post-compromise security.** Recipient device keys are
  long-lived. A party that obtains a device's private keys can decrypt every
  stored message addressed to that device.
- **Replay protection** at the cryptographic layer. Message identity and
  ordering are server-assigned.
- **Plaintext rows.** Clients render a stored message that has no encrypted
  payload as "Not end-to-end encrypted:". Such rows can only be legacy
  messages, or rows written by a modified client or by the server itself.

## Business protocol (sentient-business-*-v1)

Guaranteed, if the server's directory and recipient list are genuine:
- Messages and conversation-key wraps are signed with hybrid Ed25519 + ML-DSA-65,
  and both signatures must verify. A key commitment binds each conversation key.
- `expected` field pinning rejects replay into another conversation, epoch,
  message id or sender.

Important properties to understand:
- **The server chooses the recipient list.** The consumer's device seals the
  conversation key to whatever terminal devices and organization access key the
  server reports as required.
- **Organization access key (compliance access).** An organization can hold an
  access key that opens its conversations for audited compliance access by its
  own authorized staff. Business conversations are end-to-end encrypted to the
  business as an organization, not to one individual agent.

## Group protocol (sentient-group-*-v1)

- Signed messages, wraps and key links. Readers pin group, epoch, message id
  and sender against the server row.
- Removing a member moves the group to a new epoch that the removed member's
  devices cannot open. Keys they already held remain theirs.
- Newcomers receive all earlier epoch keys (full history access by design).
- Membership is server-enforced. A malicious server could register a member
  device key.
- Revocation checks use the server-recorded time when the server supplies one,
  otherwise the signer-claimed time (`src/internal/time.js`).
- Notification previews do not verify the group sender's signature, because an
  ML-DSA-65 signature does not fit in a push payload. A preview proves only
  that some holder of the epoch key wrote the message.

## Calls (sentient-call-hybrid-v1)

- An extra frame-encryption layer on top of WebRTC DTLS-SRTP (peer to peer;
  TURN only relays). The handshake is ephemeral X25519 plus callee-ephemeral
  ML-KEM-768, signed with hybrid Ed25519 + ML-DSA-65 per message, bound to the
  DTLS fingerprints and confirmed with an HMAC.
- Fresh per-call keys give forward secrecy for call media keys, relative to
  long-term signing keys.
- **Fallback:** if the peer has no registered signing key, the call proceeds
  with DTLS-SRTP only, and the state is reported as `unsupported` or
  `standard_encrypted`. The server can cause this by withholding the peer's
  key. Clients show the negotiated state and never claim the enhanced layer
  when it is not active.
- `pq_signed_unattested_device` means the signatures verified, but the peer's
  key was registered trust-on-first-use without platform attestation.

## Recovery formats (Android)

- v2 recovery object: the key comes from a server share plus a 160-bit client
  share that Sentient never receives (kept in Google Block Store or shown to
  the user as a recovery key). Sentient alone cannot open it.
- v1 keyring file (Android Auto Backup only): the key comes from the server
  share **alone**. Someone holding both Sentient's server share and the user's
  Google backup could decrypt it. It remains for compatibility.

## Implementation-level caveats

- JavaScript cannot guarantee that secrets are erased from memory. `wipe()`
  is best effort.
- Constant-time behaviour relies on the underlying `@noble/*` libraries and is
  not guaranteed by JavaScript engines.
- `@noble/post-quantum` (ML-KEM-768, ML-DSA-65) is a pure JavaScript
  implementation. Check its README for its current independent-audit status
  before relying on it.
- The `sentient-hybrid-v1` transcript is JSON with a fixed property order. It
  is not canonical JSON, and changing the order breaks decryption of all
  history. A test freezes it.

## Out of scope for this package

The server's authorization rules, row-level security, pairing and contact
rules, rate limiting, device enrollment and revocation, attestation policy,
push notification delivery, TURN, the apps' platform secure storage, and the
operational security of Sentient's infrastructure.
