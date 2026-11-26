# Threat model and known limitations

This document states what each protocol in this package is designed to
guarantee, what it assumes, and what it does **not** guarantee, as used by
Sentient 4.2.0. If you find a property claimed here that the code does not
provide, that is a vulnerability and we want the report (see
[SECURITY.md](SECURITY.md)).

## Parties and trust

- **Endpoints**: the Sentient app (iOS, Android) and the Business Terminal
  (browser). Private keys exist only on endpoints.
- **Sentient's server** (Supabase Postgres, Realtime, Edge Functions) stores
  ciphertext, wrapped keys, public keys and routing metadata, and enforces
  authorization (who may message whom, group membership, business routing).
- **Network attacker**: sees and modifies traffic. TLS protects client-server
  traffic. That protection is not part of this package.

## Key directory trust

Endpoints obtain other parties' public keys from Sentient's server. In Sentient
4.2.0 they do not take those keys on trust alone:

- **Pinned identities** (`session/identity-verification`): the first identity
  seen for a contact's device is pinned; a different one later is a key change
  that is shown to the user and refused until accepted. Users can compare
  safety numbers or scan a QR code to verify a contact.
- **Signed device lists** (`session/device-list`): an account's devices are
  listed in a statement signed by one of its own devices; a device the list does
  not name receives nothing and is not accepted as a sender. A list no known
  device signed is an identity reset, shown to the user.
- **Signed organization rosters** (`session/business-roster`): the Terminal
  devices and organization keys that receive business conversation keys are
  approved and signed by the organization's own Terminals.
- **Call key bindings**: each device's session identity signs a statement naming
  its call signing key; both sides of a call (consumer and Business Terminal)
  verify the other side's key against the pinned identity, the signed device list
  or the organization roster.
- **Key transparency** (`session/transparency`): every published identity,
  device list, roster and call-key binding is appended to a public, append-only
  log. Clients require proof that a key is in the log before trusting it for the
  first time and check that the log only grows; each device watches its own
  account's entries.

Remaining limits: the **first** identity or roster seen is trusted on first use
(verification by safety number closes this). The transparency log does not yet
detect a server that keeps different, internally consistent logs for different
clients (that needs clients comparing tree heads or an independent log monitor),
and a device's monitoring of its own account relies on the server returning all
of that account's entries.

## Sentient 4.2.0 session protocols

See [docs/session-protocols.md](docs/session-protocols.md) for the full
specification and claimed properties. In brief:

- Authenticated hybrid key agreement (X25519 + ML-KEM-768), hybrid-signed
  prekeys, and a signed initial message (costs deniability).
- Forward secrecy and post-compromise security from the Double Ratchet;
  post-quantum forward secrecy and post-compromise security at epoch granularity
  from the sparse ML-KEM ratchet. It is inspired by Signal's SPQR / Triple Ratchet
  and is **not** compatible with or equivalent to it.
- Not provided: metadata protection, header encryption, protection against a
  device while it is compromised, guaranteed erasure of secrets from JavaScript
  memory.

## sentient-hybrid-v1 (consumer direct messages, compatibility)

Used by Sentient 4.2.0 only to exchange messages with devices still on Sentient
4.1.0; once two accounts have used the session protocol, they never fall back.

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

Guaranteed:
- Messages and conversation-key wraps are signed with hybrid Ed25519 + ML-DSA-65,
  and both signatures must verify. A key commitment binds each conversation key.
- `expected` field pinning rejects replay into another conversation, epoch,
  message id or sender.
- With a signed organization roster, conversation keys are sealed only to the
  Terminal devices and organization keys the roster lists, and Terminal
  signatures verify only for keys a roster listed. Messages dated before the
  organization's first roster keep the trust they had before rosters existed.

Important properties to understand:
- **Organization access key (compliance access).** An organization can hold an
  access key that opens its conversations for audited compliance access by its
  own authorized staff. Business conversations are end-to-end encrypted to the
  business as an organization, not to one individual agent.
- An organization's first roster lists the Terminal devices registered at that
  moment (trust on first use). A roster expires after 30 days unless an admin
  Terminal renews it.

## Group protocols (sentient-group-sk-v0-experimental, sentient-group-*-v1)

- Sentient 4.2.0 groups use per-sender ratcheting chains, each message signed
  with the sender device's session identity and checked against its pinned
  identity and signed device list; chain keys travel over pairwise sessions.
  Groups with members on Sentient 4.1.0 use the epoch-based v1 protocol.
- v1: signed messages, wraps and key links. Readers pin group, epoch, message id
  and sender against the server row. Removing a member moves the group to a new
  epoch that the removed member's devices cannot open; keys they already held
  remain theirs. Newcomers receive earlier epoch keys (full history by design).
- Membership is server-enforced.
- Notification previews do not verify the group sender's signature, because an
  ML-DSA-65 signature does not fit in a push payload. A preview proves only
  that some holder of the group key wrote the message.

## Calls (sentient-call-hybrid-v1)

- An extra frame-encryption layer on top of WebRTC DTLS-SRTP (peer to peer;
  TURN only relays). The handshake is ephemeral X25519 plus callee-ephemeral
  ML-KEM-768, signed with hybrid Ed25519 + ML-DSA-65 per message, bound to the
  DTLS fingerprints and confirmed with an HMAC.
- Fresh per-call keys give forward secrecy for call media keys, relative to
  long-term signing keys.
- **Peer keys:** in Sentient 4.2.0 each side verifies the other side's call
  signing key against that device's pinned identity and signed device list (or,
  for a business, the organization's roster), in both call directions. A key
  that fails this check fails the handshake. A device on an older app that never
  presented a binding is shown as encrypted but not as a verified device; once a
  device has presented a binding, losing it is treated as a failure, not as an
  older app.
- **Fallback:** if the peer has no registered signing key at all, the call
  proceeds with DTLS-SRTP only and the state is reported as `unsupported` or
  `standard_encrypted`. Clients show the negotiated state and never claim the
  enhanced layer when it is not active.
- `pq_signed_unattested_device` means the signatures verified, but the peer's
  key was registered without platform attestation.

## Recovery

- **Recovery v2** (`recovery/keys`, Sentient 4.2.0): two 20-digit recovery keys
  (about 133 bits together). The server stores only a hash of a token derived
  from both keys; the backup key is wrapped under a key derived from both and
  bound to the account. A new device still needs approval. Encrypted backups of
  message history can be opened by whoever holds both recovery keys; that is the
  trade-off for being able to restore history on a new phone.
- **Android formats (compatibility)**: the v2 recovery object combines a server
  share with a 160-bit client share Sentient never receives. The v1 keyring file
  (Android Auto Backup only) comes from the server share **alone**: someone
  holding both Sentient's server share and the user's Google backup could
  decrypt it. It remains for compatibility.

## Implementation-level caveats

- JavaScript cannot guarantee that secrets are erased from memory. `wipe()`
  is best effort.
- Constant-time behaviour relies on the underlying `@noble/*` libraries and is
  not guaranteed by JavaScript engines.
- `@noble/post-quantum` (ML-KEM-768, ML-DSA-65) is a pure JavaScript
  implementation; the post-quantum guarantees here depend on it.
- The `sentient-hybrid-v1` transcript is JSON with a fixed property order. It
  is not canonical JSON, and changing the order breaks decryption of all
  history. A test freezes it.

## Implemented outside this package

Sentient's server authorization rules and row-level security, pairing and
contact rules, rate limiting, device enrollment, attestation and revocation,
push notification delivery, TURN, the apps' platform secure storage, and the
operational security of Sentient's infrastructure are part of Sentient's
security but are implemented in the app, Terminal and backend codebases.
