# Protocol specifications

Byte-level descriptions of the deployed protocols. The code is authoritative.
Where this document and the code disagree, that is a bug: please report it.
Notation: `||` concatenation, `b64` standard base64 with padding,
`utf8(x)` UTF-8 bytes, `canon(x)` the canonical JSON defined below.

## Encodings

**canon** (business, group, notification preview). `null` and `undefined`
encode as `null`. Numbers must be finite and use `JSON.stringify`. Strings and
booleans use `JSON.stringify`. Arrays are `[` + elements joined by `,` + `]`.
Objects are `{` + `"key":value` for every key whose value is not `undefined`,
keys sorted by JavaScript string order, joined by `,` + `}`. No whitespace.

**canonCallV1** (call handshake). Same as canon, except that keys with
`undefined` values are **kept** (encoded `null`) and numbers are not checked
for finiteness.

**Hybrid signature, business framing.** input = `utf8(context) || 0x00 ||
utf8(canon(fields))`. Signature = `{ ed25519: b64, mlDsa: b64 }`. Valid only if
**both** Ed25519 and ML-DSA-65 verify.

**Hybrid signature, call framing.** input = `utf8(canonCallV1(fields))`.
Signature = `{ ed25519Signature, mlDsaSignature }`. Both must verify.

## Hybrid seal (business, group)

```
eph        = random(32)
ss1        = X25519(eph, recipient.x25519PublicKey)
(ct, ss2)  = ML-KEM-768.Encaps(recipient.mlKemPublicKey, random(32))
header'    = header + { ephemeralX25519PublicKey: b64(X25519(eph, base)), mlKemCiphertext: b64(ct) }
aad        = utf8(canon(header'))
kek        = HKDF-SHA-256(ikm = ss1 || ss2, salt = SHA-256(aad), info = utf8(kdfInfo), 32)
nonce      = random(24)
box        = header' + { nonce: b64(nonce), sealed: b64(XChaCha20-Poly1305(kek, nonce, aad, plaintext)) }
```
kdfInfo: business wraps `sentient-business-wrap-v1:kek`; org key
`sentient-business-orgkey-v1:kek`; scanner `sentient-business-scan-v1:kek`;
group wraps `sentient-group-wrap-v1:kek`.

## sentient-hybrid-v1

Device keys: X25519 private key = 32 random bytes; ML-KEM-768 key pair from a
64-byte seed. Device key id = `<credentialId>:hybrid-v1`.

For each recipient device (deployed senders list the sender's own live devices
first, then the receiver's):
```
eph       = random(32);  ss1 = X25519(eph, device.x25519)
(ct, ss2) = ML-KEM-768.Encaps(device.mlkem, random(32))
T         = utf8(JSON.stringify({ version: "sentient-hybrid-v1",
              algorithm: "X25519+ML-KEM-768/XChaCha20-Poly1305", threadId,
              senderUserId, receiverUserId, deviceKeyId, userId, credentialId,
              ephemeralX25519PublicKey: b64(...), mlKemCiphertext: b64(ct) }))   // this exact order
key       = HKDF-SHA-256(ss1 || ss2, salt = SHA-256(T), info = "sentient-hybrid-v1:message-key", 32)
nonce     = random(24)
envelope  = { deviceKeyId, userId, credentialId, ephemeralX25519PublicKey, mlKemCiphertext,
              nonce: b64(nonce), ciphertext: b64(XChaCha20-Poly1305(key, nonce, aad = T, utf8(plaintext))) }
```
Payload = `{ version, algorithm, threadId, senderUserId, receiverUserId,
envelopes[] }`. Decryption rebuilds T from the payload and envelope. Plaintext
is decoded as UTF-8 with replacement (`new TextDecoder()`).

Attachments: the file is sealed with XChaCha20-Poly1305 under a random 32-byte
key and 24-byte nonce. The descriptor (key, nonce, SHA-256, name, type) is the
plaintext of a hybrid-v1 message.

## Business (sentient-business-*-v1)

- Conversation key (CK): 32 random bytes per (interaction, epoch).
  Commitment = `b64(HKDF-SHA-256(CK, salt = "sentient-business-key-v1:commitment",
  info = canon({interactionId, organizationId, epoch}), 32))`.
- Wrap = hybrid seal of CK with header `{ v, interactionId, organizationId,
  epoch, commitment, recipientKind, recipientKeyId, wrapperKind, wrapperKeyId,
  createdAt }`, signed (context `sentient-business-wrap-v1/wrap`) over the whole
  box. Open order: routing fields, signature, KEM/AEAD, commitment.
- Message: header `{ v: sentient-business-msg-v1, suite, interactionId,
  organizationId, epoch, messageId, senderType, senderKind, senderKeyId,
  senderId, createdAt }`, aad = canon(header), message key =
  `HKDF(CK, salt = SHA-256(aad), info = "sentient-business-msg-v1:message-key")`,
  content = canon(content) sealed with XChaCha20-Poly1305 and signed (context
  `sentient-business-msg-v1/message`) over header + nonce + ciphertext. The
  signature is verified **before** decryption.
- Org access key: X25519 seed (32) || ML-KEM seed (64), hybrid-sealed to
  granted terminal devices, signed by the distributor. Opening checks that the
  result matches the registered org public key.
- Attachments: AAD `sentient-business-file-v1`. The SHA-256 of the plaintext is
  checked after decryption.

## Group (sentient-group-*-v1)

Same building blocks with group labels: commitment
`sentient-group-key-v1:commitment` over canon({groupId, epoch}); wrap header
`{ v, groupId, epoch, commitment, recipientUserId, recipientKeyId,
wrapperUserId, wrapperKeyId, createdAt }`. A key link seals epoch n's key under
`HKDF(GK[n+1], SHA-256(aad), "sentient-group-keylink-v1:key")`. A message's
header is `{ v, suite, groupId, epoch, messageId, senderId, senderKeyId,
createdAt }`.

## Call (sentient-call-hybrid-v1)

Four signed messages: hello (caller ephemeral X25519, DTLS fingerprints,
nonce), accept (callee ephemeral X25519 and ephemeral ML-KEM-768 public key,
echo of the caller's values), confirm (ML-KEM ciphertext, caller key
confirmation MAC), confirmed (callee MAC). The key transcript is
`utf8(canonCallV1({ hello: helloFields, accept: acceptFields, mlKemCiphertext: b64(ct) }))`
(`fullTranscript` in `src/call/handshake.ts`).
`confirmKey` and `mediaBaseKey` are HKDF-SHA-256(ss_x25519 || ss_mlkem,
salt = SHA-256(transcript), info = `sentient-call-hybrid-v1:confirm-key` /
`:media-key`). Each MAC is HMAC-SHA-256(confirmKey, transcript || ":confirm:" ||
role). Messages whose createdAt differs from the local clock by more than 60 s
are rejected.

Frame encryption (browser, `call/frame-web`): AES-128-GCM key =
HKDF-SHA-256(mediaBaseKey, salt = "sentient-call-hybrid-v1:ratchet-salt",
info = 128 zero bytes). Audio keeps 1 header byte in the clear as AAD. Frame =
header || ciphertext || tag || IV(12) || [12, keyIndex].

## Recovery (Android)

- v1 keyring file: key = HKDF-SHA-256(serverShare(32), salt(32),
  "sentient-android-e2ee-keyring-v1"); AAD `...|user:<id>`.
- v2 object: key = HKDF-SHA-256(serverShare(32) || clientShare(20), salt(32),
  "sentient-e2ee-recovery-v2"); AAD binds user, share id and generation.
- Recovery key: Crockford base32 of the 160-bit client share plus 20 checksum bits.
- Passkey wrapper: key = HKDF-SHA-256(PRF output, salt(32),
  "sentient-passkey-e2ee-wrap-v1|credential:<id>").
