/*
 * Sentient business communications crypto core - "sentient-business-*-v1".
 *
 * THIS FILE IS SHARED, BYTE-IDENTICAL, BETWEEN TWO REPOSITORIES:
 *   sentient-app      lib/business/crypto/business-crypto-core.js   (mobile)
 *   sentient-website  src/terminal/crypto/business-crypto-core.js   (Business Terminal)
 * Both endpoints of a business conversation run this exact code, so the wire
 * format cannot drift between them. tests/business-crypto-core.test.cjs (app)
 * and tests/business-crypto-core.test.js (website) pin it with the same
 * known-answer vectors; the app's cross-repo test also byte-compares the two
 * copies when BUSINESS_TERMINAL_WEBSITE_DIR is set. Change both together.
 *
 * Pure functions only: no storage, no network, no platform APIs. Randomness
 * comes from @noble/hashes randomBytes (crypto.getRandomValues; the app loads
 * react-native-get-random-values first), replaceable only by tests.
 *
 * Enterprise model this implements (see supabase/139_business_communications_pqc.sql):
 *   - every business conversation (business_interactions row) has numbered key
 *     EPOCHS; each epoch has one random 32-byte conversation key (CK)
 *   - CK is sealed separately to every authorized recipient - the customer's
 *     capable devices, the Business Terminal devices of the conversation's
 *     routing audience, and (only if the organization set one up) the
 *     organization access key used for audited compliance access - with a
 *     hybrid X25519 + ML-KEM-768 KEM, HKDF-SHA-256 and XChaCha20-Poly1305
 *   - every sealed copy ("wrap") is signed with the wrapping device's hybrid
 *     Ed25519 + ML-DSA-65 key and carries a commitment to CK, so a server that
 *     substitutes a wrap of a key it chose is detected
 *   - every message is encrypted under a per-message key derived from CK and
 *     signed by the sending device; recipients verify BOTH signatures before
 *     rendering anything
 * The backend stores ciphertext, wraps, public keys and routing metadata. It
 * never receives a conversation key, a message key, a file key or a private key.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { hybridSeal as sharedHybridSeal, hybridOpen as sharedHybridOpen } from "../kem/index.js";

export const MESSAGE_VERSION = "sentient-business-msg-v1";
export const WRAP_VERSION = "sentient-business-wrap-v1";
export const ORG_KEY_VERSION = "sentient-business-orgkey-v1";
export const SCAN_VERSION = "sentient-business-scan-v1";
export const ATTACHMENT_VERSION = "sentient-business-file-v1";
export const KEY_COMMITMENT_LABEL = "sentient-business-key-v1:commitment";
export const MESSAGE_SUITE = "X25519+ML-KEM-768/HKDF-SHA-256/XChaCha20-Poly1305/Ed25519+ML-DSA-65";

const MESSAGE_SIGN_CONTEXT = `${MESSAGE_VERSION}/message`;
const WRAP_SIGN_CONTEXT = `${WRAP_VERSION}/wrap`;
const ORG_KEY_SIGN_CONTEXT = `${ORG_KEY_VERSION}/distribution`;

export const MAX_MESSAGE_TEXT_LENGTH = 10000;

export class BusinessCryptoError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "BusinessCryptoError";
    this.code = code;
  }
}

let randomSource = randomBytes;
/** Tests only: deterministic randomness for known-answer vectors. Pass null to restore. */
export function __setRandomSourceForTests(source) {
  randomSource = source || randomBytes;
}
function rand(length) {
  const bytes = randomSource(length);
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) throw new BusinessCryptoError("random_source");
  return bytes;
}

export function toB64(bytes) {
  return base64.encode(bytes);
}
export function fromB64(value) {
  if (typeof value !== "string") throw new BusinessCryptoError("encoding", "Expected base64 text.");
  return base64.decode(value);
}
function asBytes(value) {
  return typeof value === "string" ? fromB64(value) : value;
}

/** Best-effort zeroization; JS cannot guarantee copies were not made elsewhere. */
export function wipe(...arrays) {
  for (const array of arrays) if (array instanceof Uint8Array) array.fill(0);
}

// Same canonical form as lib/calling-pqc.ts: recursively sorted object keys,
// arrays in order. Only strings, finite numbers, booleans, null, arrays and
// plain objects are accepted, so two implementations cannot disagree.
export function canonicalize(value) {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new BusinessCryptoError("canonical", "Non-finite number.");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).filter(key => value[key] !== undefined).sort();
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(",")}}`;
  }
  throw new BusinessCryptoError("canonical", `Cannot canonicalize ${typeof value}.`);
}
export function canonicalBytes(value) {
  return utf8ToBytes(canonicalize(value));
}

function constantTimeEqualText(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ---------------------------------------------------------------------------
// Device keys. Seeds are what endpoints store; everything else is derived.
// Field names match lib/calling-pqc.ts's LocalSigningKeys so a phone's
// existing call-signing identity is usable here unchanged.
// ---------------------------------------------------------------------------
export function newDeviceSeeds() {
  return { ed25519Seed: rand(32), mlDsaSeed: rand(32), x25519Seed: rand(32), mlKemSeed: rand(64) };
}

export function signingKeysFromSeeds({ ed25519Seed, mlDsaSeed }) {
  const mlDsa = ml_dsa65.keygen(mlDsaSeed);
  return {
    ed25519PrivateKey: ed25519Seed,
    ed25519PublicKey: ed25519.getPublicKey(ed25519Seed),
    mlDsaSecretKey: mlDsa.secretKey,
    mlDsaPublicKey: mlDsa.publicKey,
  };
}

export function kemKeysFromSeeds({ x25519Seed, mlKemSeed }) {
  const kem = ml_kem768.keygen(mlKemSeed);
  return {
    x25519PrivateKey: x25519Seed,
    x25519PublicKey: x25519.getPublicKey(x25519Seed),
    mlKemSecretKey: kem.secretKey,
    mlKemPublicKey: kem.publicKey,
  };
}

// ---------------------------------------------------------------------------
// Hybrid signatures: BOTH Ed25519 and ML-DSA-65 must verify.
// ---------------------------------------------------------------------------
function signingInput(context, fields) {
  return concatBytes(utf8ToBytes(context), new Uint8Array([0]), canonicalBytes(fields));
}

export function signHybrid(context, fields, signingKeys) {
  const input = signingInput(context, fields);
  return {
    ed25519: toB64(ed25519.sign(input, signingKeys.ed25519PrivateKey)),
    mlDsa: toB64(ml_dsa65.sign(input, signingKeys.mlDsaSecretKey)),
  };
}

/** publicKeys: { ed25519_public_key, ml_dsa_public_key } (base64, as the key directories return them). */
function verifiesOrFalse(check) {
  try {
    return check() === true;
  } catch {
    return false;
  }
}

export function verifyHybrid(context, fields, signature, publicKeys) {
  const input = signingInput(context, fields);
  const ed25519Verified = verifiesOrFalse(() => ed25519.verify(fromB64(signature.ed25519), input, fromB64(publicKeys.ed25519_public_key)));
  const mlDsaVerified = verifiesOrFalse(() => ml_dsa65.verify(fromB64(signature.mlDsa), input, fromB64(publicKeys.ml_dsa_public_key)));
  return { ed25519: ed25519Verified, mlDsa: mlDsaVerified, both: ed25519Verified && mlDsaVerified };
}

// ---------------------------------------------------------------------------
// Hybrid seal: X25519 (ephemeral-static) + ML-KEM-768 encapsulation,
// concat -> HKDF-SHA-256 (salt = SHA-256 of the canonical header, which binds
// the KEM outputs and every routing field), XChaCha20-Poly1305 with the same
// canonical header as associated data. Secure while either KEM holds.
// ---------------------------------------------------------------------------
function hybridSeal({ plaintext, recipient, header, label }) {
  return sharedHybridSeal({ plaintext, recipient, header, kdfInfo: `${label}:kek`, rand });
}

function hybridOpen({ box, recipientPrivate, label }) {
  return sharedHybridOpen({ box, recipientPrivate, kdfInfo: `${label}:kek`, fail: (code, message) => new BusinessCryptoError(code, message) });
}

function requireFields(object, expected, code) {
  for (const [key, value] of Object.entries(expected)) {
    if (value === undefined) continue;
    if (object[key] !== value) throw new BusinessCryptoError(code, `Field ${key} does not match.`);
  }
}

// ---------------------------------------------------------------------------
// Conversation keys (per interaction, per epoch).
// ---------------------------------------------------------------------------
export function newConversationKey() {
  return rand(32);
}

export function conversationKeyCommitment(conversationKey, { interactionId, organizationId, epoch }) {
  return toB64(
    hkdf(sha256, conversationKey, utf8ToBytes(KEY_COMMITMENT_LABEL), canonicalBytes({ interactionId, organizationId, epoch }), 32)
  );
}

/**
 * recipient: { kind: "consumer_device" | "terminal_device" | "org_access", keyId, x25519PublicKey, mlKemPublicKey }
 * wrapper:   { kind: "consumer_device" | "terminal_device", keyId (the SIGNING key id), signingKeys }
 */
export function wrapConversationKey({ conversationKey, interactionId, organizationId, epoch, recipient, wrapper, createdAt }) {
  if (!(conversationKey instanceof Uint8Array) || conversationKey.length !== 32) throw new BusinessCryptoError("wrap_key");
  const commitment = conversationKeyCommitment(conversationKey, { interactionId, organizationId, epoch });
  const header = {
    v: WRAP_VERSION,
    interactionId,
    organizationId,
    epoch,
    commitment,
    recipientKind: recipient.kind,
    recipientKeyId: recipient.keyId,
    wrapperKind: wrapper.kind,
    wrapperKeyId: wrapper.keyId,
    createdAt,
  };
  const box = hybridSeal({ plaintext: conversationKey, recipient, header, label: WRAP_VERSION });
  return { ...box, signature: signHybrid(WRAP_SIGN_CONTEXT, box, wrapper.signingKeys) };
}

/**
 * Opens a wrap addressed to this device. Order: shape -> routing fields ->
 * wrapper's hybrid signature -> KEM/AEAD -> key commitment. Throws
 * BusinessCryptoError on any failure; never returns a partially trusted key.
 * wrapperPublicKeys comes from the server key directory for wrap.wrapperKeyId.
 */
export function unwrapConversationKey({ wrap, recipientPrivate, expected, wrapperPublicKeys }) {
  if (!wrap || typeof wrap !== "object" || wrap.v !== WRAP_VERSION) throw new BusinessCryptoError("wrap_version");
  requireFields(wrap, expected, "wrap_field_mismatch");
  if (!wrapperPublicKeys) throw new BusinessCryptoError("wrap_unknown_wrapper");
  const { signature, ...box } = wrap;
  if (!signature || !verifyHybrid(WRAP_SIGN_CONTEXT, box, signature, wrapperPublicKeys).both) {
    throw new BusinessCryptoError("wrap_signature", "The conversation key was not signed by an authorized device.");
  }
  const conversationKey = hybridOpen({ box, recipientPrivate, label: WRAP_VERSION });
  const commitment = conversationKeyCommitment(conversationKey, wrap);
  if (conversationKey.length !== 32 || !constantTimeEqualText(commitment, wrap.commitment)) {
    wipe(conversationKey);
    throw new BusinessCryptoError("wrap_commitment", "The conversation key does not match its commitment.");
  }
  return conversationKey;
}

// ---------------------------------------------------------------------------
// Messages.
// header: { interactionId, organizationId, epoch, messageId, senderType
//           ("consumer" | "business"), senderKind, senderKeyId, senderId, createdAt }
// content: { kind: "text", text } | { kind: "attachment", text, attachment }
// ---------------------------------------------------------------------------
function messageHeader(header) {
  return {
    v: MESSAGE_VERSION,
    suite: MESSAGE_SUITE,
    interactionId: header.interactionId,
    organizationId: header.organizationId,
    epoch: header.epoch,
    messageId: header.messageId,
    senderType: header.senderType,
    senderKind: header.senderKind,
    senderKeyId: header.senderKeyId,
    senderId: header.senderId,
    createdAt: header.createdAt,
  };
}

function messageKeyFor(conversationKey, aad) {
  return hkdf(sha256, conversationKey, sha256(aad), utf8ToBytes(`${MESSAGE_VERSION}:message-key`), 32);
}

export function validateMessageContent(content) {
  if (!content || typeof content !== "object") throw new BusinessCryptoError("content_shape");
  if (typeof content.text !== "string" || content.text.length > MAX_MESSAGE_TEXT_LENGTH) throw new BusinessCryptoError("content_text");
  if (content.kind === "text") {
    if (!content.text.trim()) throw new BusinessCryptoError("content_empty");
    return content;
  }
  if (content.kind === "attachment") {
    const a = content.attachment;
    if (!a || typeof a.id !== "string" || typeof a.fileKey !== "string" || typeof a.nonce !== "string" || typeof a.contentHash !== "string") {
      throw new BusinessCryptoError("content_attachment");
    }
    if (typeof a.fileName !== "string" || typeof a.mimeType !== "string" || !Number.isFinite(a.size)) {
      throw new BusinessCryptoError("content_attachment");
    }
    return content;
  }
  throw new BusinessCryptoError("content_kind");
}

export function encryptBusinessMessage({ conversationKey, header, content, signingKeys }) {
  validateMessageContent(content);
  const fullHeader = messageHeader(header);
  const aad = canonicalBytes(fullHeader);
  const messageKey = messageKeyFor(conversationKey, aad);
  const nonce = rand(24);
  const ciphertext = xchacha20poly1305(messageKey, nonce, aad).encrypt(canonicalBytes(content));
  wipe(messageKey);
  const body = { ...fullHeader, nonce: toB64(nonce), ciphertext: toB64(ciphertext) };
  return { ...body, signature: signHybrid(MESSAGE_SIGN_CONTEXT, body, signingKeys) };
}

/**
 * Verifies the sender's hybrid signature FIRST (over header + ciphertext),
 * then decrypts. `expected` pins what the server row says (interaction,
 * organization, sender type/key/id, epoch, message id) so a signed message
 * cannot be replayed into another conversation or attributed to someone else.
 */
export function decryptBusinessMessage({ payload, conversationKey, senderPublicKeys, expected }) {
  if (!payload || typeof payload !== "object" || payload.v !== MESSAGE_VERSION) throw new BusinessCryptoError("message_version");
  if (payload.suite !== MESSAGE_SUITE) throw new BusinessCryptoError("message_suite");
  requireFields(payload, expected || {}, "message_field_mismatch");
  if (!senderPublicKeys) throw new BusinessCryptoError("message_unknown_sender");
  const { signature, ...body } = payload;
  const verified = signature ? verifyHybrid(MESSAGE_SIGN_CONTEXT, body, signature, senderPublicKeys) : { ed25519: false, mlDsa: false, both: false };
  if (!verified.both) throw new BusinessCryptoError("message_signature", "The message signature is not valid.");
  const { nonce, ciphertext, ...fullHeader } = body;
  const aad = canonicalBytes(fullHeader);
  const messageKey = messageKeyFor(conversationKey, aad);
  let plaintext;
  try {
    plaintext = xchacha20poly1305(messageKey, fromB64(nonce), aad).decrypt(fromB64(ciphertext));
  } catch {
    throw new BusinessCryptoError("message_aead", "The message failed authentication.");
  } finally {
    wipe(messageKey);
  }
  let content;
  try {
    content = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new BusinessCryptoError("content_shape");
  }
  return { content: validateMessageContent(content), signature: verified };
}

// ---------------------------------------------------------------------------
// Attachments: bytes are encrypted under a fresh file key; the key, nonce,
// plaintext hash, real file name and type travel only inside a signed,
// encrypted "attachment" message.
// ---------------------------------------------------------------------------
// `aead` (optional) lets a platform supply a faster implementation of the SAME
// primitives - XChaCha20-Poly1305 seal/open (ciphertext || tag) and SHA-256 -
// e.g. the mobile app's self-tested native libsodium path. Defaults to noble.
const NOBLE_AEAD = {
  seal: (key, nonce, aad, plaintext) => xchacha20poly1305(key, nonce, aad).encrypt(plaintext),
  open: (key, nonce, aad, sealed) => xchacha20poly1305(key, nonce, aad).decrypt(sealed),
  sha256: (bytes) => sha256(bytes),
};

export function encryptAttachmentBytes(plaintext, aead = NOBLE_AEAD) {
  const fileKey = rand(32);
  const nonce = rand(24);
  const ciphertext = (aead.seal || NOBLE_AEAD.seal)(fileKey, nonce, utf8ToBytes(ATTACHMENT_VERSION), plaintext);
  return { fileKey, nonce, ciphertext, contentHash: toB64((aead.sha256 || NOBLE_AEAD.sha256)(plaintext)) };
}

// Re-creates an attachment's ciphertext from its plaintext and its OWN file key
// and nonce. XChaCha20-Poly1305 is deterministic for a given key, nonce and
// AAD, so this reproduces exactly the bytes that were uploaded (the same
// message under the same key - no new information); used to turn a legacy
// plaintext cache entry back into ciphertext. Callers verify by decrypting.
export function resealAttachmentBytes({ plaintext, fileKey, nonce }, aead = NOBLE_AEAD) {
  return (aead.seal || NOBLE_AEAD.seal)(asBytes(fileKey), asBytes(nonce), utf8ToBytes(ATTACHMENT_VERSION), plaintext);
}

export function decryptAttachmentBytes({ ciphertext, fileKey, nonce, contentHash }, aead = NOBLE_AEAD) {
  let plaintext;
  try {
    plaintext = (aead.open || NOBLE_AEAD.open)(asBytes(fileKey), asBytes(nonce), utf8ToBytes(ATTACHMENT_VERSION), ciphertext);
  } catch {
    throw new BusinessCryptoError("attachment_aead", "The attachment failed authentication.");
  }
  if (!constantTimeEqualText(toB64((aead.sha256 || NOBLE_AEAD.sha256)(plaintext)), contentHash)) throw new BusinessCryptoError("attachment_hash");
  return plaintext;
}

/**
 * Optional malware scanning without giving the backend the file key: the
 * uploader seals (fileKey, nonce) to the scanner's published hybrid key for
 * this one upload. The Edge Function forwards ciphertext + this box to the
 * scanner; it cannot open it. The scanner decrypts in memory, scans, discards.
 */
export function sealForScanner({ fileKey, nonce, uploadId, scanner, expiresAt }) {
  const header = { v: SCAN_VERSION, uploadId, scannerKeyId: scanner.keyId, expiresAt };
  return hybridSeal({ plaintext: concatBytes(asBytes(fileKey), asBytes(nonce)), recipient: scanner, header, label: SCAN_VERSION });
}

export function openScannerSeal({ box, scannerPrivate, now = Date.now() }) {
  if (!box || box.v !== SCAN_VERSION) throw new BusinessCryptoError("scan_version");
  if (!(Date.parse(box.expiresAt) > now)) throw new BusinessCryptoError("scan_expired");
  const opened = hybridOpen({ box, recipientPrivate: scannerPrivate, label: SCAN_VERSION });
  if (opened.length !== 56) throw new BusinessCryptoError("scan_shape");
  return { fileKey: opened.slice(0, 32), nonce: opened.slice(32) };
}

// ---------------------------------------------------------------------------
// Organization access key (explicit, audited compliance access). The private
// half exists only as seeds sealed to the terminal devices of users the
// organization granted compliance access; the backend holds sealed copies.
// ---------------------------------------------------------------------------
export function newOrgAccessKeySeeds() {
  return { x25519Seed: rand(32), mlKemSeed: rand(64) };
}

export function sealOrgAccessKey({ seeds, organizationId, orgKeyId, generation, recipientDevice, distributor, createdAt }) {
  const header = {
    v: ORG_KEY_VERSION,
    organizationId,
    orgKeyId,
    generation,
    recipientKeyId: recipientDevice.keyId,
    distributorKeyId: distributor.keyId,
    createdAt,
  };
  const box = hybridSeal({ plaintext: concatBytes(seeds.x25519Seed, seeds.mlKemSeed), recipient: recipientDevice, header, label: ORG_KEY_VERSION });
  return { ...box, signature: signHybrid(ORG_KEY_SIGN_CONTEXT, box, distributor.signingKeys) };
}

/**
 * Returns the org key's private KEM keys (and the seeds, so a compliance
 * holder can seal copies for granted colleagues), after checking they match
 * the registered org PUBLIC key.
 */
export function openOrgAccessKey({ box, expected, devicePrivate, distributorPublicKeys, orgPublicKeys }) {
  if (!box || box.v !== ORG_KEY_VERSION) throw new BusinessCryptoError("orgkey_version");
  requireFields(box, expected, "orgkey_field_mismatch");
  if (!distributorPublicKeys) throw new BusinessCryptoError("orgkey_unknown_distributor");
  const { signature, ...unsigned } = box;
  if (!signature || !verifyHybrid(ORG_KEY_SIGN_CONTEXT, unsigned, signature, distributorPublicKeys).both) {
    throw new BusinessCryptoError("orgkey_signature");
  }
  const opened = hybridOpen({ box: unsigned, recipientPrivate: devicePrivate, label: ORG_KEY_VERSION });
  if (opened.length !== 96) throw new BusinessCryptoError("orgkey_shape");
  const seeds = { x25519Seed: opened.slice(0, 32), mlKemSeed: opened.slice(32) };
  const keys = kemKeysFromSeeds(seeds);
  if (toB64(keys.x25519PublicKey) !== orgPublicKeys.x25519_public_key || toB64(keys.mlKemPublicKey) !== orgPublicKeys.ml_kem_public_key) {
    throw new BusinessCryptoError("orgkey_public_mismatch");
  }
  return { ...keys, seeds };
}
