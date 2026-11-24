/*
 * Sentient group chat crypto core - "sentient-group-*-v1". Pure functions only (no storage, network or platform APIs).
 *
 * It composes the SAME primitives the business crypto core uses (hybrid X25519 + ML-KEM-768 KEM, HKDF-SHA-256,
 * XChaCha20-Poly1305, hybrid Ed25519 + ML-DSA-65 signatures) and reuses its audited helpers for canonical encoding,
 * signatures and attachment bytes. Wire labels are group-specific so a group wrap or message can never be replayed as a
 * business or direct message (and vice versa).
 *
 * Model (see the implementation report for the trust assumptions):
 *   - every group has numbered key EPOCHS; each epoch has one random 32-byte group key (GK)
 *   - GK is sealed separately to every ACTIVE member device (the "wrap"), signed by the wrapping device and bound to a
 *     commitment to GK, so a server that swaps in a key of its own choosing is detected
 *   - a message is encrypted under a per-message key derived from GK, and signed by the sending device; readers verify the
 *     signature BEFORE decrypting and pin the sender, group, epoch and message id the server row claims
 *   - history for a newcomer: an existing member's device seals EVERY epoch key it holds to the newcomer's devices
 *   - removal: the group moves to a NEW epoch whose wraps exist only for remaining members (the server also deletes the
 *     removed member's wraps); the removed member keeps only keys they already held
 * The backend stores ciphertext, wraps, public keys and routing metadata. It never receives a group key, message key,
 * file key or private key.
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import {
  canonicalBytes,
  decryptAttachmentBytes,
  encryptAttachmentBytes,
  fromB64,
  signHybrid,
  toB64,
  verifyHybrid,
  wipe,
} from "../business/core.js";
import { hybridSeal as sharedHybridSeal, hybridOpen as sharedHybridOpen } from "../kem/index.js";

export { decryptAttachmentBytes, encryptAttachmentBytes, fromB64, toB64 };

export const GROUP_WRAP_VERSION = "sentient-group-wrap-v1";
export const GROUP_MESSAGE_VERSION = "sentient-group-msg-v1";
export const GROUP_LINK_VERSION = "sentient-group-keylink-v1";
export const GROUP_KEY_COMMITMENT_LABEL = "sentient-group-key-v1:commitment";
export const GROUP_MESSAGE_SUITE = "X25519+ML-KEM-768/HKDF-SHA-256/XChaCha20-Poly1305/Ed25519+ML-DSA-65";
export const MAX_GROUP_MESSAGE_TEXT_LENGTH = 10000;

const WRAP_SIGN_CONTEXT = `${GROUP_WRAP_VERSION}/wrap`;
const MESSAGE_SIGN_CONTEXT = `${GROUP_MESSAGE_VERSION}/message`;
const LINK_SIGN_CONTEXT = `${GROUP_LINK_VERSION}/link`;

export class GroupCryptoError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = "GroupCryptoError";
    this.code = code;
  }
}

let randomSource = randomBytes;
/** Tests only. */
export function __setGroupRandomSourceForTests(source) {
  randomSource = source || randomBytes;
}
function rand(length) {
  const bytes = randomSource(length);
  if (!(bytes instanceof Uint8Array) || bytes.length !== length) throw new GroupCryptoError("random_source");
  return bytes;
}
function constantTimeEqualText(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function requireFields(object, expected, code) {
  for (const [key, value] of Object.entries(expected || {})) {
    if (value === undefined) continue;
    if (object[key] !== value) throw new GroupCryptoError(code, `Field ${key} does not match.`);
  }
}

// ---------------------------------------------------------------------------
// Hybrid seal (X25519 ephemeral-static + ML-KEM-768 encapsulation -> HKDF -> XChaCha20-Poly1305, header as AAD).
// ---------------------------------------------------------------------------
function hybridSeal({ plaintext, recipient, header }) {
  return sharedHybridSeal({ plaintext, recipient, header, kdfInfo: `${GROUP_WRAP_VERSION}:kek`, rand });
}

function hybridOpen({ box, recipientPrivate }) {
  return sharedHybridOpen({ box, recipientPrivate, kdfInfo: `${GROUP_WRAP_VERSION}:kek`, fail: (code, message) => new GroupCryptoError(code, message) });
}

// ---------------------------------------------------------------------------
// Group keys (per group, per epoch).
// ---------------------------------------------------------------------------
export function newGroupKey() {
  return rand(32);
}

export function groupKeyCommitment(groupKey, { groupId, epoch }) {
  return toB64(hkdf(sha256, groupKey, utf8ToBytes(GROUP_KEY_COMMITMENT_LABEL), canonicalBytes({ groupId, epoch }), 32));
}

/**
 * recipient: { userId, keyId, x25519PublicKey, mlKemPublicKey }   (the member device's KEM key)
 * wrapper:   { userId, keyId (the SIGNING key id), signingKeys }
 */
export function wrapGroupKey({ groupKey, groupId, epoch, recipient, wrapper, createdAt }) {
  if (!(groupKey instanceof Uint8Array) || groupKey.length !== 32) throw new GroupCryptoError("wrap_key");
  const header = {
    v: GROUP_WRAP_VERSION,
    groupId,
    epoch,
    commitment: groupKeyCommitment(groupKey, { groupId, epoch }),
    recipientUserId: recipient.userId,
    recipientKeyId: recipient.keyId,
    wrapperUserId: wrapper.userId,
    wrapperKeyId: wrapper.keyId,
    createdAt,
  };
  const box = hybridSeal({ plaintext: groupKey, recipient, header });
  return { ...box, signature: signHybrid(WRAP_SIGN_CONTEXT, box, wrapper.signingKeys) };
}

/**
 * Order: shape -> routing fields -> wrapper's hybrid signature -> KEM/AEAD -> key commitment. Never returns a
 * partially trusted key. wrapperPublicKeys comes from the server directory for wrap.wrapperKeyId.
 */
export function unwrapGroupKey({ wrap, recipientPrivate, expected, wrapperPublicKeys }) {
  if (!wrap || typeof wrap !== "object" || wrap.v !== GROUP_WRAP_VERSION) throw new GroupCryptoError("wrap_version");
  requireFields(wrap, expected, "wrap_field_mismatch");
  if (!wrapperPublicKeys) throw new GroupCryptoError("wrap_unknown_wrapper");
  const { signature, ...box } = wrap;
  if (!signature || !verifyHybrid(WRAP_SIGN_CONTEXT, box, signature, wrapperPublicKeys).both) {
    throw new GroupCryptoError("wrap_signature", "The group key was not signed by a member device.");
  }
  const groupKey = hybridOpen({ box, recipientPrivate });
  const commitment = groupKeyCommitment(groupKey, wrap);
  if (groupKey.length !== 32 || !constantTimeEqualText(commitment, wrap.commitment)) {
    wipe(groupKey);
    throw new GroupCryptoError("wrap_commitment", "The group key does not match its commitment.");
  }
  return groupKey;
}

// ---------------------------------------------------------------------------
// Backward key chain. Link n seals the OLDER epoch key under the key of epoch n + 1, so whoever holds epoch k can recover every
// epoch below k without anyone's help, while an earlier key can never reveal a later one (rotation still cuts off the future).
// The link is signed by the member device that made it and is bound to the older epoch's key commitment, which the server
// also publishes for the epoch: a forged or substituted link cannot be opened into a key that matches it.
// ---------------------------------------------------------------------------
function linkKey(newerKey, aad) {
  return hkdf(sha256, newerKey, sha256(aad), utf8ToBytes(`${GROUP_LINK_VERSION}:key`), 32);
}

/** wrapper: { userId, keyId (SIGNING key id), signingKeys } */
export function sealKeyLink({ olderKey, newerKey, groupId, olderEpoch, wrapper, createdAt }) {
  if (!(olderKey instanceof Uint8Array) || olderKey.length !== 32 || !(newerKey instanceof Uint8Array) || newerKey.length !== 32) throw new GroupCryptoError("link_key");
  const header = {
    v: GROUP_LINK_VERSION, groupId, epoch: olderEpoch, newerEpoch: olderEpoch + 1,
    commitment: groupKeyCommitment(olderKey, { groupId, epoch: olderEpoch }),
    wrapperUserId: wrapper.userId, wrapperKeyId: wrapper.keyId, createdAt,
  };
  const aad = canonicalBytes(header);
  const key = linkKey(newerKey, aad);
  const nonce = rand(24);
  const sealed = xchacha20poly1305(key, nonce, aad).encrypt(olderKey);
  wipe(key);
  const box = { ...header, nonce: toB64(nonce), sealed: toB64(sealed) };
  return { ...box, signature: signHybrid(LINK_SIGN_CONTEXT, box, wrapper.signingKeys) };
}

/**
 * Order: shape -> routing fields -> wrapper's hybrid signature -> AEAD under the newer key -> commitment (own AND the one the
 * server published for that epoch). Never returns a partially trusted key.
 */
export function openKeyLink({ link, newerKey, expected, wrapperPublicKeys, expectedCommitment }) {
  if (!link || typeof link !== "object" || link.v !== GROUP_LINK_VERSION) throw new GroupCryptoError("link_version");
  requireFields(link, expected, "link_field_mismatch");
  if (!wrapperPublicKeys) throw new GroupCryptoError("link_unknown_wrapper");
  const { signature, ...box } = link;
  if (!signature || !verifyHybrid(LINK_SIGN_CONTEXT, box, signature, wrapperPublicKeys).both) throw new GroupCryptoError("link_signature", "The key link was not signed by a member device.");
  const { nonce, sealed, ...header } = box;
  const aad = canonicalBytes(header);
  const key = linkKey(newerKey, aad);
  let olderKey;
  try { olderKey = xchacha20poly1305(key, fromB64(nonce), aad).decrypt(fromB64(sealed)); }
  catch { throw new GroupCryptoError("link_aead", "The key link failed authentication."); }
  finally { wipe(key); }
  const commitment = groupKeyCommitment(olderKey, { groupId: header.groupId, epoch: header.epoch });
  if (olderKey.length !== 32 || !constantTimeEqualText(commitment, header.commitment) || (expectedCommitment && !constantTimeEqualText(commitment, expectedCommitment))) {
    wipe(olderKey);
    throw new GroupCryptoError("link_commitment", "The recovered key does not match its commitment.");
  }
  return olderKey;
}

// ---------------------------------------------------------------------------
// Messages. header: { groupId, epoch, messageId, senderId, senderKeyId, createdAt }
// content: { kind: "text", text } | { kind: "attachment", text, attachment: { id, fileKey, nonce, contentHash, fileName, mimeType, size } }
// ---------------------------------------------------------------------------
function messageHeader(h) {
  return {
    v: GROUP_MESSAGE_VERSION,
    suite: GROUP_MESSAGE_SUITE,
    groupId: h.groupId,
    epoch: h.epoch,
    messageId: h.messageId,
    senderId: h.senderId,
    senderKeyId: h.senderKeyId,
    createdAt: h.createdAt,
  };
}

function messageKeyFor(groupKey, aad) {
  return hkdf(sha256, groupKey, sha256(aad), utf8ToBytes(`${GROUP_MESSAGE_VERSION}:message-key`), 32);
}

export function validateGroupContent(content) {
  if (!content || typeof content !== "object") throw new GroupCryptoError("content_shape");
  if (typeof content.text !== "string" || content.text.length > MAX_GROUP_MESSAGE_TEXT_LENGTH) throw new GroupCryptoError("content_text");
  if (content.kind === "text") {
    if (!content.text.trim()) throw new GroupCryptoError("content_empty");
    return content;
  }
  if (content.kind === "attachment") {
    const a = content.attachment;
    if (!a || typeof a.id !== "string" || typeof a.fileKey !== "string" || typeof a.nonce !== "string" || typeof a.contentHash !== "string") {
      throw new GroupCryptoError("content_attachment");
    }
    if (typeof a.fileName !== "string" || typeof a.mimeType !== "string" || !Number.isFinite(a.size)) throw new GroupCryptoError("content_attachment");
    return content;
  }
  throw new GroupCryptoError("content_kind");
}

export function encryptGroupMessage({ groupKey, header, content, signingKeys }) {
  validateGroupContent(content);
  const fullHeader = messageHeader(header);
  const aad = canonicalBytes(fullHeader);
  const messageKey = messageKeyFor(groupKey, aad);
  const nonce = rand(24);
  const ciphertext = xchacha20poly1305(messageKey, nonce, aad).encrypt(canonicalBytes(content));
  wipe(messageKey);
  const body = { ...fullHeader, nonce: toB64(nonce), ciphertext: toB64(ciphertext) };
  return { ...body, signature: signHybrid(MESSAGE_SIGN_CONTEXT, body, signingKeys) };
}

/**
 * Verifies the sender's hybrid signature FIRST, then decrypts. `expected` pins what the server row says
 * (group, epoch, message id, sender user id, sender key id) so a signed message cannot be replayed into another
 * group, moved to another epoch, or attributed to someone else.
 */
export function decryptGroupMessage({ payload, groupKey, senderPublicKeys, expected }) {
  if (!payload || typeof payload !== "object" || payload.v !== GROUP_MESSAGE_VERSION) throw new GroupCryptoError("message_version");
  if (payload.suite !== GROUP_MESSAGE_SUITE) throw new GroupCryptoError("message_suite");
  requireFields(payload, expected, "message_field_mismatch");
  if (!senderPublicKeys) throw new GroupCryptoError("message_unknown_sender");
  const { signature, ...body } = payload;
  const verified = signature ? verifyHybrid(MESSAGE_SIGN_CONTEXT, body, signature, senderPublicKeys) : { both: false };
  if (!verified.both) throw new GroupCryptoError("message_signature", "The message signature is not valid.");
  const { nonce, ciphertext, ...fullHeader } = body;
  const aad = canonicalBytes(fullHeader);
  const messageKey = messageKeyFor(groupKey, aad);
  let plaintext;
  try {
    plaintext = xchacha20poly1305(messageKey, fromB64(nonce), aad).decrypt(fromB64(ciphertext));
  } catch {
    throw new GroupCryptoError("message_aead", "The message failed authentication.");
  } finally {
    wipe(messageKey);
  }
  let content;
  try {
    content = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new GroupCryptoError("content_shape");
  }
  return { content: validateGroupContent(content), header: fullHeader };
}
