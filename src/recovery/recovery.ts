// Android E2EE history, v2 recovery object: split-knowledge encryption of the
// device keyring, uploaded to Sentient the moment it changes (pure: no React
// Native / Expo imports, so tests load it directly).
//
// Why v2: the v1 keyring file (./e2ee-keyring) is keyed by the server restore
// share alone, which is fine while only Android Auto Backup carries the file,
// but Auto Backup runs roughly once a day and often never before an uninstall.
// v2 is stored on Sentient's server immediately, so its key must NOT be
// derivable from anything Sentient holds:
//
//   clientShare = 20 random bytes (160 bits). Never sent to Sentient. Held in
//                 SecureStore, in Google Block Store (end-to-end encrypted with
//                 the screen lock when available) and, as the user's fallback,
//                 shown once as a recovery key (formatRecoveryKey).
//   shareId     = hex(SHA-256("sentient-e2ee-recovery-share-id-v1:" || clientShare))[0..32)
//                 names the object that share opens; reveals nothing usable.
//   key         = HKDF-SHA256(ikm = serverShare (32 B) || clientShare (20 B),
//                             salt = 32 random, info = "sentient-e2ee-recovery-v2")
//   ciphertext  = XChaCha20-Poly1305(key, nonce 24 random,
//                   aad = "sentient-e2ee-recovery-v2|user:<id>|share:<shareId>|generation:<n>")
//   plaintext   = the v1 keyring plaintext (same entry validation and limits).
//
// Sentient alone (server share + ciphertext) faces 2^160 client shares; Google
// alone (client share) has no ciphertext and no server share. The generation
// in the associated data ties each ciphertext to the server row's generation,
// so an old ciphertext cannot be replayed under a newer generation.
//
// The recovery key is a NEW secret with one purpose. It is never the account
// recovery PIN or phrase.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { KeyringError, decodeKeyringPlaintext, encodeKeyringPlaintext, type KeyringEntry } from "./keyring.js";

export const RECOVERY_CONTEXT = "sentient-e2ee-recovery-v2";
export const RECOVERY_FORMAT = "sentient-e2ee-recovery";
export const RECOVERY_VERSION = 2;
export const CLIENT_SHARE_BYTES = 20;
const SHARE_ID_CONTEXT = "sentient-e2ee-recovery-share-id-v1:";
const CHECKSUM_CONTEXT = "sentient-e2ee-recovery-key-checksum-v1:";
export const MAX_RECOVERY_OBJECT_CHARS = 65536;

const SHARE_ID = /^[0-9a-f]{32}$/;

function assertClientShare(share: Uint8Array) {
  if (!(share instanceof Uint8Array) || share.length !== CLIENT_SHARE_BYTES) throw new KeyringError("client_share_length");
}

export function newClientShare(randomBytes: (length: number) => Uint8Array) {
  const share = randomBytes(CLIENT_SHARE_BYTES);
  assertClientShare(share);
  if (share.every((byte) => byte === 0)) throw new KeyringError("random");
  return share;
}

export function shareIdFor(clientShare: Uint8Array) {
  assertClientShare(clientShare);
  const prefix = utf8ToBytes(SHARE_ID_CONTEXT);
  const input = new Uint8Array(prefix.length + clientShare.length);
  input.set(prefix);
  input.set(clientShare, prefix.length);
  return bytesToHex(sha256(input)).slice(0, 32);
}

function deriveRecoveryKey(serverShare: Uint8Array, clientShare: Uint8Array, salt: Uint8Array) {
  if (!(serverShare instanceof Uint8Array) || serverShare.length !== 32) throw new KeyringError("share_length");
  assertClientShare(clientShare);
  if (!(salt instanceof Uint8Array) || salt.length !== 32) throw new KeyringError("salt_length");
  const ikm = new Uint8Array(serverShare.length + clientShare.length);
  ikm.set(serverShare);
  ikm.set(clientShare, serverShare.length);
  try {
    return hkdf(sha256, ikm, salt, utf8ToBytes(RECOVERY_CONTEXT), 32);
  } finally {
    ikm.fill(0);
  }
}

function aad(userId: string, shareId: string, generation: number) {
  return utf8ToBytes(`${RECOVERY_CONTEXT}|user:${userId}|share:${shareId}|generation:${generation}`);
}

function assertGeneration(generation: number) {
  if (!Number.isSafeInteger(generation) || generation < 1) throw new KeyringError("generation");
}

export function encryptRecoveryObject(params: {
  userId: string;
  entries: KeyringEntry[];
  serverShare: Uint8Array;
  clientShare: Uint8Array;
  generation: number;
  randomBytes: (length: number) => Uint8Array;
}) {
  assertGeneration(params.generation);
  const shareId = shareIdFor(params.clientShare);
  const salt = params.randomBytes(32);
  const nonce = params.randomBytes(24);
  if (salt.length !== 32 || nonce.length !== 24) throw new KeyringError("random");
  const key = deriveRecoveryKey(params.serverShare, params.clientShare, salt);
  const plaintext = utf8ToBytes(encodeKeyringPlaintext(params.userId, params.entries));
  try {
    const ciphertext = xchacha20poly1305(key, nonce, aad(params.userId, shareId, params.generation)).encrypt(plaintext);
    const text = JSON.stringify({
      format: RECOVERY_FORMAT,
      v: RECOVERY_VERSION,
      shareId,
      generation: params.generation,
      salt: base64.encode(salt),
      nonce: base64.encode(nonce),
      ciphertext: base64.encode(ciphertext),
    });
    if (text.length > MAX_RECOVERY_OBJECT_CHARS) throw new KeyringError("too_large");
    return { text, shareId };
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

// expectedGeneration: the generation the SERVER row reports. A ciphertext made
// for any other generation, share or account fails authentication.
export function decryptRecoveryObject(params: {
  text: string;
  userId: string;
  serverShare: Uint8Array;
  clientShare: Uint8Array;
  expectedGeneration: number;
}): KeyringEntry[] {
  assertGeneration(params.expectedGeneration);
  let file: any;
  try {
    file = JSON.parse(params.text);
  } catch {
    throw new KeyringError("file_json");
  }
  if (!file || file.format !== RECOVERY_FORMAT || file.v !== RECOVERY_VERSION) throw new KeyringError("version");
  const shareId = shareIdFor(params.clientShare);
  if (file.shareId !== shareId) throw new KeyringError("wrong_share");
  if (file.generation !== params.expectedGeneration) throw new KeyringError("generation_mismatch");
  let salt: Uint8Array;
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    salt = base64.decode(String(file.salt ?? ""));
    nonce = base64.decode(String(file.nonce ?? ""));
    ciphertext = base64.decode(String(file.ciphertext ?? ""));
  } catch {
    throw new KeyringError("file_encoding");
  }
  if (nonce.length !== 24) throw new KeyringError("nonce_length");
  const key = deriveRecoveryKey(params.serverShare, params.clientShare, salt);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(key, nonce, aad(params.userId, shareId, params.expectedGeneration)).decrypt(ciphertext);
  } catch {
    // Wrong server share, wrong client share, wrong account/generation, or altered bytes.
    throw new KeyringError("authentication");
  } finally {
    key.fill(0);
  }
  try {
    return decodeKeyringPlaintext(new TextDecoder().decode(plaintext), params.userId);
  } finally {
    plaintext.fill(0);
  }
}

export function isShareId(value: unknown): value is string {
  return typeof value === "string" && SHARE_ID.test(value);
}

// ---------------------------------------------------------------------------
// Recovery key: the client share in a form a person can write down.
// Crockford base32 (no I, L, O, U), 32 characters for the 160-bit share plus 4
// checksum characters (20 bits of SHA-256) that catch typos before any network
// call. Shown as 9 groups of 4: "ABCD-EFGH-...". Case, spaces and dashes are
// ignored on entry; I/L read as 1 and O as 0.
// ---------------------------------------------------------------------------
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function toBase32(bytes: Uint8Array, bitCount: number) {
  let out = "";
  for (let bit = 0; bit < bitCount; bit += 5) {
    let value = 0;
    for (let i = 0; i < 5; i++) {
      const index = bit + i;
      const on = index < bitCount && ((bytes[index >> 3] >> (7 - (index & 7))) & 1) === 1;
      value = (value << 1) | (on ? 1 : 0);
    }
    out += ALPHABET[value];
  }
  return out;
}

function fromBase32(text: string, byteCount: number) {
  const bytes = new Uint8Array(byteCount);
  let bit = 0;
  for (const char of text) {
    const value = ALPHABET.indexOf(char);
    if (value < 0) throw new KeyringError("recovery_key_format");
    for (let i = 4; i >= 0; i--) {
      if (bit < byteCount * 8 && ((value >> i) & 1) === 1) bytes[bit >> 3] |= 1 << (7 - (bit & 7));
      bit++;
    }
  }
  return bytes;
}

function checksum(share: Uint8Array) {
  const prefix = utf8ToBytes(CHECKSUM_CONTEXT);
  const input = new Uint8Array(prefix.length + share.length);
  input.set(prefix);
  input.set(share, prefix.length);
  return toBase32(sha256(input), 20);
}

export function formatRecoveryKey(clientShare: Uint8Array) {
  assertClientShare(clientShare);
  const body = toBase32(clientShare, CLIENT_SHARE_BYTES * 8) + checksum(clientShare);
  return body.match(/.{4}/g)!.join("-");
}

export function parseRecoveryKey(input: string): Uint8Array {
  const normalized = String(input ?? "")
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/[IL]/g, "1")
    .replace(/O/g, "0");
  if (normalized.length !== 36) throw new KeyringError("recovery_key_format");
  const share = fromBase32(normalized.slice(0, 32), CLIENT_SHARE_BYTES);
  if (normalized.slice(32) !== checksum(share)) throw new KeyringError("recovery_key_checksum");
  return share;
}
