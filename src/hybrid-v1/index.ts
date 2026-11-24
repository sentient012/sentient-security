/*
 * sentient-hybrid-v1: Sentient's deployed consumer direct-message encryption.
 *
 * Per message, per recipient device:
 *   eph          = 32 random bytes (X25519 ephemeral private key)
 *   ss1          = X25519(eph, recipient X25519 public key)
 *   (ct, ss2)    = ML-KEM-768.Encaps(recipient ML-KEM public key, 32 random bytes)
 *   transcript   = UTF-8(JSON.stringify({ version, algorithm, threadId,
 *                    senderUserId, receiverUserId, deviceKeyId, userId,
 *                    credentialId, ephemeralX25519PublicKey, mlKemCiphertext }))
 *                  -- THIS EXACT PROPERTY ORDER; it is not canonical JSON.
 *   key          = HKDF-SHA-256(ss1 || ss2, salt = SHA-256(transcript),
 *                    info = "sentient-hybrid-v1:message-key", 32)
 *   ciphertext   = XChaCha20-Poly1305(key, nonce = 24 random bytes, aad = transcript)
 *
 * SECURITY PROPERTIES (see THREAT_MODEL.md). Confidentiality to the listed
 * devices holds if either X25519 or ML-KEM-768 holds. It does NOT provide:
 *   - sender authentication (anyone holding the recipient's public keys can
 *     produce an envelope naming any sender; the backend's insert policy is
 *     the only sender check),
 *   - independent key verification (recipient keys come from the server),
 *   - forward secrecy or post-compromise security against compromise of a
 *     recipient device's long-term keys.
 * These are properties of the deployed protocol and are preserved here
 * unchanged for compatibility. Do not add fields or reorder anything.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { fromB64, toB64, utf8Decode, wipe } from "../encoding/index.js";

export const PROTOCOL_VERSION = "sentient-hybrid-v1" as const;
export const ALGORITHM = "X25519+ML-KEM-768/XChaCha20-Poly1305" as const;
export const DEVICE_KEY_SUFFIX = ":hybrid-v1";

export type RandomSource = (length: number) => Uint8Array;

export type DevicePublicKeyBundle = {
  id: string;
  user_id: string;
  credential_id: string;
  x25519_public_key: string;
  ml_kem_public_key: string;
  is_active?: boolean;
  created_at?: string;
};

export type HybridEnvelope = {
  deviceKeyId: string;
  userId: string;
  credentialId: string;
  ephemeralX25519PublicKey: string;
  mlKemCiphertext: string;
  nonce: string;
  ciphertext: string;
};

export type HybridMessagePayload = {
  version: typeof PROTOCOL_VERSION;
  algorithm: typeof ALGORITHM;
  threadId: string;
  senderUserId: string;
  receiverUserId: string;
  envelopes: HybridEnvelope[];
};

export type DevicePrivateKeys = {
  deviceKeyId: string;
  x25519PrivateKey: Uint8Array;
  mlKemSecretKey: Uint8Array;
};

export class HybridV1Error extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message || code);
    this.name = "HybridV1Error";
    this.code = code;
  }
}

export function deviceKeyIdFor(credentialId: string): string {
  return `${credentialId}${DEVICE_KEY_SUFFIX}`;
}

/** Public keys and ML-KEM secret key from the stored device secrets (32-byte X25519 private key, 64-byte ML-KEM seed). */
export function deviceKeysFromSecrets(x25519PrivateKey: Uint8Array, mlKemSeed: Uint8Array) {
  if (x25519PrivateKey.length !== 32) throw new HybridV1Error("x25519_length");
  if (mlKemSeed.length !== 64) throw new HybridV1Error("mlkem_seed_length");
  const kem = ml_kem768.keygen(mlKemSeed);
  return {
    x25519PublicKey: x25519.getPublicKey(x25519PrivateKey),
    mlKemPublicKey: kem.publicKey,
    mlKemSecretKey: kem.secretKey,
  };
}

/** Fresh device secrets: 32 bytes X25519 private key, then 64 bytes ML-KEM seed (deployed order). */
export function newDeviceSecrets(rand: RandomSource = randomBytes) {
  return { x25519PrivateKey: rand(32), mlKemSeed: rand(64) };
}

/**
 * The exact transcript bytes. Property insertion order is part of the wire
 * format (JSON.stringify follows insertion order for string keys).
 */
export function buildTranscript(params: {
  threadId: string;
  senderUserId: string;
  receiverUserId: string;
  deviceKeyId: string;
  userId: string;
  credentialId: string;
  ephemeralX25519PublicKey: string;
  mlKemCiphertext: string;
}): Uint8Array {
  const ordered = {
    version: PROTOCOL_VERSION,
    algorithm: ALGORITHM,
    threadId: params.threadId,
    senderUserId: params.senderUserId,
    receiverUserId: params.receiverUserId,
    deviceKeyId: params.deviceKeyId,
    userId: params.userId,
    credentialId: params.credentialId,
    ephemeralX25519PublicKey: params.ephemeralX25519PublicKey,
    mlKemCiphertext: params.mlKemCiphertext,
  };
  return utf8ToBytes(JSON.stringify(ordered));
}

function deriveMessageKey(x25519Shared: Uint8Array, mlKemShared: Uint8Array, transcript: Uint8Array) {
  const ikm = concatBytes(x25519Shared, mlKemShared);
  try {
    return hkdf(sha256, ikm, sha256(transcript), utf8ToBytes(`${PROTOCOL_VERSION}:message-key`), 32);
  } finally {
    wipe(ikm);
  }
}

/** One envelope. Randomness order: 32 (ephemeral), 32 (ML-KEM message), 24 (nonce). */
export function encryptEnvelope(params: {
  plaintext: string;
  threadId: string;
  senderUserId: string;
  receiverUserId: string;
  recipient: DevicePublicKeyBundle;
  rand?: RandomSource;
}): HybridEnvelope {
  const rand = params.rand ?? randomBytes;
  const ephemeralPrivate = rand(32);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const x25519Shared = x25519.getSharedSecret(ephemeralPrivate, fromB64(params.recipient.x25519_public_key));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(fromB64(params.recipient.ml_kem_public_key), rand(32));
  const transcript = buildTranscript({
    threadId: params.threadId,
    senderUserId: params.senderUserId,
    receiverUserId: params.receiverUserId,
    deviceKeyId: params.recipient.id,
    userId: params.recipient.user_id,
    credentialId: params.recipient.credential_id,
    ephemeralX25519PublicKey: toB64(ephemeralPublic),
    mlKemCiphertext: toB64(cipherText),
  });
  const key = deriveMessageKey(x25519Shared, sharedSecret, transcript);
  const nonce = rand(24);
  const ciphertext = xchacha20poly1305(key, nonce, transcript).encrypt(utf8ToBytes(params.plaintext));
  wipe(ephemeralPrivate, x25519Shared, sharedSecret, key);
  return {
    deviceKeyId: params.recipient.id,
    userId: params.recipient.user_id,
    credentialId: params.recipient.credential_id,
    ephemeralX25519PublicKey: toB64(ephemeralPublic),
    mlKemCiphertext: toB64(cipherText),
    nonce: toB64(nonce),
    ciphertext: toB64(ciphertext),
  };
}

/** A payload with one envelope per recipient device, in the given order (deployed clients pass sender devices first). */
export function encryptPayload(params: {
  plaintext: string;
  threadId: string;
  senderUserId: string;
  receiverUserId: string;
  recipients: DevicePublicKeyBundle[];
  rand?: RandomSource;
}): HybridMessagePayload {
  const envelopes = params.recipients.map((recipient) =>
    encryptEnvelope({
      plaintext: params.plaintext,
      threadId: params.threadId,
      senderUserId: params.senderUserId,
      receiverUserId: params.receiverUserId,
      recipient,
      rand: params.rand,
    })
  );
  return {
    version: PROTOCOL_VERSION,
    algorithm: ALGORITHM,
    threadId: params.threadId,
    senderUserId: params.senderUserId,
    receiverUserId: params.receiverUserId,
    envelopes,
  };
}

/** Opens one envelope. Throws on any failure (wrong key, tampering, malformed input). */
export function decryptEnvelope(payload: Pick<HybridMessagePayload, "threadId" | "senderUserId" | "receiverUserId">, envelope: HybridEnvelope, keys: DevicePrivateKeys): string {
  const ephemeralPublic = fromB64(envelope.ephemeralX25519PublicKey);
  const mlKemCiphertext = fromB64(envelope.mlKemCiphertext);
  const nonce = fromB64(envelope.nonce);
  const ciphertext = fromB64(envelope.ciphertext);
  const transcript = buildTranscript({
    threadId: payload.threadId,
    senderUserId: payload.senderUserId,
    receiverUserId: payload.receiverUserId,
    deviceKeyId: envelope.deviceKeyId,
    userId: envelope.userId,
    credentialId: envelope.credentialId,
    ephemeralX25519PublicKey: toB64(ephemeralPublic),
    mlKemCiphertext: toB64(mlKemCiphertext),
  });
  const x25519Shared = x25519.getSharedSecret(keys.x25519PrivateKey, ephemeralPublic);
  const mlKemShared = ml_kem768.decapsulate(mlKemCiphertext, keys.mlKemSecretKey);
  const key = deriveMessageKey(x25519Shared, mlKemShared, transcript);
  try {
    return utf8Decode(xchacha20poly1305(key, nonce, transcript).decrypt(ciphertext));
  } finally {
    wipe(x25519Shared, mlKemShared, key);
  }
}

/**
 * Parses a stored e2ee_payload (object or JSON text). Returns null for
 * anything that is not a structurally valid sentient-hybrid-v1 payload;
 * use classifyPayload to tell "absent" from "malformed".
 */
export function parsePayload(value: unknown): HybridMessagePayload | null {
  const result = classifyPayload(value);
  return result.kind === "hybrid-v1" ? result.payload : null;
}

export type PayloadClassification =
  | { kind: "absent" }
  | { kind: "malformed"; reason: string }
  | { kind: "unknown_version"; version: unknown }
  | { kind: "hybrid-v1"; payload: HybridMessagePayload };

const isText = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/** Strict structural classification of a stored payload. Never throws. */
export function classifyPayload(value: unknown): PayloadClassification {
  if (value === null || value === undefined || value === "") return { kind: "absent" };
  let parsed: unknown = value;
  if (typeof value === "string") {
    try {
      parsed = JSON.parse(value);
    } catch {
      return { kind: "malformed", reason: "json" };
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return { kind: "malformed", reason: "shape" };
  const p = parsed as Record<string, unknown>;
  if (p.version !== PROTOCOL_VERSION) return { kind: "unknown_version", version: p.version };
  if (!isText(p.threadId) || !isText(p.senderUserId) || !isText(p.receiverUserId)) return { kind: "malformed", reason: "routing" };
  if (!Array.isArray(p.envelopes) || p.envelopes.length === 0) return { kind: "malformed", reason: "envelopes" };
  for (const e of p.envelopes as unknown[]) {
    const env = e as Record<string, unknown> | null;
    if (!env || typeof env !== "object") return { kind: "malformed", reason: "envelope" };
    for (const field of ["deviceKeyId", "userId", "credentialId", "ephemeralX25519PublicKey", "mlKemCiphertext", "nonce", "ciphertext"]) {
      if (!isText(env[field])) return { kind: "malformed", reason: `envelope_${field}` };
    }
  }
  return { kind: "hybrid-v1", payload: parsed as HybridMessagePayload };
}

// ---------------------------------------------------------------------------
// Consumer attachments ("xchacha20poly1305-v1", descriptor marker
// "sentient-attachment-v1"). The file is sealed under a random 32-byte key and
// 24-byte nonce; the descriptor (key, nonce, SHA-256 of the plaintext, name,
// type) travels as the plaintext of a sentient-hybrid-v1 message.
// AAD is JSON with THIS property order (not canonical JSON).
// ---------------------------------------------------------------------------
export const ATTACHMENT_MESSAGE_MARKER = "sentient-attachment-v1" as const;
export const ATTACHMENT_ENCRYPTION_VERSION = "xchacha20poly1305-v1" as const;

export type AttachmentAead = {
  seal: (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, plaintext: Uint8Array) => Uint8Array;
  open: (key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, sealed: Uint8Array) => Uint8Array;
};
const NOBLE_ATTACHMENT_AEAD: AttachmentAead = {
  seal: (key, nonce, aad, plaintext) => xchacha20poly1305(key, nonce, aad).encrypt(plaintext),
  open: (key, nonce, aad, sealed) => xchacha20poly1305(key, nonce, aad).decrypt(sealed),
};

export function attachmentAad(params: { attachmentId: string; threadId: string; senderUserId: string; receiverUserId: string }): Uint8Array {
  return utf8ToBytes(
    JSON.stringify({
      version: ATTACHMENT_MESSAGE_MARKER,
      attachmentId: params.attachmentId,
      threadId: params.threadId,
      senderUserId: params.senderUserId,
      receiverUserId: params.receiverUserId,
    })
  );
}

/** Seals attachment bytes. `aead` lets a platform supply a faster implementation of the SAME construction (ciphertext || 16-byte tag). */
export function sealAttachment(params: {
  plaintext: Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
  attachmentId: string;
  threadId: string;
  senderUserId: string;
  receiverUserId: string;
  aead?: AttachmentAead;
}): Uint8Array {
  if (params.key.length !== 32 || params.nonce.length !== 24) throw new HybridV1Error("attachment_key_nonce");
  return (params.aead ?? NOBLE_ATTACHMENT_AEAD).seal(params.key, params.nonce, attachmentAad(params), params.plaintext);
}

/** Opens attachment bytes; throws on authentication failure. The caller also checks the descriptor's SHA-256. */
export function openAttachment(params: {
  ciphertext: Uint8Array;
  key: Uint8Array;
  nonce: Uint8Array;
  attachmentId: string;
  threadId: string;
  senderUserId: string;
  receiverUserId: string;
  aead?: AttachmentAead;
}): Uint8Array {
  if (params.key.length !== 32 || params.nonce.length !== 24) throw new HybridV1Error("attachment_key_nonce");
  return (params.aead ?? NOBLE_ATTACHMENT_AEAD).open(params.key, params.nonce, attachmentAad(params), params.ciphertext);
}
