// Android E2EE historical keyring: format, validation and encryption (pure:
// no React Native / Expo imports, so tests load it directly).
//
// The keyring holds this installation's consumer E2EE private keys - the
// current credential's and every earlier one - for DECRYPTION ONLY. It never
// reactivates a credential, is never published and never selects recipients
// for new messages (lib/e2ee.ts still encrypts to server-listed live devices).
//
// Encrypted backup file (lib/e2ee-keyring-store.ts writes it; only Android Auto
// Backup carries it, Sentient's server never receives it):
//
//   { "format": "sentient-android-e2ee-keyring", "v": 1,
//     "salt": b64(32 random), "nonce": b64(24 random), "ciphertext": b64 }
//
//   key        = HKDF-SHA256(ikm = server restore share (32 B), salt,
//                            info = "sentient-android-e2ee-keyring-v1")
//   ciphertext = XChaCha20-Poly1305(key, nonce,
//                   aad = "sentient-android-e2ee-keyring-v1|user:" + userId)
//
// The share comes from get_my_e2ee_restore_share (migration 153): random, per
// user, never derived from the recovery PIN/phrase, ANDROID_ID or any id. The
// associated data binds the file to one Sentient account: another account's
// keyring fails authentication and is never imported.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

export const KEYRING_CONTEXT = "sentient-android-e2ee-keyring-v1";
export const KEYRING_FILE_FORMAT = "sentient-android-e2ee-keyring";
export const KEYRING_VERSION = 1;
export const MAX_KEYRING_ENTRIES = 64;
export const DEVICE_KEY_SUFFIX = ":hybrid-v1";

// SecureStore item names, shared with lib/e2ee.ts (same names as today).
export const X25519_PRIVATE_KEY_STORE = "sentient_e2ee_x25519_private_v1";
export const ML_KEM_SEED_STORE = "sentient_e2ee_mlkem_seed_v1";

export type KeyringEntry = {
  credentialId: string;
  deviceKeyId: string;
  x25519PrivateKey: Uint8Array; // 32 bytes
  mlKemSeed: Uint8Array; // 64 bytes
};

export class KeyringError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message || code);
    this.name = "KeyringError";
    this.code = code;
  }
}

export function deviceKeyIdFor(credentialId: string) {
  return `${credentialId}${DEVICE_KEY_SUFFIX}`;
}

export function secureStoreKeyName(base: string, credentialId: string) {
  return `${base}.${credentialId}`;
}

const CREDENTIAL_ID = /^[A-Za-z0-9_.:-]{1,200}$/;

function isValidCredentialId(value: unknown): value is string {
  return typeof value === "string" && CREDENTIAL_ID.test(value) && !value.endsWith(DEVICE_KEY_SUFFIX);
}

function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function validateEntry(entry: KeyringEntry): KeyringEntry {
  if (!entry || !isValidCredentialId(entry.credentialId)) throw new KeyringError("entry_credential");
  if (entry.deviceKeyId !== deviceKeyIdFor(entry.credentialId)) throw new KeyringError("entry_device_key_id");
  if (!(entry.x25519PrivateKey instanceof Uint8Array) || entry.x25519PrivateKey.length !== 32) throw new KeyringError("entry_x25519_length");
  if (!(entry.mlKemSeed instanceof Uint8Array) || entry.mlKemSeed.length !== 64) throw new KeyringError("entry_mlkem_seed_length");
  return entry;
}

// One entry per deviceKeyId, in first-seen order. An identical duplicate is
// dropped; a CONFLICTING duplicate (same id, different key material) keeps the
// first one seen (callers pass live local keys first) and is reported.
export function mergeEntries(...lists: KeyringEntry[][]) {
  const byId = new Map<string, KeyringEntry>();
  let conflicts = 0;
  for (const list of lists) {
    for (const entry of list) {
      const existing = byId.get(entry.deviceKeyId);
      if (!existing) {
        byId.set(entry.deviceKeyId, entry);
      } else if (!equalBytes(existing.x25519PrivateKey, entry.x25519PrivateKey) || !equalBytes(existing.mlKemSeed, entry.mlKemSeed)) {
        conflicts += 1;
      }
    }
  }
  const entries = [...byId.values()];
  if (entries.length > MAX_KEYRING_ENTRIES) throw new KeyringError("too_many_entries");
  return { entries, conflicts };
}

function aad(userId: string) {
  return utf8ToBytes(`${KEYRING_CONTEXT}|user:${userId}`);
}

function deriveKey(share: Uint8Array, salt: Uint8Array) {
  if (!(share instanceof Uint8Array) || share.length !== 32) throw new KeyringError("share_length");
  if (!(salt instanceof Uint8Array) || salt.length !== 32) throw new KeyringError("salt_length");
  return hkdf(sha256, share, salt, utf8ToBytes(KEYRING_CONTEXT), 32);
}

export function encodeKeyringPlaintext(userId: string, entries: KeyringEntry[]) {
  if (typeof userId !== "string" || !userId) throw new KeyringError("user_id");
  const { entries: merged } = mergeEntries(entries.map(validateEntry));
  return JSON.stringify({
    v: KEYRING_VERSION,
    userId,
    entries: merged.map((entry) => ({
      credentialId: entry.credentialId,
      deviceKeyId: entry.deviceKeyId,
      x25519PrivateKey: base64.encode(entry.x25519PrivateKey),
      mlKemSeed: base64.encode(entry.mlKemSeed),
    })),
  });
}

export function decodeKeyringPlaintext(text: string, expectedUserId: string): KeyringEntry[] {
  let parsed: any;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new KeyringError("plaintext_json");
  }
  if (!parsed || parsed.v !== KEYRING_VERSION) throw new KeyringError("version");
  if (parsed.userId !== expectedUserId) throw new KeyringError("wrong_account");
  if (!Array.isArray(parsed.entries) || parsed.entries.length > MAX_KEYRING_ENTRIES) throw new KeyringError("entries");
  const entries = parsed.entries.map((raw: any) => {
    let x25519PrivateKey: Uint8Array;
    let mlKemSeed: Uint8Array;
    try {
      x25519PrivateKey = base64.decode(String(raw?.x25519PrivateKey ?? ""));
      mlKemSeed = base64.decode(String(raw?.mlKemSeed ?? ""));
    } catch {
      throw new KeyringError("entry_encoding");
    }
    return validateEntry({ credentialId: raw?.credentialId, deviceKeyId: raw?.deviceKeyId, x25519PrivateKey, mlKemSeed });
  });
  return mergeEntries(entries).entries;
}

export function encryptKeyring(params: {
  userId: string;
  entries: KeyringEntry[];
  share: Uint8Array;
  randomBytes: (length: number) => Uint8Array;
}) {
  const salt = params.randomBytes(32);
  const nonce = params.randomBytes(24);
  if (salt.length !== 32 || nonce.length !== 24) throw new KeyringError("random");
  const key = deriveKey(params.share, salt);
  const plaintext = utf8ToBytes(encodeKeyringPlaintext(params.userId, params.entries));
  try {
    const ciphertext = xchacha20poly1305(key, nonce, aad(params.userId)).encrypt(plaintext);
    return JSON.stringify({
      format: KEYRING_FILE_FORMAT,
      v: KEYRING_VERSION,
      salt: base64.encode(salt),
      nonce: base64.encode(nonce),
      ciphertext: base64.encode(ciphertext),
    });
  } finally {
    key.fill(0);
    plaintext.fill(0);
  }
}

export function decryptKeyring(params: { fileText: string; share: Uint8Array; userId: string }): KeyringEntry[] {
  let file: any;
  try {
    file = JSON.parse(params.fileText);
  } catch {
    throw new KeyringError("file_json");
  }
  if (!file || file.format !== KEYRING_FILE_FORMAT || file.v !== KEYRING_VERSION) throw new KeyringError("version");
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
  const key = deriveKey(params.share, salt);
  let plaintext: Uint8Array;
  try {
    plaintext = xchacha20poly1305(key, nonce, aad(params.userId)).decrypt(ciphertext);
  } catch {
    // Wrong share, wrong account, or altered salt/nonce/ciphertext.
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