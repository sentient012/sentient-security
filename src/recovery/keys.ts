/*
 * Sentient recovery v2 ("sentient-recovery-v2"), published since 0.3.0 as
 * @sentient012/security/recovery/keys. Moved here unchanged from the Sentient
 * app (lib/recovery-keys.ts, 4.2.0) so there is one implementation; formats
 * are byte-identical. The website's WebCrypto copy (deletion pages) derives
 * the same authToken; test/recovery-keys.test.mjs pins vectors for both.
 *
 * - Each key: 20 uniformly random decimal digits from the OS CSPRNG
 *   (rejection sampling, no modulo bias, leading zeros kept): log2(10^20)
 *   = 66.4 bits. Both together: 132.9 bits. Recovery always needs BOTH.
 * - Derivation (HKDF-SHA-256 over both keys together, domain separated):
 *     authToken = HKDF(ikm, "sentient-recovery-v2/auth", 32)       sent to the server, which
 *                                                                stores only SHA-256(authToken)
 *     wrapKey   = HKDF(ikm, "sentient-recovery-v2/backup-wrap", 32) never leaves the device
 *   There is no value derived from one key alone, so the server has no
 *   per-key verification oracle; guessing must cover 2^132.9 combinations,
 *   which is why a fast KDF is acceptable here (unlike a human password).
 * - The encrypted backup is sealed under a random 32-byte backup key; the
 *   backup key is wrapped under wrapKey and stored on the server. Rotating
 *   the recovery keys re-wraps the backup key (backups stay readable).
 * - AEAD: XChaCha20-Poly1305; the associated data binds the account and,
 *   for backups, the version, so ciphertexts cannot be moved between
 *   accounts or versions.
 * Pure module: randomness is injectable for tests; nothing here logs.
 */
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { randomBytes } from "@noble/hashes/utils.js";

export const RECOVERY_KEY_DIGITS = 20;
export const RECOVERY_V2 = "sentient-recovery-v2" as const;
const TEN_POW_20 = 10n ** 20n;
// 72 random bits; values >= LIMIT are rejected so the result is uniform mod 10^20.
const LIMIT = (2n ** 72n / TEN_POW_20) * TEN_POW_20;

export type RandomBytes = (n: number) => Uint8Array;

export class RecoveryKeyError extends Error {
  code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
    this.name = "RecoveryKeyError";
  }
}

/** One 20-digit recovery key (string of exactly 20 ASCII digits). */
export function generateRecoveryKey(random: RandomBytes = randomBytes): string {
  for (let attempt = 0; attempt < 64; attempt++) {
    const bytes = random(9);
    let value = 0n;
    for (const b of bytes) value = (value << 8n) | BigInt(b);
    if (value < LIMIT) return (value % TEN_POW_20).toString().padStart(RECOVERY_KEY_DIGITS, "0");
  }
  throw new RecoveryKeyError("rng");
}

/** Two independent keys. They are never equal (a repeat would mean a broken RNG). */
export function generateRecoveryKeyPair(random: RandomBytes = randomBytes): [string, string] {
  const one = generateRecoveryKey(random);
  let two = generateRecoveryKey(random);
  if (two === one) two = generateRecoveryKey(random);
  if (two === one) throw new RecoveryKeyError("rng");
  return [one, two];
}

/** "1234-56789-01234-567890" (4-5-5-6). Display only. */
export function formatRecoveryKey(key: string): string {
  if (!/^\d{20}$/.test(key)) throw new RecoveryKeyError("format");
  return `${key.slice(0, 4)}-${key.slice(4, 9)}-${key.slice(9, 14)}-${key.slice(14)}`;
}

const DIGIT_BLOCKS = [0x0660, 0x06f0, 0x0966, 0xff10]; // Arabic-Indic, Eastern Arabic-Indic, Devanagari, full-width

/**
 * Accepts typed or pasted input: spaces, hyphens, dashes, dots and similar
 * separators are ignored; non-ASCII decimal digits used by Sentient's
 * languages are mapped to ASCII. Returns exactly 20 digits, or null.
 */
export function parseRecoveryKey(input: string): string | null {
  let out = "";
  for (const ch of String(input ?? "")) {
    const code = ch.codePointAt(0)!;
    if (code >= 0x30 && code <= 0x39) { out += ch; continue; }
    const block = DIGIT_BLOCKS.find((b) => code >= b && code <= b + 9);
    if (block !== undefined) { out += String(code - block); continue; }
    if (/[\s\-‐-―−._·,/]/u.test(ch)) continue;
    return null;
  }
  return /^\d{20}$/.test(out) ? out : null;
}

function ikmOf(key1: string, key2: string) {
  if (!/^\d{20}$/.test(key1) || !/^\d{20}$/.test(key2)) throw new RecoveryKeyError("format");
  return utf8ToBytes(`${RECOVERY_V2}|${key1}|${key2}`);
}
const SALT = utf8ToBytes(`${RECOVERY_V2}/salt`);

/** authToken (hex, for the server) and wrapKey (bytes, device only) from BOTH keys. */
export function deriveRecoveryMaterial(key1: string, key2: string) {
  const ikm = ikmOf(key1, key2);
  return {
    authToken: bytesToHex(hkdf(sha256, ikm, SALT, utf8ToBytes(`${RECOVERY_V2}/auth`), 32)),
    wrapKey: hkdf(sha256, ikm, SALT, utf8ToBytes(`${RECOVERY_V2}/backup-wrap`), 32),
  };
}

/** What the server stores for an authToken (also computed server-side in SQL). */
export function authTokenHash(authToken: string): string {
  return bytesToHex(sha256(hexToBytes(authToken)));
}

const keyAd = (userId: string) => utf8ToBytes(`sentient-backup-key-v1|user:${userId}`);
const backupAd = (userId: string, version: number) => utf8ToBytes(`sentient-backup-v1|user:${userId}|version:${version}`);

export function wrapBackupKey(wrapKey: Uint8Array, backupKey: Uint8Array, userId: string, random: RandomBytes = randomBytes): string {
  if (backupKey.length !== 32) throw new RecoveryKeyError("backup_key");
  const nonce = random(24);
  return JSON.stringify({ v: 1, n: base64.encode(nonce), c: base64.encode(xchacha20poly1305(wrapKey, nonce, keyAd(userId)).encrypt(backupKey)) });
}

export function unwrapBackupKey(wrapKey: Uint8Array, wrapped: string, userId: string): Uint8Array {
  try {
    const w = JSON.parse(wrapped);
    if (w?.v !== 1) throw new Error("version");
    return xchacha20poly1305(wrapKey, base64.decode(w.n), keyAd(userId)).decrypt(base64.decode(w.c));
  } catch {
    throw new RecoveryKeyError("unwrap"); // wrong keys, other account, or tampered
  }
}

/** Seal a backup snapshot (any JSON-serializable value). */
export function sealBackup(backupKey: Uint8Array, userId: string, version: number, snapshot: unknown, random: RandomBytes = randomBytes): string {
  if (!Number.isSafeInteger(version) || version < 1) throw new RecoveryKeyError("version");
  const nonce = random(24);
  const plain = utf8ToBytes(JSON.stringify({ v: 1, version, createdAt: new Date().toISOString(), snapshot }));
  return JSON.stringify({ v: 1, version, n: base64.encode(nonce), c: base64.encode(xchacha20poly1305(backupKey, nonce, backupAd(userId, version)).encrypt(plain)) });
}

export function openBackup(backupKey: Uint8Array, userId: string, sealed: string): { version: number; createdAt: string; snapshot: any } {
  try {
    const s = JSON.parse(sealed);
    if (s?.v !== 1 || !Number.isSafeInteger(s.version)) throw new Error("shape");
    const plain = xchacha20poly1305(backupKey, base64.decode(s.n), backupAd(userId, s.version)).decrypt(base64.decode(s.c));
    const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plain));
    if (body.version !== s.version) throw new Error("version");
    return { version: body.version, createdAt: body.createdAt, snapshot: body.snapshot };
  } catch {
    throw new RecoveryKeyError("backup_integrity");
  }
}
