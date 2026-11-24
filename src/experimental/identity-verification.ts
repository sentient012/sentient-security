/*
 * EXPERIMENTAL - NOT USED BY ANY SENTIENT CLIENT. NOT REVIEWED.
 * Protocol id: "sentient-identity-fingerprint-v0-experimental".
 *
 * Independent key verification and key-change detection building blocks for a
 * future protocol version. They address one deployed limitation: clients
 * accept whatever device keys the server's directory returns.
 *
 * 1. Fingerprint (comparison code). For two accounts, each with a SET of
 *    device public keys, both sides compute the same 60-digit code:
 *
 *      for each account (ordered by userId, byte-wise):
 *        keys   = sorted, de-duplicated list of "<kind>:<base64 public key>"
 *        digest = SHA-256( "sentient-identity-fingerprint-v0" || 0x00 ||
 *                          len(userId) || userId || count || for each key: len || key )
 *                 iterated 5200 times as digest = SHA-256(digest || fixed input)
 *      code = 30 digits from each account's digest (5-digit groups, each group
 *             = 40-bit big-endian chunk mod 100000), lower userId first.
 *
 *    This follows the general shape of published "safety number" designs
 *    (iterated hash over identity keys, displayed as digit groups) without
 *    reusing any implementation. Iteration count raises the cost of a
 *    targeted second-preimage search over keys an attacker controls; it is not
 *    a substitute for collision resistance analysis (see THREAT_MODEL.md).
 *
 * 2. Key-change detection (TOFU pins). A pure state machine over a pinned
 *    key set per account: first sight pins; identical set -> "unchanged";
 *    any added or removed key -> "changed" with the diff. The caller decides
 *    policy (warn, block, require re-verification). Persisting pins is the
 *    application's job.
 *
 * Limits: a fingerprint only helps if users actually compare it out of band
 * (QR scan or reading digits). Multi-device sets mean the code changes
 * whenever either account adds or removes a device, which is noisy by design.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export const FINGERPRINT_VERSION = "sentient-identity-fingerprint-v0" as const;
export const FINGERPRINT_ITERATIONS = 5200;
export const EXPERIMENTAL = true as const;

export type IdentityKey = { kind: string; publicKey: string };
export type AccountKeys = { userId: string; keys: IdentityKey[] };

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  if (bytes.length > 0xffff) throw new RangeError("field too long");
  return concatBytes(new Uint8Array([bytes.length >> 8, bytes.length & 0xff]), bytes);
}

export function normalizeKeySet(keys: IdentityKey[]): string[] {
  const out = new Set<string>();
  for (const key of keys) {
    if (!key || typeof key.kind !== "string" || typeof key.publicKey !== "string" || !key.kind || !key.publicKey) throw new TypeError("identity key");
    if (key.kind.includes(":")) throw new TypeError("identity key kind must not contain ':'");
    out.add(`${key.kind}:${key.publicKey}`);
  }
  // Byte-wise (UTF-16 code unit) order; inputs are ASCII base64 and ASCII kinds.
  return [...out].sort();
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function accountDigest(account: AccountKeys, iterations = FINGERPRINT_ITERATIONS): Uint8Array {
  if (!account || typeof account.userId !== "string" || !account.userId) throw new TypeError("userId");
  const keys = normalizeKeySet(account.keys);
  if (keys.length === 0) throw new RangeError("an account needs at least one key");
  if (keys.length > 0xffff) throw new RangeError("too many keys");
  const input = concatBytes(
    utf8ToBytes(FINGERPRINT_VERSION),
    new Uint8Array([0]),
    lengthPrefixed(utf8ToBytes(account.userId)),
    new Uint8Array([keys.length >> 8, keys.length & 0xff]),
    ...keys.map((k) => lengthPrefixed(utf8ToBytes(k)))
  );
  let digest = sha256(input);
  for (let i = 1; i < iterations; i++) digest = sha256(concatBytes(digest, input));
  return digest;
}

function digits30(digest: Uint8Array): string {
  let out = "";
  for (let group = 0; group < 6; group++) {
    let value = 0;
    for (let i = 0; i < 5; i++) value = value * 256 + digest[group * 5 + i];
    out += String(value % 100000).padStart(5, "0");
  }
  return out;
}

/** 60-digit comparison code, identical on both sides regardless of who computes it. */
export function comparisonCode(a: AccountKeys, b: AccountKeys, iterations = FINGERPRINT_ITERATIONS): string {
  if (a.userId === b.userId) throw new RangeError("two different accounts are required");
  const [first, second] = compareText(a.userId, b.userId) <= 0 ? [a, b] : [b, a];
  return digits30(accountDigest(first, iterations)) + digits30(accountDigest(second, iterations));
}

/** "12345 67890 ..." for display. */
export function formatComparisonCode(code: string): string {
  if (!/^\d{60}$/.test(code)) throw new TypeError("code");
  return code.match(/\d{5}/g)!.join(" ");
}

export type PinState = { version: typeof FINGERPRINT_VERSION; userId: string; keys: string[]; verified: boolean };
export type PinResult =
  | { status: "first_seen"; next: PinState }
  | { status: "unchanged"; next: PinState }
  | { status: "changed"; added: string[]; removed: string[]; wasVerified: boolean; next: PinState };

/**
 * Compare the directory's current keys for an account with the stored pin.
 * A change always clears `verified`: the user must compare codes again.
 */
export function checkKeyPin(pinned: PinState | null, current: AccountKeys): PinResult {
  const keys = normalizeKeySet(current.keys);
  const next: PinState = { version: FINGERPRINT_VERSION, userId: current.userId, keys, verified: false };
  if (!pinned) return { status: "first_seen", next };
  if (pinned.version !== FINGERPRINT_VERSION || pinned.userId !== current.userId) throw new TypeError("pin does not belong to this account");
  const before = new Set(pinned.keys);
  const after = new Set(keys);
  const added = keys.filter((k) => !before.has(k));
  const removed = pinned.keys.filter((k) => !after.has(k));
  if (added.length === 0 && removed.length === 0) return { status: "unchanged", next: { ...next, verified: pinned.verified } };
  return { status: "changed", added, removed, wasVerified: pinned.verified, next };
}

/** Mark a pin verified after the user compared codes out of band. */
export function markVerified(pin: PinState): PinState {
  return { ...pin, verified: true };
}
