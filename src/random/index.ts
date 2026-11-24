/*
 * Cryptographically secure, unbiased token generation (pairing tokens, PINs).
 *
 * Source: @noble/hashes randomBytes -> crypto.getRandomValues (Web Crypto;
 * React Native apps must install a getRandomValues polyfill backed by the OS
 * CSPRNG, e.g. react-native-get-random-values, before first use).
 *
 * A token is only one layer. Low-entropy secrets such as 6-digit PINs are
 * safe ONLY together with server-side expiry, single use, attempt limits
 * and throttling. This module cannot provide those.
 */
import { randomBytes } from "@noble/hashes/utils.js";
import { base64urlnopad } from "@scure/base";

export type RandomSource = (length: number) => Uint8Array;

/** Uniform integer in [0, bound) by rejection sampling (no modulo bias). bound <= 2^32. */
export function uniformInt(bound: number, rand: RandomSource = randomBytes): number {
  if (!Number.isSafeInteger(bound) || bound < 1 || bound > 0x100000000) throw new RangeError("bound");
  if (bound === 1) return 0;
  const limit = Math.floor(0x100000000 / bound) * bound;
  for (;;) {
    const b = rand(4);
    if (!(b instanceof Uint8Array) || b.length !== 4) throw new Error("random_source");
    const value = ((b[0] << 24) >>> 0) + (b[1] << 16) + (b[2] << 8) + b[3];
    if (value < limit) return value % bound;
  }
}

/** Decimal PIN of exactly `digits` digits, each position uniform (leading zeros allowed). */
export function randomNumericPin(digits = 6, rand: RandomSource = randomBytes): string {
  if (!Number.isSafeInteger(digits) || digits < 4 || digits > 12) throw new RangeError("digits");
  let out = "";
  for (let i = 0; i < digits; i++) out += String(uniformInt(10, rand));
  return out;
}

/** Decimal PIN in [10^(digits-1), 10^digits): no leading zero (the format Sentient's PIN pairing screen has always produced). */
export function randomNumericPinNoLeadingZero(digits = 6, rand: RandomSource = randomBytes): string {
  if (!Number.isSafeInteger(digits) || digits < 4 || digits > 9) throw new RangeError("digits");
  const low = 10 ** (digits - 1);
  return String(low + uniformInt(9 * low, rand));
}

/** URL-safe opaque token with `bytes` bytes of entropy (default 32 = 256 bits). */
export function randomToken(bytes = 32, rand: RandomSource = randomBytes): string {
  if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 64) throw new RangeError("bytes");
  const value = rand(bytes);
  if (!(value instanceof Uint8Array) || value.length !== bytes) throw new Error("random_source");
  return base64urlnopad.encode(value);
}

/** Lowercase hex identifier with `bytes` bytes of entropy (default 16 = 128 bits). Same character class as base-36 ids, so it fits id fields that only allow [0-9a-z]. */
export function randomHexId(bytes = 16, rand: RandomSource = randomBytes): string {
  if (!Number.isSafeInteger(bytes) || bytes < 8 || bytes > 64) throw new RangeError("bytes");
  const value = rand(bytes);
  if (!(value instanceof Uint8Array) || value.length !== bytes) throw new Error("random_source");
  let out = "";
  for (const b of value) out += b.toString(16).padStart(2, "0");
  return out;
}
