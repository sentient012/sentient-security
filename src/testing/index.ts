/*
 * TEST-ONLY utilities. Never use anything here to generate production keys.
 *
 * deterministicRandom: a byte stream from HKDF-SHA-256 in counter mode over a
 * public seed. It exists so known-answer vectors can be reproduced across
 * implementations and runtimes. Its output is predictable by design.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

export const TEST_ONLY = true as const;

export type DeterministicRandom = ((length: number) => Uint8Array) & { readonly consumed: number; readonly label: string };

export function deterministicRandom(seedLabel: string): DeterministicRandom {
  if (typeof seedLabel !== "string" || !seedLabel.startsWith("TEST ONLY")) {
    throw new Error('deterministicRandom seeds must start with "TEST ONLY" so they can never be mistaken for a production source.');
  }
  const seed = sha256(utf8ToBytes(seedLabel));
  let counter = 0;
  let consumed = 0;
  let buffer = new Uint8Array(0);
  const next = (length: number) => {
    if (!Number.isSafeInteger(length) || length < 0) throw new RangeError("length");
    while (buffer.length < length) {
      const block = hkdf(sha256, seed, undefined, utf8ToBytes(`sentient-test-drbg:${counter++}`), 64);
      const merged = new Uint8Array(buffer.length + block.length);
      merged.set(buffer);
      merged.set(block, buffer.length);
      buffer = merged;
    }
    const out = buffer.slice(0, length);
    buffer = buffer.slice(length);
    consumed += length;
    return out;
  };
  Object.defineProperty(next, "consumed", { get: () => consumed });
  Object.defineProperty(next, "label", { value: seedLabel });
  return next as DeterministicRandom;
}

/**
 * Temporarily routes globalThis.crypto.getRandomValues (which @noble/* uses
 * internally) through `rand`, runs `fn`, then restores the original. For
 * capturing vectors from code that does not accept an injected RNG.
 */
export async function withPatchedGetRandomValues<T>(rand: (length: number) => Uint8Array, fn: () => T | Promise<T>): Promise<T> {
  const cryptoObj = globalThis.crypto as Crypto;
  const original = cryptoObj.getRandomValues.bind(cryptoObj);
  const patched = <A extends ArrayBufferView | null>(array: A): A => {
    if (!array) return array;
    const view = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    view.set(rand(view.length));
    return array;
  };
  Object.defineProperty(cryptoObj, "getRandomValues", { value: patched, configurable: true, writable: true });
  try {
    return await fn();
  } finally {
    Object.defineProperty(cryptoObj, "getRandomValues", { value: original, configurable: true, writable: true });
  }
}
