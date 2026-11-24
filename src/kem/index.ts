/*
 * Hybrid KEM seal used by the business and group protocols
 * ("sentient-business-wrap-v1", "sentient-business-orgkey-v1",
 * "sentient-business-scan-v1", "sentient-group-wrap-v1").
 *
 *   ephemeral X25519 (ephemeral-static) + ML-KEM-768 encapsulation
 *   ikm  = X25519 shared || ML-KEM shared
 *   aad  = canonical(header + ephemeralX25519PublicKey + mlKemCiphertext)
 *   kek  = HKDF-SHA-256(ikm, salt = SHA-256(aad), info = kdfInfo, 32)
 *   box  = XChaCha20-Poly1305(kek, nonce 24 random, aad)
 *
 * Moved here unchanged from the two copies that existed in the business and
 * group cores; known-answer vectors captured from those copies pin it.
 * Randomness consumption order (relied on by the vectors): 32 bytes X25519
 * ephemeral, 32 bytes ML-KEM message, 24 bytes nonce.
 */
import { x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";

import { canonicalBytes, fromB64, toB64, wipe } from "../encoding/index.js";

export type KemRecipient = { x25519PublicKey: Uint8Array | string; mlKemPublicKey: Uint8Array | string };
export type KemRecipientPrivate = { x25519PrivateKey: Uint8Array | string; mlKemSecretKey: Uint8Array | string };
export type SealedBox = Record<string, unknown> & {
  ephemeralX25519PublicKey: string;
  mlKemCiphertext: string;
  nonce: string;
  sealed: string;
};
export type Fail = (code: "seal_kem" | "seal_aead", message: string) => Error;

function asBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === "string" ? fromB64(value) : value;
}

export function hybridSeal(params: {
  plaintext: Uint8Array;
  recipient: KemRecipient;
  header: Record<string, unknown>;
  kdfInfo: string;
  rand: (length: number) => Uint8Array;
}): SealedBox {
  const ephemeralPrivate = params.rand(32);
  const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
  const x25519Shared = x25519.getSharedSecret(ephemeralPrivate, asBytes(params.recipient.x25519PublicKey));
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(asBytes(params.recipient.mlKemPublicKey), params.rand(32));
  const sealedHeader = { ...params.header, ephemeralX25519PublicKey: toB64(ephemeralPublic), mlKemCiphertext: toB64(cipherText) };
  const aad = canonicalBytes(sealedHeader);
  const ikm = concatBytes(x25519Shared, sharedSecret);
  const kek = hkdf(sha256, ikm, sha256(aad), utf8ToBytes(params.kdfInfo), 32);
  const nonce = params.rand(24);
  const sealed = xchacha20poly1305(kek, nonce, aad).encrypt(params.plaintext);
  wipe(ephemeralPrivate, x25519Shared, sharedSecret, ikm, kek);
  return { ...sealedHeader, nonce: toB64(nonce), sealed: toB64(sealed) };
}

export function hybridOpen(params: { box: SealedBox; recipientPrivate: KemRecipientPrivate; kdfInfo: string; fail: Fail }): Uint8Array {
  const { nonce, sealed, ...sealedHeader } = params.box;
  const aad = canonicalBytes(sealedHeader);
  let x25519Shared: Uint8Array;
  let sharedSecret: Uint8Array;
  try {
    x25519Shared = x25519.getSharedSecret(asBytes(params.recipientPrivate.x25519PrivateKey), fromB64(sealedHeader.ephemeralX25519PublicKey));
    sharedSecret = ml_kem768.decapsulate(fromB64(sealedHeader.mlKemCiphertext), asBytes(params.recipientPrivate.mlKemSecretKey));
  } catch {
    throw params.fail("seal_kem", "Key encapsulation could not be opened.");
  }
  const ikm = concatBytes(x25519Shared, sharedSecret);
  const kek = hkdf(sha256, ikm, sha256(aad), utf8ToBytes(params.kdfInfo), 32);
  try {
    return xchacha20poly1305(kek, fromB64(nonce), aad).decrypt(fromB64(sealed));
  } catch {
    throw params.fail("seal_aead", "Sealed key failed authentication.");
  } finally {
    wipe(x25519Shared, sharedSecret, ikm, kek);
  }
}
