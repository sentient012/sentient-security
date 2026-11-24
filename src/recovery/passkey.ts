import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { randomBytes } from "@noble/hashes/utils.js";

import { CLIENT_SHARE_BYTES, shareIdFor } from "./recovery.js";

export const PASSKEY_PRF_CONTEXT = "sentient-passkey-e2ee-prf-v1";
export const PASSKEY_WRAPPER_VERSION = 1 as const;

export type PasskeyShareWrapper = {
  version: 1;
  shareId: string;
  salt: string;
  nonce: string;
  ciphertext: string;
};

function aad(userId: string, credentialId: string, shareId: string) {
  return utf8ToBytes(
    `sentient-passkey-e2ee-wrap-v1|user:${userId}|credential:${credentialId}|share:${shareId}|version:1`
  );
}

function deriveKey(prfOutput: Uint8Array, salt: Uint8Array, credentialId: string) {
  if (prfOutput.length < 32) throw new Error("passkey_prf_output_invalid");
  return hkdf(
    sha256,
    prfOutput,
    salt,
    utf8ToBytes(`sentient-passkey-e2ee-wrap-v1|credential:${credentialId}`),
    32
  );
}

export function wrapClientShare(params: {
  userId: string;
  credentialId: string;
  clientShare: Uint8Array;
  prfOutput: Uint8Array;
}): PasskeyShareWrapper {
  if (params.clientShare.length !== CLIENT_SHARE_BYTES) throw new Error("client_share_invalid");
  const shareId = shareIdFor(params.clientShare);
  const salt = randomBytes(32);
  const nonce = randomBytes(24);
  const key = deriveKey(params.prfOutput, salt, params.credentialId);
  try {
    const ciphertext = xchacha20poly1305(
      key,
      nonce,
      aad(params.userId, params.credentialId, shareId)
    ).encrypt(params.clientShare);
    return {
      version: PASSKEY_WRAPPER_VERSION,
      shareId,
      salt: base64.encode(salt),
      nonce: base64.encode(nonce),
      ciphertext: base64.encode(ciphertext),
    };
  } finally {
    key.fill(0);
  }
}

export function unwrapClientShare(params: {
  userId: string;
  credentialId: string;
  wrapper: PasskeyShareWrapper;
  prfOutput: Uint8Array;
}) {
  if (params.wrapper.version !== PASSKEY_WRAPPER_VERSION) throw new Error("passkey_wrapper_version");
  const salt = base64.decode(params.wrapper.salt);
  const nonce = base64.decode(params.wrapper.nonce);
  const ciphertext = base64.decode(params.wrapper.ciphertext);
  if (salt.length !== 32 || nonce.length !== 24) throw new Error("passkey_wrapper_format");
  const key = deriveKey(params.prfOutput, salt, params.credentialId);
  try {
    const share = xchacha20poly1305(
      key,
      nonce,
      aad(params.userId, params.credentialId, params.wrapper.shareId)
    ).decrypt(ciphertext);
    if (share.length !== CLIENT_SHARE_BYTES || shareIdFor(share) !== params.wrapper.shareId) {
      share.fill(0);
      throw new Error("passkey_wrapper_binding");
    }
    return share;
  } finally {
    key.fill(0);
  }
}
