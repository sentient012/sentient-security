/*
 * Browser implementation of the phone's native frame encryption for
 * business calls, byte-compatible with libwebrtc's FrameCryptorTransformer
 * (webrtc-sdk m144, which @livekit/react-native-webrtc 144 ships) as the
 * phone configures it in lib/calling-pqc-frame-cryptor.ts:
 *   sharedKey mode, keyDerivationAlgorithm HKDF, ratchetSalt
 *   "sentient-call-hybrid-v1:ratchet-salt", algorithm kAesGcm.
 *
 * Native behaviour this reproduces (frame_crypto_transformer.cc):
 *   AES key   = HKDF-SHA-256(ikm = 32-byte mediaBaseKey, salt = UTF-8 ratchet
 *               salt, info = 128 zero bytes) -> 16 bytes -> AES-128-GCM
 *   audio     = first byte (Opus TOC) stays clear and is the AAD
 *   frame out = header || AES-GCM(ciphertext || 16-byte tag) || IV(12) || [12, keyIndex]
 * The key index is always 0: business calls never ratchet mid-call.
 * Pure functions over WebCrypto, so the worker and Node tests run the same code.
 */

export const FRAME_RATCHET_SALT = "sentient-call-hybrid-v1:ratchet-salt";
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;
export const AUDIO_UNENCRYPTED_BYTES = 1;

export async function deriveFrameKey(mediaBaseKey, subtle = globalThis.crypto.subtle) {
  if (!(mediaBaseKey instanceof Uint8Array) || mediaBaseKey.length !== 32) throw new Error("Frame base key must be 32 bytes.");
  const ikm = await subtle.importKey("raw", mediaBaseKey, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode(FRAME_RATCHET_SALT), info: new Uint8Array(128) },
    ikm,
    { name: "AES-GCM", length: 128 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptFrame(key, data, { keyIndex = 0, unencryptedBytes = AUDIO_UNENCRYPTED_BYTES, iv, subtle = globalThis.crypto.subtle } = {}) {
  const frame = data instanceof Uint8Array ? data : new Uint8Array(data);
  const header = frame.slice(0, unencryptedBytes);
  const payload = frame.slice(unencryptedBytes);
  const nonce = iv || globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const sealed = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: header, tagLength: TAG_LENGTH * 8 }, key, payload));
  const out = new Uint8Array(header.length + sealed.length + IV_LENGTH + 2);
  out.set(header, 0);
  out.set(sealed, header.length);
  out.set(nonce, header.length + sealed.length);
  out[out.length - 2] = IV_LENGTH;
  out[out.length - 1] = keyIndex;
  return out;
}

/** Returns the decrypted frame, or null for anything that is not a valid frame under this key (dropped, never played). */
export async function decryptFrame(key, data, { keyIndex = 0, unencryptedBytes = AUDIO_UNENCRYPTED_BYTES, subtle = globalThis.crypto.subtle } = {}) {
  const frame = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (frame.length < unencryptedBytes + TAG_LENGTH + IV_LENGTH + 2) return null;
  if (frame[frame.length - 2] !== IV_LENGTH || frame[frame.length - 1] !== keyIndex) return null;
  const header = frame.slice(0, unencryptedBytes);
  const ivStart = frame.length - 2 - IV_LENGTH;
  const iv = frame.slice(ivStart, ivStart + IV_LENGTH);
  const sealed = frame.slice(unencryptedBytes, ivStart);
  try {
    const payload = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: header, tagLength: TAG_LENGTH * 8 }, key, sealed));
    const out = new Uint8Array(header.length + payload.length);
    out.set(header, 0);
    out.set(payload, header.length);
    return out;
  } catch {
    return null;
  }
}

export const KEY_RING_SIZE = 16;

/**
 * True when `data` has the native sealed-frame trailer ([12, keyIndex < 16])
 * and room for header + tag + IV. Used only while a handshake is in flight
 * and no key is installed yet: such a frame is the peer's ciphertext, and
 * handing it to the Opus decoder produces loud digital noise instead of
 * speech. A plaintext Opus frame matches by chance ~1 in 4096 frames, and
 * dropping that one 20 ms frame only triggers packet-loss concealment.
 */
export function looksLikeSealedFrame(data, unencryptedBytes = AUDIO_UNENCRYPTED_BYTES) {
  return data.length >= unencryptedBytes + TAG_LENGTH + IV_LENGTH + 2
    && data[data.length - 2] === IV_LENGTH
    && data[data.length - 1] < KEY_RING_SIZE;
}

/**
 * Per-call media-encryption state shared by one call's sender and receiver
 * transforms (in the worker, or on the main thread for encoded streams).
 *   expectSealed - a handshake is in flight: sealed-looking frames that arrive
 *                  before our key is installed are dropped, never decoded.
 *   key          - installed only after a CONFIRMED handshake.
 *   encrypting   - outgoing frames are sealed. The caller turns this on with
 *                  the key (the callee's "confirmed" proves the callee holds
 *                  it). The callee waits until a peer frame authenticates
 *                  (proof the caller holds the key) or the fallback timer
 *                  fires, so the caller never decodes ciphertext either.
 */
export function createFrameCryptoSession() {
  return {
    expectSealed: false,
    key: null,
    encrypting: false,
    peerFrameAuthenticated: false,
    stats: { encrypted: 0, decrypted: 0, dropped: 0, passthrough: 0, heldForKey: 0 },
  };
}

/**
 * Transform for one sender ("encrypt") or receiver ("decrypt") over a session
 * from createFrameCryptoSession(). onEvent(kind) reports stats kinds plus
 * "peer-authenticated" / "encrypting" transitions.
 */
export function createSessionFrameTransformer(operation, session, onEvent) {
  return async (encodedFrame, controller) => {
    const data = new Uint8Array(encodedFrame.data);
    const count = kind => {
      session.stats[kind] += 1;
      onEvent?.(kind);
    };
    if (operation === "encrypt") {
      if (!session.key || !session.encrypting) {
        controller.enqueue(encodedFrame);
        count("passthrough");
        return;
      }
      encodedFrame.data = (await encryptFrame(session.key, data)).buffer;
      controller.enqueue(encodedFrame);
      count("encrypted");
      return;
    }
    if (!session.key) {
      if (session.expectSealed && looksLikeSealedFrame(data)) {
        count("heldForKey");
        return;
      }
      controller.enqueue(encodedFrame);
      count("passthrough");
      return;
    }
    const plain = await decryptFrame(session.key, data);
    if (!plain) {
      count("dropped");
      return;
    }
    encodedFrame.data = plain.buffer;
    controller.enqueue(encodedFrame);
    count("decrypted");
    if (!session.peerFrameAuthenticated) {
      session.peerFrameAuthenticated = true;
      onEvent?.("peer-authenticated");
    }
    if (!session.encrypting) {
      session.encrypting = true;
      onEvent?.("encrypting");
    }
  };
}

/**
 * Single-key transform kept for callers that only need "key or no key":
 * before a key is installed frames pass through untouched (the call is still
 * DTLS-SRTP protected); once installed, outgoing frames are encrypted and
 * incoming frames that do not authenticate are DROPPED - there is no
 * plaintext fallback after the key exists.
 */
export function createFrameTransformer(operation, getKey, onStats) {
  return async (encodedFrame, controller) => {
    const key = getKey();
    if (!key) {
      controller.enqueue(encodedFrame);
      return;
    }
    const data = new Uint8Array(encodedFrame.data);
    if (operation === "encrypt") {
      encodedFrame.data = (await encryptFrame(key, data)).buffer;
      controller.enqueue(encodedFrame);
      onStats?.("encrypted");
      return;
    }
    const plain = await decryptFrame(key, data);
    if (!plain) {
      onStats?.("dropped");
      return;
    }
    encodedFrame.data = plain.buffer;
    controller.enqueue(encodedFrame);
    onStats?.("decrypted");
  };
}
