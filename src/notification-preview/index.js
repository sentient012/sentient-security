// Notification-preview decryption (2026-11-17 follow-up). Pure JavaScript (noble only, no React
// Native), so the SAME code runs in the app, in the Android background notification task, and -
// bundled by scripts/build-preview-crypto.cjs - in the iOS Notification Service Extension's
// JavaScriptCore context.
//
// It only DECRYPTS, on the receiving device, with that device's own keys:
//   * direct chats: one sentient-hybrid-v1 envelope (X25519 + ML-KEM-768 -> HKDF-SHA-256 ->
//     XChaCha20-Poly1305, transcript-bound), exactly as lib/e2ee.ts decryptEnvelope does;
//   * group chats: a sentient-group-msg-v1 body with the epoch's group key (HKDF-SHA-256 ->
//     XChaCha20-Poly1305 over the canonical header), exactly as lib/group/group-crypto-core.js does.
// tests/notification-preview-crypto.test.cjs proves both against the real encrypting code.
//
// For a notification the group sender's hybrid signature is not re-verified (the ML-DSA signature
// alone is larger than a push payload). The content is still authenticated: only holders of the
// group key - members - can produce a ciphertext that opens. The full message is verified as
// always when the conversation is opened. Nothing here encrypts, stores or sends anything.
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { canonicalBytes, fromB64, utf8Decode } from "../encoding/index.js";
import { decryptEnvelope } from "../hybrid-v1/index.js";

const GROUP_MESSAGE_VERSION = "sentient-group-msg-v1";
const GROUP_MESSAGE_SUITE = "X25519+ML-KEM-768/HKDF-SHA-256/XChaCha20-Poly1305/Ed25519+ML-DSA-65";
const ATTACHMENT_MESSAGE_MARKER = "sentient-attachment-v1";
const MAX_PREVIEW = 120;

const b64 = (value) => fromB64(String(value));

/**
 * Direct chat. `payload`: { threadId, senderUserId, receiverUserId, envelopes: HybridEnvelope[] }
 * (only envelopes for the receiving account are ever sent). `keys`: this device's
 * { x25519PrivateKey, mlKemSecretKey } as Uint8Array or base64. Returns the plaintext.
 *
 * sentient-hybrid-v1 has no sender signature: the sender shown in a notification is the
 * server's claim (as it is in the full chat view). Callers must not present it as verified.
 */
export function openDirectMessage(payload, keys) {
  if (!payload || !Array.isArray(payload.envelopes) || !payload.envelopes.length) throw new Error("preview_payload");
  const x25519PrivateKey = typeof keys.x25519PrivateKey === "string" ? b64(keys.x25519PrivateKey) : keys.x25519PrivateKey;
  const mlKemSecretKey = typeof keys.mlKemSecretKey === "string" ? b64(keys.mlKemSecretKey) : keys.mlKemSecretKey;
  for (const envelope of payload.envelopes) {
    if (envelope.userId !== payload.receiverUserId) continue;
    try {
      return decryptEnvelope(payload, envelope, { deviceKeyId: envelope.deviceKeyId, x25519PrivateKey, mlKemSecretKey });
    } catch {
      // Not this device's envelope (or damaged): try the next one.
    }
  }
  throw new Error("preview_no_envelope");
}

/**
 * Group chat. `body`: the stored message body WITHOUT its signature ({ v, suite, groupId, epoch,
 * messageId, senderId, senderKeyId, createdAt, nonce, ciphertext }). `groupKey`: the epoch key
 * (Uint8Array or base64). `expected`: what the push says ({ groupId, messageId }) - a body for
 * another group or message is refused. Returns the content object ({ kind, text, attachment? }).
 *
 * The sender's hybrid signature is NOT verified here (an ML-DSA-65 signature does not fit in a
 * push payload). Decryption proves only that SOME holder of the epoch key - a member - wrote it;
 * senderId is unauthenticated in a preview. The conversation view verifies it in full.
 */
export function openGroupMessage(body, groupKey, expected) {
  if (!body || body.v !== GROUP_MESSAGE_VERSION || body.suite !== GROUP_MESSAGE_SUITE) throw new Error("preview_version");
  if (expected && ((expected.groupId && body.groupId !== expected.groupId) || (expected.messageId && body.messageId !== expected.messageId))) throw new Error("preview_mismatch");
  const key = typeof groupKey === "string" ? b64(groupKey) : groupKey;
  const header = {
    v: body.v, suite: body.suite, groupId: body.groupId, epoch: body.epoch, messageId: body.messageId,
    senderId: body.senderId, senderKeyId: body.senderKeyId, createdAt: body.createdAt,
  };
  const aad = canonicalBytes(header);
  const messageKey = hkdf(sha256, key, sha256(aad), utf8ToBytes(`${GROUP_MESSAGE_VERSION}:message-key`), 32);
  const plaintext = xchacha20poly1305(messageKey, b64(body.nonce), aad).decrypt(b64(body.ciphertext));
  const content = JSON.parse(utf8Decode(plaintext));
  if (!content || typeof content !== "object" || typeof content.text !== "string") throw new Error("preview_content");
  return content;
}

const BIDI_AND_CONTROL = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩﻿]/g;

/** One plain line: no control or direction-override characters, whitespace collapsed, cut at 120. */
export function plainPreview(text, max = MAX_PREVIEW) {
  const flat = String(text || "").replace(BIDI_AND_CONTROL, "").replace(/\s+/g, " ").trim();
  if (flat.length <= max) return flat;
  return `${Array.from(flat).slice(0, max - 1).join("").trimEnd()}…`;
}

/** "photo" | "video" | "voice" | "file" from a MIME type only (never a file name). */
export function attachmentKind(mimeType) {
  const mime = String(mimeType || "").toLowerCase();
  if (mime.startsWith("image/")) return "photo";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "voice";
  return "file";
}

/**
 * What a notification may show for a decrypted message: { kind: "text", text } or
 * { kind: "photo" | "video" | "voice" | "file" } (the caller words it in the user's language).
 * Attachments never reveal their file name, size or key. Empty text -> null (show the generic text).
 */
export function describeDirect(plaintext) {
  if (typeof plaintext === "string" && plaintext.startsWith("{")) {
    try {
      const parsed = JSON.parse(plaintext);
      if (parsed && parsed.messageType === ATTACHMENT_MESSAGE_MARKER) return { kind: attachmentKind(parsed.mimeType) };
    } catch { /* plain text that starts with "{" */ }
  }
  const text = plainPreview(plaintext);
  return text ? { kind: "text", text } : null;
}

export function describeGroup(content) {
  if (content && content.kind === "attachment") return { kind: attachmentKind(content.attachment && content.attachment.mimeType) };
  const text = plainPreview(content && content.text);
  return text ? { kind: "text", text } : null;
}
