/*
 * Conversation-key epochs for business conversations - shared, byte-identical
 * between sentient-app (lib/business/crypto/) and sentient-website
 * (src/terminal/crypto/), like business-crypto-core.js next to it.
 *
 * The server (migration 139) returns one "key state" object per conversation,
 * scoped to the calling device:
 *   { interaction_id, organization_id, consumer_user_id, current_epoch,
 *     rotation_required, epochs[], wrap_index[], my_wraps[],
 *     required_recipients[], signing_keys[], self{} }
 * It decides WHO must be able to read (the routing audience); only endpoints
 * decide WHAT the key is. Rules implemented here:
 *   - a device opens only wraps addressed to itself, and only when the wrap is
 *     signed by a directory key that was valid when the wrap was made
 *   - any holder of an epoch key seals it for required recipients that lack a
 *     copy (a new device of the customer, a newly assigned agent, the
 *     organization access key once the organization creates one)
 *   - a sender never encrypts under an epoch whose copy set includes someone
 *     who is no longer authorized (revoked terminal, removed employee, retired
 *     organization key): it starts a new epoch sealed only to the current set
 */

import {
  BusinessCryptoError,
  conversationKeyCommitment,
  decryptBusinessMessage,
  newConversationKey,
  unwrapConversationKey,
  wrapConversationKey,
} from "./core.js";
import { trustedTime } from "../internal/time.js";

export const ENCRYPTED_MESSAGE_VERSION = 1;

function parseTime(value) {
  const t = Date.parse(value || "");
  return Number.isFinite(t) ? t : null;
}

/** (kind, keyId, atIso) -> directory row usable as publicKeys, or null when unknown or revoked at that time. */
export function signingKeyLookup(state) {
  const rows = Array.isArray(state?.signing_keys) ? state.signing_keys : [];
  return (kind, keyId, atIso) => {
    const row = rows.find(r => r.kind === kind && r.key_id === keyId);
    if (!row) return null;
    const revokedAt = parseTime(row.revoked_at);
    if (revokedAt !== null) {
      const at = parseTime(atIso);
      if (at === null || at >= revokedAt) return null;
    }
    return row;
  };
}

function epochRow(state, epoch) {
  return (state.epochs || []).find(e => e.epoch === epoch) || null;
}

export function unwrapMyConversationKeys({ state, recipientPrivate, recipientKind, recipientKeyId }) {
  const lookup = signingKeyLookup(state);
  const keys = new Map();
  const failures = [];
  for (const entry of state.my_wraps || []) {
    const epoch = entry.epoch;
    try {
      const row = epochRow(state, epoch);
      if (!row) throw new BusinessCryptoError("wrap_unknown_epoch");
      const wrap = entry.wrap;
      const wrapper = lookup(wrap?.wrapperKind, wrap?.wrapperKeyId, trustedTime(entry.created_at, wrap?.createdAt));
      const key = unwrapConversationKey({
        wrap,
        recipientPrivate,
        wrapperPublicKeys: wrapper,
        expected: {
          interactionId: state.interaction_id,
          organizationId: state.organization_id,
          epoch,
          recipientKind,
          recipientKeyId,
          commitment: row.key_commitment,
        },
      });
      keys.set(epoch, key);
    } catch (error) {
      failures.push({ epoch, code: error?.code || "wrap_error" });
    }
  }
  return { keys, failures };
}

function recipientTarget(recipient) {
  return {
    kind: recipient.kind,
    keyId: recipient.key_id,
    x25519PublicKey: recipient.x25519_public_key,
    mlKemPublicKey: recipient.ml_kem_public_key,
  };
}

/** Required recipients without a copy, for every epoch this device can open. */
export function missingWraps({ state, keys }) {
  const have = new Set((state.wrap_index || []).map(w => `${w.epoch}|${w.recipient_kind}|${w.recipient_key_id}`));
  const result = [];
  for (const epoch of keys.keys()) {
    for (const recipient of state.required_recipients || []) {
      if (!have.has(`${epoch}|${recipient.kind}|${recipient.key_id}`)) result.push({ epoch, recipient });
    }
  }
  return result;
}

export function buildWraps({ state, keys, targets, wrapper, now }) {
  return targets.map(({ epoch, recipient }) => ({
    epoch,
    recipient_kind: recipient.kind,
    recipient_key_id: recipient.key_id,
    wrap: wrapConversationKey({
      conversationKey: keys.get(epoch),
      interactionId: state.interaction_id,
      organizationId: state.organization_id,
      epoch,
      recipient: recipientTarget(recipient),
      wrapper,
      createdAt: now(),
    }),
  }));
}

function isEpochConflict(error) {
  const text = `${error?.code || ""} ${error?.message || ""}`;
  return text.includes("BUSINESS_KEY_EPOCH_CONFLICT");
}

/**
 * local: { recipientKind, recipientKeyId, recipientPrivate, wrapperKind, wrapperKeyId, signingKeys }
 * api:   { load(), createEpoch({ epoch, keyCommitment, wraps }), addWraps({ wraps }) }
 * Returns { state, keys, failures, sendEpoch, sendKey, filled }.
 */
export async function syncConversationKeys({ state: initialState, local, api, forSend = false, now = () => new Date().toISOString() }) {
  let state = initialState || (await api.load());
  const wrapper = { kind: local.wrapperKind, keyId: local.wrapperKeyId, signingKeys: local.signingKeys };
  let filled = 0;

  for (let attempt = 0; attempt < 4; attempt++) {
    const { keys, failures } = unwrapMyConversationKeys({
      state,
      recipientPrivate: local.recipientPrivate,
      recipientKind: local.recipientKind,
      recipientKeyId: local.recipientKeyId,
    });

    const targets = missingWraps({ state, keys });
    if (targets.length && local.signingKeys) {
      try {
        await api.addWraps({ wraps: buildWraps({ state, keys, targets, wrapper, now }) });
        filled += targets.length;
      } catch (error) {
        failures.push({ epoch: null, code: `fill:${error?.message || error}` });
      }
    }

    const current = state.current_epoch ?? null;
    if (!forSend) return { state, keys, failures, sendEpoch: null, sendKey: null, filled };
    if (current !== null && !state.rotation_required && keys.has(current)) {
      return { state, keys, failures, sendEpoch: current, sendKey: keys.get(current), filled };
    }

    if (!state.self?.in_audience) throw new BusinessCryptoError("not_in_audience", "This device is not authorized to send in this conversation.");
    const recipients = state.required_recipients || [];
    const selfIncluded = recipients.some(r => r.kind === local.recipientKind && r.key_id === local.recipientKeyId);
    if (!selfIncluded) throw new BusinessCryptoError("self_not_recipient", "This device is not registered for this conversation.");

    const epoch = (current ?? 0) + 1;
    const conversationKey = newConversationKey();
    const epochKeys = new Map([[epoch, conversationKey]]);
    const wraps = buildWraps({ state, keys: epochKeys, targets: recipients.map(recipient => ({ epoch, recipient })), wrapper, now });
    const keyCommitment = conversationKeyCommitment(conversationKey, {
      interactionId: state.interaction_id,
      organizationId: state.organization_id,
      epoch,
    });
    try {
      await api.createEpoch({ epoch, keyCommitment, wraps });
      keys.set(epoch, conversationKey);
      return { state, keys, failures, sendEpoch: epoch, sendKey: conversationKey, filled };
    } catch (error) {
      if (!isEpochConflict(error)) throw error;
      state = await api.load();
    }
  }
  throw new BusinessCryptoError("epoch_contention", "The conversation key changed repeatedly; try again.");
}

/**
 * Decrypts one encrypted timeline row. Never throws: returns
 *   { status: "ok", content, signature }         verified and decrypted
 *   { status: "unavailable", reason }            no key for this device (yet)
 *   { status: "invalid", reason }                failed verification - never render
 * row: { encryption_version, e2ee_payload, key_epoch, sender_type, sender_key_id,
 *        sender_id, client_message_id, created_at }
 */
export function decryptTimelineRow({ row, state, keys }) {
  if (row.encryption_version !== ENCRYPTED_MESSAGE_VERSION) return { status: "invalid", reason: "unknown_version" };
  const key = keys.get(row.key_epoch);
  if (!key) return { status: "unavailable", reason: "no_key" };
  const payload = row.e2ee_payload;
  const senderKind = row.sender_type === "consumer" ? "consumer_device" : row.sender_type === "business" ? "terminal_device" : null;
  if (!senderKind) return { status: "invalid", reason: "sender_type" };
  const sender = signingKeyLookup(state)(senderKind, row.sender_key_id, row.created_at);
  if (!sender) return { status: "invalid", reason: "unknown_sender_key" };
  if (sender.owner_id !== row.sender_id) return { status: "invalid", reason: "sender_owner_mismatch" };
  try {
    const { content, signature } = decryptBusinessMessage({
      payload,
      conversationKey: key,
      senderPublicKeys: sender,
      expected: {
        interactionId: state.interaction_id,
        organizationId: state.organization_id,
        epoch: row.key_epoch,
        messageId: row.client_message_id,
        senderType: row.sender_type,
        senderKind,
        senderKeyId: row.sender_key_id,
        senderId: row.sender_id,
      },
    });
    return { status: "ok", content, signature };
  } catch (error) {
    return { status: "invalid", reason: error?.code || "decrypt_error" };
  }
}
