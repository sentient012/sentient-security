/*
 * Group key synchronisation and message decryption, independent of React Native and of Supabase (the server calls are
 * injected through `api`). Pure orchestration over lib/group/group-crypto-core.js.
 *
 * What one sync does for a device of an ACTIVE member:
 *   1. read the wraps addressed to this device, verify each (wrapper signature, commitment) and open it
 *   2. give every member device that still lacks a wrap a sealed copy of every epoch key this device holds
 *      (this is how a newcomer gets the whole history, and how a member's new device is brought in)
 *   3. when the server says the group needs a new epoch (a member left or was removed, or none exists yet), create it,
 *      seal it to every active member device in bounded batches, and publish it
 * A key this device cannot obtain is reported as a failure; nothing is invented and nothing is silently skipped.
 */

import {
  GroupCryptoError,
  decryptGroupMessage,
  groupKeyCommitment,
  newGroupKey,
  openKeyLink,
  sealKeyLink,
  unwrapGroupKey,
  wrapGroupKey,
} from "./core.js";
import { trustedTime } from "../internal/time.js";

const SIGNING_LOOKUP_CHUNK = 100;
const WRAP_BATCH = 200;
const MAX_SHARE_PAGES = 25;

function parseTime(value) {
  const t = Date.parse(value || "");
  return Number.isFinite(t) ? t : null;
}

/** Cache of signing-key directory rows: keyId -> row. `load(ids)` fills unknown ids from the server. */
export function createSigningDirectory(api) {
  const rows = new Map();
  return {
    rows,
    async ensure(keyIds) {
      const unknown = [...new Set(keyIds)].filter(id => id && !rows.has(id));
      for (let i = 0; i < unknown.length; i += SIGNING_LOOKUP_CHUNK) {
        const chunk = unknown.slice(i, i + SIGNING_LOOKUP_CHUNK);
        const found = await api.getSigningKeys(chunk);
        for (const row of found || []) rows.set(row.key_id, row);
      }
    },
    /** Usable as publicKeys for verifyHybrid, or null when unknown / revoked at that time. */
    lookup(keyId, atIso) {
      const row = rows.get(keyId);
      if (!row) return null;
      const revoked = parseTime(row.revoked_at);
      if (revoked !== null) {
        const at = parseTime(atIso);
        if (at === null || at >= revoked) return null;
      }
      return row;
    },
  };
}

async function shareEpoch({ api, local, groupId, epoch, groupKey, now }) {
  let shared = 0;
  let afterUser = null;
  for (let page = 0; page < MAX_SHARE_PAGES; page++) {
    const missing = await api.keysMissing(epoch, afterUser);
    if (!missing || !missing.length) break;
    const wraps = [];
    for (const target of missing) {
      wraps.push({
        recipient_key_id: target.key_id,
        wrap: wrapGroupKey({
          groupKey,
          groupId,
          epoch,
          recipient: { userId: target.user_id, keyId: target.key_id, x25519PublicKey: target.x25519_public_key, mlKemPublicKey: target.ml_kem_public_key },
          wrapper: { userId: local.userId, keyId: local.signingKeyId, signingKeys: local.signingKeys },
          createdAt: now(),
        }),
      });
    }
    for (let i = 0; i < wraps.length; i += WRAP_BATCH) {
      await api.provideWraps(epoch, local.signingKeyId, wraps.slice(i, i + WRAP_BATCH));
    }
    shared += wraps.length;
    // keysMissing only returns members still lacking a wrap; the next page starts after the last user we served.
    afterUser = missing[missing.length - 1].user_id;
    if (missing.length < 200) break;
  }
  return shared;
}

const MAX_LINKS_PER_SYNC = 25;
const MAX_HISTORICAL_PAGES = 10;

/** Recover every epoch below the highest one this device holds from the backward chain (no other device needed). */
async function deriveFromChain({ api, keys, groupId, dir, failures }) {
  if (!keys.size || !api.getKeyLinks) return 0;
  const rows = (await api.getKeyLinks()) || [];
  if (!rows.length) return 0;
  await dir.ensure(rows.map(row => row.created_by_key_id));
  const byEpoch = new Map(rows.map(row => [row.epoch, row]));
  let derived = 0;
  for (let epoch = Math.max(...keys.keys()) - 1; epoch >= 1; epoch--) {
    if (keys.has(epoch)) continue;
    const row = byEpoch.get(epoch);
    const newer = keys.get(epoch + 1);
    if (!row || !newer) continue;                                     // the chain is broken here; explicit provisioning is the fallback
    try {
      keys.set(epoch, openKeyLink({
        link: row.link, newerKey: newer,
        expected: { groupId, epoch, newerEpoch: epoch + 1 },
        wrapperPublicKeys: dir.lookup(row.created_by_key_id, trustedTime(row.created_at, row.link?.createdAt)),
        expectedCommitment: row.key_commitment,
      }));
      derived += 1;
    } catch (error) {
      failures.push({ epoch, code: error?.code || "link_failed" });
    }
  }
  return derived;
}

/** An active member that holds both keys writes any missing link (self-healing chain). */
async function maintainChain({ api, local, groupId, keys, current, now }) {
  if (!api.getKeyLinks || !api.putKeyLink) return 0;
  const have = new Set(((await api.getKeyLinks()) || []).map(row => row.epoch));
  let made = 0;
  for (let epoch = 1; epoch < current && made < MAX_LINKS_PER_SYNC; epoch++) {
    if (have.has(epoch) || !keys.has(epoch) || !keys.has(epoch + 1)) continue;
    const link = sealKeyLink({ olderKey: keys.get(epoch), newerKey: keys.get(epoch + 1), groupId, olderEpoch: epoch, wrapper: { userId: local.userId, keyId: local.signingKeyId, signingKeys: local.signingKeys }, createdAt: now() });
    await api.putKeyLink(epoch, link, local.signingKeyId);
    made += 1;
  }
  return made;
}

/** Give FORMER members' devices the snapshot's newest epoch key (and any epoch the chain does not cover). The server decides who qualifies. */
async function provisionFormer({ api, local, groupId, keys, now }) {
  if (!api.historicalMissing || !api.provideHistorical) return 0;
  let provided = 0;
  let afterUser = null;
  for (let page = 0; page < MAX_HISTORICAL_PAGES; page++) {
    const missing = (await api.historicalMissing(afterUser)) || [];
    if (!missing.length) break;
    const items = [];
    for (const target of missing) {
      const key = keys.get(target.epoch);
      if (!key) continue;                                            // not held here: another member's device may hold it
      items.push({
        recipient_user_id: target.user_id, recipient_key_id: target.key_id, epoch: target.epoch,
        wrap: wrapGroupKey({
          groupKey: key, groupId, epoch: target.epoch,
          recipient: { userId: target.user_id, keyId: target.key_id, x25519PublicKey: target.x25519_public_key, mlKemPublicKey: target.ml_kem_public_key },
          wrapper: { userId: local.userId, keyId: local.signingKeyId, signingKeys: local.signingKeys }, createdAt: now(),
        }),
      });
    }
    for (let i = 0; i < items.length; i += 200) provided += Number((await api.provideHistorical(local.signingKeyId, items.slice(i, i + 200)))?.stored || 0);
    afterUser = missing[missing.length - 1].user_id;
    if (missing.length < 100 || !items.length) break;
  }
  return provided;
}

export async function syncGroupKeys({ api, local, groupId, directory, now = () => new Date().toISOString() }) {
  const dir = directory || createSigningDirectory(api);
  const failures = [];
  const keys = new Map();
  let state = await api.getGroup();
  let shared = 0;
  let createdEpoch = null;

  const wraps = (await api.getMyWraps(local.kemKeyId, 0)) || [];
  await dir.ensure(wraps.map(row => row.wrapper_key_id));
  for (const row of wraps) {
    try {
      const wrapperRow = dir.lookup(row.wrapper_key_id, trustedTime(row.created_at, row.wrap?.createdAt));
      const key = unwrapGroupKey({
        wrap: row.wrap,
        recipientPrivate: local.kemPrivate,
        expected: { groupId, epoch: row.epoch, recipientKeyId: local.kemKeyId, recipientUserId: local.userId, wrapperKeyId: row.wrapper_key_id },
        wrapperPublicKeys: wrapperRow,
      });
      // The server-published commitment for the epoch must match what the wrapper sealed: a substituted key fails here.
      if (row.key_commitment && row.wrap.commitment !== row.key_commitment) throw new GroupCryptoError("wrap_commitment", "Epoch commitment mismatch.");
      keys.set(row.epoch, key);
    } catch (error) {
      failures.push({ epoch: row.epoch, code: error?.code || "wrap_failed" });
    }
  }

  // Epochs below the highest one held come from the backward chain, for active AND former members.
  await deriveFromChain({ api, keys, groupId, dir, failures });

  // A REMOVED member holds a read-only snapshot: it opens the keys it already has and neither shares nor rotates anything.
  const activeMember = state.my_membership === undefined || state.my_membership === "active";
  if (state.status === "active" && activeMember) {
    for (const [epoch, key] of keys) {
      shared += await shareEpoch({ api, local, groupId, epoch, groupKey: key, now });
    }
    if (state.rotation_pending || state.current_key_epoch === 0) {
      const epoch = state.current_key_epoch + 1;
      const key = newGroupKey();
      try {
        await api.beginEpoch(epoch, groupKeyCommitment(key, { groupId, epoch }), local.signingKeyId);
        for (let attempt = 0; attempt < 3; attempt++) {
          shared += await shareEpoch({ api, local, groupId, epoch, groupKey: key, now });
          const done = await api.finishEpoch(epoch);
          if (done?.ok) {
            keys.set(epoch, key);
            createdEpoch = epoch;
            break;
          }
        }
        if (createdEpoch === null) failures.push({ epoch, code: "epoch_incomplete" });
      } catch (error) {
        // Another member published this epoch first (or the group changed): reload and use theirs.
        failures.push({ epoch, code: error?.message?.includes("GROUP_EPOCH_INVALID") ? "epoch_taken" : error?.code || "epoch_failed" });
      }
      state = await api.getGroup();
      if (createdEpoch === null) {
        const again = (await api.getMyWraps(local.kemKeyId, 0)) || [];
        await dir.ensure(again.map(row => row.wrapper_key_id));
        for (const row of again) {
          if (keys.has(row.epoch)) continue;
          try {
            keys.set(row.epoch, unwrapGroupKey({
              wrap: row.wrap,
              recipientPrivate: local.kemPrivate,
              expected: { groupId, epoch: row.epoch, recipientKeyId: local.kemKeyId, recipientUserId: local.userId, wrapperKeyId: row.wrapper_key_id },
              wrapperPublicKeys: dir.lookup(row.wrapper_key_id, trustedTime(row.created_at, row.wrap?.createdAt)),
            }));
          } catch { /* reported by the next sync */ }
        }
      }
    }
  }

  if (state.status === "active" && activeMember) {
    try {
      await maintainChain({ api, local, groupId, keys, current: state.current_key_epoch, now });
      shared += await provisionFormer({ api, local, groupId, keys, now });
    } catch { /* best effort: the next sync repeats it; reading and sending are unaffected */ }
  }

  const required = state.current_key_epoch;
  return { keys, currentEpoch: required, canSend: activeMember && state.status === "active" && !state.rotation_pending && keys.has(required), failures, shared, createdEpoch, state, directory: dir };
}

/**
 * Decrypts message rows (as returned by group_get_messages). A row is "ok" only when its sender's signature verified
 * with a key that belongs to the row's sender_user_id, was not revoked before the message, and the epoch key is held.
 */
export function decryptGroupRows({ rows, keys, directory, groupId }) {
  return rows.map(row => {
    if (row.kind === "system") return { row, status: "system" };
    if (row.deleted_for_everyone_at) return { row, status: "deleted" };
    const key = keys.get(row.key_epoch);
    if (!key) return { row, status: "missing_key", reason: "epoch_key_unavailable" };
    const payload = row.e2ee_payload;
    const senderKey = directory.lookup(payload?.senderKeyId, row.created_at);
    if (!senderKey) return { row, status: "undecryptable", reason: "unknown_sender_key" };
    if (senderKey.user_id !== row.sender_user_id) return { row, status: "undecryptable", reason: "sender_mismatch" };
    try {
      const { content } = decryptGroupMessage({
        payload,
        groupKey: key,
        senderPublicKeys: senderKey,
        expected: { groupId, epoch: row.key_epoch, messageId: row.id, senderId: row.sender_user_id },
      });
      return { row, status: "ok", content };
    } catch (error) {
      return { row, status: "undecryptable", reason: error?.code || "decrypt_failed" };
    }
  });
}

/** Key ids that must be in the directory before decryptGroupRows can verify these rows. */
export function senderKeyIdsOf(rows) {
  return [...new Set(rows.map(row => row.e2ee_payload?.senderKeyId).filter(Boolean))];
}
