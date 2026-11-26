/*
 * NOT REVIEWED. Published as @sentient012/security/session/business-roster since 0.3.0.
 * Protocol id: "sentient-business-roster-v0-experimental".
 *
 * Signed organization roster for the Business Terminal.
 *
 * Business v1 (business/conversation-keys.js) lets the SERVER decide who must
 * be able to read a business conversation ("required_recipients": Terminal
 * devices of the organization and its organization access key) and which
 * Terminal signing keys are genuine. A server that adds a Terminal device, or
 * swaps the organization access key, would then be handed conversation keys
 * by customers' phones and by other Terminals.
 *
 * Here the organization publishes a signed, versioned roster:
 *   - every authorized Terminal device (key id, business user, Ed25519 +
 *     ML-DSA-65 signing keys, X25519 + ML-KEM-768 encryption keys) and every
 *     current organization access key (id, generation, encryption keys);
 *   - version n+1 must be signed (hybrid, both signatures) by a device listed
 *     in version n: an already-authorized Terminal approves every change, so
 *     the server cannot add a device or an organization key by itself;
 *   - versions only increase; the same version with different content is
 *     equivocation; every roster carries a signed expiry and is re-signed
 *     weekly, so a server that freezes an old roster is detected;
 *   - a roster that no listed device signed (every authorized Terminal was
 *     lost) is an "identity reset": never accepted silently.
 * Endpoints pin the first roster they see per organization (trust on first
 * use) and then only follow signed changes. rosterFilterState() applies the
 * roster to a business key state before business v1 uses it.
 *
 * NOT provided: key transparency (a server that shows different rosters to
 * customers who never compare them is not detected), and binding of the
 * organization to its real-world identity (Sentient's business verification
 * does that, outside cryptography).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { canonicalBytes, toB64 } from "../encoding/index.js";
import { signHybrid, verifyHybrid } from "../business/core.js";

export const BUSINESS_ROSTER_PROTOCOL = "sentient-business-roster-v0-experimental" as const;
const CONTEXT = `${BUSINESS_ROSTER_PROTOCOL}/statement`;
export const MAX_ROSTER_DEVICES = 500;
export const MAX_ROSTER_ORG_KEYS = 16;
export const ROSTER_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
export const ROSTER_REFRESH_MS = 7 * 24 * 60 * 60 * 1000;

export class BusinessRosterError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message ? `${code}: ${message}` : code);
    this.name = "BusinessRosterError";
    this.code = code;
  }
}

export type RosterDevice = {
  keyId: string;
  businessUserId: string;
  ed25519_public_key: string;
  ml_dsa_public_key: string;
  x25519_public_key: string;
  ml_kem_public_key: string;
};
export type RosterOrgKey = { orgKeyId: string; generation: number; x25519_public_key: string; ml_kem_public_key: string };
export type RosterStatement = {
  v: typeof BUSINESS_ROSTER_PROTOCOL;
  organizationId: string;
  version: number;
  devices: RosterDevice[];
  orgKeys: RosterOrgKey[];
  issuedAt: string;
  expiresAt: string;
  signerKeyId: string;
  signature: { ed25519: string; mlDsa: string };
};
type SigningKeys = { ed25519PrivateKey: Uint8Array; ed25519PublicKey: Uint8Array; mlDsaSecretKey: Uint8Array; mlDsaPublicKey: Uint8Array };

const isText = (v: unknown, max = 500) => typeof v === "string" && v.length > 0 && v.length <= max;
const isKey = (v: unknown) => isText(v, 4000);

function checkDevice(d: RosterDevice) {
  if (!d || !isText(d.keyId, 200) || !isText(d.businessUserId, 200) || !isKey(d.ed25519_public_key) || !isKey(d.ml_dsa_public_key) || !isKey(d.x25519_public_key) || !isKey(d.ml_kem_public_key)) {
    throw new BusinessRosterError("shape", "Roster device entry is malformed.");
  }
}
function checkOrgKey(k: RosterOrgKey) {
  if (!k || !isText(k.orgKeyId, 200) || !Number.isSafeInteger(k.generation) || k.generation < 1 || !isKey(k.x25519_public_key) || !isKey(k.ml_kem_public_key)) {
    throw new BusinessRosterError("shape", "Roster organization key entry is malformed.");
  }
}
function normalize(devices: RosterDevice[], orgKeys: RosterOrgKey[]) {
  if (!Array.isArray(devices) || devices.length < 1 || devices.length > MAX_ROSTER_DEVICES) throw new BusinessRosterError("shape", "A roster lists 1 to 500 devices.");
  if (!Array.isArray(orgKeys) || orgKeys.length > MAX_ROSTER_ORG_KEYS) throw new BusinessRosterError("shape", "Too many organization keys.");
  devices.forEach(checkDevice);
  orgKeys.forEach(checkOrgKey);
  const d = devices.map((x) => ({ keyId: x.keyId, businessUserId: x.businessUserId, ed25519_public_key: x.ed25519_public_key, ml_dsa_public_key: x.ml_dsa_public_key, x25519_public_key: x.x25519_public_key, ml_kem_public_key: x.ml_kem_public_key }))
    .sort((a, b) => (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0));
  const k = orgKeys.map((x) => ({ orgKeyId: x.orgKeyId, generation: x.generation, x25519_public_key: x.x25519_public_key, ml_kem_public_key: x.ml_kem_public_key }))
    .sort((a, b) => a.generation - b.generation || (a.orgKeyId < b.orgKeyId ? -1 : 1));
  if (new Set(d.map((x) => x.keyId)).size !== d.length || new Set(k.map((x) => x.orgKeyId)).size !== k.length) throw new BusinessRosterError("shape", "Duplicate roster entry.");
  return { devices: d, orgKeys: k };
}

/** The roster entry for a Terminal device, from its keys (base64 as the directories store them). */
export function rosterDeviceEntry(params: { keyId: string; businessUserId: string; signingKeys: { ed25519PublicKey: Uint8Array; mlDsaPublicKey: Uint8Array }; kemPublic: { x25519PublicKey: Uint8Array; mlKemPublicKey: Uint8Array } }): RosterDevice {
  return {
    keyId: params.keyId,
    businessUserId: params.businessUserId,
    ed25519_public_key: toB64(params.signingKeys.ed25519PublicKey),
    ml_dsa_public_key: toB64(params.signingKeys.mlDsaPublicKey),
    x25519_public_key: toB64(params.kemPublic.x25519PublicKey),
    ml_kem_public_key: toB64(params.kemPublic.mlKemPublicKey),
  };
}

/** signer: an authorized Terminal device ({ keyId, signingKeys }). */
export function signRoster(params: { signer: { keyId: string; signingKeys: SigningKeys }; organizationId: string; version: number; devices: RosterDevice[]; orgKeys: RosterOrgKey[]; issuedAt?: string; expiresAt?: string }): RosterStatement {
  if (!isText(params.organizationId, 200) || !Number.isSafeInteger(params.version) || params.version < 1) throw new BusinessRosterError("shape");
  const { devices, orgKeys } = normalize(params.devices, params.orgKeys);
  const issuedAt = params.issuedAt ?? new Date().toISOString();
  const expiresAt = params.expiresAt ?? new Date(Date.parse(issuedAt) + ROSTER_LIFETIME_MS).toISOString();
  const unsigned = { v: BUSINESS_ROSTER_PROTOCOL, organizationId: params.organizationId, version: params.version, devices, orgKeys, issuedAt, expiresAt, signerKeyId: params.signer.keyId };
  return { ...unsigned, signature: signHybrid(CONTEXT, unsigned, params.signer.signingKeys) };
}

/** Re-sign the same content with a fresh expiry (version + 1). */
export function refreshRoster(current: RosterStatement, signer: { keyId: string; signingKeys: SigningKeys }, now = new Date()): RosterStatement {
  return signRoster({ signer, organizationId: current.organizationId, version: current.version + 1, devices: current.devices, orgKeys: current.orgKeys, issuedAt: now.toISOString() });
}

export function rosterNeedsRefresh(current: RosterStatement, now = new Date()): boolean {
  return now.getTime() - Date.parse(current.issuedAt) >= ROSTER_REFRESH_MS || Date.parse(current.expiresAt) - now.getTime() < ROSTER_LIFETIME_MS - ROSTER_REFRESH_MS;
}

export function rosterDigest(s: RosterStatement): string {
  return bytesToHex(sha256(canonicalBytes(s)));
}

function signedBy(s: RosterStatement, device: RosterDevice | undefined): boolean {
  if (!device || device.keyId !== s.signerKeyId || !s.signature) return false;
  const { signature, ...unsigned } = s;
  return verifyHybrid(CONTEXT, unsigned, signature, device).both;
}
function wellFormed(s: RosterStatement): boolean {
  try {
    if (!s || s.v !== BUSINESS_ROSTER_PROTOCOL || !isText(s.organizationId, 200) || !Number.isSafeInteger(s.version) || s.version < 1) return false;
    if (!Number.isFinite(Date.parse(s.issuedAt)) || !Number.isFinite(Date.parse(s.expiresAt)) || !isText(s.signerKeyId, 200)) return false;
    const n = normalize(s.devices, s.orgKeys);
    return JSON.stringify(n.devices) === JSON.stringify(s.devices) && JSON.stringify(n.orgKeys) === JSON.stringify(s.orgKeys);
  } catch {
    return false;
  }
}
const sameSigning = (a?: RosterDevice, b?: RosterDevice) => !!a && !!b && a.ed25519_public_key === b.ed25519_public_key && a.ml_dsa_public_key === b.ml_dsa_public_key;

export type RosterVerdict =
  | { status: "first_seen"; accepted: RosterStatement }
  | { status: "unchanged"; accepted: RosterStatement }
  | { status: "changed"; accepted: RosterStatement; added: string[]; removed: string[] }
  | { status: "stale"; accepted: RosterStatement }
  | { status: "identity_reset"; candidate: RosterStatement }
  | { status: "rejected"; reason: "shape" | "organization" | "expired" | "signature" | "equivocation" | "gap" | "frozen" };

/**
 * One step: `candidate` against the pinned roster (null: first contact).
 * A changed roster must be version pinned + 1 and signed by a device listed
 * (with the same signing keys) in the pinned roster.
 */
export function evaluateRoster(pinned: RosterStatement | null, candidate: RosterStatement, opts: { now?: Date; organizationId?: string } = {}): RosterVerdict {
  const now = opts.now ?? new Date();
  if (!wellFormed(candidate)) return { status: "rejected", reason: "shape" };
  if ((opts.organizationId && candidate.organizationId !== opts.organizationId) || (pinned && pinned.organizationId !== candidate.organizationId)) return { status: "rejected", reason: "organization" };
  const selfSigned = signedBy(candidate, candidate.devices.find((d) => d.keyId === candidate.signerKeyId));
  if (!pinned) {
    if (Date.parse(candidate.expiresAt) <= now.getTime()) return { status: "rejected", reason: "expired" };
    return selfSigned ? { status: "first_seen", accepted: candidate } : { status: "rejected", reason: "signature" };
  }
  if (candidate.version < pinned.version) {
    return Date.parse(pinned.expiresAt) <= now.getTime() ? { status: "rejected", reason: "frozen" } : { status: "stale", accepted: pinned };
  }
  if (candidate.version === pinned.version) {
    if (rosterDigest(candidate) !== rosterDigest(pinned)) return { status: "rejected", reason: "equivocation" };
    return Date.parse(pinned.expiresAt) <= now.getTime() ? { status: "rejected", reason: "frozen" } : { status: "unchanged", accepted: pinned };
  }
  if (Date.parse(candidate.expiresAt) <= now.getTime()) return { status: "rejected", reason: "expired" };
  const authorizer = pinned.devices.find((d) => d.keyId === candidate.signerKeyId);
  if (authorizer && signedBy(candidate, authorizer)) {
    if (candidate.version !== pinned.version + 1) return { status: "rejected", reason: "gap" };
    const before = new Set(pinned.devices.map((d) => d.keyId));
    const after = new Set(candidate.devices.map((d) => d.keyId));
    return { status: "changed", accepted: candidate, added: [...after].filter((k) => !before.has(k)), removed: [...before].filter((k) => !after.has(k)) };
  }
  // Signed by a device the pinned roster does not authorize: a reset if it is at least self-consistent.
  return selfSigned ? { status: "identity_reset", candidate } : { status: "rejected", reason: "signature" };
}

/**
 * Follow a sequence of published rosters (any order) from the pinned one.
 * Returns the last accepted roster, every roster accepted on the way
 * (`history`, oldest first, the pinned one included), and the verdict that
 * stopped the walk (a reset or a rejection), if any.
 */
export function evaluateRosterChain(pinned: RosterStatement | null, statements: RosterStatement[], opts: { now?: Date; organizationId?: string } = {}): { accepted: RosterStatement | null; history: RosterStatement[]; stopped: RosterVerdict | null } {
  const sorted = [...(statements || [])].sort((a, b) => (a?.version ?? 0) - (b?.version ?? 0));
  let current = pinned;
  const history: RosterStatement[] = pinned ? [pinned] : [];
  // Intermediate versions are checked only for authorization; expiry matters for the newest one.
  for (let i = 0; i < sorted.length; i++) {
    const s = sorted[i];
    if (current && s.version <= current.version) {
      const v = evaluateRoster(current, s, { ...opts, now: new Date(0) });
      if (v.status === "rejected") return { accepted: current, history, stopped: v };
      continue;
    }
    const last = i === sorted.length - 1;
    const v = evaluateRoster(current, s, { ...opts, now: last ? opts.now : new Date(Math.min(Date.parse(s.issuedAt), (opts.now ?? new Date()).getTime())) });
    if (v.status === "first_seen" || v.status === "changed") {
      current = v.accepted;
      history.push(v.accepted);
      continue;
    }
    if (v.status === "unchanged" || v.status === "stale") continue;
    return { accepted: current, history, stopped: v };
  }
  if (current && Date.parse(current.expiresAt) <= (opts.now ?? new Date()).getTime()) return { accepted: current, history, stopped: { status: "rejected", reason: "frozen" } };
  return { accepted: current, history, stopped: null };
}

export function rosterDevice(roster: RosterStatement | null, keyId: string): RosterDevice | null {
  return roster?.devices.find((d) => d.keyId === keyId) ?? null;
}

type KeyState = { required_recipients?: any[]; signing_keys?: any[]; organization_id?: string; [k: string]: unknown };

/**
 * Applies the roster to a business v1 key state (business/conversation-keys.js):
 *   - required_recipients: a Terminal device or organization access key is
 *     kept only if the CURRENT roster lists it with the same encryption keys;
 *     customer devices are not the organization's to list and pass unchanged;
 *   - signing_keys: a Terminal signing key is kept only if some roster in
 *     `history` listed it with the same signing keys (messages from an
 *     employee who has since left stay verifiable; a key the server made up
 *     never verifies).
 * Returns the filtered state and what was left out (for diagnostics).
 */
export function rosterFilterState<T extends KeyState>(state: T, current: RosterStatement, history: RosterStatement[] = [current]): { state: T; excluded: { kind: string; key_id: string }[] } {
  if (state?.organization_id && state.organization_id !== current.organizationId) throw new BusinessRosterError("organization", "The roster is for another organization.");
  const excluded: { kind: string; key_id: string }[] = [];
  const recipients = (state.required_recipients || []).filter((r: any) => {
    let keep = true;
    if (r?.kind === "terminal_device") {
      const d = rosterDevice(current, r.key_id);
      keep = !!d && d.x25519_public_key === r.x25519_public_key && d.ml_kem_public_key === r.ml_kem_public_key;
    } else if (r?.kind === "org_access") {
      const k = current.orgKeys.find((o) => o.orgKeyId === r.key_id);
      keep = !!k && k.x25519_public_key === r.x25519_public_key && k.ml_kem_public_key === r.ml_kem_public_key;
    }
    if (!keep) excluded.push({ kind: r?.kind, key_id: r?.key_id });
    return keep;
  });
  const everListed = [...history, current];
  const signing = (state.signing_keys || []).filter((row: any) => {
    if (row?.kind !== "terminal_device") return true;
    const keep = everListed.some((s) => sameSigning(rosterDevice(s, row.key_id) ?? undefined, row as RosterDevice));
    if (!keep) excluded.push({ kind: "terminal_signing_key", key_id: row?.key_id });
    return keep;
  });
  return { state: { ...state, required_recipients: recipients, signing_keys: signing }, excluded };
}
