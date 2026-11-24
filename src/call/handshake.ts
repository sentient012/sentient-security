/**
 * Sentient call hybrid post-quantum protection - "sentient-call-hybrid-v1".
 *
 * Adds a second, Sentient-controlled media-encryption layer ON TOP OF the
 * existing WebRTC DTLS-SRTP transport (never replacing it), with:
 *
 *  - a fresh per-call hybrid key agreement (X25519 ephemeral, both sides;
 *    ML-KEM-768 ephemeral, generated fresh per call by the callee - never a
 *    long-term KEM decryption key, so compromising a device later cannot
 *    retroactively expose a past call's media key)
 *  - AUTHENTICATION of that agreement via a hybrid signature (Ed25519 +
 *    ML-DSA-65) from each device's persistent per-device signing identity,
 *    binding protocol id/version, call id, both user ids, both device ids,
 *    roles, capability, the DTLS certificate fingerprints already present
 *    in the SDP, and an anti-replay nonce into every signed message
 *  - explicit mutual key confirmation (HMAC over the transcript) before the
 *    call is ever reported as authenticated/protected
 *
 * This module is pure protocol/crypto logic. It does not touch the WebRTC
 * peer connection, native frame cryptor, or signaling transport directly -
 * see lib/calling-pqc-frame-cryptor.ts for the native RTCFrameCryptor
 * lifecycle wrapper, and the call sites in lib/calling.ts /
 * lib/business/business-calling.ts for how handshake messages actually
 * travel over the existing consumer/business signaling channels.
 *
 * THREAT MODEL / WHAT THIS DOES AND DOES NOT PROVE
 * --------------------------------------------------
 * Chat's existing hybrid E2EE (lib/e2ee.ts) trusts whatever public key rows
 * Supabase returns with no independent authentication at all (confirmed by
 * this codebase's own prior security audit). This module does NOT reproduce
 * that weakness: every handshake message is signed by a persistent
 * per-device signing key, and the peer's signing PUBLIC key is fetched
 * separately (getPeerCallSigningKeyBundle) and verified against the
 * signature on every message. Registration itself (registerDeviceCallSigningKeys)
 * never supplies any client-chosen installation/attestation identifier - the
 * server (migration 132's register_device_call_signing_key) derives
 * attestation status entirely from the caller's own already-active
 * device_credentials row and the existing trusted-device-binding/platform-
 * attestation state (migrations 122/123), so a normal RLS-constrained
 * client cannot self-select or launder attestation credit onto a different
 * device. What remains true is the boundary any client-authenticated system
 * has: an attacker who has fully compromised Supabase's service-role/server
 * signing authority itself (not merely RLS-constrained table access) could
 * still write or alter rows directly - see the accompanying report's
 * SECURITY QUESTION answer for the precise, evidence-based line between
 * those two attacker models. This module reports its own
 * attestation-verification state so callers can decide policy accordingly;
 * it does not claim a stronger guarantee than what was actually achieved.
 */

import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

import { canonicalBytesCallV1, canonicalizeCallV1 } from "../encoding/index.js";


// ============================================================================
// Feature flag (PART 14). This gates the ENTIRE layer: when false, no
// handshake messages are ever sent, no frame cryptor is ever attached, and
// calling behaves exactly as it did before this module existed. Enabled now
// that migration 132 (device signing keys + the 'pqc_handshake' signal type)
// is applied. Enabling it does NOT mean every call reaches a post-quantum
// state: a legacy/incapable peer stays standard-encrypted or unsupported, and
// the UI renders only the negotiated runtime state (see
// components/call/call-security.ts).
// ============================================================================
export const ENABLE_PQC_CALL_LAYER = true;

export const CALL_PQC_PROTOCOL_VERSION = "sentient-call-hybrid-v1";
/** Bumped whenever the wire format or transcript field set changes. */
export const CALL_PQC_CAPABILITY = 1;
const FRAME_ALGORITHM_LABEL = "X25519+ML-KEM-768/AES-GCM-frame";

/** ML-DSA-65 keygen accepts an optional 32-byte seed for deterministic re-derivation, mirroring lib/e2ee.ts's ML-KEM seed persistence pattern instead of storing the ~4KB raw secret key. */
const ML_DSA_SEED_BYTES = 32;

const HANDSHAKE_FRESHNESS_WINDOW_MS = 60_000;

// ============================================================================
// Security state (PART 15) - internal, factual only. No marketing strings.
// Future UI reads this; this module never renders anything from it.
// ============================================================================
// Three tiers, deliberately not collapsed into one another, because
// cryptographic signature verification and platform-attested device
// identity are different claims and must never be conflated (see the
// lifecycle/security review that added the middle tier below):
//   pq_confidential_only        - key agreed, not yet signature-proven
//   pq_signed_unattested_device - BOTH hybrid signatures + key confirmation
//                                 verified (the handshake is genuinely
//                                 forgery-resistant), but the peer's
//                                 registered signing key was accepted as
//                                 TOFU at registration time (migration 132's
//                                 attestation_verified = false) - i.e. the
//                                 cryptography is sound, but nothing proves
//                                 the peer's key was ever tied to a
//                                 platform-attested genuine device. Reported
//                                 as its own state, never as "authenticated".
//   pq_authenticated             - everything pq_signed_unattested_device
//                                 has, PLUS the peer's registered signing
//                                 key WAS attestation-backed at registration
//                                 (migration 132's attestation_verified =
//                                 true). This is the only state name that
//                                 implies attestation-backed identity, and
//                                 it is only ever assigned when that is
//                                 actually true - see peerAttestationVerified
//                                 below, which is what gates it.
export type CallPqcSecurityStateValue =
  | "disabled" // feature flag off
  | "unsupported" // peer has no registered signing bundle (legacy/incapable peer)
  | "handshake_in_progress"
  | "standard_encrypted" // DTLS-SRTP only, no enhanced layer active (expected fallback)
  | "pq_confidential_only" // media key derived and hybrid-confidential, but mutual signature/confirmation not (yet) both proven
  | "pq_signed_unattested_device" // hybrid signatures + key confirmation both verified, but peer's device identity was registered without attestation (TOFU) - genuinely forgery-resistant, but NOT identity-attested; never call this "authenticated"
  | "pq_authenticated" // hybrid signatures + key confirmation both verified AND peer's device identity was attestation-backed at registration - the only state that implies attestation-backed identity
  | "verification_failed"; // a capable peer's handshake failed signature/confirmation verification - never silently downgraded

export type CallPqcSecurityState = {
  state: CallPqcSecurityStateValue;
  protocolVersion: string | null;
  capability: number | null;
  dtlsConnected: boolean;
  frameCryptorActive: boolean;
  hybridHandshakeComplete: boolean;
  classicalSignatureVerified: boolean; // Ed25519
  pqSignatureVerified: boolean; // ML-DSA-65
  peerDeviceKeyVerified: boolean; // peer's signing bundle was found and used
  peerAttestationVerified: boolean; // peer's signing bundle was attestation-backed at registration, not bare TOFU
  keyConfirmationPassed: boolean;
  currentKeyIndex: number | null;
  fallbackReason: string | null;
};

export function initialCallPqcSecurityState(): CallPqcSecurityState {
  return {
    state: ENABLE_PQC_CALL_LAYER ? "handshake_in_progress" : "disabled",
    protocolVersion: null,
    capability: null,
    dtlsConnected: false,
    frameCryptorActive: false,
    hybridHandshakeComplete: false,
    classicalSignatureVerified: false,
    pqSignatureVerified: false,
    peerDeviceKeyVerified: false,
    peerAttestationVerified: false,
    keyConfirmationPassed: false,
    currentKeyIndex: null,
    fallbackReason: ENABLE_PQC_CALL_LAYER ? null : "feature_flag_disabled",
  };
}

// ============================================================================
// Byte helpers
// ============================================================================
function bytesToBase64(value: Uint8Array) {
  return base64.encode(value);
}
function base64ToBytes(value: string) {
  return base64.decode(value);
}

/** Best-effort zeroization (PART 20). JS cannot guarantee memory is actually cleared (GC/JIT may have copied it), but this removes the only reference this module holds and overwrites the backing bytes it controls. */
export function wipeBytes(...arrays: (Uint8Array | undefined | null)[]) {
  for (const array of arrays) {
    if (array) array.fill(0);
  }
}

// ============================================================================
// Canonical serialization (PART 6) - deterministic, not "JSON.stringify on an
// object literal and hope key order is stable". Recursively sorts object
// keys; arrays keep their given order (order is semantically meaningful for
// them, e.g. dtlsFingerprints). Verified deterministic by
// tests/calling-pqc-protocol.test.cjs.
// ============================================================================
export const canonicalize = canonicalizeCallV1;
export const canonicalBytes = canonicalBytesCallV1;

// ============================================================================
// DTLS fingerprint extraction (PART 7) - binds the authenticated handshake to
// the specific underlying DTLS/SRTP session so a validly-signed hybrid
// exchange cannot be re-attached to a different, substituted DTLS transport.
// ============================================================================
export function extractDtlsFingerprints(sdp: string | null | undefined): string[] {
  if (!sdp) return [];
  const lines = sdp.split(/\r?\n/);
  const fingerprints: string[] = [];
  for (const line of lines) {
    const match = /^a=fingerprint:(\S+)\s+(\S+)/.exec(line.trim());
    if (match) fingerprints.push(`${match[1].toLowerCase()}:${match[2].toLowerCase()}`);
  }
  // Deterministic order regardless of SDP m-line ordering quirks, since this
  // value is bound into a signed transcript and must be reproducible.
  return [...new Set(fingerprints)].sort();
}

// ============================================================================
// Device signing identity (PART 3) - one hybrid signing keypair PER DEVICE
// CREDENTIAL, never shared account-wide. Reuses the exact SecureStore /
// credentialId persistence pattern already proven in lib/e2ee.ts.
// ============================================================================
export type DeviceCallSigningKeyBundle = {
  id: string;
  user_id: string;
  credential_id: string;
  protocol_version: string;
  ed25519_public_key: string;
  ml_dsa_public_key: string;
  is_active: boolean;
  attestation_verified: boolean;
  attestation_verified_at?: string | null;
  created_at?: string;
};

export type LocalSigningKeys = {
  credentialId: string;
  deviceKeyId: string;
  ed25519PrivateKey: Uint8Array;
  ed25519PublicKey: Uint8Array;
  mlDsaSeed: Uint8Array;
  mlDsaSecretKey: Uint8Array;
  mlDsaPublicKey: Uint8Array;
};

export function createSigningDeviceKeyId(credentialId: string) {
  return `${credentialId}:call-sign-v1`;
}

/**
 * Derives a device call-signing identity from its stored seeds (32-byte
 * Ed25519 private key, 32-byte ML-DSA-65 seed). Storage of the seeds is the
 * application's job (Sentient keeps them in the platform secure store).
 */
export function signingIdentityFromSeeds(credentialId: string, ed25519PrivateKey: Uint8Array, mlDsaSeed: Uint8Array): LocalSigningKeys {
  if (ed25519PrivateKey.length !== 32 || mlDsaSeed.length !== ML_DSA_SEED_BYTES) throw new Error("call signing seed length");
  const mlDsaKeys = ml_dsa65.keygen(mlDsaSeed);
  return {
    credentialId,
    deviceKeyId: createSigningDeviceKeyId(credentialId),
    ed25519PrivateKey,
    ed25519PublicKey: ed25519.getPublicKey(ed25519PrivateKey),
    mlDsaSeed,
    mlDsaSecretKey: mlDsaKeys.secretKey,
    mlDsaPublicKey: mlDsaKeys.publicKey,
  };
}

/** Fresh random seeds for a new call-signing identity (the app persists them). */
export function newSigningSeeds() {
  return { ed25519PrivateKey: randomBytes(32), mlDsaSeed: randomBytes(ML_DSA_SEED_BYTES) };
}

// ============================================================================
// Hybrid signatures (PART 2/6) - BOTH Ed25519 and ML-DSA-65 must verify for a
// message to be considered authenticated. Requiring both (rather than
// either) is what makes this a genuine hybrid authentication upgrade: an
// attacker must break both a mature classical scheme AND a NIST PQC
// signature scheme to forge a handshake message.
// ============================================================================
export type HybridSignature = {
  ed25519Signature: string; // base64
  mlDsaSignature: string; // base64
};

export function signTranscriptHybrid(
  transcript: Uint8Array,
  identity: LocalSigningKeys
): HybridSignature {
  return {
    ed25519Signature: bytesToBase64(ed25519.sign(transcript, identity.ed25519PrivateKey)),
    mlDsaSignature: bytesToBase64(ml_dsa65.sign(transcript, identity.mlDsaSecretKey)),
  };
}

export function verifyTranscriptHybrid(
  transcript: Uint8Array,
  signature: HybridSignature,
  bundle: DeviceCallSigningKeyBundle
): { ed25519Verified: boolean; mlDsaVerified: boolean; bothVerified: boolean } {
  let ed25519Verified = false;
  let mlDsaVerified = false;
  try {
    ed25519Verified = ed25519.verify(
      base64ToBytes(signature.ed25519Signature),
      transcript,
      base64ToBytes(bundle.ed25519_public_key)
    );
  } catch {
    ed25519Verified = false;
  }
  try {
    mlDsaVerified = ml_dsa65.verify(
      base64ToBytes(signature.mlDsaSignature),
      transcript,
      base64ToBytes(bundle.ml_dsa_public_key)
    );
  } catch {
    mlDsaVerified = false;
  }
  return { ed25519Verified, mlDsaVerified, bothVerified: ed25519Verified && mlDsaVerified };
}

// ============================================================================
// KDF (PART 5/9/10) - reuses lib/e2ee.ts's exact combiner shape
// (concat(X25519, ML-KEM) -> HKDF-SHA256), domain-separated from chat and
// versioned distinctly ("sentient-call-hybrid-v1" vs chat's
// "sentient-hybrid-v1"), with a SEPARATE info string per derived-key
// purpose so a confirmation-key leak (if one ever occurred) cannot be
// replayed as a media key or vice versa.
//
// The combiner remains secure if only one of {X25519, ML-KEM} remains
// secure: concatenation-then-HKDF is a standard hybrid-KEM combiner
// property, not something specific to this construction - see the report's
// quantum-security section for the precise claim and its limits.
// ============================================================================
function deriveCallKeys(
  x25519SharedSecret: Uint8Array,
  mlKemSharedSecret: Uint8Array,
  transcript: Uint8Array
) {
  const inputKeyMaterial = concatBytes(x25519SharedSecret, mlKemSharedSecret);
  const salt = sha256(transcript);
  const confirmKey = hkdf(sha256, inputKeyMaterial, salt, utf8ToBytes(`${CALL_PQC_PROTOCOL_VERSION}:confirm-key`), 32);
  // The frame-cryptor's RTCKeyProvider does its own internal HKDF-based
  // ratcheting from whatever base key it is given (see
  // lib/calling-pqc-frame-cryptor.ts) - this 32-byte value is that BASE key,
  // not a raw AES-GCM key applied directly. Documented precisely rather than
  // claiming a specific AES key size the native layer alone controls.
  const mediaBaseKey = hkdf(sha256, inputKeyMaterial, salt, utf8ToBytes(`${CALL_PQC_PROTOCOL_VERSION}:media-key`), 32);
  wipeBytes(inputKeyMaterial);
  return { confirmKey, mediaBaseKey };
}

function confirmationMac(confirmKey: Uint8Array, transcript: Uint8Array, role: "caller" | "callee") {
  return hmac(sha256, confirmKey, concatBytes(transcript, utf8ToBytes(`:confirm:${role}`)));
}

// ============================================================================
// Handshake message wire types
// ============================================================================
export type CallPqcRole = "caller" | "callee";

type HelloFields = {
  step: "hello";
  v: string;
  capability: number;
  callId: string;
  callerUserId: string;
  calleeUserId: string;
  callerDeviceKeyId: string;
  role: "caller";
  nonce: string;
  ephemeralX25519PublicKey: string;
  dtlsFingerprints: string[];
  algorithm: string;
  createdAt: string;
};

type AcceptFields = {
  step: "accept";
  v: string;
  capability: number;
  callId: string;
  callerUserId: string;
  calleeUserId: string;
  calleeDeviceKeyId: string;
  role: "callee";
  nonce: string;
  ephemeralX25519PublicKey: string;
  mlKemPublicKey: string;
  dtlsFingerprints: string[];
  peerEphemeralX25519PublicKey: string;
  peerDtlsFingerprints: string[];
  algorithm: string;
  createdAt: string;
};

type ConfirmFields = {
  step: "confirm";
  v: string;
  callId: string;
  nonce: string;
  mlKemCiphertext: string;
  confirmationMac: string;
  keyIndex: number;
  createdAt: string;
};

type ConfirmedFields = {
  step: "confirmed";
  v: string;
  callId: string;
  nonce: string;
  confirmationMac: string;
  createdAt: string;
};

export type CallPqcHandshakeMessage<T> = T & {
  signingDeviceKeyId: string;
  signature: HybridSignature;
};

export type CallPqcWireMessage =
  | CallPqcHandshakeMessage<HelloFields>
  | CallPqcHandshakeMessage<AcceptFields>
  | CallPqcHandshakeMessage<ConfirmFields>
  | CallPqcHandshakeMessage<ConfirmedFields>;

function signedTranscriptOf(fields: Record<string, unknown>) {
  return canonicalBytes(fields);
}

/**
 * Strips the wire envelope (signingDeviceKeyId, signature) off a received
 * handshake message, recovering exactly the bare fields object the sender
 * originally signed via signTranscriptHybrid(signedTranscriptOf(fields), ...)
 * in buildHello/handleHelloBuildAccept/handleAcceptBuildConfirm/
 * handleConfirmBuildConfirmed (each of those signs `fields` BEFORE wrapping
 * it with `{ ...fields, signingDeviceKeyId, signature }` for transmission).
 *
 * This must be used both (a) to recompute the transcript being verified, so
 * it matches what was actually signed, and (b) wherever a received message
 * is retained as this.helloFields/this.acceptFields for later inclusion in
 * fullTranscript() - otherwise the caller (who stores its OWN bare
 * pre-wrap fields locally) and the callee (who would otherwise store the
 * PEER's full enveloped wire message) derive different canonical bytes for
 * the "same" logical hello/accept, and every signature verification and key
 * confirmation MAC in the entire handshake fails unconditionally, even
 * between two fully legitimate devices. signingDeviceKeyId is intentionally
 * excluded from the authenticated transcript: it is redundant with
 * callerDeviceKeyId/calleeDeviceKeyId, which are already bare fields on
 * HelloFields/AcceptFields and thus already part of what is signed.
 */
function stripEnvelope<T extends Record<string, unknown>>(
  message: CallPqcHandshakeMessage<T>
): T {
  const { signingDeviceKeyId: _signingDeviceKeyId, signature: _signature, ...fields } = message as Record<string, unknown>;
  return fields as T;
}

function isFreshAt(createdAt: string, nowMs: number): boolean {
  const t = Date.parse(createdAt);
  if (!Number.isFinite(t)) return false;
  return Math.abs(nowMs - t) <= HANDSHAKE_FRESHNESS_WINDOW_MS;
}

// ============================================================================
// Handshake state machine
// ============================================================================
export type CallPqcHandshakeResult = {
  mediaBaseKey: Uint8Array;
  peerAttestationVerified: boolean;
};

export type CallPqcHandshakeCallbacks = {
  onSecurityState?: (state: CallPqcSecurityState) => void;
};

/**
 * Drives one side of the four-message handshake
 * (caller: hello -> [accept] -> confirm -> [confirmed] -> done;
 *  callee: [hello] -> accept -> [confirm] -> confirmed -> done).
 * Construct one instance per call attempt; it is single-use.
 */
export class CallPqcHandshake {
  private readonly role: CallPqcRole;
  private readonly callId: string;
  private readonly callerUserId: string;
  private readonly calleeUserId: string;
  private readonly localIdentity: LocalSigningKeys;
  private readonly localDeviceKeyId: string;
  private readonly getPeerBundle: (deviceKeyId: string) => Promise<DeviceCallSigningKeyBundle | null>;
  private readonly localDtlsFingerprints: () => string[];

  private nonce: string | null = null;
  private ephemeralX25519Private: Uint8Array | null = null;
  private ephemeralX25519Public: Uint8Array | null = null;
  private mlKemEphemeral: { publicKey: Uint8Array; secretKey: Uint8Array } | null = null;
  private helloFields: HelloFields | null = null;
  private acceptFields: AcceptFields | null = null;
  /** The confirm message this side built or accepted (diagnostics). */
  confirmFields: ConfirmFields | null = null;
  private peerBundle: DeviceCallSigningKeyBundle | null = null;
  private result: CallPqcHandshakeResult | null = null;

  state: CallPqcSecurityState = initialCallPqcSecurityState();
  private readonly callbacks: CallPqcHandshakeCallbacks;

  constructor(params: {
    role: CallPqcRole;
    callId: string;
    callerUserId: string;
    calleeUserId: string;
    localIdentity: LocalSigningKeys;
    getPeerBundle: (deviceKeyId: string) => Promise<DeviceCallSigningKeyBundle | null>;
    localDtlsFingerprints: () => string[];
    callbacks?: CallPqcHandshakeCallbacks;
    /**
     * Optional local binding check on the peer's directory row (for example
     * `bundle.user_id === expectedPeerUserId`). A row that fails it ends the
     * handshake as verification_failed ("peer_identity_mismatch"). Default:
     * accept any row the directory returned (deployed phone behaviour).
     */
    expectPeer?: (bundle: DeviceCallSigningKeyBundle) => boolean;
    /** Randomness source (default: CSPRNG). Tests inject a deterministic one. */
    random?: (length: number) => Uint8Array;
    /** Clock in milliseconds (default: Date.now). */
    now?: () => number;
  }) {
    this.role = params.role;
    this.callId = params.callId;
    this.callerUserId = params.callerUserId;
    this.calleeUserId = params.calleeUserId;
    this.localIdentity = params.localIdentity;
    this.localDeviceKeyId = params.localIdentity.deviceKeyId;
    this.getPeerBundle = params.getPeerBundle;
    this.localDtlsFingerprints = params.localDtlsFingerprints;
    this.callbacks = params.callbacks ?? {};
    this.expectPeer = params.expectPeer ?? (() => true);
    this.random = params.random ?? randomBytes;
    this.now = params.now ?? (() => Date.now());
  }

  private readonly expectPeer: (bundle: DeviceCallSigningKeyBundle) => boolean;
  private readonly random: (length: number) => Uint8Array;
  private readonly now: () => number;
  /** Assignable listener (Business Terminal style); called in addition to callbacks.onSecurityState. */
  onSecurityState: ((state: CallPqcSecurityState) => void) | null = null;

  private nowIso() {
    return new Date(this.now()).toISOString();
  }

  private isFresh(createdAt: string) {
    return isFreshAt(createdAt, this.now());
  }

  /** Directory lookup + optional local binding check. */
  private async peer(deviceKeyId: string): Promise<{ bundle: DeviceCallSigningKeyBundle | null; reason: string | null }> {
    const bundle = await this.getPeerBundle(deviceKeyId).catch(() => null);
    if (!bundle) return { bundle: null, reason: "peer_no_signing_bundle" };
    if (!this.expectPeer(bundle)) return { bundle: null, reason: "peer_identity_mismatch" };
    return { bundle, reason: null };
  }

  private emit() {
    this.callbacks.onSecurityState?.(this.state);
    this.onSecurityState?.(this.state);
  }

  private fail(reason: string) {
    this.state = {
      ...this.state,
      state: "verification_failed",
      fallbackReason: reason,
    };
    this.emit();
  }

  private unsupported(reason: string) {
    this.state = { ...this.state, state: "unsupported", fallbackReason: reason };
    this.emit();
  }

  getResult(): CallPqcHandshakeResult | null {
    return this.result;
  }

  /** Caller only: builds and signs the initial "hello" message. */
  async buildHello(): Promise<CallPqcHandshakeMessage<HelloFields>> {
    if (this.role !== "caller") throw new Error("buildHello is caller-only");
    this.nonce = bytesToBase64(this.random(16));
    this.ephemeralX25519Private = this.random(32);
    this.ephemeralX25519Public = x25519.getPublicKey(this.ephemeralX25519Private);

    const fields: HelloFields = {
      step: "hello",
      v: CALL_PQC_PROTOCOL_VERSION,
      capability: CALL_PQC_CAPABILITY,
      callId: this.callId,
      callerUserId: this.callerUserId,
      calleeUserId: this.calleeUserId,
      callerDeviceKeyId: this.localDeviceKeyId,
      role: "caller",
      nonce: this.nonce,
      ephemeralX25519PublicKey: bytesToBase64(this.ephemeralX25519Public),
      dtlsFingerprints: this.localDtlsFingerprints(),
      algorithm: FRAME_ALGORITHM_LABEL,
      createdAt: this.nowIso(),
    };
    this.helloFields = fields;
    const signature = signTranscriptHybrid(signedTranscriptOf(fields), this.localIdentity);
    return { ...fields, signingDeviceKeyId: this.localDeviceKeyId, signature };
  }

  /** Callee only: verifies "hello", generates its ephemeral material, builds and signs "accept". */
  async handleHelloBuildAccept(
    message: CallPqcHandshakeMessage<HelloFields>
  ): Promise<CallPqcHandshakeMessage<AcceptFields> | null> {
    if (this.role !== "callee") throw new Error("handleHelloBuildAccept is callee-only");
    if (message.callId !== this.callId || message.v !== CALL_PQC_PROTOCOL_VERSION) {
      this.fail("hello_field_mismatch");
      return null;
    }
    if (!this.isFresh(message.createdAt)) {
      this.fail("hello_stale");
      return null;
    }

    const { bundle: peerBundle, reason: peerReason } = await this.peer(message.callerDeviceKeyId);
    if (!peerBundle) {
      if (peerReason === "peer_identity_mismatch") this.fail(peerReason);
      else this.unsupported("peer_no_signing_bundle");
      return null;
    }
    const helloFieldsOnly = stripEnvelope(message);
    const { bothVerified } = verifyTranscriptHybrid(
      signedTranscriptOf(helloFieldsOnly),
      message.signature,
      peerBundle
    );
    if (!bothVerified) {
      this.fail("hello_signature_invalid");
      return null;
    }

    this.peerBundle = peerBundle;
    this.helloFields = helloFieldsOnly;
    this.nonce = message.nonce;
    this.ephemeralX25519Private = this.random(32);
    this.ephemeralX25519Public = x25519.getPublicKey(this.ephemeralX25519Private);
    this.mlKemEphemeral = ml_kem768.keygen(this.random(64));

    const fields: AcceptFields = {
      step: "accept",
      v: CALL_PQC_PROTOCOL_VERSION,
      capability: CALL_PQC_CAPABILITY,
      callId: this.callId,
      callerUserId: this.callerUserId,
      calleeUserId: this.calleeUserId,
      calleeDeviceKeyId: this.localDeviceKeyId,
      role: "callee",
      nonce: this.nonce,
      ephemeralX25519PublicKey: bytesToBase64(this.ephemeralX25519Public),
      mlKemPublicKey: bytesToBase64(this.mlKemEphemeral.publicKey),
      dtlsFingerprints: this.localDtlsFingerprints(),
      peerEphemeralX25519PublicKey: message.ephemeralX25519PublicKey,
      peerDtlsFingerprints: message.dtlsFingerprints,
      algorithm: FRAME_ALGORITHM_LABEL,
      createdAt: this.nowIso(),
    };
    this.acceptFields = fields;
    const signature = signTranscriptHybrid(signedTranscriptOf(fields), this.localIdentity);
    this.state = {
      ...this.state,
      classicalSignatureVerified: true,
      pqSignatureVerified: true,
      peerDeviceKeyVerified: true,
      peerAttestationVerified: peerBundle.attestation_verified,
    };
    this.emit();
    return { ...fields, signingDeviceKeyId: this.localDeviceKeyId, signature };
  }

  /** Caller only: verifies "accept", encapsulates ML-KEM, derives keys, builds and signs "confirm". */
  async handleAcceptBuildConfirm(
    message: CallPqcHandshakeMessage<AcceptFields>
  ): Promise<CallPqcHandshakeMessage<ConfirmFields> | null> {
    if (this.role !== "caller") throw new Error("handleAcceptBuildConfirm is caller-only");
    if (!this.helloFields || !this.ephemeralX25519Private) {
      this.fail("confirm_before_hello");
      return null;
    }
    if (
      message.callId !== this.callId ||
      message.v !== CALL_PQC_PROTOCOL_VERSION ||
      message.nonce !== this.nonce ||
      message.peerEphemeralX25519PublicKey !== this.helloFields.ephemeralX25519PublicKey
    ) {
      this.fail("accept_field_mismatch");
      return null;
    }
    if (!this.isFresh(message.createdAt)) {
      this.fail("accept_stale");
      return null;
    }

    const { bundle: peerBundle, reason: peerReason } = await this.peer(message.calleeDeviceKeyId);
    if (!peerBundle) {
      if (peerReason === "peer_identity_mismatch") this.fail(peerReason);
      else this.unsupported("peer_no_signing_bundle");
      return null;
    }
    const acceptFieldsOnly = stripEnvelope(message);
    const { bothVerified } = verifyTranscriptHybrid(
      signedTranscriptOf(acceptFieldsOnly),
      message.signature,
      peerBundle
    );
    if (!bothVerified) {
      this.fail("accept_signature_invalid");
      return null;
    }

    this.peerBundle = peerBundle;
    this.acceptFields = acceptFieldsOnly;

    const calleeEphemeralX25519Public = base64ToBytes(message.ephemeralX25519PublicKey);
    const x25519SharedSecret = x25519.getSharedSecret(
      this.ephemeralX25519Private,
      calleeEphemeralX25519Public
    );
    const calleeMlKemPublicKey = base64ToBytes(message.mlKemPublicKey);
    const { cipherText, sharedSecret: mlKemSharedSecret } = ml_kem768.encapsulate(calleeMlKemPublicKey, this.random(32));

    const transcript = this.fullTranscript(cipherText);
    const { confirmKey, mediaBaseKey } = deriveCallKeys(x25519SharedSecret, mlKemSharedSecret, transcript);
    wipeBytes(x25519SharedSecret, mlKemSharedSecret);

    const mac = confirmationMac(confirmKey, transcript, "caller");
    const fields: ConfirmFields = {
      step: "confirm",
      v: CALL_PQC_PROTOCOL_VERSION,
      callId: this.callId,
      nonce: this.nonce!,
      mlKemCiphertext: bytesToBase64(cipherText),
      confirmationMac: bytesToBase64(mac),
      keyIndex: 0,
      createdAt: this.nowIso(),
    };
    this.confirmFields = fields;
    (this as any)._pendingConfirmKey = confirmKey;
    (this as any)._pendingMediaBaseKey = mediaBaseKey;
    (this as any)._pendingTranscript = transcript;

    const signature = signTranscriptHybrid(signedTranscriptOf(fields), this.localIdentity);
    this.state = {
      ...this.state,
      classicalSignatureVerified: true,
      pqSignatureVerified: true,
      peerDeviceKeyVerified: true,
      peerAttestationVerified: peerBundle.attestation_verified,
      hybridHandshakeComplete: true,
      state: "pq_confidential_only",
    };
    this.emit();
    return { ...fields, signingDeviceKeyId: this.localDeviceKeyId, signature };
  }

  /** Callee only: verifies "confirm", decapsulates, derives keys, verifies caller's MAC, builds "confirmed". */
  async handleConfirmBuildConfirmed(
    message: CallPqcHandshakeMessage<ConfirmFields>
  ): Promise<CallPqcHandshakeMessage<ConfirmedFields> | null> {
    if (this.role !== "callee") throw new Error("handleConfirmBuildConfirmed is callee-only");
    if (!this.helloFields || !this.acceptFields || !this.mlKemEphemeral || !this.ephemeralX25519Private || !this.peerBundle) {
      this.fail("confirm_before_accept");
      return null;
    }
    if (message.callId !== this.callId || message.v !== CALL_PQC_PROTOCOL_VERSION || message.nonce !== this.nonce) {
      this.fail("confirm_field_mismatch");
      return null;
    }
    if (!this.isFresh(message.createdAt)) {
      this.fail("confirm_stale");
      return null;
    }
    const { bothVerified } = verifyTranscriptHybrid(
      signedTranscriptOf(stripEnvelope(message)),
      message.signature,
      this.peerBundle
    );
    if (!bothVerified) {
      this.fail("confirm_signature_invalid");
      return null;
    }

    const callerEphemeralX25519Public = base64ToBytes(this.helloFields.ephemeralX25519PublicKey);
    const x25519SharedSecret = x25519.getSharedSecret(
      this.ephemeralX25519Private,
      callerEphemeralX25519Public
    );
    const cipherText = base64ToBytes(message.mlKemCiphertext);
    let mlKemSharedSecret: Uint8Array;
    try {
      mlKemSharedSecret = ml_kem768.decapsulate(cipherText, this.mlKemEphemeral.secretKey);
    } catch {
      this.fail("mlkem_decapsulate_failed");
      return null;
    }

    const transcript = this.fullTranscript(cipherText);
    const { confirmKey, mediaBaseKey } = deriveCallKeys(x25519SharedSecret, mlKemSharedSecret, transcript);
    wipeBytes(x25519SharedSecret, mlKemSharedSecret);

    const expectedCallerMac = confirmationMac(confirmKey, transcript, "caller");
    if (!constantTimeEqual(expectedCallerMac, base64ToBytes(message.confirmationMac))) {
      this.fail("confirmation_mac_mismatch");
      wipeBytes(confirmKey, mediaBaseKey);
      return null;
    }

    const ownMac = confirmationMac(confirmKey, transcript, "callee");
    const fields: ConfirmedFields = {
      step: "confirmed",
      v: CALL_PQC_PROTOCOL_VERSION,
      callId: this.callId,
      nonce: this.nonce!,
      confirmationMac: bytesToBase64(ownMac),
      createdAt: this.nowIso(),
    };
    const signature = signTranscriptHybrid(signedTranscriptOf(fields), this.localIdentity);

    this.result = { mediaBaseKey, peerAttestationVerified: this.peerBundle.attestation_verified };
    wipeBytes(confirmKey);
    this.state = {
      ...this.state,
      hybridHandshakeComplete: true,
      keyConfirmationPassed: true,
      currentKeyIndex: 0,
      state: terminalStateFor(this.peerBundle.attestation_verified),
      fallbackReason: null,
    };
    this.emit();
    return { ...fields, signingDeviceKeyId: this.localDeviceKeyId, signature };
  }

  /** Caller only: verifies callee's "confirmed" MAC using the key material saved from handleAcceptBuildConfirm. */
  async handleConfirmed(message: CallPqcHandshakeMessage<ConfirmedFields>): Promise<boolean> {
    if (this.role !== "caller") throw new Error("handleConfirmed is caller-only");
    const confirmKey: Uint8Array | undefined = (this as any)._pendingConfirmKey;
    const mediaBaseKey: Uint8Array | undefined = (this as any)._pendingMediaBaseKey;
    const transcript: Uint8Array | undefined = (this as any)._pendingTranscript;
    if (!confirmKey || !mediaBaseKey || !transcript || !this.peerBundle) {
      this.fail("confirmed_before_confirm");
      return false;
    }
    if (message.callId !== this.callId || message.v !== CALL_PQC_PROTOCOL_VERSION || message.nonce !== this.nonce) {
      this.fail("confirmed_field_mismatch");
      return false;
    }
    const { bothVerified } = verifyTranscriptHybrid(
      signedTranscriptOf(stripEnvelope(message)),
      message.signature,
      this.peerBundle
    );
    if (!bothVerified) {
      this.fail("confirmed_signature_invalid");
      return false;
    }
    const expectedCalleeMac = confirmationMac(confirmKey, transcript, "callee");
    if (!constantTimeEqual(expectedCalleeMac, base64ToBytes(message.confirmationMac))) {
      this.fail("confirmation_mac_mismatch");
      wipeBytes(confirmKey, mediaBaseKey);
      return false;
    }

    this.result = { mediaBaseKey, peerAttestationVerified: this.peerBundle.attestation_verified };
    wipeBytes(confirmKey);
    (this as any)._pendingConfirmKey = undefined;
    (this as any)._pendingTranscript = undefined;
    this.state = {
      ...this.state,
      keyConfirmationPassed: true,
      currentKeyIndex: 0,
      state: terminalStateFor(this.peerBundle.attestation_verified),
      fallbackReason: null,
    };
    this.emit();
    return true;
  }

  markUnsupportedPeer(reason: string) {
    this.unsupported(reason);
  }

  markTransportFallback(reason: string) {
    // Never overwrite a proven-good terminal state - both tiers passed the
    // full hybrid signature + key confirmation check; they differ only in
    // whether the peer's identity was attestation-backed (see
    // terminalStateFor), not in whether verification itself succeeded.
    if (this.state.state === "pq_authenticated" || this.state.state === "pq_signed_unattested_device") return;
    this.state = { ...this.state, state: "standard_encrypted", fallbackReason: reason };
    this.emit();
  }

  private fullTranscript(mlKemCiphertext: Uint8Array): Uint8Array {
    if (!this.helloFields || !this.acceptFields) throw new Error("Transcript requested before hello/accept exchanged");
    return canonicalBytes({
      hello: this.helloFields,
      accept: this.acceptFields,
      mlKemCiphertext: bytesToBase64(mlKemCiphertext),
    });
  }
}

/**
 * The terminal state after a fully-verified handshake (both hybrid
 * signatures + key confirmation succeeded) depends ENTIRELY on whether the
 * peer's registered signing key was attestation-backed at registration
 * (migration 132's attestation_verified) - never on the fact that
 * verification itself succeeded. This is the single choke point that
 * enforces "do not conflate cryptographic signature verification with
 * platform-attested device identity": both callers below route through it
 * instead of hardcoding "pq_authenticated".
 */
function terminalStateFor(peerAttestationVerified: boolean): CallPqcSecurityStateValue {
  return peerAttestationVerified ? "pq_authenticated" : "pq_signed_unattested_device";
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

