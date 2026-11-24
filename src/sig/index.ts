/*
 * Hybrid Ed25519 + ML-DSA-65 signatures. A signature is accepted only when
 * BOTH component signatures verify.
 *
 * Two deployed framings exist and are kept distinct:
 *   signHybrid / verifyHybrid (business, group):
 *     input = UTF-8(context) || 0x00 || canonicalBytes(fields)
 *     signature = { ed25519, mlDsa } (base64)
 *   signTranscriptHybrid / verifyTranscriptHybrid (sentient-call-hybrid-v1):
 *     input = the raw transcript bytes (canonicalizeCallV1 of the fields)
 *     signature = { ed25519Signature, mlDsaSignature } (base64)
 * ML-DSA-65 is used in its default (hedged, empty-context) mode as
 * implemented by @noble/post-quantum.
 */
export { signHybrid, verifyHybrid, signingKeysFromSeeds } from "../business/core.js";
export { signTranscriptHybrid, verifyTranscriptHybrid, type HybridSignature } from "../call/handshake.js";
