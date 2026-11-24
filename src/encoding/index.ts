/*
 * Encoding helpers shared by every Sentient protocol.
 *
 * TWO canonical JSON forms exist in deployed protocols and they are NOT
 * interchangeable:
 *   canonicalize        business / group / notification preview: drops
 *                       object keys whose value is undefined; rejects
 *                       non-finite numbers.
 *   canonicalizeCallV1  sentient-call-hybrid-v1 handshake transcripts: keeps
 *                       undefined-valued keys (encoded as null); no
 *                       finiteness check.
 * Both are pinned by known-answer vectors. Never "unify" them: that would
 * change signed bytes and break interoperability with deployed clients.
 */
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";

export class EncodingError extends Error {
  code: string;
  constructor(code: string, message?: string) {
    super(message || code);
    this.name = "EncodingError";
    this.code = code;
  }
}

export function toB64(bytes: Uint8Array): string {
  return base64.encode(bytes);
}

export function fromB64(value: unknown): Uint8Array {
  if (typeof value !== "string") throw new EncodingError("encoding", "Expected base64 text.");
  return base64.decode(value);
}

export function canonicalize(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new EncodingError("canonical", "Non-finite number.");
    return JSON.stringify(value);
  }
  if (typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).filter((key) => record[key] !== undefined).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(",")}}`;
  }
  throw new EncodingError("canonical", `Cannot canonicalize ${typeof value}.`);
}

export function canonicalBytes(value: unknown): Uint8Array {
  return utf8ToBytes(canonicalize(value));
}

/** Byte-exact equality, constant time in the length of the inputs. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function constantTimeEqualText(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Best-effort zeroization; JavaScript cannot guarantee no copies exist elsewhere. */
export function wipe(...arrays: (Uint8Array | null | undefined)[]): void {
  for (const array of arrays) if (array instanceof Uint8Array) array.fill(0);
}

/**
 * UTF-8 decode that also works where TextDecoder is missing (iOS
 * JavaScriptCore notification extensions).
 * fatal=false (default) matches `new TextDecoder().decode()`, which is what
 * deployed sentient-hybrid-v1 decryption uses: invalid sequences become
 * U+FFFD. The no-TextDecoder fallback replaces per offending byte, which can
 * differ from WHATWG "maximal subpart" replacement for invalid input only;
 * valid UTF-8 always decodes identically.
 */
export function utf8Decode(bytes: Uint8Array, options: { fatal?: boolean } = {}): string {
  const fatal = options.fatal === true;
  if (typeof TextDecoder !== "undefined") return new TextDecoder("utf-8", { fatal }).decode(bytes);
  let out = "";
  let i = 0;
  while (i < bytes.length) {
    const start = i;
    const c = bytes[i++];
    try {
      const cont = () => {
        const b = bytes[i++];
        if (b === undefined || (b & 0xc0) !== 0x80) throw new EncodingError("utf8");
        return b & 0x3f;
      };
      if (c < 0x80) out += String.fromCharCode(c);
      else if (c >= 0xc2 && c < 0xe0) out += String.fromCharCode(((c & 0x1f) << 6) | cont());
      else if (c >= 0xe0 && c < 0xf0) {
        const cp = ((c & 0x0f) << 12) | (cont() << 6) | cont();
        if (cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff)) throw new EncodingError("utf8");
        out += String.fromCharCode(cp);
      } else if (c >= 0xf0 && c < 0xf5) {
        const cp = ((c & 0x07) << 18) | (cont() << 12) | (cont() << 6) | cont();
        if (cp < 0x10000 || cp > 0x10ffff) throw new EncodingError("utf8");
        const v = cp - 0x10000;
        out += String.fromCharCode(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
      } else throw new EncodingError("utf8");
    } catch (error) {
      if (fatal) throw error;
      out += "�";
      i = start + 1;
    }
  }
  return out;
}

/**
 * sentient-call-hybrid-v1 transcript canonicalization (moved unchanged from
 * the call handshake). Recursively sorted keys; undefined values are kept and
 * encoded as null; numbers are not checked for finiteness.
 */
export function canonicalizeCallV1(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalizeCallV1).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalizeCallV1((value as Record<string, unknown>)[key])}`);
    return `{${parts.join(",")}}`;
  }
  throw new Error(`Cannot canonicalize value of type ${typeof value}`);
}

export function canonicalBytesCallV1(value: unknown): Uint8Array {
  return utf8ToBytes(canonicalizeCallV1(value));
}
