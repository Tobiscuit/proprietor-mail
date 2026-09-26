/**
 * Byte helpers built on Uint8Array and TextEncoder/TextDecoder only, so they
 * run unchanged in browsers, Workers and Node (and avoid atob/btoa quirks).
 */

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(s: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(s);
}

/** Strict UTF-8 decoding: malformed bytes throw instead of becoming U+FFFD. */
export function fromUtf8(bytes: Uint8Array): string {
  return strictDecoder.decode(bytes);
}

/** A fresh copy on its own ArrayBuffer (Web Crypto rejects shared or resizable buffers). */
export function copy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

export function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  let length = 0;
  for (const p of parts) length += p.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

// ---- base64url (RFC 4648 §5, no padding) ------------------------------------

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_VALUE = new Int8Array(128).fill(-1);
for (let i = 0; i < B64URL.length; i++) B64URL_VALUE[B64URL.charCodeAt(i)] = i;

export function base64url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out += B64URL[n >>> 18]! + B64URL[(n >>> 12) & 63]! + B64URL[(n >>> 6) & 63]! + B64URL[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i]! << 16;
    out += B64URL[n >>> 18]! + B64URL[(n >>> 12) & 63]!;
  } else if (rest === 2) {
    const n = (bytes[i]! << 16) | (bytes[i + 1]! << 8);
    out += B64URL[n >>> 18]! + B64URL[(n >>> 12) & 63]! + B64URL[(n >>> 6) & 63]!;
  }
  return out;
}

/**
 * Strict base64url decoding: only the URL-safe alphabet, no padding, no
 * whitespace, and the unused low bits of the last symbol must be zero, so a
 * string has exactly one decoding and a changed symbol never decodes to the
 * same bytes. Returns null for anything else.
 */
export function fromBase64url(s: string): Uint8Array<ArrayBuffer> | null {
  if (typeof s !== "string" || s.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((s.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64URL_VALUE[c]! : -1;
    if (v < 0) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (acc !== 0) return null; // non-canonical: leftover bits must be zero
  return out;
}
