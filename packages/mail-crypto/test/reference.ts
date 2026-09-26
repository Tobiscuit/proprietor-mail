/**
 * Independent reference readings of contracts/envelope-v1.md, used only by
 * tests. They deliberately use different code paths from src/ (Node's Buffer,
 * BigInt arithmetic, raw Web Crypto calls) so that a test comparing the two
 * catches a misreading of the contract, not just a disagreement with itself.
 */
import { Buffer } from "node:buffer";

export const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

export const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");
export const fromHex = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, "hex"));
export const b64urlDecode = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, "base64url"));
export const b64urlEncode = (bytes: Uint8Array): string => Buffer.from(bytes).toString("base64url");
export const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);

/**
 * Crockford base32 as Crockford defines it: the symbols spell one number,
 * most significant first ("zero-extend the number to make its bit-length a
 * multiple of 5"). Returns null when the number does not fit in `length` bytes.
 */
export function crockfordToBytes(symbols: string, length: number): Uint8Array | null {
  let n = 0n;
  for (const c of symbols.toLowerCase()) {
    const v = CROCKFORD.indexOf(c);
    if (v < 0) return null;
    n = n * 32n + BigInt(v);
  }
  if (n >> BigInt(8 * length) !== 0n) return null;
  const out = new Uint8Array(length);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return out;
}

export async function sha256(bytes: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

/** Every byte string of `bytes` with one bit flipped at position `i`. */
export function flipBit(bytes: Uint8Array, i: number, bit = 0): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(bytes);
  copy[i] = (copy[i] ?? 0) ^ (1 << bit);
  return copy;
}
