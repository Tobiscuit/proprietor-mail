/**
 * Crockford base32 (https://www.crockford.com/base32.html).
 *
 * Crockford encodes a number: the byte string is read as one big-endian
 * number, "zero-extended to make its bit-length a multiple of 5", and written
 * five bits at a time from the most significant end. So the padding bits are
 * leading zeros (as in ULID and TypeID): 16 bytes give 26 symbols whose first
 * is 0-7, and 34 bytes give 55 symbols whose first is 0-3.
 */

const LOWER = "0123456789abcdefghjkmnpqrstvwxyz";
const UPPER = LOWER.toUpperCase();

const VALUE = new Int8Array(128).fill(-1);
for (let i = 0; i < 32; i++) {
  VALUE[LOWER.charCodeAt(i)] = i;
  VALUE[UPPER.charCodeAt(i)] = i;
}

export function crockfordLength(byteLength: number): number {
  return Math.ceil((byteLength * 8) / 5);
}

export function crockfordEncode(bytes: Uint8Array, alphabet: "lower" | "upper"): string {
  const symbols = alphabet === "lower" ? LOWER : UPPER;
  const length = crockfordLength(bytes.length);
  // Start with the leading zero bits already in the accumulator.
  let bits = length * 5 - bytes.length * 8;
  let acc = 0;
  let out = "";
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += symbols[(acc >>> bits) & 31]!;
    }
    acc &= (1 << bits) - 1;
  }
  return out;
}

/**
 * Decodes exactly `byteLength` bytes from canonical symbols (either case, no
 * separators, no aliases: callers normalize first). Returns null when a symbol
 * is not in the alphabet, the length is wrong, or a leading pad bit is set.
 */
export function crockfordDecode(s: string, byteLength: number): Uint8Array<ArrayBuffer> | null {
  if (s.length !== crockfordLength(byteLength)) return null;
  const pad = s.length * 5 - byteLength * 8;
  const out = new Uint8Array(byteLength);
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? VALUE[c]! : -1;
    if (v < 0) return null;
    acc = (acc << 5) | v;
    bits += 5;
    if (i === 0) {
      if (acc >>> (5 - pad) !== 0) return null; // a leading pad bit is set
      bits -= pad;
    }
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >>> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  return o === byteLength && bits === 0 ? out : null;
}
