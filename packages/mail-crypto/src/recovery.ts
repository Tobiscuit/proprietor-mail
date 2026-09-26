/**
 * The recovery key as people see it (contracts/envelope-v1.md): the 32-byte
 * secret, then the first 2 bytes of SHA-256(secret), in Crockford base32 -
 * 55 symbols, shown upper-case in 11 groups of 5 joined by hyphens.
 */
import { bytesEqual, concat, randomBytes } from "./bytes";
import { crockfordDecode, crockfordEncode } from "./crockford";
import { RecoveryKeyTypo } from "./errors";
import { sha256 } from "./sha256";

const SECRET_BYTES = 32;
const CHECKSUM_BYTES = 2;

function checksum(raw: Uint8Array): Uint8Array {
  return sha256(raw).subarray(0, CHECKSUM_BYTES);
}

export function recoveryDisplay(raw: Uint8Array): string {
  if (!(raw instanceof Uint8Array) || raw.length !== SECRET_BYTES) {
    throw new TypeError("a recovery secret is exactly 32 bytes");
  }
  const symbols = crockfordEncode(concat(raw, checksum(raw)), "upper");
  return symbols.match(/.{5}/g)!.join("-");
}

export function newRecoveryKey(): { secret: Uint8Array; display: string } { // pragma: allowlist secret (a type)
  const raw = randomBytes(SECRET_BYTES);
  return { secret: raw, display: recoveryDisplay(raw) };
}

/**
 * Accepts lower case, spaces and hyphens anywhere, reads I and L as 1 and O
 * as 0, and throws RecoveryKeyTypo for anything else that is not exactly a
 * valid key: a wrong length, a symbol outside the alphabet (including U and
 * any non-ASCII character), a set leading pad bit, or a checksum mismatch.
 * No decryption is involved.
 */
export function parseRecoveryKey(display: string): Uint8Array {
  if (typeof display !== "string") throw new TypeError("a recovery key is a string");
  const compact = display.replace(/[\s-]/g, "");
  if (!/^[\x21-\x7e]*$/.test(compact)) throw new RecoveryKeyTypo();
  const symbols = compact.toUpperCase().replace(/[IL]/g, "1").replace(/O/g, "0");
  const bytes = crockfordDecode(symbols, SECRET_BYTES + CHECKSUM_BYTES);
  if (bytes === null) throw new RecoveryKeyTypo();
  const raw = bytes.slice(0, SECRET_BYTES);
  if (!bytesEqual(checksum(raw), bytes.subarray(SECRET_BYTES))) throw new RecoveryKeyTypo();
  return raw;
}
