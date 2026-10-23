import { InvalidRequest } from "../errors";
import * as v from "./validate";

/**
 * Public keys that reach Mail in a request (contracts/device-v1.md A2, A3),
 * checked before they are stored: a key Mail would later seal a challenge to,
 * or verify a signature with, must be one Web Crypto accepts. Error messages
 * name the field, never echo the key.
 */

type DeriveBitsParams = Parameters<SubtleCrypto["deriveBits"]>[0];

/**
 * A raw uncompressed P-256 point (A3): 65 bytes, 0x04 || X || Y, on the curve.
 * Web Crypto's raw import refuses a point that is not on the curve, and
 * accepts a compressed one, so the form is checked here first.
 */
export async function p256Point(value: unknown, what: string, use: "ECDSA" | "ECDH"): Promise<Uint8Array> {
  const bytes = v.decodeBase64url(v.base64url(value, what, { bytes: 65 }));
  if (bytes[0] !== 0x04) throw new InvalidRequest(`${what} must be an uncompressed P-256 point`);
  try {
    await crypto.subtle.importKey("raw", bytes, { name: use, namedCurve: "P-256" }, false, use === "ECDSA" ? ["verify"] : []);
  } catch {
    throw new InvalidRequest(`${what} must be a point on P-256`);
  }
  return bytes;
}

/**
 * An X25519 public key (A2's factor keys, a rotation's new key): 32 bytes
 * whose agreement with a fresh key is not all zeros. A low-order point would
 * make every challenge sealed to it fail (Web Crypto refuses the all-zero
 * secret), so it is refused here instead.
 */
export async function x25519Key(value: unknown, what: string): Promise<Uint8Array> {
  const bytes = v.decodeBase64url(v.base64url(value, what, { bytes: 32 }));
  try {
    const peer = await crypto.subtle.importKey("raw", bytes, { name: "X25519" }, false, []);
    const probe = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
    // `public` is the Secure Curves name; @cloudflare/workers-types spells the field `$public` (see mail-crypto's keys.ts).
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: peer } as unknown as DeriveBitsParams, probe.privateKey, 256));
    if (shared.every((b) => b === 0)) throw new Error("low-order point");
  } catch {
    throw new InvalidRequest(`${what} must be a usable X25519 public key`);
  }
  return bytes;
}

/**
 * A factor's signing key (A2b, D44): an Ed25519 public key, 32 bytes, that
 * Web Crypto imports for `verify`. Mail verifies the factor's admissions and
 * transitions with it (A11, M25).
 */
export async function ed25519Key(value: unknown, what: string): Promise<Uint8Array> {
  const bytes = v.decodeBase64url(v.base64url(value, what, { bytes: 32 }));
  try {
    await crypto.subtle.importKey("raw", bytes, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    throw new InvalidRequest(`${what} must be an Ed25519 public key`);
  }
  return bytes;
}
