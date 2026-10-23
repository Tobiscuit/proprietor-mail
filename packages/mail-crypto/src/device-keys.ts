/**
 * Device keys (contracts/device-v1.md A3) and device proofs (A7).
 *
 * A kept device holds two P-256 key pairs made in the browser: an ECDSA
 * signing key and an ECDH unlock key. Their private halves are
 * non-extractable CryptoKeys, so the kept-device store can keep them in
 * IndexedDB (structured clone keeps `extractable` false) and nothing on the
 * page can read their bytes. P-256, not X25519, because WebKit cannot read an
 * X25519 CryptoKey back from IndexedDB (spec 002 §9). The public halves are
 * raw uncompressed points, 65 bytes (0x04 || X || Y).
 *
 * The signing key signs only device proofs:
 *   ctx("device-proof", mailboxId, deviceId, challengeId, b64u(nonce)),
 * ECDSA P-256 with SHA-256, IEEE P1363 (r || s), 64 bytes: the form Web
 * Crypto produces. The Worker verifies them (src/proofs.ts).
 */
import { base64url } from "./bytes";
import { context } from "./envelope";

/** A device key pair: the non-extractable private CryptoKey, and the public key as a 65-byte uncompressed point. */
export interface DeviceKeyPair {
  readonly privateKey: CryptoKey; // pragma: allowlist secret (a type)
  readonly publicKey: Uint8Array<ArrayBuffer>;
}

const P256_POINT_BYTES = 65;
const SIGNATURE_BYTES = 64;

async function exportPair(pair: CryptoKeyPair): Promise<DeviceKeyPair> {
  // workers-types returns ArrayBuffer | JsonWebKey for every format; "raw" is always an ArrayBuffer.
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  if (raw.length !== P256_POINT_BYTES || raw[0] !== 0x04) throw new Error("internal: a P-256 public key is a 65-byte uncompressed point");
  return { privateKey: pair.privateKey, publicKey: raw }; // pragma: allowlist secret (a CryptoKey reference)
}

// generateKey makes the public half extractable whatever `extractable` says; only the private half is bound by it.

/** A new ECDSA P-256 signing key (A3): the private half non-extractable, usage sign. */
export async function generateSigningKey(): Promise<DeviceKeyPair> {
  return exportPair((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair);
}

/** A new ECDH P-256 unlock key (A3): the private half non-extractable, usage deriveBits. */
export async function generateUnlockKey(): Promise<DeviceKeyPair> {
  return exportPair((await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair);
}

function isP256Private(key: unknown, name: "ECDSA" | "ECDH", usage: string): key is CryptoKey {
  if (typeof CryptoKey === "undefined" || !(key instanceof CryptoKey)) return false;
  const algorithm = key.algorithm as unknown as { name?: unknown; namedCurve?: unknown };
  return (
    key.type === "private" &&
    key.extractable === false &&
    algorithm.name === name &&
    algorithm.namedCurve === "P-256" &&
    key.usages.length === 1 &&
    key.usages[0] === usage
  );
}

/** True for exactly what generateSigningKey makes: a non-extractable ECDSA P-256 private key for sign only. */
export function isDeviceSigningKey(key: unknown): key is CryptoKey {
  return isP256Private(key, "ECDSA", "sign");
}

/** True for exactly what generateUnlockKey makes: a non-extractable ECDH P-256 private key for deriveBits only. */
export function isDeviceUnlockKey(key: unknown): key is CryptoKey {
  return isP256Private(key, "ECDH", "deriveBits");
}

/** A7: the device's signature over a session challenge, base64url of 64 bytes. */
export async function signDeviceProof(
  signingKey: CryptoKey, // pragma: allowlist secret (a parameter type)
  ids: { mailboxId: string; deviceId: string; challengeId: string; nonce: Uint8Array },
): Promise<string> {
  if (!isDeviceSigningKey(signingKey)) throw new TypeError("a device proof is signed with the device's ECDSA P-256 signing key");
  if (!(ids.nonce instanceof Uint8Array) || ids.nonce.length !== 32) throw new TypeError("a challenge nonce is exactly 32 bytes");
  const message = context("device-proof", ids.mailboxId, ids.deviceId, ids.challengeId, base64url(ids.nonce));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signingKey, message));
  if (signature.length !== SIGNATURE_BYTES) throw new Error("internal: an ECDSA P-256 signature in IEEE P1363 form is 64 bytes");
  return base64url(signature);
}
