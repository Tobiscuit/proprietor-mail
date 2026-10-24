/**
 * The two formats of contracts/device-v1.md that the Mail Worker uses: A6,
 * sealing a challenge (round 3: "factor" and "key" challenges bound to an
 * action digest), and A7, verifying a kept device's signature over one.
 * Mail proves nothing to the browser with these; it learns from the browser
 * that it holds the mailbox key now (a key proof), that the person just used
 * a factor (a factor proof), and that a call comes from a device it knows (a
 * device proof). The browser's halves, opening a challenge and signing a
 * proof, are elsewhere in this package.
 *
 * Mail never learns a private key from either: it seals to a public key and
 * keeps only the hash of the answer (A6), and it verifies with a public key
 * (A7).
 */
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { base64url, concat, copy, fromBase64url, randomBytes, utf8 } from "./bytes";
import { context } from "./envelope";

/**
 * HPKE base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM: the
 * suite of envelope v1's key envelope, under an `info` nothing else uses (K4).
 */
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

/** A6's `info`. A ciphertext made under any other info does not open as a challenge, and a challenge opens as nothing else. */
export const CHALLENGE_INFO = utf8("proprietor-mail/v1/challenge");
export const CHALLENGE_ANSWER_BYTES = 32;
/** enc (32) || ct (the 32-byte answer + the 16-byte tag). */
export const SEALED_CHALLENGE_BYTES = 80;
export const CHALLENGE_NONCE_BYTES = 32;
/** A raw uncompressed P-256 point: 0x04 || X || Y (A3). */
export const P256_POINT_BYTES = 65;
/** ECDSA P-256 in IEEE P1363 form, r || s (A7): what Web Crypto signs and verifies. */
export const DEVICE_PROOF_BYTES = 64;

/** "session" and "key" are key proofs (sealed to the active mailbox key), "factor" a factor proof (round 3 adds "key"). */
export type ChallengePurpose = "session" | "factor" | "key";

const ACTION_DIGEST = /^[A-Za-z0-9_-]{43}$/;

const X25519: { name: string } = { name: "X25519" };
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" };

/**
 * A6: a fresh 32-byte answer sealed to `target`, the active mailbox public
 * key (purposes "session" and "key", targetId its keyId) or a factor key
 * (purpose "factor", targetId the factor id), with
 *
 *   aad = ctx("challenge", mailboxId, challengeId, purpose, targetId)                 for "session"
 *       | ctx("challenge", mailboxId, challengeId, purpose, targetId, actionDigest)   for "factor" and "key"
 *
 * Round 3 (D36): `actionDigest` is the digest of the challenge's action
 * descriptor (A10: base64url of SHA-256 over its bytes, 43 characters), so
 * the browser opens, and answers, only the challenge of the action it is
 * about to send. It is required for "factor" and "key" and refused for
 * "session". Returns the 80 sealed bytes as base64url, and the answer, which
 * the caller hashes and forgets.
 */
export async function sealChallenge(
  target: { publicKey: Uint8Array },
  ids: { mailboxId: string; challengeId: string; purpose: ChallengePurpose; targetId: string; actionDigest?: string },
): Promise<{ sealed: string; answer: Uint8Array }> {
  const publicKey = target?.publicKey;
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new TypeError("a challenge is sealed to an X25519 public key of exactly 32 bytes");
  }
  if (ids.purpose !== "session" && ids.purpose !== "factor" && ids.purpose !== "key") throw new TypeError('a challenge\'s purpose is "session", "factor" or "key"');
  let aad: Uint8Array<ArrayBuffer>;
  if (ids.purpose === "session") {
    if (ids.actionDigest !== undefined) throw new TypeError("a session challenge carries no action digest");
    aad = context("challenge", ids.mailboxId, ids.challengeId, ids.purpose, ids.targetId);
  } else {
    const digest = ids.actionDigest as unknown;
    if (typeof digest !== "string" || !ACTION_DIGEST.test(digest) || fromBase64url(digest)?.length !== 32) {
      throw new TypeError(`a ${ids.purpose} challenge carries its action digest: base64url (no padding) of 32 bytes`);
    }
    aad = context("challenge", ids.mailboxId, ids.challengeId, ids.purpose, ids.targetId, digest);
  }
  const recipientPublicKey = await crypto.subtle.importKey("raw", copy(publicKey), X25519, true, []);
  const answer = randomBytes(CHALLENGE_ANSWER_BYTES);
  // A target whose agreement is all zeros (a low-order point) makes the KEM throw: nothing is sealed to it.
  const { enc, ct } = await suite.seal({ recipientPublicKey, info: CHALLENGE_INFO }, copy(answer), aad);
  const sealed = concat(new Uint8Array(enc), new Uint8Array(ct));
  if (sealed.length !== SEALED_CHALLENGE_BYTES) throw new Error("internal: a sealed challenge must be 80 bytes");
  return { sealed: base64url(sealed), answer };
}

/**
 * A7: true when `signature` is the device's ECDSA P-256 / SHA-256 signature,
 * in P1363 form, over ctx("device-proof", mailboxId, deviceId, challengeId,
 * b64u(nonce)). Anything that is not such a signature, whatever its length or
 * encoding, is false. A signing key that is not a 65-byte uncompressed P-256
 * point on the curve, a nonce that is not 32 bytes, or ids that ctx() refuses
 * throw TypeError: those come from the caller's own records, never from the
 * device.
 */
export async function verifyDeviceProof(
  signingKey: Uint8Array, // pragma: allowlist secret (a type annotation: a public P-256 point)
  ids: { mailboxId: string; deviceId: string; challengeId: string; nonce: Uint8Array },
  signature: Uint8Array,
): Promise<boolean> {
  if (!(signingKey instanceof Uint8Array) || signingKey.length !== P256_POINT_BYTES || signingKey[0] !== 0x04) {
    throw new TypeError("a device signing key is a 65-byte uncompressed P-256 point");
  }
  if (!(ids.nonce instanceof Uint8Array) || ids.nonce.length !== CHALLENGE_NONCE_BYTES) throw new TypeError("a challenge nonce is 32 bytes");
  const message = context("device-proof", ids.mailboxId, ids.deviceId, ids.challengeId, base64url(ids.nonce));
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", copy(signingKey), ECDSA_P256, false, ["verify"]);
  } catch {
    throw new TypeError("a device signing key must be a point on P-256");
  }
  if (!(signature instanceof Uint8Array) || signature.length !== DEVICE_PROOF_BYTES) return false;
  return crypto.subtle.verify(ECDSA_SHA256, key, copy(signature), message);
}
