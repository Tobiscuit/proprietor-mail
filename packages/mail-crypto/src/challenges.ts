/**
 * Opening challenges (contracts/device-v1.md A6), the browser's half. Mail
 * seals a 32-byte answer to the active mailbox key (purpose "session", a key
 * proof; purpose "key", a key proof bound to the upgrade) or to a factor key
 * (purpose "factor", a factor proof):
 *
 *   sealed = enc || ct = HPKE base mode Seal(pkR = target, info = UTF-8("proprietor-mail/v1/challenge"),
 *            aad, pt = answer)
 *            DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM: 32 + 48 = 80 bytes
 *   aad    = ctx("challenge", mailboxId, challengeId, purpose, targetId)                for "session"
 *          | ctx("challenge", mailboxId, challengeId, purpose, targetId, actionDigest)  for "factor" and "key"
 *
 * Round 3 (D36, K4): actionDigest is the digest of the challenge's action
 * descriptor (A10). The caller builds the descriptor it expects for the
 * request it is about to send, compares it with Mail's bytes, and passes
 * ITS OWN digest here; a challenge issued for another action does not open,
 * so nothing is answered. A factor key never opens a challenge without a
 * digest. The mailbox key opens purpose "key" when given a digest, and
 * purpose "session" when not.
 *
 * K4, no decryption oracle: a challenge opens only under its own info, which
 * nothing else uses, so a message's key envelope (the same suite and length,
 * info "proprietor-mail/v1/message-key"), a draft's, a wrap or a seal never
 * opens here, and the browser answers nothing. The purpose and the target
 * come from the key itself: a mailbox key answers only session challenges
 * for its own keyId, a factor key only factor challenges for its own id.
 * Mail's sealer is src/proofs.ts.
 */
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { fromBase64url, utf8 } from "./bytes";
import { context } from "./envelope";
import { DecryptionFailed } from "./errors";
import { factorMaterialOf, isFactorKey, type FactorPrivateKey } from "./factor-keys";
import type { MailboxPrivateKey } from "./index";
import { materialOf } from "./keys";

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
const CHALLENGE_INFO = utf8("proprietor-mail/v1/challenge");
const ENC_BYTES = 32;
const ANSWER_BYTES = 32;

/** A challenge's length: enc (32) || ct (32 + 16). */
export const CHALLENGE_BYTES = ENC_BYTES + ANSWER_BYTES + 16;

const ACTION_DIGEST = /^[A-Za-z0-9_-]{43}$/;

/** An action digest (A10): 43 base64url characters of a 32-byte SHA-256; a TypeError for anything else. */
function actionDigestOf(value: unknown): string {
  if (typeof value !== "string" || !ACTION_DIGEST.test(value) || fromBase64url(value)?.length !== 32) {
    throw new TypeError("an action digest is base64url (no padding) of 32 bytes: actionDigest() of the descriptor's bytes");
  }
  return value;
}

/**
 * The answer to a challenge: with the mailbox key for purpose "session"
 * (targetId = its keyId, no digest) or "key" (its keyId, with the digest of
 * the action it confirms, kind upgrade), with a factor key for purpose
 * "factor" (targetId = the factor id, with its action's digest, required).
 * Any failure of the bytes is DecryptionFailed; a caller's mistake (a key
 * that is neither handle, a factor key without a digest, a malformed digest)
 * is a TypeError.
 */
export async function openChallenge(
  key: MailboxPrivateKey | FactorPrivateKey,
  ids: { mailboxId: string; challengeId: string; actionDigest?: string },
  sealed: string,
): Promise<Uint8Array<ArrayBuffer>> {
  let recipientKey: CryptoKeyPair;
  let purpose: "session" | "factor" | "key";
  let targetId: string;
  const digest = ids.actionDigest === undefined ? null : actionDigestOf(ids.actionDigest);
  if (isFactorKey(key)) {
    if (digest === null) throw new TypeError("a factor challenge is opened only with the digest of the action it confirms (K4)");
    recipientKey = factorMaterialOf(key).keyPair;
    purpose = "factor";
    targetId = key.factorId;
  } else {
    const material = materialOf(key as MailboxPrivateKey); // TypeError for anything that is neither handle
    recipientKey = material.keyPair;
    purpose = digest === null ? "session" : "key";
    targetId = material.keyId;
  }
  const aad =
    digest === null
      ? context("challenge", ids.mailboxId, ids.challengeId, purpose, targetId)
      : context("challenge", ids.mailboxId, ids.challengeId, purpose, targetId, digest);
  const bytes = fromBase64url(sealed);
  if (bytes === null || bytes.length !== CHALLENGE_BYTES) throw new DecryptionFailed();
  let answer: Uint8Array<ArrayBuffer>;
  try {
    answer = new Uint8Array(await suite.open({ recipientKey, enc: bytes.slice(0, ENC_BYTES), info: CHALLENGE_INFO }, bytes.slice(ENC_BYTES), aad));
  } catch {
    throw new DecryptionFailed();
  }
  if (answer.length !== ANSWER_BYTES) {
    answer.fill(0);
    throw new DecryptionFailed();
  }
  return answer;
}
