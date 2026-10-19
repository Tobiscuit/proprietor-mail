/**
 * Opening challenges (contracts/device-v1.md A6), the browser's half. Mail
 * seals a 32-byte answer to the active mailbox key (purpose "session", a key
 * proof) or to a factor key (purpose "factor", a factor proof):
 *
 *   sealed = enc || ct = HPKE base mode Seal(pkR = target, info = UTF-8("proprietor-mail/v1/challenge"),
 *            aad = ctx("challenge", mailboxId, challengeId, purpose, targetId), pt = answer)
 *            DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM: 32 + 48 = 80 bytes
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

/**
 * The answer to a challenge: with the mailbox key for purpose "session"
 * (targetId = its keyId), with a factor key for purpose "factor" (targetId =
 * the factor id). Any failure of the bytes is DecryptionFailed.
 */
export async function openChallenge(
  key: MailboxPrivateKey | FactorPrivateKey,
  ids: { mailboxId: string; challengeId: string },
  sealed: string,
): Promise<Uint8Array<ArrayBuffer>> {
  let recipientKey: CryptoKeyPair;
  let purpose: "session" | "factor";
  let targetId: string;
  if (isFactorKey(key)) {
    recipientKey = factorMaterialOf(key).keyPair;
    purpose = "factor";
    targetId = key.factorId;
  } else {
    const material = materialOf(key as MailboxPrivateKey); // TypeError for anything that is neither handle
    recipientKey = material.keyPair;
    purpose = "session";
    targetId = material.keyId;
  }
  const aad = context("challenge", ids.mailboxId, ids.challengeId, purpose, targetId);
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
