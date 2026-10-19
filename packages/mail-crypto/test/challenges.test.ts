// D1a, contracts/device-v1.md A6 (opening challenges) and Part C K4 (only challenges are answered).
// A challenge is HPKE base mode, DHKEM(X25519) / HKDF-SHA256 / AES-256-GCM, with its own info
// "proprietor-mail/v1/challenge" and aad ctx("challenge", mailboxId, challengeId, purpose, targetId),
// over a 32-byte answer: enc (32) || ct (48) = 80 bytes. The sealer is Mail's (src/proofs.ts, slice
// D2); the one here is written from the contract, for the test only.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  deriveFactorKey,
  factorPublicKey,
  generateMailboxKey,
  newId,
  openChallenge,
  openKeySeal,
  sealDraft,
  sealKey,
  sealMessage,
  wrapPrivateKey,
} from "../src/index";
import { materialOf } from "../src/keys";
import { draft, smallHeader, smallRaw } from "./fixtures";
import { b64urlDecode, b64urlEncode, flipBit, hex, utf8 } from "./reference";

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });
const mailboxId = newId("mbx");
const mailbox = await generateMailboxKey();
const factorId = newId("wrp");
const factor = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (random test value)

/** A6's sealer, written from the contract for this test (Mail's is sealChallenge in src/proofs.ts). */
async function referenceSeal(
  publicKey: Uint8Array,
  ids: { mailboxId: string; challengeId: string; purpose: string; targetId: string },
  answer: Uint8Array<ArrayBuffer> = crypto.getRandomValues(new Uint8Array(32)),
): Promise<{ sealed: string; answer: Uint8Array }> {
  const recipientPublicKey = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), { name: "X25519" }, true, []);
  const aad = utf8(`proprietor-mail/v1/challenge|${ids.mailboxId}|${ids.challengeId}|${ids.purpose}|${ids.targetId}`);
  const { enc, ct } = await suite.seal({ recipientPublicKey, info: utf8("proprietor-mail/v1/challenge") }, answer, aad);
  return { sealed: b64urlEncode(new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)])), answer };
}

const sessionChallenge = (challengeId = newId("chl")) =>
  referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "session", targetId: mailbox.publicKey.keyId });
const factorChallenge = (challengeId = newId("chl")) => referenceSeal(factorPublicKey(factor), { mailboxId, challengeId, purpose: "factor", targetId: factorId });

describe("A6 openChallenge", () => {
  test("purpose session: the mailbox key opens a challenge sealed to its public key, targetId = its keyId, and gives the 32-byte answer", async () => {
    const challengeId = newId("chl");
    const { sealed, answer } = await sessionChallenge(challengeId);
    expect(b64urlDecode(sealed).length).toBe(80);
    expect(hex(await openChallenge(mailbox.privateKey, { mailboxId, challengeId }, sealed))).toBe(hex(answer));
  });

  test("purpose factor: the factor key opens a challenge sealed to pkF, targetId = the factor id", async () => {
    const challengeId = newId("chl");
    const { sealed, answer } = await factorChallenge(challengeId);
    expect(hex(await openChallenge(factor, { mailboxId, challengeId }, sealed))).toBe(hex(answer));
  });

  test("a decrypt-only mailbox key answers too (a session never holds anything else)", async () => {
    const wrapId = newId("wrp");
    const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)
    const { unwrapPrivateKey } = await import("../src/index");
    const wrap = await wrapPrivateKey(mailbox.privateKey, { mailboxId, wrapId, kind: "recovery", secret });
    const decryptOnly = await unwrapPrivateKey(wrap, { mailboxId, secret });
    expect(materialOf(decryptOnly).wrappable).toBe(false);
    const challengeId = newId("chl");
    const { sealed, answer } = await sessionChallenge(challengeId);
    expect(hex(await openChallenge(decryptOnly, { mailboxId, challengeId }, sealed))).toBe(hex(answer));
  });

  test("bound to its mailbox, its id, its purpose and its target", async () => {
    const challengeId = newId("chl");
    const other = await generateMailboxKey();
    const cases = [
      // the right key, another challenge id or mailbox
      [mailbox.privateKey, { mailboxId, challengeId: newId("chl") }, (await sessionChallenge(challengeId)).sealed],
      [mailbox.privateKey, { mailboxId: newId("mbx"), challengeId }, (await sessionChallenge(challengeId)).sealed],
      // a factor challenge offered to the mailbox key, and a session challenge offered to the factor key
      [mailbox.privateKey, { mailboxId, challengeId }, (await factorChallenge(challengeId)).sealed],
      [factor, { mailboxId, challengeId }, (await sessionChallenge(challengeId)).sealed],
      // sealed to the right key, but naming another purpose or target in its associated data
      [mailbox.privateKey, { mailboxId, challengeId }, (await referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "factor", targetId: mailbox.publicKey.keyId })).sealed],
      [mailbox.privateKey, { mailboxId, challengeId }, (await referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "session", targetId: other.publicKey.keyId })).sealed],
      [factor, { mailboxId, challengeId }, (await referenceSeal(factorPublicKey(factor), { mailboxId, challengeId, purpose: "factor", targetId: newId("wrp") })).sealed],
      // another key
      [other.privateKey, { mailboxId, challengeId }, (await sessionChallenge(challengeId)).sealed],
    ] as const;
    for (const [key, ids, sealed] of cases) await expect(openChallenge(key, ids, sealed)).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("an answer that is not 32 bytes, another length, a flipped bit, or text that is not base64url: DecryptionFailed", async () => {
    const challengeId = newId("chl");
    const short = await referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "session", targetId: mailbox.publicKey.keyId }, crypto.getRandomValues(new Uint8Array(31)));
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId }, short.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    const bytes = b64urlDecode((await sessionChallenge(challengeId)).sealed);
    const variants = [bytes.subarray(0, 79), new Uint8Array([...bytes, 0])];
    for (let i = 0; i < bytes.length; i += 3) variants.push(flipBit(bytes, i, i % 8));
    for (const v of variants) await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId }, b64urlEncode(v))).rejects.toBeInstanceOf(DecryptionFailed);
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId }, "*")).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("caller mistakes are TypeErrors: a key that is neither a mailbox key nor a factor key, an id holding the separator", async () => {
    const { sealed } = await sessionChallenge();
    await expect(openChallenge({ keyId: mailbox.publicKey.keyId } as never, { mailboxId, challengeId: newId("chl") }, sealed)).rejects.toBeInstanceOf(TypeError);
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId: "chl_x|y" }, sealed)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("K4: nothing but a challenge is answered (no decryption oracle)", () => {
  test("a message's key envelope (envelope v1, the same suite and length) fails to open as a challenge", async () => {
    const messageId = newId("msg");
    const sealed = await sealMessage(mailbox.publicKey, { mailboxId, messageId }, smallHeader, smallRaw);
    expect(b64urlDecode(sealed.keyEnvelope).length).toBe(80);
    // Even with the message id passed as the challenge id, the info differs, so the key schedule does.
    for (const challengeId of [messageId, newId("chl")]) {
      await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId }, sealed.keyEnvelope)).rejects.toBeInstanceOf(DecryptionFailed);
    }
  });

  test("a draft's key envelope, a wrap and a key seal each fail to open as a challenge", async () => {
    const draftId = newId("drf");
    const sealedDraft = await sealDraft(mailbox.publicKey, { mailboxId, draftId }, draft);
    const wrap = await wrapPrivateKey(mailbox.privateKey, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (random test value)
    const seal = await sealKey(mailbox.privateKey, { mailboxId }, { kind: "factor", factorId, publicKey: factorPublicKey(factor) });
    for (const [key, sealed] of [
      [mailbox.privateKey, sealedDraft.keyEnvelope],
      [mailbox.privateKey, wrap.wrapped],
      [factor, seal],
    ] as const) {
      await expect(openChallenge(key, { mailboxId, challengeId: newId("chl") }, sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    }
  });

  test("a challenge fails to open as a key seal", async () => {
    const { sealed } = await factorChallenge();
    await expect(openKeySeal({ kind: "factor", key: factor }, { mailboxId, sealedKeyId: mailbox.publicKey.keyId }, sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    const successorChallenge = await sessionChallenge();
    await expect(openKeySeal({ kind: "successor", key: mailbox.privateKey }, { mailboxId, sealedKeyId: (await generateMailboxKey()).publicKey.keyId }, successorChallenge.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
  });
});
