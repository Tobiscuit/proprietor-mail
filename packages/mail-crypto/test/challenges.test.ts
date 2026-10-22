// D1a, contracts/device-v1.md A6 (opening challenges) and Part C K4 (only challenges are answered).
// A challenge is HPKE base mode, DHKEM(X25519) / HKDF-SHA256 / AES-256-GCM, with its own info
// "proprietor-mail/v1/challenge" and aad ctx("challenge", mailboxId, challengeId, purpose, targetId)
// for purpose "session", or ctx("challenge", mailboxId, challengeId, purpose, targetId, actionDigest)
// for "factor" and "key" (round 3, D36: the digest of the challenge's action descriptor, A10), over
// a 32-byte answer: enc (32) || ct (48) = 80 bytes. The sealer is Mail's (src/proofs.ts, slice D2);
// the one here is written from the contract, for the test only.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { describe, expect, test } from "vitest";
import {
  actionDescriptorFor,
  actionDigest,
  buildActionDescriptor,
  DecryptionFailed,
  deriveFactorKey,
  factorPublicKey,
  generateMailboxKey,
  newId,
  openChallenge,
  openKeySeal,
  requestDigest,
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
  ids: { mailboxId: string; challengeId: string; purpose: string; targetId: string; actionDigest?: string },
  answer: Uint8Array<ArrayBuffer> = crypto.getRandomValues(new Uint8Array(32)),
): Promise<{ sealed: string; answer: Uint8Array }> {
  const recipientPublicKey = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), { name: "X25519" }, true, []);
  const digest = ids.actionDigest === undefined ? "" : `|${ids.actionDigest}`;
  const aad = utf8(`proprietor-mail/v1/challenge|${ids.mailboxId}|${ids.challengeId}|${ids.purpose}|${ids.targetId}${digest}`);
  const { enc, ct } = await suite.seal({ recipientPublicKey, info: utf8("proprietor-mail/v1/challenge") }, answer, aad);
  return { sealed: b64urlEncode(new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)])), answer };
}

/** A descriptor's digest, as Mail issues it with a challenge (A10), for an action of this mailbox. */
async function digestOf(kind: "open-session" | "add-factor" | "upgrade", request: Record<string, unknown>): Promise<string> {
  const nonce = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const descriptor = actionDescriptorFor({ kind, request: await requestDigest(request) }, { mailboxId, nonce, issuedAt: 1792627200 });
  return actionDigest(buildActionDescriptor(descriptor));
}
const digest = await digestOf("open-session", { challengeId: newId("chl") });
const otherDigest = await digestOf("open-session", { challengeId: newId("chl") });
const keyDigest = await digestOf("upgrade", { factors: [] });

const sessionChallenge = (challengeId = newId("chl")) =>
  referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "session", targetId: mailbox.publicKey.keyId });
const factorChallenge = (challengeId = newId("chl"), actionDigest = digest) =>
  referenceSeal(factorPublicKey(factor), { mailboxId, challengeId, purpose: "factor", targetId: factorId, actionDigest });
const keyChallenge = (challengeId = newId("chl"), actionDigest = keyDigest) =>
  referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "key", targetId: mailbox.publicKey.keyId, actionDigest });

describe("A6 openChallenge", () => {
  test("purpose session: the mailbox key opens a challenge sealed to its public key, targetId = its keyId, and gives the 32-byte answer", async () => {
    const challengeId = newId("chl");
    const { sealed, answer } = await sessionChallenge(challengeId);
    expect(b64urlDecode(sealed).length).toBe(80);
    expect(hex(await openChallenge(mailbox.privateKey, { mailboxId, challengeId }, sealed))).toBe(hex(answer));
  });

  test("purpose factor: the factor key opens a challenge sealed to pkF, targetId = the factor id, with its action's digest", async () => {
    const challengeId = newId("chl");
    const { sealed, answer } = await factorChallenge(challengeId);
    expect(hex(await openChallenge(factor, { mailboxId, challengeId, actionDigest: digest }, sealed))).toBe(hex(answer));
  });

  test("purpose key (round 3): the mailbox key opens a challenge sealed to its public key with the upgrade's digest", async () => {
    const challengeId = newId("chl");
    const { sealed, answer } = await keyChallenge(challengeId);
    expect(hex(await openChallenge(mailbox.privateKey, { mailboxId, challengeId, actionDigest: keyDigest }, sealed))).toBe(hex(answer));
  });

  test("K4 (round 3): a factor or key challenge issued for another action does not open, so nothing is answered", async () => {
    const challengeId = newId("chl");
    const forFactor = await factorChallenge(challengeId);
    await expect(openChallenge(factor, { mailboxId, challengeId, actionDigest: otherDigest }, forFactor.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    await expect(openChallenge(factor, { mailboxId, challengeId, actionDigest: keyDigest }, forFactor.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    const forKey = await keyChallenge(challengeId);
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId, actionDigest: digest }, forKey.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    // A digest that differs in one character of its base64url is another action.
    const oneOff = `${keyDigest.slice(0, 10)}${keyDigest[10] === "A" ? "B" : "A"}${keyDigest.slice(11)}`;
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId, actionDigest: oneOff }, forKey.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("purposes stay apart: a key challenge is not a session challenge, and the reverse", async () => {
    const challengeId = newId("chl");
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId }, (await keyChallenge(challengeId)).sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId, actionDigest: keyDigest }, (await sessionChallenge(challengeId)).sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    // A key challenge's associated data under purpose "factor", or a factor challenge's under "key", does not open either.
    const asFactor = await referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "factor", targetId: mailbox.publicKey.keyId, actionDigest: keyDigest });
    await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId, actionDigest: keyDigest }, asFactor.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    const asKey = await referenceSeal(factorPublicKey(factor), { mailboxId, challengeId, purpose: "key", targetId: factorId, actionDigest: digest });
    await expect(openChallenge(factor, { mailboxId, challengeId, actionDigest: digest }, asKey.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("a factor challenge is never opened without its action: no digest, or one that is not 43 base64url characters of 32 bytes, is a TypeError", async () => {
    const challengeId = newId("chl");
    const { sealed } = await factorChallenge(challengeId);
    await expect(openChallenge(factor, { mailboxId, challengeId }, sealed)).rejects.toBeInstanceOf(TypeError);
    for (const bad of ["", digest.slice(0, 42), `${digest}A`, `${digest.slice(0, 42)}+`, `${digest.slice(0, 42)}=`, 7 as unknown as string]) {
      await expect(openChallenge(factor, { mailboxId, challengeId, actionDigest: bad }, sealed)).rejects.toBeInstanceOf(TypeError);
      await expect(openChallenge(mailbox.privateKey, { mailboxId, challengeId, actionDigest: bad }, sealed)).rejects.toBeInstanceOf(TypeError);
    }
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
      [mailbox.privateKey, { mailboxId, challengeId, actionDigest: digest }, (await factorChallenge(challengeId)).sealed],
      [factor, { mailboxId, challengeId, actionDigest: digest }, (await sessionChallenge(challengeId)).sealed],
      // the right factor key and digest, another challenge id or mailbox
      [factor, { mailboxId, challengeId: newId("chl"), actionDigest: digest }, (await factorChallenge(challengeId)).sealed],
      [factor, { mailboxId: newId("mbx"), challengeId, actionDigest: digest }, (await factorChallenge(challengeId)).sealed],
      // sealed to the right key, but naming another purpose or target in its associated data
      [mailbox.privateKey, { mailboxId, challengeId }, (await referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "factor", targetId: mailbox.publicKey.keyId })).sealed],
      [mailbox.privateKey, { mailboxId, challengeId }, (await referenceSeal(mailbox.publicKey.publicKey, { mailboxId, challengeId, purpose: "session", targetId: other.publicKey.keyId })).sealed],
      [factor, { mailboxId, challengeId, actionDigest: digest }, (await referenceSeal(factorPublicKey(factor), { mailboxId, challengeId, purpose: "factor", targetId: newId("wrp"), actionDigest: digest })).sealed],
      // a factor challenge sealed with the round 2 associated data (no digest) does not open with one
      [factor, { mailboxId, challengeId, actionDigest: digest }, (await referenceSeal(factorPublicKey(factor), { mailboxId, challengeId, purpose: "factor", targetId: factorId })).sealed],
      // another key
      [other.privateKey, { mailboxId, challengeId }, (await sessionChallenge(challengeId)).sealed],
    ] as const;
    for (const [key, ids, sealed] of cases) await expect(openChallenge(key, ids as { mailboxId: string; challengeId: string; actionDigest?: string }, sealed)).rejects.toBeInstanceOf(DecryptionFailed);
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
    for (const [key, sealed, actionDigest] of [
      [mailbox.privateKey, sealedDraft.keyEnvelope, undefined],
      [mailbox.privateKey, wrap.wrapped, undefined],
      [mailbox.privateKey, sealedDraft.keyEnvelope, keyDigest],
      [factor, seal, digest],
    ] as const) {
      await expect(openChallenge(key, { mailboxId, challengeId: newId("chl"), ...(actionDigest === undefined ? {} : { actionDigest }) }, sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    }
  });

  test("a challenge fails to open as a key seal", async () => {
    const { sealed } = await factorChallenge();
    await expect(openKeySeal({ kind: "factor", key: factor }, { mailboxId, sealedKeyId: mailbox.publicKey.keyId }, sealed)).rejects.toBeInstanceOf(DecryptionFailed);
    const successorChallenge = await sessionChallenge();
    await expect(openKeySeal({ kind: "successor", key: mailbox.privateKey }, { mailboxId, sealedKeyId: (await generateMailboxKey()).publicKey.keyId }, successorChallenge.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
  });
});
