// D1a, contracts/device-v1.md A4: key seals. HPKE base mode with the export-only AEAD; the
// exported secret is an AES-256-GCM key that wrapKey/unwrapKey use on the key's PKCS #8 form, so
// the mailbox private key never exists as bytes in JavaScript. bytes = 0x01 || enc || iv || ct:
// 109 bytes to an X25519 recipient (factor, successor), 142 to a P-256 one (device).
import { CipherSuite, DhkemP256HkdfSha256, DhkemX25519HkdfSha256, ExportOnly, HkdfSha256 } from "@hpke/core";
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  deriveFactorKey,
  factorPublicKey,
  generateMailboxKey,
  generateUnlockKey,
  newId,
  openHeader,
  openKeySeal,
  sealKey,
  sealMessage,
  type MailboxPrivateKey,
} from "../src/index";
import { importPrivateScalar, materialOf } from "../src/keys";
import { openSealWith, sealWith } from "../src/seals";
import { smallHeader, smallRaw } from "./fixtures";
import { b64urlDecode, b64urlEncode, flipBit, hex, utf8 } from "./reference";

const mailboxId = newId("mbx");
const PKCS8_PREFIX = "302e020100300506032b656e04220420";
const x25519Suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new ExportOnly() });
const p256Suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new ExportOnly() });
const info = (sealedKeyId: string, toKind: string, toId: string) => utf8(`proprietor-mail/v1/key-seal|${mailboxId}|${sealedKeyId}|${toKind}|${toId}`);

/** A wrappable mailbox key with a known scalar, so the reference reading can compare plaintexts. */
async function knownKey(): Promise<{ priv: MailboxPrivateKey; scalarHex: string }> {
  const scalar = crypto.getRandomValues(new Uint8Array(32));
  scalar[0] = scalar[0]! & 248;
  scalar[31] = (scalar[31]! & 127) | 64;
  const scalarHex = hex(scalar);
  return { priv: await importPrivateScalar(scalar, { wrappable: true }), scalarHex };
}

/** A4 read straight from the contract: SetupBaseR, Export, then AES-GCM decrypt (not unwrapKey) to see the PKCS #8 bytes. */
async function referenceOpen(suite: CipherSuite, recipientKey: CryptoKeyPair, encBytes: number, aad: Uint8Array<ArrayBuffer>, sealed: string): Promise<string> {
  const bytes = b64urlDecode(sealed);
  expect(bytes[0]).toBe(0x01);
  expect(bytes.length).toBe(1 + encBytes + 12 + 64);
  const ctx = await suite.createRecipientContext({ recipientKey, enc: bytes.slice(1, 1 + encBytes), info: aad });
  const kek = await crypto.subtle.importKey("raw", await ctx.export(utf8("proprietor-mail/v1/key-seal/kek"), 32), "AES-GCM", false, ["decrypt"]);
  const iv = bytes.slice(1 + encBytes, 13 + encBytes);
  return hex(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: aad }, kek, bytes.slice(13 + encBytes))));
}

async function unlockPair() {
  const unlock = await generateUnlockKey();
  const publicCryptoKey = await crypto.subtle.importKey("raw", unlock.publicKey, { name: "ECDH", namedCurve: "P-256" }, true, []);
  return { unlock, pair: { privateKey: unlock.privateKey, publicKey: publicCryptoKey } as CryptoKeyPair };
}

async function opensMail(priv: MailboxPrivateKey, sealedTo: MailboxPrivateKey): Promise<boolean> {
  const { keyId, publicKey } = materialOf(sealedTo);
  const ids = { mailboxId, messageId: newId("msg") };
  const sealed = await sealMessage({ keyId, publicKey }, ids, smallHeader, smallRaw);
  return (await openHeader(priv, ids, sealed)).subject === smallHeader.subject;
}

describe("A4 the bytes, read from the contract", () => {
  test("to a device: 142 bytes, DHKEM(P-256), the PKCS #8 PrivateKeyInfo of the sealed key under the exported KEK", async () => {
    const { priv, scalarHex } = await knownKey();
    const { unlock, pair } = await unlockPair();
    const deviceId = newId("dev");
    const sealed = await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
    expect(b64urlDecode(sealed).length).toBe(142);
    expect(await referenceOpen(p256Suite, pair, 65, info(priv.keyId, "device", deviceId), sealed)).toBe(PKCS8_PREFIX + scalarHex);
  });

  test("to a factor: 109 bytes, DHKEM(X25519)", async () => {
    const { priv, scalarHex } = await knownKey();
    const factorId = newId("wrp");
    const factor = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (random test value)
    const sealed = await sealKey(priv, { mailboxId }, { kind: "factor", factorId, publicKey: factorPublicKey(factor) });
    expect(b64urlDecode(sealed).length).toBe(109);
    const { factorMaterialOf } = await import("../src/factor-keys");
    expect(await referenceOpen(x25519Suite, factorMaterialOf(factor).keyPair, 32, info(priv.keyId, "factor", factorId), sealed)).toBe(PKCS8_PREFIX + scalarHex);
  });

  test("a successor seal: 109 bytes, the retired key sealed to its successor's public key, toId = the successor's keyId", async () => {
    const { priv: retired, scalarHex } = await knownKey();
    const successor = await generateMailboxKey();
    const sealed = await sealKey(retired, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey });
    expect(b64urlDecode(sealed).length).toBe(109);
    const aad = info(retired.keyId, "successor", successor.publicKey.keyId);
    expect(await referenceOpen(x25519Suite, materialOf(successor.privateKey).keyPair, 32, aad, sealed)).toBe(PKCS8_PREFIX + scalarHex);
  });

  test("every seal uses a fresh encapsulation and IV", async () => {
    const { priv } = await knownKey();
    const successor = await generateMailboxKey();
    const to = { kind: "successor" as const, publicKey: successor.publicKey.publicKey };
    const [a, b] = [await sealKey(priv, { mailboxId }, to), await sealKey(priv, { mailboxId }, to)];
    expect(a).not.toBe(b);
    expect(hex(b64urlDecode(a).subarray(1, 33))).not.toBe(hex(b64urlDecode(b).subarray(1, 33)));
  });
});

describe("A4 openKeySeal", () => {
  test("each recipient kind opens its seal to the sealed key, which opens that key's mail", async () => {
    const { priv } = await knownKey();
    const { unlock } = await unlockPair();
    const deviceId = newId("dev");
    const factorId = newId("wrp");
    const factor = await deriveFactorKey({ mailboxId, factorId, kind: "passkey-prf", secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (random test value)
    const successor = await generateMailboxKey();
    const sealedKeyId = priv.keyId;
    const opened = [
      await openKeySeal({ kind: "device", deviceId, privateKey: unlock.privateKey, publicKey: unlock.publicKey }, { mailboxId, sealedKeyId }, await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey })), // pragma: allowlist secret (a CryptoKey reference)
      await openKeySeal({ kind: "factor", key: factor }, { mailboxId, sealedKeyId }, await sealKey(priv, { mailboxId }, { kind: "factor", factorId, publicKey: factorPublicKey(factor) })),
      await openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId }, await sealKey(priv, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey })),
    ];
    for (const key of opened) {
      expect(key.keyId).toBe(sealedKeyId);
      expect(await opensMail(key, priv)).toBe(true);
    }
  });

  test("K1′: the opened key is non-extractable unless the caller asks for `wrappable`, for the one step that seals it again", async () => {
    const { priv } = await knownKey();
    const successor = await generateMailboxKey();
    const sealed = await sealKey(priv, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey });
    const by = { kind: "successor" as const, key: successor.privateKey };
    const decryptOnly = await openKeySeal(by, { mailboxId, sealedKeyId: priv.keyId }, sealed);
    expect(materialOf(decryptOnly).keyPair.privateKey.extractable).toBe(false);
    await expect(sealKey(decryptOnly, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey })).rejects.toBeInstanceOf(TypeError);
    const wrappable = await openKeySeal(by, { mailboxId, sealedKeyId: priv.keyId }, sealed, { wrappable: true });
    expect(materialOf(wrappable).keyPair.privateKey.extractable).toBe(true);
    expect(b64urlDecode(await sealKey(wrappable, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey })).length).toBe(109);
  });

  test("a seal opens only with its own mailbox, sealed key id, recipient kind, recipient id and recipient key", async () => {
    const { priv } = await knownKey();
    const { unlock } = await unlockPair();
    const other = await unlockPair();
    const deviceId = newId("dev");
    const sealed = await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
    const by = { kind: "device" as const, deviceId, privateKey: unlock.privateKey, publicKey: unlock.publicKey }; // pragma: allowlist secret (a CryptoKey reference)
    const ids = { mailboxId, sealedKeyId: priv.keyId };
    const otherKeyId = (await generateMailboxKey()).publicKey.keyId;
    // Each attempt starts only when its rejection is awaited, so none is ever an unhandled rejection.
    const attempts = [
      () => openKeySeal(by, { mailboxId: newId("mbx"), sealedKeyId: priv.keyId }, sealed),
      () => openKeySeal(by, { mailboxId, sealedKeyId: otherKeyId }, sealed),
      () => openKeySeal({ ...by, deviceId: newId("dev") }, ids, sealed),
      () => openKeySeal({ ...by, privateKey: other.unlock.privateKey, publicKey: other.unlock.publicKey }, ids, sealed), // pragma: allowlist secret (a CryptoKey reference)
      // The right private key with another public key: the KEM context binds the recipient's public key.
      () => openKeySeal({ ...by, publicKey: other.unlock.publicKey }, ids, sealed),
    ];
    for (const attempt of attempts) await expect(attempt()).rejects.toBeInstanceOf(DecryptionFailed);
    expect((await openKeySeal(by, ids, sealed)).keyId).toBe(priv.keyId);
  });

  test("toKind is bound: a factor seal opened as a successor seal, or a successor seal as a factor seal, fails", async () => {
    const { priv } = await knownKey();
    const successor = await generateMailboxKey();
    const pair = materialOf(successor.privateKey).keyPair;
    const toId = successor.publicKey.keyId;
    const asSuccessor = await sealKey(priv, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey });
    await expect(openSealWith("x25519", pair, info(priv.keyId, "factor", toId), b64urlDecode(asSuccessor), false)).rejects.toBeInstanceOf(DecryptionFailed);
    const asFactor = b64urlEncode(await sealWith("x25519", pair.publicKey, info(priv.keyId, "factor", toId), materialOf(priv).keyPair.privateKey));
    await expect(openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId: priv.keyId }, asFactor)).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("a seal whose content is another key than the one it names is refused (anyone can seal to a public key)", async () => {
    const named = await generateMailboxKey();
    const { priv: actual } = await knownKey();
    const successor = await generateMailboxKey();
    const pair = materialOf(successor.privateKey).keyPair;
    // Made the way a server could: the right info for `named`, but `actual` inside.
    const forged = b64urlEncode(await sealWith("x25519", pair.publicKey, info(named.publicKey.keyId, "successor", successor.publicKey.keyId), materialOf(actual).keyPair.privateKey));
    await expect(openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId: named.publicKey.keyId }, forged)).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("another length, another lead byte, a flipped bit anywhere, or text that is not base64url: DecryptionFailed", async () => {
    const { priv } = await knownKey();
    const successor = await generateMailboxKey();
    const by = { kind: "successor" as const, key: successor.privateKey };
    const ids = { mailboxId, sealedKeyId: priv.keyId };
    const bytes = b64urlDecode(await sealKey(priv, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey }));
    const variants = [bytes.subarray(0, 108), new Uint8Array([...bytes, 0]), new Uint8Array([0x02, ...bytes.subarray(1)])];
    for (let i = 0; i < bytes.length; i += 3) variants.push(flipBit(bytes, i, i % 8));
    for (const v of variants) await expect(openKeySeal(by, ids, b64urlEncode(v))).rejects.toBeInstanceOf(DecryptionFailed);
    await expect(openKeySeal(by, ids, "not base64url!")).rejects.toBeInstanceOf(DecryptionFailed);
    await expect(openKeySeal(by, ids, "")).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("a device seal is refused at an X25519 length, and an X25519 seal at the device length", async () => {
    const { priv } = await knownKey();
    const { unlock } = await unlockPair();
    const deviceId = newId("dev");
    const successor = await generateMailboxKey();
    const deviceSeal = b64urlDecode(await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey }));
    const successorSeal = b64urlDecode(await sealKey(priv, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey }));
    await expect(openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId: priv.keyId }, b64urlEncode(deviceSeal.subarray(0, 109)))).rejects.toBeInstanceOf(DecryptionFailed);
    const padded = new Uint8Array(142);
    padded.set(successorSeal);
    await expect(openKeySeal({ kind: "device", deviceId, privateKey: unlock.privateKey, publicKey: unlock.publicKey }, { mailboxId, sealedKeyId: priv.keyId }, b64urlEncode(padded))).rejects.toBeInstanceOf(DecryptionFailed); // pragma: allowlist secret (a CryptoKey reference)
  });
});

describe("A4 caller mistakes are TypeErrors, not DecryptionFailed", () => {
  test("sealing a decrypt-only key, to a public key of the wrong length or not on the curve, or with ids holding the separator", async () => {
    const { priv } = await knownKey();
    const { unlock } = await unlockPair();
    const deviceId = newId("dev");
    const decryptOnly = await (async () => {
      const fresh = (await generateMailboxKey()).privateKey; // wrappable: generateKey made it
      const successor = await generateMailboxKey();
      const sealed = await sealKey(fresh, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey });
      return openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId: fresh.keyId }, sealed);
    })();
    await expect(sealKey(decryptOnly, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey })).rejects.toBeInstanceOf(TypeError);
    await expect(sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey.subarray(0, 64) })).rejects.toBeInstanceOf(TypeError);
    const offCurve = new Uint8Array(unlock.publicKey);
    offCurve[64] = offCurve[64]! ^ 1;
    await expect(sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: offCurve })).rejects.toBeInstanceOf(TypeError);
    await expect(sealKey(priv, { mailboxId }, { kind: "factor", factorId: newId("wrp"), publicKey: new Uint8Array(31) })).rejects.toBeInstanceOf(TypeError);
    await expect(sealKey(priv, { mailboxId: `${mailboxId}|x` }, { kind: "device", deviceId, publicKey: unlock.publicKey })).rejects.toBeInstanceOf(TypeError);
  });

  test("opening with a key that is not a device unlock key, or naming a sealed key id that is not a keyId", async () => {
    const { priv } = await knownKey();
    const extractable = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", extractable.publicKey)) as ArrayBuffer);
    const deviceId = newId("dev");
    const sealed = await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: raw });
    await expect(openKeySeal({ kind: "device", deviceId, privateKey: extractable.privateKey, publicKey: raw }, { mailboxId, sealedKeyId: priv.keyId }, sealed)).rejects.toBeInstanceOf(TypeError); // pragma: allowlist secret (a CryptoKey reference)
    const successor = await generateMailboxKey();
    await expect(openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId: "not-a-key-id" }, sealed)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("A4 a non-extractable P-256 recipient (spec 002 §9, listed there as not verified)", () => {
  test("opens with @hpke/core 1.9.0 for every key, whichever parity its y coordinate has, because the reader passes the key pair", async () => {
    const { priv } = await knownKey();
    const parities = new Set<number>();
    for (let i = 0; i < 24; i++) {
      const { unlock } = await unlockPair();
      parities.add(unlock.publicKey[64]! & 1);
      const deviceId = newId("dev");
      const sealed = await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
      const opened = await openKeySeal({ kind: "device", deviceId, privateKey: unlock.privateKey, publicKey: unlock.publicKey }, { mailboxId, sealedKeyId: priv.keyId }, sealed); // pragma: allowlist secret (a CryptoKey reference)
      expect(opened.keyId).toBe(priv.keyId);
    }
    expect(parities.size).toBe(2); // 24 keys with only one parity: probability 2^-23
  });

  test("why the pair: given the private key alone, @hpke/core derives the public key with an even y, so it fails for every odd-y key", async () => {
    let odd = 0;
    for (let i = 0; i < 24 && odd < 3; i++) {
      const { unlock, pair } = await unlockPair();
      const aad = utf8("proprietor-mail/v1/test|lone key");
      const sender = await p256Suite.createSenderContext({ recipientPublicKey: pair.publicKey, info: aad });
      const expected = hex(new Uint8Array(await sender.export(utf8("x"), 32)));
      const alone = await p256Suite.createRecipientContext({ recipientKey: unlock.privateKey, enc: sender.enc, info: aad }).then(
        async (ctx) => hex(new Uint8Array(await ctx.export(utf8("x"), 32))),
        () => "failed",
      );
      const paired = await p256Suite.createRecipientContext({ recipientKey: pair, enc: sender.enc, info: aad });
      expect(hex(new Uint8Array(await paired.export(utf8("x"), 32)))).toBe(expected);
      if ((unlock.publicKey[64]! & 1) === 1) {
        odd += 1;
        expect(alone).not.toBe(expected);
      } else {
        expect(alone).toBe(expected);
      }
    }
    expect(odd).toBeGreaterThan(0);
  });
});
