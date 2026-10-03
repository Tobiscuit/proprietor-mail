// S1b: generateMailboxKey, sealMessage, openHeader, openBody
// (contracts/envelope-v1.md "Sealing one message", "Checks the browser makes").
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  generateMailboxKey,
  keyIdOf,
  newId,
  openBody,
  openHeader,
  sealMessage,
  type MailboxPrivateKey,
  type MailboxPublicKey,
  type MessageHeader,
  type SealedMessage,
} from "../src/index";
import { openKeyEnvelope, sealKeyEnvelope } from "../src/envelope";
import { importPrivateScalar, materialOf } from "../src/keys";
import { smallHeader, smallRaw, unicodeHeader, unicodeRaw } from "./fixtures";
import { b64urlDecode, b64urlEncode, flipBit, fromHex, hex, utf8 } from "./reference";

const mailboxId = newId("mbx");
const messageId = newId("msg");
const ids = { mailboxId, messageId };
const { publicKey: pub, privateKey: priv } = await generateMailboxKey();

async function expectDecryptionFailed(p: Promise<unknown>) {
  await expect(p).rejects.toBeInstanceOf(DecryptionFailed);
}

describe("S1b generateMailboxKey", () => {
  test("returns a raw 32-byte public key, its keyId, and an opaque private key with the same keyId", async () => {
    expect(pub.publicKey).toBeInstanceOf(Uint8Array);
    expect(pub.publicKey.length).toBe(32);
    expect(pub.keyId).toBe(await keyIdOf(pub.publicKey));
    expect(priv.keyId).toBe(pub.keyId);
  });

  test("every call makes a new key pair", async () => {
    const other = await generateMailboxKey();
    expect(hex(other.publicKey.publicKey)).not.toBe(hex(pub.publicKey));
  });

  test("known answer: the public key of RFC 7748 §6.1's private keys is X25519(k, 9)", async () => {
    const alice = await importPrivateScalar(fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    const bob = await importPrivateScalar(fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"));
    expect(hex(materialOf(alice).publicKey)).toBe("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect(hex(materialOf(bob).publicKey)).toBe("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
  });

  test("the private key handle carries only its keyId: no raw bytes through any property, JSON or clone", async () => {
    const scalar = fromHex("a8abababababababababababababababababababababababababababababab6b"); // already clamped
    const key = await importPrivateScalar(scalar);
    const hexScalar = hex(scalar);
    const b64Scalar = b64urlEncode(scalar);
    expect(Object.keys(key)).toEqual(["keyId"]);
    expect(Reflect.ownKeys(key)).toEqual(["keyId"]);
    expect(Object.isFrozen(key)).toBe(true);
    const json = JSON.stringify(key);
    expect(json).toBe(JSON.stringify({ keyId: key.keyId }));
    expect(json).not.toContain(hexScalar);
    expect(json).not.toContain(b64Scalar);
    // A clone (postMessage, IndexedDB) is a plain object that this module does not recognise.
    const clone = structuredClone(key) as MailboxPrivateKey;
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    await expect(openHeader(clone, ids, sealed)).rejects.toBeInstanceOf(TypeError);
    // Nor is a forged object with the right keyId.
    await expect(openHeader({ keyId: priv.keyId }, ids, sealed)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("S1b round trips", () => {
  test("seal → open returns the exact header and the exact raw bytes", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    expect(await openHeader(priv, ids, sealed)).toStrictEqual(smallHeader);
    expect(hex(await openBody(priv, ids, sealed))).toBe(hex(smallRaw));
  });

  test("seal → open with a non-ASCII subject, names and an attachment", async () => {
    const sealed = await sealMessage(pub, ids, unicodeHeader, unicodeRaw);
    expect(await openHeader(priv, ids, sealed)).toStrictEqual(unicodeHeader);
    expect(hex(await openBody(priv, ids, sealed))).toBe(hex(unicodeRaw));
  });

  test("seal → open a 5 MiB body, byte for byte", async () => {
    const raw = new Uint8Array(5 * 1024 * 1024);
    for (let i = 0; i < raw.length; i += 65536) crypto.getRandomValues(raw.subarray(i, i + 65536));
    const sealed = await sealMessage(pub, ids, smallHeader, raw);
    const opened = await openBody(priv, ids, sealed);
    expect(opened.length).toBe(raw.length);
    expect(Buffer.compare(opened, raw)).toBe(0);
  });

  test("the sealed bytes have the contract's layout", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    expect(sealed.keyId).toBe(pub.keyId);
    const envelope = b64urlDecode(sealed.keyEnvelope);
    expect(envelope.length).toBe(80); // enc (32) || ct (48)
    expect(sealed.keyEnvelope).toMatch(/^[A-Za-z0-9_-]{107}$/); // base64url, no padding
    const header = b64urlDecode(sealed.header);
    expect(header[0]).toBe(0x01);
    expect(header.length).toBe(1 + 12 + utf8(JSON.stringify(smallHeader)).length + 16);
    expect(new TextDecoder().decode(sealed.body.subarray(0, 4))).toBe("PMB1");
    expect(sealed.body.length).toBe(4 + 12 + smallRaw.length + 16);
  });
});

describe("S1b binding (associated data)", () => {
  test("a header opened with another message id throws DecryptionFailed", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    await expectDecryptionFailed(openHeader(priv, { mailboxId, messageId: newId("msg") }, sealed));
  });

  test("a body opened with another mailbox id throws DecryptionFailed", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    await expectDecryptionFailed(openBody(priv, { mailboxId: newId("mbx"), messageId }, sealed));
  });

  test("a key envelope from another message throws DecryptionFailed", async () => {
    const other = { mailboxId, messageId: newId("msg") };
    const a = await sealMessage(pub, ids, smallHeader, smallRaw);
    const b = await sealMessage(pub, other, smallHeader, smallRaw);
    await expectDecryptionFailed(openHeader(priv, ids, { ...a, keyEnvelope: b.keyEnvelope }));
    await expectDecryptionFailed(openBody(priv, ids, { ...a, keyEnvelope: b.keyEnvelope }));
  });

  test("the header and body blocks are bound on their own: moved with a key envelope re-sealed for the new ids, they still fail", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    const { keyPair } = materialOf(priv);
    const dek = await openKeyEnvelope(keyPair, mailboxId, messageId, b64urlDecode(sealed.keyEnvelope));
    const pkR = keyPair.publicKey;
    const movedMessage = { mailboxId, messageId: newId("msg") };
    const movedMailbox = { mailboxId: newId("mbx"), messageId };
    for (const target of [movedMessage, movedMailbox]) {
      const keyEnvelope = b64urlEncode(await sealKeyEnvelope(pkR, target.mailboxId, target.messageId, dek));
      // The re-sealed envelope itself opens for the new ids (same message key)...
      const again = await openKeyEnvelope(keyPair, target.mailboxId, target.messageId, b64urlDecode(keyEnvelope));
      expect(hex(again)).toBe(hex(dek));
      // ...but the header and body blocks name the ids they were sealed for.
      await expectDecryptionFailed(openHeader(priv, target, { ...sealed, keyEnvelope }));
      await expectDecryptionFailed(openBody(priv, target, { ...sealed, keyEnvelope }));
    }
  });

  test("another mailbox's private key throws DecryptionFailed", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    const stranger = await generateMailboxKey();
    await expectDecryptionFailed(openHeader(stranger.privateKey, ids, sealed));
    await expectDecryptionFailed(openBody(stranger.privateKey, ids, sealed));
  });
});

describe("S1b tampering", () => {
  test("a flipped bit anywhere in the key envelope, the header block or the body throws DecryptionFailed", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    const envelope = b64urlDecode(sealed.keyEnvelope);
    const header = b64urlDecode(sealed.header);
    for (let i = 0; i < envelope.length; i++) {
      const keyEnvelope = b64urlEncode(flipBit(envelope, i, i % 8));
      await expectDecryptionFailed(openHeader(priv, ids, { ...sealed, keyEnvelope }));
    }
    for (let i = 0; i < header.length; i++) {
      await expectDecryptionFailed(openHeader(priv, ids, { ...sealed, header: b64urlEncode(flipBit(header, i, i % 8)) }));
    }
    for (let i = 0; i < sealed.body.length; i++) {
      await expectDecryptionFailed(openBody(priv, ids, { ...sealed, body: flipBit(sealed.body, i, i % 8) }));
    }
  });

  test("truncated tags, empty and malformed blobs throw DecryptionFailed", async () => {
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    const header = b64urlDecode(sealed.header);
    const envelope = b64urlDecode(sealed.keyEnvelope);
    const bad: Array<Partial<SealedMessage>> = [
      { header: b64urlEncode(header.subarray(0, header.length - 1)) },
      { header: b64urlEncode(header.subarray(0, 13)) },
      { header: "" },
      { header: sealed.header + "=" },
      { header: sealed.header.replace(/.$/, (c) => (c === "A" ? "B" : "A")) }, // non-canonical or changed last symbol
      { keyEnvelope: b64urlEncode(envelope.subarray(0, 79)) },
      { keyEnvelope: sealed.keyEnvelope + "AAAA" },
      { keyEnvelope: "not base64url!" },
    ];
    for (const change of bad) await expectDecryptionFailed(openHeader(priv, ids, { ...sealed, ...change }));
    await expectDecryptionFailed(openBody(priv, ids, { ...sealed, body: sealed.body.subarray(0, sealed.body.length - 1) }));
    await expectDecryptionFailed(openBody(priv, ids, { ...sealed, body: new Uint8Array(0) }));
  });

  test("ids that contain the separator are refused: TypeError when sealing, DecryptionFailed when opening", async () => {
    await expect(sealMessage(pub, { mailboxId: "mbx_a|b", messageId }, smallHeader, smallRaw)).rejects.toBeInstanceOf(TypeError);
    await expect(sealMessage(pub, { mailboxId, messageId: "" }, smallHeader, smallRaw)).rejects.toBeInstanceOf(TypeError);
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    await expectDecryptionFailed(openHeader(priv, { mailboxId, messageId: `${messageId}|x` }, sealed));
  });
});

describe("S1b freshness", () => {
  test("sealMessage uses a fresh message key and fresh IVs every call (two seals of the same input differ)", async () => {
    const a = await sealMessage(pub, ids, smallHeader, smallRaw);
    const b = await sealMessage(pub, ids, smallHeader, smallRaw);
    const { keyPair } = materialOf(priv);
    const dekA = await openKeyEnvelope(keyPair, mailboxId, messageId, b64urlDecode(a.keyEnvelope));
    const dekB = await openKeyEnvelope(keyPair, mailboxId, messageId, b64urlDecode(b.keyEnvelope));
    expect(hex(dekA)).not.toBe(hex(dekB));
    expect(a.keyEnvelope.slice(0, 43)).not.toBe(b.keyEnvelope.slice(0, 43)); // enc: a fresh ephemeral key
    expect(hex(b64urlDecode(a.header).subarray(1, 13))).not.toBe(hex(b64urlDecode(b.header).subarray(1, 13)));
    expect(hex(a.body.subarray(4, 16))).not.toBe(hex(b.body.subarray(4, 16)));
    expect(a.header).not.toBe(b.header);
    expect(hex(a.body)).not.toBe(hex(b.body));
  });
});

describe("S1b refusals when sealing", () => {
  test("a public key whose keyId does not match it is refused", async () => {
    const other = await generateMailboxKey();
    const lying: MailboxPublicKey = { keyId: other.publicKey.keyId, publicKey: pub.publicKey };
    await expect(sealMessage(lying, ids, smallHeader, smallRaw)).rejects.toBeInstanceOf(TypeError);
    await expect(sealMessage({ keyId: pub.keyId, publicKey: pub.publicKey.subarray(1) }, ids, smallHeader, smallRaw)).rejects.toBeInstanceOf(TypeError);
  });

  test("a MessageHeader without one of its keys is refused (every key is always present)", async () => {
    const { snippet: _, ...missing } = smallHeader;
    await expect(sealMessage(pub, ids, missing as MessageHeader, smallRaw)).rejects.toBeInstanceOf(TypeError);
    // envelopeTo joined v1 on 2026-09-28 (slice S2b), before anything was sealed under it: it is as required as the rest.
    const { envelopeTo: __, ...earlierForm } = smallHeader;
    await expect(sealMessage(pub, ids, earlierForm as MessageHeader, smallRaw)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("S1b the 64 KiB header rule", () => {
  const MAX = 64 * 1024;

  test("references keep their last 20 entries when the JSON would be larger than 64 KiB", async () => {
    const references = Array.from({ length: 3000 }, (_, i) => `ref-${i}@example.com`);
    const header = { ...smallHeader, references };
    expect(utf8(JSON.stringify(header)).length).toBeGreaterThan(MAX);
    const opened = await openHeader(priv, ids, await sealMessage(pub, ids, header, smallRaw));
    expect(opened).toStrictEqual({ ...header, references: references.slice(-20) });
  });

  test("then the snippet is shortened, and only as much as needed", async () => {
    const base = { ...smallHeader, snippet: "x".repeat(200) };
    const room = MAX - utf8(JSON.stringify(base)).length;
    const header = { ...base, subject: base.subject + "s".repeat(room + 50) };
    const opened = await openHeader(priv, ids, await sealMessage(pub, ids, header, smallRaw));
    expect(opened.snippet).toBe("x".repeat(150));
    expect(utf8(JSON.stringify(opened)).length).toBe(MAX);
    expect({ ...opened, snippet: header.snippet }).toStrictEqual(header);
  });

  test("a header still larger than 64 KiB after both steps is refused with RangeError", async () => {
    const header = { ...smallHeader, subject: "s".repeat(MAX) };
    await expect(sealMessage(pub, ids, header, smallRaw)).rejects.toBeInstanceOf(RangeError);
  });
});
