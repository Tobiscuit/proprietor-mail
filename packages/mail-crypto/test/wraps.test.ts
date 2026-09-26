// S1d: prfInput, wrapPrivateKey, unwrapPrivateKey, publicKeyMatches
// (contracts/envelope-v1.md "Wrapping the private key", "Checks the browser makes"; domain-model G7).
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  generateMailboxKey,
  newId,
  openHeader,
  prfInput,
  publicKeyMatches,
  sealMessage,
  unwrapPrivateKey,
  wrapPrivateKey,
  type KeyWrap,
  type WrapKind,
} from "../src/index";
import { importPrivateScalar, materialOf } from "../src/keys";
import { smallHeader, smallRaw } from "./fixtures";
import { b64urlDecode, b64urlEncode, flipBit, fromHex, hex, sha256, utf8 } from "./reference";

const mailboxId = newId("mbx");
const { publicKey: pub, privateKey: priv } = await generateMailboxKey();
/** A random stand-in for a passkey PRF output or a recovery secret, made for this test run. */
const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)

async function expectDecryptionFailed(p: Promise<unknown>) {
  await expect(p).rejects.toBeInstanceOf(DecryptionFailed);
}

/** The contract's KEK, computed independently with raw Web Crypto. */
async function referenceKek(ikm: Uint8Array<ArrayBuffer>, wrapId: string, kind: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: utf8(wrapId), info: utf8(`platform-mail/v1/kek/${kind}`) }, // pragma: allowlist secret (HKDF parameter names)
    base,
    256,
  );
  return crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["encrypt", "decrypt"]);
}

const wrapAad = (mbx: string, wrapId: string, kind: string, keyId: string) =>
  utf8(`platform-mail/v1/wrap|${mbx}|${wrapId}|${kind}|${keyId}`);

describe("S1d prfInput", () => {
  test('prf.eval.first = SHA-256("platform-mail/v1/prf|" + mailboxId + "|" + wrapId), 32 bytes', async () => {
    const wrapId = newId("wrp");
    const expected = await sha256(utf8(`platform-mail/v1/prf|${mailboxId}|${wrapId}`));
    const input = await prfInput(mailboxId, wrapId);
    expect(input.length).toBe(32);
    expect(hex(input)).toBe(hex(expected));
  });

  test("prfInput refuses ids containing the separator", async () => {
    await expect(prfInput(`${mailboxId}|x`, newId("wrp"))).rejects.toBeInstanceOf(TypeError);
  });
});

describe("S1d wraps", () => {
  test.each(["passkey-prf", "recovery"] as const)("a %s wrap round-trips to a key that opens the mailbox's mail", async (kind) => {
    const wrapId = newId("wrp");
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId, kind, secret });
    expect(wrap).toEqual({ id: wrapId, keyId: pub.keyId, kind, wrapped: expect.any(String) });
    const block = b64urlDecode(wrap.wrapped);
    expect(block.length).toBe(1 + 12 + 32 + 16);
    expect(block[0]).toBe(0x01);

    const unwrapped = await unwrapPrivateKey(wrap, { mailboxId, secret });
    expect(unwrapped.keyId).toBe(pub.keyId);
    expect(await publicKeyMatches(unwrapped, pub)).toBe(true);
    const ids = { mailboxId, messageId: newId("msg") };
    const sealed = await sealMessage(pub, ids, smallHeader, smallRaw);
    expect(await openHeader(unwrapped, ids, sealed)).toStrictEqual(smallHeader);
  });

  test("the wrap is the contract's bytes: HKDF-SHA256 KEK, AES-256-GCM over the clamped raw private key", async () => {
    const scalar = crypto.getRandomValues(new Uint8Array(32));
    const key = await importPrivateScalar(scalar);
    const clamped = new Uint8Array(scalar);
    clamped[0] = clamped[0]! & 248;
    clamped[31] = (clamped[31]! & 127) | 64;
    const wrapId = newId("wrp");
    const wrap = await wrapPrivateKey(key, { mailboxId, wrapId, kind: "recovery", secret });
    const block = b64urlDecode(wrap.wrapped);
    const kek = await referenceKek(secret, wrapId, "recovery");
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: block.subarray(1, 13), additionalData: wrapAad(mailboxId, wrapId, "recovery", key.keyId) },
      kek,
      block.subarray(13),
    );
    expect(hex(new Uint8Array(plain))).toBe(hex(clamped));
  });

  test("portability: an unclamped raw key wrapped by another implementation unwraps to the same key pair", async () => {
    // RFC 7748 §6.1, Alice: an unclamped scalar, as a pure-JS fallback might serialize it.
    const alice = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const alicePublic = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const keyId = hex((await sha256(fromHex(alicePublic))).subarray(0, 16));
    const wrapId = newId("wrp");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await referenceKek(secret, wrapId, "passkey-prf");
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: wrapAad(mailboxId, wrapId, "passkey-prf", keyId) },
      kek,
      alice,
    );
    const wrap: KeyWrap = {
      id: wrapId,
      keyId,
      kind: "passkey-prf",
      wrapped: b64urlEncode(new Uint8Array([0x01, ...iv, ...new Uint8Array(ct)])),
    };
    const unwrapped = await unwrapPrivateKey(wrap, { mailboxId, secret });
    expect(unwrapped.keyId).toBe(keyId);
    expect(hex(materialOf(unwrapped).publicKey)).toBe(alicePublic);
  });

  test("a wrap opens only with its own secret, mailbox, wrap id, kind and key id", async () => {
    const wrapId = newId("wrp");
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId, kind: "passkey-prf", secret });
    const other = await generateMailboxKey();
    const wrongSecret = new Uint8Array(secret);
    wrongSecret[0] = wrongSecret[0]! ^ 1;
    await expectDecryptionFailed(unwrapPrivateKey(wrap, { mailboxId, secret: wrongSecret })); // pragma: allowlist secret (a test variable)
    await expectDecryptionFailed(unwrapPrivateKey(wrap, { mailboxId: newId("mbx"), secret }));
    await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, id: newId("wrp") }, { mailboxId, secret }));
    await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, kind: "recovery" }, { mailboxId, secret }));
    await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, keyId: other.publicKey.keyId }, { mailboxId, secret }));
    await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, kind: "passphrase" as WrapKind }, { mailboxId, secret }));
    // ...and it still opens with all five of its own.
    expect((await unwrapPrivateKey(wrap, { mailboxId, secret })).keyId).toBe(pub.keyId);
  });

  test("a flipped bit anywhere in a wrap, or a truncated wrap, throws DecryptionFailed", async () => {
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
    const block = b64urlDecode(wrap.wrapped);
    for (let i = 0; i < block.length; i++) {
      await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, wrapped: b64urlEncode(flipBit(block, i, i % 8)) }, { mailboxId, secret }));
    }
    await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, wrapped: b64urlEncode(block.subarray(0, 60)) }, { mailboxId, secret }));
    await expectDecryptionFailed(unwrapPrivateKey({ ...wrap, wrapped: "" }, { mailboxId, secret }));
  });

  test("every wrap uses a fresh IV", async () => {
    const ctx = { mailboxId, wrapId: newId("wrp"), kind: "recovery" as const, secret };
    const a = await wrapPrivateKey(priv, ctx);
    const b = await wrapPrivateKey(priv, ctx);
    expect(a.wrapped).not.toBe(b.wrapped);
  });

  test("secrets must be 32 bytes, and the kind must be one the contract defines", async () => {
    const wrapId = newId("wrp");
    await expect(wrapPrivateKey(priv, { mailboxId, wrapId, kind: "recovery", secret: new Uint8Array(31) })).rejects.toBeInstanceOf(TypeError);
    await expect(wrapPrivateKey(priv, { mailboxId, wrapId, kind: "passphrase" as WrapKind, secret })).rejects.toBeInstanceOf(TypeError);
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId, kind: "recovery", secret });
    await expect(unwrapPrivateKey(wrap, { mailboxId, secret: new Uint8Array(33) })).rejects.toBeInstanceOf(TypeError);
  });
});

describe("S1d publicKeyMatches (domain-model G7)", () => {
  test("true for the key pair's own public key", async () => {
    expect(await publicKeyMatches(priv, pub)).toBe(true);
  });

  test("false for a different key pair", async () => {
    const other = await generateMailboxKey();
    expect(await publicKeyMatches(priv, other.publicKey)).toBe(false);
    expect(await publicKeyMatches(other.privateKey, pub)).toBe(false);
  });

  test("false when the advertised keyId or bytes are swapped for another key's", async () => {
    const other = await generateMailboxKey();
    expect(await publicKeyMatches(priv, { keyId: other.publicKey.keyId, publicKey: pub.publicKey })).toBe(false);
    expect(await publicKeyMatches(priv, { keyId: pub.keyId, publicKey: other.publicKey.publicKey })).toBe(false);
    expect(await publicKeyMatches(priv, { keyId: pub.keyId, publicKey: pub.publicKey.subarray(0, 31) })).toBe(false);
  });
});
