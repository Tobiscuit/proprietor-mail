// What the package hands Web Crypto, for the engine that mishandles some X25519 keys. WebKit's
// libgcrypt backend (WebKitGTK and WPE on Linux, and so Playwright's WebKit there; not Safari, whose
// backend is CryptoKit) drops a leading zero byte from an X25519 scalar: WebKit bug 307095, fixed on
// WebKit main on 2026-10-09 (323215@main), in no Playwright WebKit build yet. So it refuses a PKCS #8
// X25519 key whose first byte is zero (DataError), which is 1 clamped scalar in 32, and fails a
// generateKey that drew such a scalar (OperationError), 1 draw in 256. The browser probe
// (packages/mail-client/test/browser) measures both in the engine itself; these tests pin what the
// package does about them, in Node, by watching the calls it makes.
//
// 1. A key that is never serialized is imported with the three low bits of its first byte SET. X25519
//    ignores those bits (RFC 7748 §5, decodeScalar25519, clears them before every use; BoringSSL sets
//    them in every key it makes, on purpose), so it is the same key, and its first byte is never zero.
//    An extractable import, the form envelope v1 serializes, stays clamped.
// 2. A fresh X25519 key pair (a mailbox key, and every HPKE seal's ephemeral key) is asked for again
//    when generateKey answers OperationError: nothing has kept the failed draw, so another one loses
//    nothing. Any other error, or a fourth OperationError, is thrown.
import { createPrivateKey, createPublicKey } from "node:crypto";
import { DhkemX25519HkdfSha256 } from "@hpke/core";
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  deriveFactorKey,
  factorPublicKey,
  generateMailboxKey,
  newId,
  openHeader,
  openKeySeal,
  sealKey,
  sealMessage,
  x25519Supported,
  type WrapKind,
} from "../src/index";
import { importPrivateScalar } from "../src/keys";
import { smallHeader, smallRaw } from "./fixtures";
import { hex, utf8 } from "./reference";

const PKCS8_PREFIX = "302e020100300506032b656e04220420";
const mailboxId = newId("mbx");

afterEach(() => vi.restoreAllMocks());

/** X25519(k, 9) with OpenSSL (node:crypto), from the scalar's PKCS #8 form. */
function opensslPublicKey(scalar: Uint8Array): string {
  const der = Buffer.from(PKCS8_PREFIX + hex(scalar), "hex");
  return createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}

/** decodeScalar25519's bit operations (RFC 7748 §5). */
function clamp(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const k = new Uint8Array(raw);
  k[0] = k[0]! & 248;
  k[31] = (k[31]! & 127) | 64;
  return k;
}

/** A2 from the contract's text, with @hpke/core's DeriveKeyPair: a factor whose skF, clamped, starts with a zero byte (1 in 32). */
async function factorWithZeroFirstByte(kind: WrapKind) {
  const kem = new DhkemX25519HkdfSha256();
  for (;;) {
    const factorId = newId("wrp");
    const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const info = utf8(`proprietor-mail/v1/factor-key|${mailboxId}|${factorId}|${kind}`);
    const ikm = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(factorId), info }, base, 256); // pragma: allowlist secret (HKDF parameter names)
    const pair = await kem.deriveKeyPair(ikm);
    const skF = new Uint8Array(await kem.serializePrivateKey(pair.privateKey));
    if ((skF[0]! & 248) !== 0) continue;
    return { factorId, secret, skF, pkF: hex(new Uint8Array(await kem.serializePublicKey(pair.publicKey))) };
  }
}

/** Every PKCS #8 X25519 key the package hands importKey, copied at the call (the package zeroes its buffer afterwards). */
function watchPkcs8Imports(): Uint8Array[] {
  const seen: Uint8Array[] = [];
  const importKey = crypto.subtle.importKey.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "importKey").mockImplementation(((format: string, data: Uint8Array, ...rest: unknown[]) => {
    if (format === "pkcs8") seen.push(new Uint8Array(data));
    return (importKey as (...args: unknown[]) => Promise<CryptoKey>)(format, data, ...rest);
  }) as typeof crypto.subtle.importKey);
  return seen;
}

/** generateKey for X25519 answers `name` for its next `times` calls, as the GCrypt engine does for 1 draw in 256; other algorithms are untouched. */
function failX25519Draws(times: number, name = "OperationError"): { draws: number } {
  const generateKey = crypto.subtle.generateKey.bind(crypto.subtle);
  const counted = { draws: 0 };
  let left = times;
  vi.spyOn(crypto.subtle, "generateKey").mockImplementation(((algorithm: string | { name: string }, ...rest: unknown[]) => {
    if ((typeof algorithm === "string" ? algorithm : algorithm.name) === "X25519") {
      counted.draws += 1;
      if (left > 0) {
        left -= 1;
        return Promise.reject(new DOMException("The operation failed for an operation-specific reason", name));
      }
    }
    return (generateKey as (...args: unknown[]) => Promise<CryptoKeyPair>)(algorithm, ...rest);
  }) as typeof crypto.subtle.generateKey);
  return counted;
}

describe("1. a key that is never serialized never reaches the engine with a zero first byte", () => {
  test.each(["passkey-prf", "recovery"] as const)(
    "A2: a %s factor whose clamped scalar starts with a zero byte is imported with the three ignored bits set: OpenSSL and @hpke/core give the same public key",
    async (kind) => {
      const f = await factorWithZeroFirstByte(kind);
      const seen = watchPkcs8Imports();
      const key = await deriveFactorKey({ mailboxId, factorId: f.factorId, kind, secret: f.secret }); // pragma: allowlist secret (a random test value)
      expect(seen.length).toBe(1);
      const scalar = seen[0]!.subarray(16);
      expect(hex(seen[0]!.subarray(0, 16))).toBe(PKCS8_PREFIX);
      expect(scalar[0]).toBe(0x07); // clamped it would be 0x00, which the GCrypt engine refuses
      expect(hex(scalar.subarray(1, 31))).toBe(hex(f.skF.subarray(1, 31)));
      expect(scalar[31]).toBe((f.skF[31]! & 127) | 64);
      // The same key: X25519 decodes both byte strings to one scalar.
      expect(hex(factorPublicKey(key))).toBe(f.pkF);
      expect(opensslPublicKey(clamp(f.skF))).toBe(f.pkF);
      expect(opensslPublicKey(scalar)).toBe(f.pkF);
    },
  );

  test("every non-extractable import sets the three bits (no value-dependent branch); an extractable one keeps the clamped form envelope v1 serializes; both are one key", async () => {
    for (const first of [0x00, 0x05, 0x08, 0x2a, 0xff]) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      raw[0] = first;
      const seen = watchPkcs8Imports();
      const decryptOnly = await importPrivateScalar(raw);
      const wrappable = await importPrivateScalar(raw, { wrappable: true });
      vi.restoreAllMocks();
      expect(seen.length).toBe(2);
      expect(seen[0]![16]).toBe((first & 248) | 7);
      expect(seen[1]![16]).toBe(first & 248);
      expect(hex(seen[0]!.subarray(17))).toBe(hex(seen[1]!.subarray(17)));
      expect(decryptOnly.keyId).toBe(wrappable.keyId);
    }
  });
});

describe("2. a fresh X25519 key pair is drawn again after an OperationError, at most four times", () => {
  test("generateMailboxKey: one OperationError, then a key", async () => {
    const counted = failX25519Draws(1);
    const { privateKey, publicKey } = await generateMailboxKey();
    expect(privateKey.keyId).toBe(publicKey.keyId);
    expect(counted.draws).toBe(2);
  });

  test("generateMailboxKey: four OperationErrors in a row are thrown, after exactly four draws", async () => {
    const counted = failX25519Draws(4);
    await expect(generateMailboxKey()).rejects.toMatchObject({ name: "OperationError" });
    expect(counted.draws).toBe(4);
  });

  test("generateMailboxKey: any other error is thrown at once (a runtime without X25519 is not drawn again)", async () => {
    const counted = failX25519Draws(1, "NotSupportedError");
    await expect(generateMailboxKey()).rejects.toMatchObject({ name: "NotSupportedError" });
    expect(counted.draws).toBe(1);
  });

  test("a key seal's ephemeral key (HPKE encap): sealKey survives one OperationError, and the seal opens", async () => {
    const sealed = await generateMailboxKey();
    const successor = await generateMailboxKey();
    const counted = failX25519Draws(1);
    const s = await sealKey(sealed.privateKey, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey });
    expect(counted.draws).toBe(2);
    vi.restoreAllMocks();
    const opened = await openKeySeal({ kind: "successor", key: successor.privateKey }, { mailboxId, sealedKeyId: sealed.publicKey.keyId }, s);
    expect(opened.keyId).toBe(sealed.publicKey.keyId);
  });

  test("a key seal to a factor key, the same", async () => {
    const sealed = await generateMailboxKey();
    const factorId = newId("wrp");
    const factor = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (random test value)
    const counted = failX25519Draws(1);
    const s = await sealKey(sealed.privateKey, { mailboxId }, { kind: "factor", factorId, publicKey: factorPublicKey(factor) });
    expect(counted.draws).toBe(2);
    vi.restoreAllMocks();
    expect((await openKeySeal({ kind: "factor", key: factor }, { mailboxId, sealedKeyId: sealed.publicKey.keyId }, s)).keyId).toBe(sealed.publicKey.keyId);
  });

  test("a message (envelope v1): sealMessage survives one OperationError, and the header opens", async () => {
    const { privateKey, publicKey } = await generateMailboxKey();
    const ids = { mailboxId, messageId: newId("msg") };
    const counted = failX25519Draws(1);
    const sealed = await sealMessage(publicKey, ids, smallHeader, smallRaw);
    expect(counted.draws).toBe(2);
    vi.restoreAllMocks();
    expect((await openHeader(privateKey, ids, sealed)).subject).toBe(smallHeader.subject);
  });

  test("a seal whose ephemeral key fails four times is refused, after exactly four draws", async () => {
    const sealed = await generateMailboxKey();
    const successor = await generateMailboxKey();
    const counted = failX25519Draws(4);
    await expect(sealKey(sealed.privateKey, { mailboxId }, { kind: "successor", publicKey: successor.publicKey.publicKey })).rejects.toThrow();
    expect(counted.draws).toBe(4);
  });

  test("x25519Supported is not fooled by one OperationError", async () => {
    failX25519Draws(1);
    expect(await x25519Supported()).toBe(true);
  });
});
