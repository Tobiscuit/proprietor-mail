// Round 3, contracts/device-v1.md A2b (Ed25519 by D44): factor signing keys. From the factor's secret,
//   seedS = HKDF-SHA256(secret, salt = factor id, info = ctx("factor-signing-key", mailboxId, factorId, kind), L = 32)
//   (sS, vS) = the Ed25519 key pair whose private key is seedS (RFC 8032 §5.1.5).
// sS is imported as PKCS #8 (RFC 8410) for Ed25519, non-extractable, usage sign; vS (32 bytes) is read
// from the engine by importing the same PKCS #8 once extractable and exporting JWK `x`. Every byte
// string that held the secret, seedS or the PKCS #8 encoding is zeroed after the imports. Signatures
// are verified, never compared: Safari's Ed25519 signatures are randomized.
import { createPrivateKey, createPublicKey, verify as nodeVerify } from "node:crypto";
import { afterEach, describe, expect, test, vi } from "vitest";
import { deriveFactorKey, factorPublicKey, factorSigningKey, newId, type WrapKind } from "../src/index";
import { factorMaterialOf, importEd25519SigningKey } from "../src/factor-keys";
import { fromHex, hex, utf8 } from "./reference";

const mailboxId = newId("mbx");
const factorId = newId("wrp");
const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)
const PKCS8_ED25519 = "302e020100300506032b657004220420";

/** seedS from the contract's text, with raw Web Crypto. */
async function referenceSeed(s: Uint8Array<ArrayBuffer>, mbx: string, wrp: string, kind: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey("raw", s, "HKDF", false, ["deriveBits"]);
  const info = utf8(`proprietor-mail/v1/factor-signing-key|${mbx}|${wrp}|${kind}`);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(wrp), info }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
}

/** The Ed25519 public key of a 32-byte private key, by OpenSSL (node:crypto), from RFC 8410's PKCS #8. */
function opensslPublicKey(seedHex: string): string {
  const key = createPrivateKey({ key: Buffer.from(PKCS8_ED25519 + seedHex, "hex"), format: "der", type: "pkcs8" });
  return Buffer.from(createPublicKey(key).export({ format: "jwk" }).x!, "base64url").toString("hex");
}

/** An Ed25519 signature verified by OpenSSL from the 32-byte public key. */
function opensslVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKey).toString("base64url") }, format: "jwk" });
  return nodeVerify(null, message, key, signature);
}

afterEach(() => vi.restoreAllMocks());

describe("A2b an Ed25519 key from 32 bytes (RFC 8032 §5.1.5, RFC 8410 PKCS #8)", () => {
  // RFC 8032 §7.1 TEST 1 and TEST 2, read from the RFC Editor's text: the secret key, its public key,
  // the message and the RFC's signature. The RFC's signature verifies under the key the engine reports;
  // the engine's own signature verifies with OpenSSL (never compared: Safari randomizes them).
  test.each([
    ["TEST 1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"],
    ["TEST 2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"],
  ])("RFC 8032 %s: the public key the engine reports is the RFC's; the key is non-extractable, sign only, and signs", async (_, sk, pk, message, rfcSignature) => {
    expect(opensslPublicKey(sk)).toBe(pk);
    const pair = await importEd25519SigningKey(fromHex(sk));
    expect(hex(pair.publicKey)).toBe(pk);
    expect(pair.privateKey.type).toBe("private");
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm).toEqual({ name: "Ed25519" });
    expect(pair.privateKey.usages).toEqual(["sign"]);
    await expect(crypto.subtle.exportKey("pkcs8", pair.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey("jwk", pair.privateKey)).rejects.toThrow();
    expect(opensslVerify(pair.publicKey, fromHex(message), fromHex(rfcSignature))).toBe(true);
    const signature = new Uint8Array(await crypto.subtle.sign("Ed25519", pair.privateKey, fromHex(message)));
    expect(signature.length).toBe(64);
    expect(opensslVerify(pair.publicKey, fromHex(message), signature)).toBe(true);
  });

  test("any 32 bytes are a private key: the reported public key agrees with OpenSSL over 64 random seeds, zero and all-ones included", async () => {
    const seeds = [new Uint8Array(32), new Uint8Array(32).fill(0xff), ...Array.from({ length: 62 }, () => crypto.getRandomValues(new Uint8Array(32)))];
    for (const seed of seeds) {
      const expected = opensslPublicKey(hex(seed));
      expect(hex((await importEd25519SigningKey(new Uint8Array(seed))).publicKey)).toBe(expected);
    }
  });

  test("the caller's seed is zeroed with the PKCS #8 buffers that carried it (both imports); only vS leaves", async () => {
    const pkcs8: Uint8Array[] = [];
    const importKey = crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "importKey").mockImplementation(((format: string, data: Uint8Array, ...rest: unknown[]) => {
      if (format === "pkcs8") pkcs8.push(data);
      return (importKey as (...args: unknown[]) => Promise<CryptoKey>)(format, data, ...rest);
    }) as typeof crypto.subtle.importKey);
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const pair = await importEd25519SigningKey(seed);
    expect(pkcs8.length).toBe(2); // non-extractable for signing; extractable once, for its JWK `x`
    for (const data of pkcs8) {
      expect(data.length).toBe(48);
      expect(data.every((b) => b === 0)).toBe(true);
    }
    expect(seed.every((b) => b === 0)).toBe(true);
    expect(pair.publicKey.length).toBe(32);
  });

  test("refuses a seed that is not 32 bytes", async () => {
    await expect(importEd25519SigningKey(new Uint8Array(31))).rejects.toBeInstanceOf(TypeError);
    await expect(importEd25519SigningKey(new Uint8Array(33))).rejects.toBeInstanceOf(TypeError);
  });
});

describe("A2b a factor's signing key", () => {
  test.each(["passkey-prf", "recovery"] as const)("a %s factor's vS is the Ed25519 public key of the contract's seedS; sS is non-extractable, sign only", async (kind) => {
    const key = await deriveFactorKey({ mailboxId, factorId, kind, secret });
    const vS = factorSigningKey(key);
    expect(vS.length).toBe(32);
    expect(hex(vS)).toBe(opensslPublicKey(hex(await referenceSeed(secret, mailboxId, factorId, kind))));
    const { signingKey } = factorMaterialOf(key);
    expect(signingKey.extractable).toBe(false);
    expect(signingKey.usages).toEqual(["sign"]);
    expect(signingKey.algorithm).toEqual({ name: "Ed25519" });
  });

  test("deterministic, and bound to its mailbox, factor id, kind and secret", async () => {
    const base = hex(factorSigningKey(await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret })));
    expect(hex(factorSigningKey(await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: new Uint8Array(secret) })))).toBe(base);
    const other = new Uint8Array(secret);
    other[31] = other[31]! ^ 0x80;
    for (const ctx of [
      { mailboxId: newId("mbx"), factorId, kind: "recovery" as WrapKind, secret },
      { mailboxId, factorId: newId("wrp"), kind: "recovery" as WrapKind, secret },
      { mailboxId, factorId, kind: "passkey-prf" as WrapKind, secret },
      { mailboxId, factorId, kind: "recovery" as WrapKind, secret: other }, // pragma: allowlist secret (a test variable)
    ]) {
      expect(hex(factorSigningKey(await deriveFactorKey(ctx)))).not.toBe(base);
    }
  });

  test("the info strings keep the KEK, the factor key and the signing key apart: seedS differs from the factor key's ikm", async () => {
    const seedS = await referenceSeed(secret, mailboxId, factorId, "recovery");
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const ikm = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(factorId), info: utf8(`proprietor-mail/v1/factor-key|${mailboxId}|${factorId}|recovery`) }, base, 256), // pragma: allowlist secret (HKDF parameter names)
    );
    expect(hex(seedS)).not.toBe(hex(ikm));
    const key = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret });
    expect(hex(factorSigningKey(key))).not.toBe(hex(factorPublicKey(key)));
  });

  test("the handle signs without exposing the key: the CryptoKey is reachable only inside the package, and vS handed out is a copy", async () => {
    const key = await deriveFactorKey({ mailboxId, factorId, kind: "passkey-prf", secret });
    expect(Object.keys(key).sort()).toEqual(["factorId", "kind"]);
    expect(JSON.stringify(key)).not.toContain("signing");
    const vS = factorSigningKey(key);
    const copy = hex(vS);
    vS.fill(0);
    expect(hex(factorSigningKey(key))).toBe(copy);
    expect(() => factorSigningKey({ factorId, kind: "passkey-prf" })).toThrow(TypeError);
  });

  test("every buffer that held the secret, ikm, seedS or a private key is zeroed: skF's PKCS #8 and sS's two included", async () => {
    const pkcs8: { name: string; data: Uint8Array }[] = [];
    const hkdfInputs: Uint8Array[] = [];
    const importKey = crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "importKey").mockImplementation(((format: string, data: Uint8Array, algorithm: unknown, ...rest: unknown[]) => {
      const name = typeof algorithm === "string" ? algorithm : (algorithm as { name: string }).name;
      if (format === "pkcs8") pkcs8.push({ name, data });
      if (format === "raw" && name === "HKDF") hkdfInputs.push(data);
      return (importKey as (...args: unknown[]) => Promise<CryptoKey>)(format, data, algorithm, ...rest);
    }) as typeof crypto.subtle.importKey);
    const derived: ArrayBuffer[] = [];
    const deriveBits = crypto.subtle.deriveBits.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "deriveBits").mockImplementation((async (algorithm: { name: string }, ...rest: unknown[]) => {
      const bits = await (deriveBits as (...args: unknown[]) => Promise<ArrayBuffer>)(algorithm, ...rest);
      if (algorithm.name === "HKDF") derived.push(bits);
      return bits;
    }) as typeof crypto.subtle.deriveBits);

    const callerSecret = new Uint8Array(secret);
    await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: callerSecret }); // pragma: allowlist secret (a test variable)
    // skF (X25519), then sS twice (Ed25519: for signing, and once extractable for vS); 48 bytes each.
    expect(pkcs8.map((p) => [p.name, p.data.length])).toEqual([
      ["X25519", 48],
      ["Ed25519", 48],
      ["Ed25519", 48],
    ]);
    for (const p of pkcs8) expect(p.data.every((b) => b === 0)).toBe(true);
    // ikm, skF and seedS.
    expect(derived.length).toBe(3);
    for (const bits of derived) expect(new Uint8Array(bits).every((b) => b === 0)).toBe(true);
    // a copy of the secret, then the labeled ikm.
    expect(hkdfInputs.length).toBe(2);
    for (const input of hkdfInputs) expect(input.every((b) => b === 0)).toBe(true);
    expect(hex(callerSecret)).toBe(hex(secret));
  });
});
