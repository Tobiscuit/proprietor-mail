// Round 3, contracts/device-v1.md A2b: factor signing keys. From the factor's secret,
//   ikmS = HKDF-SHA256(secret, salt = factor id, info = ctx("factor-signing-key", mailboxId, factorId, kind), L = 32)
//   (sS, vS) = DeriveKeyPair(ikmS) for DHKEM(P-256, HKDF-SHA256) (RFC 9180 §7.1.3: the candidate loop
//   with its counter, bitmask 0xFF, until 0 < sk < n).
// sS is imported for ECDSA P-256, non-extractable, usage sign; every byte string that held the
// secret, ikmS or the scalar is zeroed after the import. vS is the raw uncompressed point, 65 bytes.
import { createECDH, createPublicKey, verify as nodeVerify } from "node:crypto";
import { DhkemP256HkdfSha256 } from "@hpke/core";
import { afterEach, describe, expect, test, vi } from "vitest";
import { deriveFactorKey, factorPublicKey, factorSigningKey, newId, type WrapKind } from "../src/index";
import { deriveP256SigningKey, factorMaterialOf } from "../src/factor-keys";
import { fromHex, hex, utf8 } from "./reference";

const mailboxId = newId("mbx");
const factorId = newId("wrp");
const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/** ikmS from the contract's text, with raw Web Crypto. */
async function referenceIkmS(s: Uint8Array<ArrayBuffer>, mbx: string, wrp: string, kind: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey("raw", s, "HKDF", false, ["deriveBits"]);
  const info = utf8(`proprietor-mail/v1/factor-signing-key|${mbx}|${wrp}|${kind}`);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(wrp), info }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
}

/** RFC 9180 DeriveKeyPair for DHKEM(P-256) as @hpke/core implements it: an independent reading. */
async function hpkePublicKey(ikm: Uint8Array<ArrayBuffer>): Promise<string> {
  const kem = new DhkemP256HkdfSha256();
  const pair = await kem.deriveKeyPair(ikm);
  return hex(new Uint8Array(await kem.serializePublicKey(pair.publicKey)));
}

/** The labeled candidate of RFC 9180 §7.1.3 for one counter, written out with raw Web Crypto. */
async function candidate(ikm: Uint8Array, counter: number): Promise<Uint8Array<ArrayBuffer>> {
  const suite = [0x4b, 0x45, 0x4d, 0x00, 0x10];
  const labeledIkm = new Uint8Array([...utf8("HPKE-v1"), ...suite, ...utf8("dkp_prk"), ...ikm]);
  const labeledInfo = new Uint8Array([0, 32, ...utf8("HPKE-v1"), ...suite, ...utf8("candidate"), counter]);
  const base = await crypto.subtle.importKey("raw", labeledIkm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: labeledInfo }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
}

/** The P-256 public point of a scalar, by OpenSSL. */
function opensslPoint(scalar: Uint8Array): string {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(scalar));
  return hex(new Uint8Array(ecdh.getPublicKey()));
}

/** Verifies an IEEE P1363 ECDSA P-256 signature with OpenSSL, from the 65-byte point. */
function opensslVerify(point: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  const jwk = { kty: "EC", crv: "P-256", x: Buffer.from(point.subarray(1, 33)).toString("base64url"), y: Buffer.from(point.subarray(33)).toString("base64url") };
  return nodeVerify("sha256", message, { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, signature);
}

afterEach(() => vi.restoreAllMocks());

describe("A2b DeriveKeyPair (RFC 9180 §7.1.3) for DHKEM(P-256, HKDF-SHA256)", () => {
  // RFC 9180 Appendix A.3.1 (read from the RFC Editor's text): ikmE and ikmR with the key pairs
  // they derive. The public points are also checked against OpenSSL's point of the RFC's scalars.
  test.each([
    [
      "ikmE",
      "4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e",
      "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb",
      "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4",
    ],
    [
      "ikmR",
      "668b37171f1072f3cf12ea8a236a45df23fc13b82af3609ad1e354f6ef817550",
      "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2",
      "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0",
    ],
  ])("RFC 9180 A.3.1 %s derives the RFC's key pair, as an ECDSA key that signs", async (_, ikm, sk, pk) => {
    expect(opensslPoint(fromHex(sk))).toBe(pk);
    expect(hex(await candidate(fromHex(ikm), 0))).toBe(sk);
    const pair = await deriveP256SigningKey(fromHex(ikm));
    expect(hex(pair.publicKey)).toBe(pk);
    expect(pair.privateKey.type).toBe("private");
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm).toEqual({ name: "ECDSA", namedCurve: "P-256" });
    expect(pair.privateKey.usages).toEqual(["sign"]);
    await expect(crypto.subtle.exportKey("pkcs8", pair.privateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey("jwk", pair.privateKey)).rejects.toThrow();
    const message = utf8("a message");
    const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, message));
    expect(signature.length).toBe(64);
    expect(opensslVerify(pair.publicKey, message, signature)).toBe(true);
  });

  test("the public point is the right one of the two with its x, whichever y it has (agrees with @hpke/core and OpenSSL over 64 inputs)", async () => {
    let odd = 0;
    for (let i = 0; i < 64; i++) {
      const ikm = crypto.getRandomValues(new Uint8Array(32));
      const pair = await deriveP256SigningKey(ikm);
      expect(pair.publicKey.length).toBe(65);
      expect(pair.publicKey[0]).toBe(0x04);
      expect(hex(pair.publicKey)).toBe(await hpkePublicKey(ikm));
      expect(hex(pair.publicKey)).toBe(opensslPoint(await candidate(ikm, 0)));
      odd += pair.publicKey[64]! & 1;
    }
    // Both parities occur (a derivation that always chose one y would be wrong half the time).
    expect(odd).toBeGreaterThan(0);
    expect(odd).toBeLessThan(64);
  });

  test("the candidate loop: a candidate of zero or of at least n is skipped, and the counter moves on", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    const deriveBits = crypto.subtle.deriveBits.bind(crypto.subtle);
    const rejected: ArrayBuffer[] = [];
    let hkdfCalls = 0;
    vi.spyOn(crypto.subtle, "deriveBits").mockImplementation((async (algorithm: { name: string }, ...rest: unknown[]) => {
      const bits = await (deriveBits as (...args: unknown[]) => Promise<ArrayBuffer>)(algorithm, ...rest);
      if (algorithm.name !== "HKDF") return bits;
      hkdfCalls++;
      // counter 0: n itself (not below n); counter 1: zero; counter 2: the real candidate.
      if (hkdfCalls === 1) {
        const n = fromHex(P256_N.toString(16));
        rejected.push(n.buffer);
        return n.buffer;
      }
      if (hkdfCalls === 2) {
        const zero = new Uint8Array(32).fill(0);
        rejected.push(zero.buffer);
        return zero.buffer;
      }
      return bits;
    }) as typeof crypto.subtle.deriveBits);
    const pair = await deriveP256SigningKey(ikm);
    vi.restoreAllMocks();
    expect(hkdfCalls).toBe(3);
    expect(hex(pair.publicKey)).toBe(opensslPoint(await candidate(ikm, 2)));
    // n - 1, the largest scalar, is accepted; a skipped candidate is zeroed like any other.
    for (const buffer of rejected) expect(new Uint8Array(buffer).every((b) => b === 0)).toBe(true);
  });

  test("the largest scalar, n - 1, is accepted at counter 0", async () => {
    const ikm = crypto.getRandomValues(new Uint8Array(32));
    const nMinus1 = fromHex((P256_N - 1n).toString(16));
    const expected = opensslPoint(nMinus1);
    const deriveBits = crypto.subtle.deriveBits.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "deriveBits").mockImplementation((async (algorithm: { name: string }, ...rest: unknown[]) => {
      if (algorithm.name === "HKDF") return new Uint8Array(nMinus1).buffer;
      return (deriveBits as (...args: unknown[]) => Promise<ArrayBuffer>)(algorithm, ...rest);
    }) as typeof crypto.subtle.deriveBits);
    expect(hex((await deriveP256SigningKey(ikm)).publicKey)).toBe(expected);
  });

  test("after 256 candidates with none below n, DeriveKeyPair fails (RFC 9180: counter > 255)", async () => {
    let hkdfCalls = 0;
    const deriveBits = crypto.subtle.deriveBits.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "deriveBits").mockImplementation((async (algorithm: { name: string }, ...rest: unknown[]) => {
      if (algorithm.name !== "HKDF") return (deriveBits as (...args: unknown[]) => Promise<ArrayBuffer>)(algorithm, ...rest);
      hkdfCalls++;
      return new Uint8Array(32).fill(0xff).buffer;
    }) as typeof crypto.subtle.deriveBits);
    await expect(deriveP256SigningKey(new Uint8Array(32))).rejects.toThrow();
    expect(hkdfCalls).toBe(256);
  });

  test("refuses input keying material shorter than 32 bytes", async () => {
    await expect(deriveP256SigningKey(new Uint8Array(31))).rejects.toBeInstanceOf(TypeError);
  });
});

describe("A2b a factor's signing key", () => {
  test.each(["passkey-prf", "recovery"] as const)("a %s factor's vS is DeriveKeyPair(ikmS) of the contract's ikmS; sS is non-extractable, sign only", async (kind) => {
    const key = await deriveFactorKey({ mailboxId, factorId, kind, secret });
    const vS = factorSigningKey(key);
    expect(vS.length).toBe(65);
    expect(hex(vS)).toBe(await hpkePublicKey(await referenceIkmS(secret, mailboxId, factorId, kind)));
    const { signingKey } = factorMaterialOf(key);
    expect(signingKey.extractable).toBe(false);
    expect(signingKey.usages).toEqual(["sign"]);
    expect(signingKey.algorithm).toEqual({ name: "ECDSA", namedCurve: "P-256" });
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

  test("the info strings keep the KEK, the factor key and the signing key apart: ikmS differs from the factor key's ikm", async () => {
    const ikmS = await referenceIkmS(secret, mailboxId, factorId, "recovery");
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const ikm = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(factorId), info: utf8(`proprietor-mail/v1/factor-key|${mailboxId}|${factorId}|recovery`) }, base, 256), // pragma: allowlist secret (HKDF parameter names)
    );
    expect(hex(ikmS)).not.toBe(hex(ikm));
    const key = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret });
    expect(hex(factorSigningKey(key)).slice(2, 66)).not.toBe(hex(factorPublicKey(key)));
  });

  test("the handle signs without exposing the key: the CryptoKey is reachable only inside the package, and vS handed out is a copy", async () => {
    const key = await deriveFactorKey({ mailboxId, factorId, kind: "passkey-prf", secret });
    expect(Object.keys(key).sort()).toEqual(["factorId", "kind"]);
    expect(JSON.stringify(key)).not.toContain("signing");
    const vS = factorSigningKey(key);
    vS.fill(0);
    expect(factorSigningKey(key)[0]).toBe(0x04);
    expect(() => factorSigningKey({ factorId, kind: "passkey-prf" })).toThrow(TypeError);
  });

  test("every buffer that held the secret, ikm, ikmS or a scalar is zeroed: the two PKCS #8 imports of sS and the one of skF included", async () => {
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
    // skF (X25519, 48 bytes), then sS twice (ECDSA for signing, ECDH for its public point; 67 bytes each).
    expect(pkcs8.map((p) => [p.name, p.data.length])).toEqual([
      ["X25519", 48],
      ["ECDSA", 67],
      ["ECDH", 67],
    ]);
    for (const p of pkcs8) expect(p.data.every((b) => b === 0)).toBe(true);
    // ikm, skF, ikmS and sS's candidate(s).
    expect(derived.length).toBeGreaterThanOrEqual(4);
    for (const bits of derived) expect(new Uint8Array(bits).every((b) => b === 0)).toBe(true);
    // a copy of the secret, then the labeled ikm and the labeled ikmS.
    expect(hkdfInputs.length).toBe(3);
    for (const input of hkdfInputs) expect(input.every((b) => b === 0)).toBe(true);
    expect(hex(callerSecret)).toBe(hex(secret));
  });
});
