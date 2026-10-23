// D1a, contracts/device-v1.md A2: factor keys. ikm is HKDF-SHA256 over the factor's secret with
// the factor id for its salt and ctx("factor-key", mailboxId, factorId, kind) for its info, then
// RFC 9180 §7.1.3 DeriveKeyPair(ikm) for DHKEM(X25519, HKDF-SHA256). skF is imported non-extractable with
// usage deriveBits, and the derived scalar is zeroed after the import.
import { createPrivateKey, createPublicKey } from "node:crypto";
import { DhkemX25519HkdfSha256 } from "@hpke/core";
import { afterEach, describe, expect, test, vi } from "vitest";
import { deriveFactorKey, factorPublicKey, newId, type WrapKind } from "../src/index";
import { deriveX25519KeyPair, factorMaterialOf } from "../src/factor-keys";
import { fromHex, hex, utf8 } from "./reference";

const mailboxId = newId("mbx");
const factorId = newId("wrp");
const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)

/** The contract's ikm, computed with raw Web Crypto. */
async function referenceIkm(s: Uint8Array<ArrayBuffer>, mbx: string, wrp: string, kind: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await crypto.subtle.importKey("raw", s, "HKDF", false, ["deriveBits"]);
  const info = utf8(`proprietor-mail/v1/factor-key|${mbx}|${wrp}|${kind}`);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(wrp), info }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
}

/** RFC 9180 DeriveKeyPair as @hpke/core implements it: a second, independent reading. */
async function referencePublicKey(ikm: Uint8Array<ArrayBuffer>): Promise<string> {
  const kem = new DhkemX25519HkdfSha256();
  const pair = await kem.deriveKeyPair(ikm);
  return hex(new Uint8Array(await kem.serializePublicKey(pair.publicKey)));
}

/** X25519(sk, 9) with OpenSSL (node:crypto): a third implementation. */
function opensslPublicKey(scalarHex: string): string {
  const der = Buffer.from("302e020100300506032b656e04220420" + scalarHex, "hex");
  return createPublicKey(createPrivateKey({ key: der, format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}

afterEach(() => vi.restoreAllMocks());

describe("A2 DeriveKeyPair (RFC 9180 §7.1.3) for DHKEM(X25519, HKDF-SHA256)", () => {
  // RFC 9180 Appendix A.1.1: ikmE gives skEm/pkEm, ikmR gives skRm. The public keys are checked
  // against OpenSSL's X25519 of those scalars, not copied from memory.
  test.each([
    ["ikmE", "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234", "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"],
    ["ikmR", "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037", "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"],
  ])("RFC 9180 A.1.1 %s derives the RFC's private key", async (_, ikm, sk) => {
    const pair = await deriveX25519KeyPair(fromHex(ikm));
    expect(hex(pair.publicKey)).toBe(opensslPublicKey(sk));
    expect(hex(pair.publicKey)).toBe(await referencePublicKey(fromHex(ikm)));
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.usages).toEqual(["deriveBits"]);
  });

  test("the derived scalar, the PKCS #8 buffer that carried it, and every HKDF input and output are zeroed after use", async () => {
    const imported: Uint8Array[] = [];
    const hkdfInputs: Uint8Array[] = [];
    const importKey = crypto.subtle.importKey.bind(crypto.subtle);
    vi.spyOn(crypto.subtle, "importKey").mockImplementation(((format: string, data: Uint8Array, algorithm: unknown, ...rest: unknown[]) => {
      if (format === "pkcs8") imported.push(data);
      if (format === "raw" && (algorithm === "HKDF" || (algorithm as { name?: string }).name === "HKDF")) hkdfInputs.push(data);
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
    // skF's PKCS #8, then round 3's signing key sS twice (test/factor-signing-keys.test.ts); 48 bytes each.
    expect(imported.map((p) => p.length)).toEqual([48, 48, 48]);
    for (const p of imported) expect(p.every((b) => b === 0)).toBe(true);
    expect(derived.length).toBeGreaterThanOrEqual(2); // ikm, then sk (and A2b's ikmS and candidate)
    for (const bits of derived) expect(new Uint8Array(bits).every((b) => b === 0)).toBe(true);
    expect(hkdfInputs.length).toBeGreaterThanOrEqual(2); // a copy of the secret, then the labeled ikm (which contains ikm)
    for (const input of hkdfInputs) expect(input.every((b) => b === 0)).toBe(true);
    // The caller's own buffer is the caller's: it is not changed.
    expect(hex(callerSecret)).toBe(hex(secret));
  });
});

describe("A2 deriveFactorKey", () => {
  test.each(["passkey-prf", "recovery"] as const)("a %s factor key is DeriveKeyPair of the contract's ikm, non-extractable, deriveBits only", async (kind) => {
    const key = await deriveFactorKey({ mailboxId, factorId, kind, secret });
    expect(key.factorId).toBe(factorId);
    expect(key.kind).toBe(kind);
    expect(Object.isFrozen(key)).toBe(true);
    const pk = factorPublicKey(key);
    expect(pk.length).toBe(32);
    expect(hex(pk)).toBe(await referencePublicKey(await referenceIkm(secret, mailboxId, factorId, kind)));
    const { keyPair } = factorMaterialOf(key);
    expect(keyPair.privateKey.extractable).toBe(false);
    expect(keyPair.privateKey.algorithm.name).toBe("X25519");
    expect(keyPair.privateKey.usages).toEqual(["deriveBits"]);
    await expect(crypto.subtle.exportKey("pkcs8", keyPair.privateKey)).rejects.toThrow();
  });

  test("deterministic: the same secret gives the same key, in another page as in this one", async () => {
    const a = await deriveFactorKey({ mailboxId, factorId, kind: "passkey-prf", secret });
    const b = await deriveFactorKey({ mailboxId, factorId, kind: "passkey-prf", secret: new Uint8Array(secret) });
    expect(hex(factorPublicKey(a))).toBe(hex(factorPublicKey(b)));
  });

  test("bound to its mailbox, factor id, kind and secret: changing any one gives another key", async () => {
    const base = hex(factorPublicKey(await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret })));
    const other = new Uint8Array(secret);
    other[0] = other[0]! ^ 1;
    for (const ctx of [
      { mailboxId: newId("mbx"), factorId, kind: "recovery" as const, secret },
      { mailboxId, factorId: newId("wrp"), kind: "recovery" as const, secret },
      { mailboxId, factorId, kind: "passkey-prf" as const, secret },
      { mailboxId, factorId, kind: "recovery" as const, secret: other }, // pragma: allowlist secret (a test variable)
    ]) {
      expect(hex(factorPublicKey(await deriveFactorKey(ctx)))).not.toBe(base);
    }
  });

  test("the factor key and envelope v1's KEK come from one secret through different HKDF info, so neither reveals the other", async () => {
    const ikm = await referenceIkm(secret, mailboxId, factorId, "recovery");
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const kek = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(factorId), info: utf8("proprietor-mail/v1/kek/recovery") }, base, 256), // pragma: allowlist secret (HKDF parameter names)
    );
    expect(hex(ikm)).not.toBe(hex(kek));
  });

  test("the public key handed out is a copy: changing it changes nothing", async () => {
    const key = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret });
    const pk = factorPublicKey(key);
    pk.fill(0);
    expect(factorPublicKey(key).some((b) => b !== 0)).toBe(true);
  });

  test("refuses a secret that is not 32 bytes, an unknown kind, and an id that is empty or holds the separator", async () => {
    await expect(deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: new Uint8Array(31) })).rejects.toBeInstanceOf(TypeError);
    await expect(deriveFactorKey({ mailboxId, factorId, kind: "password" as WrapKind, secret })).rejects.toBeInstanceOf(TypeError);
    await expect(deriveFactorKey({ mailboxId: `${mailboxId}|x`, factorId, kind: "recovery", secret })).rejects.toBeInstanceOf(TypeError);
    await expect(deriveFactorKey({ mailboxId, factorId: "", kind: "recovery", secret })).rejects.toBeInstanceOf(TypeError);
  });

  test("a forged or cloned handle is refused", () => {
    expect(() => factorPublicKey({ factorId, kind: "recovery" })).toThrow(TypeError);
  });
});
