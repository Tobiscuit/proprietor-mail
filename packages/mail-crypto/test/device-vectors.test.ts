// D1b: contracts/device-v1.vectors.json (contracts/device-v1.md A9). Every positive vector opens
// or verifies with the package AND a second time straight from the contract's text (OpenSSL through
// node:crypto, @hpke/core and raw Web Crypto, none of src/), so the vectors cannot merely agree with
// the code; every negative case is refused by both.
import { createECDH, createHash, createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, DhkemX25519HkdfSha256, ExportOnly, HkdfSha256 } from "@hpke/core";
import { describe, expect, test } from "vitest";
import {
  actionPurpose,
  bindingKey,
  canonicalJson,
  DecryptionFailed,
  deriveFactorKey,
  factorPublicKey,
  openChallenge,
  openKeySeal,
  parseRecoveryKey,
  readActionDescriptor,
  signDeviceProof,
  verifyBindingTag,
  type FactorPrivateKey,
  type MailboxPrivateKey,
  type SealOpener,
  type TagRecipient,
} from "../src/index";
import { factorMaterialOf } from "../src/factor-keys";
import { importPrivateScalar, materialOf } from "../src/keys";
import { openSealWith } from "../src/seals";
import { b64urlDecode, b64urlEncode, fromHex, hex, sha256, utf8 } from "./reference";

const vectorsPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../contracts/device-v1.vectors.json");
const PKCS8_X25519 = "302e020100300506032b656e04220420";

interface KeyVector { label: string; sk: string; pk: string; keyId: string }
interface FactorVector { name: string; kind: "passkey-prf" | "recovery"; factorId: string; secretLabel: string; secret: string; recoveryDisplay?: string; ikm: string; skF: string; pkF: string }
interface P256Vector { label: string; d: string; publicKey: string }
interface SealVector { name: string; toKind: "device" | "factor" | "successor"; toId: string; sealedKeyId: string; recipient: string; sealed: string }
interface TagVector { name: string; keyId: string; recipient: Record<string, string | null>; message: string; tag: string }
interface ChallengeVector {
  name: string;
  purpose: "session" | "factor" | "key";
  challengeId: string;
  targetId: string;
  sealed: string;
  answer: string;
  /** Round 3, purposes factor and key: the descriptor's bytes (base64url), the request it digests, and the descriptor's digest. */
  descriptor?: string;
  request?: Record<string, unknown>;
  requestDigest?: string;
  actionDigest?: string;
}
type NegativeVector =
  | { name: string; open: "seal"; sealed: string; toKind: string; toId: string; sealedKeyId: string; recipient: string; expect: "DecryptionFailed" }
  | { name: string; open: "challenge"; sealed: string; purpose: string; challengeId: string; targetId: string; actionDigest?: string; recipient: string; expect: "DecryptionFailed" }
  | { name: string; open: "tag"; of: "device"; label: string; tag: string; expect: "invalid" }
  | { name: string; open: "deviceProof"; nonce: string; signature: string; expect: "invalid" };
interface Vectors {
  contract: string;
  mailboxId: string;
  mailboxKey: KeyVector;
  successorKey: KeyVector;
  factors: FactorVector[];
  device: { deviceId: string; label: string; signing: P256Vector; unlock: P256Vector };
  seals: SealVector[];
  tags: TagVector[];
  challenges: ChallengeVector[];
  deviceProof: { deviceId: string; challengeId: string; nonce: string; message: string; publicKey: string; signature: string };
  negative: NegativeVector[];
}

const vectors: Vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
const { mailboxId } = vectors;

// ---- The contract, read independently ------------------------------------------------------------

const clamp = (bytes: Uint8Array) => {
  const k = new Uint8Array(bytes);
  k[0] = k[0]! & 248;
  k[31] = (k[31]! & 127) | 64;
  return k;
};
function opensslX25519Public(skHex: string): string {
  const key = createPrivateKey({ key: Buffer.from(PKCS8_X25519 + skHex, "hex"), format: "der", type: "pkcs8" });
  return createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
}
function opensslZ(skHex: string): Uint8Array<ArrayBuffer> {
  const privateKey = createPrivateKey({ key: Buffer.from(PKCS8_X25519 + skHex, "hex"), format: "der", type: "pkcs8" }); // pragma: allowlist secret (a test variable)
  return new Uint8Array(diffieHellman({ privateKey, publicKey: createPublicKey(privateKey) })); // pragma: allowlist secret (a test variable)
}
const x25519Seals = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new ExportOnly() });
const p256Seals = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new ExportOnly() });
const challengeSuite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

async function x25519Pair(skHex: string): Promise<CryptoKeyPair> {
  const privateKey = await crypto.subtle.importKey("pkcs8", fromHex(PKCS8_X25519 + skHex), { name: "X25519" }, false, ["deriveBits"]); // pragma: allowlist secret (a test variable)
  const publicKey = await crypto.subtle.importKey("raw", fromHex(opensslX25519Public(skHex)), { name: "X25519" }, true, []);
  return { privateKey, publicKey };
}
async function p256Pair(v: P256Vector, name: "ECDH" | "ECDSA"): Promise<CryptoKeyPair> {
  const point = Buffer.from(v.publicKey, "hex");
  const jwk = { kty: "EC", crv: "P-256", d: Buffer.from(v.d, "hex").toString("base64url"), x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") };
  const privateKey = await crypto.subtle.importKey("jwk", jwk, { name, namedCurve: "P-256" }, false, name === "ECDH" ? ["deriveBits"] : ["sign"]); // pragma: allowlist secret (a test variable)
  const publicKey = await crypto.subtle.importKey("raw", point, { name, namedCurve: "P-256" }, true, name === "ECDH" ? [] : ["verify"]);
  return { privateKey, publicKey };
}
const factorByName = (name: string) => vectors.factors.find((f) => f.name === name)!;

/** The recipient's key pair for a vector's `recipient` reference, from the vector's own scalars. */
async function recipientPair(recipient: string): Promise<{ kem: "x25519" | "p256"; pair: CryptoKeyPair }> {
  if (recipient === "device.unlock") return { kem: "p256", pair: await p256Pair(vectors.device.unlock, "ECDH") };
  if (recipient === "mailboxKey") return { kem: "x25519", pair: await x25519Pair(vectors.mailboxKey.sk) };
  if (recipient === "successorKey") return { kem: "x25519", pair: await x25519Pair(vectors.successorKey.sk) };
  if (recipient.startsWith("factors.")) return { kem: "x25519", pair: await x25519Pair(factorByName(recipient.slice(8)).skF) };
  throw new Error(`unknown recipient ${recipient}`);
}

const sealInfo = (sealedKeyId: string, toKind: string, toId: string) => utf8(`proprietor-mail/v1/key-seal|${mailboxId}|${sealedKeyId}|${toKind}|${toId}`);

/** A4 from the contract's text: SetupBaseR, Export, AES-GCM decrypt (not unwrapKey): the PKCS #8 bytes. */
async function contractOpenSeal(kem: "x25519" | "p256", pair: CryptoKeyPair, aad: Uint8Array<ArrayBuffer>, sealed: string): Promise<string> {
  const bytes = b64urlDecode(sealed);
  const encBytes = kem === "p256" ? 65 : 32;
  if (bytes[0] !== 0x01 || bytes.length !== 1 + encBytes + 12 + 64) throw new Error("not a key seal");
  const ctx = await (kem === "p256" ? p256Seals : x25519Seals).createRecipientContext({ recipientKey: pair, enc: bytes.slice(1, 1 + encBytes), info: aad });
  const kek = await crypto.subtle.importKey("raw", await ctx.export(utf8("proprietor-mail/v1/key-seal/kek"), 32), "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(1 + encBytes, 13 + encBytes), additionalData: aad }, kek, bytes.slice(13 + encBytes));
  return hex(new Uint8Array(plain));
}

/** A6 from the contract's text: open with @hpke/core directly. */
async function contractOpenChallenge(pair: CryptoKeyPair, aad: string, sealed: string): Promise<string> {
  const bytes = b64urlDecode(sealed);
  if (bytes.length !== 80) throw new Error("not a challenge");
  return hex(new Uint8Array(await challengeSuite.open({ recipientKey: pair, enc: bytes.slice(0, 32), info: utf8("proprietor-mail/v1/challenge") }, bytes.slice(32), utf8(aad))));
}

/** A5 from the contract's text: OpenSSL's z, then HKDF and HMAC with raw Web Crypto. */
async function contractTag(skHex: string, keyId: string, message: string): Promise<string> {
  const base = await crypto.subtle.importKey("raw", opensslZ(skHex), "HKDF", false, ["deriveBits"]);
  const kbind = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(`proprietor-mail/v1/binding|${mailboxId}|${keyId}`) }, base, 256); // pragma: allowlist secret (HKDF parameter names)
  const hmac = await crypto.subtle.importKey("raw", kbind, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64urlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, utf8(message))));
}

/** A7 from the contract's text: a verifier written for the test (Mail's is verifyDeviceProof in src/proofs.ts). */
async function contractVerifyProof(publicKeyHex: string, message: string, signature: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", fromHex(publicKeyHex), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64urlDecode(signature), utf8(message));
}

// ---- The package's handles for the vectors' keys --------------------------------------------------

const k1: MailboxPrivateKey = await importPrivateScalar(fromHex(vectors.mailboxKey.sk));
const k2: MailboxPrivateKey = await importPrivateScalar(fromHex(vectors.successorKey.sk));
const factorKeys = new Map<string, FactorPrivateKey>();
for (const f of vectors.factors) {
  factorKeys.set(f.name, await deriveFactorKey({ mailboxId, factorId: f.factorId, kind: f.kind, secret: fromHex(f.secret) })); // pragma: allowlist secret (a test vector)
}
async function opener(v: { recipient: string; toId: string }): Promise<SealOpener> {
  if (v.recipient === "device.unlock") {
    const pair = await p256Pair(vectors.device.unlock, "ECDH");
    return { kind: "device", deviceId: v.toId, privateKey: pair.privateKey, publicKey: fromHex(vectors.device.unlock.publicKey) }; // pragma: allowlist secret (a CryptoKey reference)
  }
  if (v.recipient === "successorKey") return { kind: "successor", key: k2 };
  return { kind: "factor", key: factorKeys.get(v.recipient.slice(8))! };
}

// ---- Tests ----------------------------------------------------------------------------------------

describe("D1b vectors: the file has every case A9 lists", () => {
  test("a fixed mailbox key, a PRF output and a recovery secret with their factor keys, a seal to each recipient kind, two tags, a challenge per purpose, a device proof, and the negative cases", () => {
    expect(vectors.contract).toBe("contracts/device-v1.md");
    expect(vectors.factors.map((f) => f.kind)).toEqual(["passkey-prf", "recovery"]);
    expect(vectors.seals.map((s) => s.toKind)).toEqual(["device", "factor", "successor"]);
    expect(vectors.tags.map((t) => t.recipient.kind)).toEqual(["device", "factor"]);
    expect(vectors.challenges.map((c) => c.purpose)).toEqual(["session", "factor", "key"]);
    expect(vectors.deviceProof.signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
    const names = vectors.negative.map((n) => n.name);
    for (const required of [
      "a device seal opened with another device id",
      "a factor seal opened with another factor id",
      "a successor seal opened with toKind factor",
      "a factor seal opened with toKind successor",
      "a challenge opened as a key seal",
      "a key seal opened as a challenge",
      "a message key envelope (envelope v1) presented as a challenge",
      "a factor challenge opened with another action's digest",
      "a key challenge opened with another action's digest",
      "a tag over a changed label",
      "a device proof over another nonce",
    ]) {
      expect(names, required).toContain(required);
    }
  });
});

describe("D1b vectors: the keys", () => {
  test.each([["mailboxKey"], ["successorKey"]] as const)("%s: sk = SHA-256(label), clamped; pk = X25519(sk, 9) by OpenSSL; keyId from pk", async (which) => {
    const v = vectors[which];
    expect(v.sk).toBe(hex(clamp(await sha256(utf8(v.label)))));
    expect(v.pk).toBe(opensslX25519Public(v.sk));
    expect(v.keyId).toBe(hex((await sha256(fromHex(v.pk))).subarray(0, 16)));
    expect((which === "mailboxKey" ? k1 : k2).keyId).toBe(v.keyId);
  });

  test.each(vectors.factors.map((f) => [f.name, f] as const))("factor %s: ikm, skF and pkF follow A2 (Web Crypto HKDF, then RFC 9180 DeriveKeyPair; pkF by OpenSSL and @hpke/core)", async (_, f) => {
    expect(f.secret).toBe(hex(await sha256(utf8(f.secretLabel))));
    if (f.recoveryDisplay !== undefined) expect(hex(parseRecoveryKey(f.recoveryDisplay))).toBe(f.secret);
    const base = await crypto.subtle.importKey("raw", fromHex(f.secret), "HKDF", false, ["deriveBits"]);
    const ikm = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(f.factorId), info: utf8(`proprietor-mail/v1/factor-key|${mailboxId}|${f.factorId}|${f.kind}`) }, base, 256), // pragma: allowlist secret (HKDF parameter names)
    );
    expect(hex(ikm)).toBe(f.ikm);
    const kem = new DhkemX25519HkdfSha256();
    const derived = await kem.deriveKeyPair(fromHex(f.ikm));
    expect(hex(new Uint8Array(await kem.serializePrivateKey(derived.privateKey)))).toBe(f.skF);
    expect(hex(new Uint8Array(await kem.serializePublicKey(derived.publicKey)))).toBe(f.pkF);
    expect(opensslX25519Public(f.skF)).toBe(f.pkF);
    expect(hex(factorPublicKey(factorKeys.get(f.name)!))).toBe(f.pkF);
  });

  test("the device's keys: d = SHA-256(label) as a P-256 scalar; the public points by OpenSSL", async () => {
    for (const v of [vectors.device.signing, vectors.device.unlock]) {
      expect(v.d).toBe(hex(await sha256(utf8(v.label))));
      const ecdh = createECDH("prime256v1");
      ecdh.setPrivateKey(Buffer.from(v.d, "hex"));
      expect(v.publicKey).toBe(hex(new Uint8Array(ecdh.getPublicKey())));
    }
  });
});

describe("D1b vectors: every positive vector opens or verifies", () => {
  test.each(vectors.seals.map((s) => [s.name, s] as const))("key seal %s: opens with the package and from the contract to the sealed key's PKCS #8 form", async (_, s) => {
    expect(s.sealedKeyId).toBe(vectors.mailboxKey.keyId);
    expect(b64urlDecode(s.sealed).length).toBe(s.toKind === "device" ? 142 : 109);
    const opened = await openKeySeal(await opener(s), { mailboxId, sealedKeyId: s.sealedKeyId }, s.sealed);
    expect(opened.keyId).toBe(s.sealedKeyId);
    const { kem, pair } = await recipientPair(s.recipient);
    expect(await contractOpenSeal(kem, pair, sealInfo(s.sealedKeyId, s.toKind, s.toId), s.sealed)).toBe(PKCS8_X25519 + vectors.mailboxKey.sk);
    if (s.toKind === "successor") expect(s.toId).toBe(vectors.successorKey.keyId);
    if (s.toKind === "device") expect(s.toId).toBe(vectors.device.deviceId);
  });

  test.each(vectors.tags.map((t) => [t.name, t] as const))("binding tag for a %s: the message is the contract's, the tag is HMAC under kbind, and the package verifies it", async (_, t) => {
    const r = t.recipient;
    const expectedMessage =
      r.kind === "device"
        ? `proprietor-mail/v1/recipient|${mailboxId}|${t.keyId}|device|${r.deviceId}|${b64urlEncode(utf8(r.label!))}|${r.signingKey}|${r.unlockKey ?? "-"}`
        : `proprietor-mail/v1/recipient|${mailboxId}|${t.keyId}|factor|${r.factorId}|${r.factorKind}|${b64urlEncode(utf8(r.label!))}|${r.factorKey}|${r.credentialId ?? "-"}`;
    expect(t.message).toBe(expectedMessage);
    expect(await contractTag(vectors.mailboxKey.sk, t.keyId, t.message)).toBe(t.tag);
    const recipient: TagRecipient =
      r.kind === "device"
        ? { kind: "device", deviceId: r.deviceId!, label: r.label!, signingKey: b64urlDecode(r.signingKey!), unlockKey: r.unlockKey === null ? null : b64urlDecode(r.unlockKey!) }
        : { kind: "factor", factorId: r.factorId!, factorKind: r.factorKind as "passkey-prf", label: r.label!, factorKey: b64urlDecode(r.factorKey!), credentialId: r.credentialId ?? null }; // pragma: allowlist secret (public test keys from the vectors)
    expect(await verifyBindingTag(await bindingKey(k1, { mailboxId }), recipient, t.tag)).toBe(true);
  });

  test.each(vectors.challenges.map((c) => [c.name, c] as const))("challenge %s: the package and @hpke/core both open it to its answer", async (_, c) => {
    const sha = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("base64url");
    let digestPart = "";
    if (c.purpose === "session") {
      expect(c.descriptor ?? c.actionDigest).toBeUndefined();
    } else {
      // Round 3 (A6, A10): the descriptor reads strictly, its kind belongs to the purpose, it holds the
      // request's digest (RFC 8785, checked against this file's request), and its digest is the AAD's.
      const bytes = b64urlDecode(c.descriptor!);
      const descriptor = readActionDescriptor(bytes)!;
      expect(descriptor).not.toBeNull();
      expect(descriptor.mailboxId).toBe(mailboxId);
      expect(actionPurpose(descriptor.kind)).toBe(c.purpose);
      expect(descriptor.kind).toBe(c.purpose === "factor" ? "open-session" : "upgrade");
      expect(descriptor.request).toBe(c.requestDigest);
      expect(sha(utf8(canonicalJson(c.request)))).toBe(c.requestDigest);
      expect(sha(bytes)).toBe(c.actionDigest);
      if (c.purpose === "factor") expect(c.request).toEqual({ challengeId: vectors.challenges[0]!.challengeId });
      digestPart = `|${c.actionDigest}`;
    }
    const aad = `proprietor-mail/v1/challenge|${mailboxId}|${c.challengeId}|${c.purpose}|${c.targetId}${digestPart}`;
    const key = c.purpose === "factor" ? factorKeys.get("passkey")! : k1;
    expect(c.targetId).toBe(c.purpose === "factor" ? factorByName("passkey").factorId : vectors.mailboxKey.keyId);
    const ids = { mailboxId, challengeId: c.challengeId, ...(c.actionDigest === undefined ? {} : { actionDigest: c.actionDigest }) };
    expect(hex(await openChallenge(key, ids, c.sealed))).toBe(c.answer);
    const pair = c.purpose === "factor" ? factorMaterialOf(factorKeys.get("passkey")!).keyPair : await x25519Pair(vectors.mailboxKey.sk);
    expect(await contractOpenChallenge(pair, aad, c.sealed)).toBe(c.answer);
  });

  test("the device proof verifies against its public key, over the contract's message; the package's own signature over it does too", async () => {
    const p = vectors.deviceProof;
    expect(p.publicKey).toBe(vectors.device.signing.publicKey);
    expect(p.message).toBe(`proprietor-mail/v1/device-proof|${mailboxId}|${p.deviceId}|${p.challengeId}|${p.nonce}`);
    expect(await contractVerifyProof(p.publicKey, p.message, p.signature)).toBe(true);
    const { privateKey } = await p256Pair(vectors.device.signing, "ECDSA"); // pragma: allowlist secret (a test variable)
    const fresh = await signDeviceProof(privateKey, { mailboxId, deviceId: p.deviceId, challengeId: p.challengeId, nonce: b64urlDecode(p.nonce) });
    expect(await contractVerifyProof(p.publicKey, p.message, fresh)).toBe(true);
  });
});

describe("D1b vectors: every negative case is refused", () => {
  test.each(vectors.negative.map((n) => [n.name, n] as const))("%s", async (_, n) => {
    if (n.open === "seal") {
      const { kem, pair } = await recipientPair(n.recipient);
      const info = sealInfo(n.sealedKeyId, n.toKind, n.toId);
      await expect(openSealWith(kem, pair, info, b64urlDecode(n.sealed), false)).rejects.toBeInstanceOf(DecryptionFailed);
      await expect(contractOpenSeal(kem, pair, info, n.sealed)).rejects.toThrow();
      // Where the public API can name the recipient this way, it refuses too.
      if ((n.toKind === "device" && n.recipient === "device.unlock") || (n.toKind === "factor" && n.recipient.startsWith("factors.") && n.toId === factorByName(n.recipient.slice(8)).factorId)) {
        await expect(openKeySeal(await opener(n), { mailboxId, sealedKeyId: n.sealedKeyId }, n.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
      }
      return;
    }
    if (n.open === "challenge") {
      const ids = { mailboxId, challengeId: n.challengeId, ...(n.actionDigest === undefined ? {} : { actionDigest: n.actionDigest }) };
      if (n.recipient.startsWith("factors.")) {
        const key = factorKeys.get(n.recipient.slice(8))!;
        expect(n.targetId).toBe(key.factorId);
        await expect(openChallenge(key, ids, n.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
      } else {
        const key = n.recipient === "mailboxKey" ? k1 : k2;
        expect(n.targetId).toBe(materialOf(key).keyId);
        await expect(openChallenge(key, ids, n.sealed)).rejects.toBeInstanceOf(DecryptionFailed);
      }
      const { pair } = await recipientPair(n.recipient);
      const digestPart = n.actionDigest === undefined ? "" : `|${n.actionDigest}`;
      await expect(contractOpenChallenge(pair, `proprietor-mail/v1/challenge|${mailboxId}|${n.challengeId}|${n.purpose}|${n.targetId}${digestPart}`, n.sealed)).rejects.toThrow();
      return;
    }
    if (n.open === "tag") {
      const t = vectors.tags.find((x) => x.name === n.of)!;
      const r = t.recipient;
      const changed: TagRecipient = { kind: "device", deviceId: r.deviceId!, label: n.label, signingKey: b64urlDecode(r.signingKey!), unlockKey: b64urlDecode(r.unlockKey!) }; // pragma: allowlist secret (public test keys from the vectors)
      expect(await verifyBindingTag(await bindingKey(k1, { mailboxId }), changed, n.tag)).toBe(false);
      expect(await contractTag(vectors.mailboxKey.sk, t.keyId, t.message.replace(b64urlEncode(utf8(r.label!)), b64urlEncode(utf8(n.label))))).not.toBe(n.tag);
      return;
    }
    const p = vectors.deviceProof;
    const message = `proprietor-mail/v1/device-proof|${mailboxId}|${p.deviceId}|${p.challengeId}|${n.nonce}`;
    expect(await contractVerifyProof(p.publicKey, message, n.signature)).toBe(false);
  });

  test("each negative differs from a positive vector in exactly the way its name says", () => {
    const byName = (name: string) => vectors.negative.find((n) => n.name === name)!;
    const [deviceSeal, factorSeal, successorSeal] = vectors.seals;
    const n1 = byName("a device seal opened with another device id") as Extract<NegativeVector, { open: "seal" }>;
    expect(n1.sealed).toBe(deviceSeal!.sealed);
    expect(n1.toKind).toBe("device");
    expect(n1.toId).not.toBe(deviceSeal!.toId);
    const n2 = byName("a factor seal opened with another factor id") as Extract<NegativeVector, { open: "seal" }>;
    expect(n2.sealed).toBe(factorSeal!.sealed);
    expect(n2.toKind).toBe("factor");
    expect(n2.toId).not.toBe(factorSeal!.toId);
    const n3 = byName("a successor seal opened with toKind factor") as Extract<NegativeVector, { open: "seal" }>;
    expect([n3.sealed, n3.toId, n3.recipient]).toEqual([successorSeal!.sealed, successorSeal!.toId, successorSeal!.recipient]);
    const n4 = byName("a factor seal opened with toKind successor") as Extract<NegativeVector, { open: "seal" }>;
    expect([n4.sealed, n4.toId, n4.recipient]).toEqual([factorSeal!.sealed, factorSeal!.toId, factorSeal!.recipient]);
    const n5 = byName("a challenge opened as a key seal") as Extract<NegativeVector, { open: "seal" }>;
    expect(n5.sealed).toBe(vectors.challenges[0]!.sealed);
    const n6 = byName("a key seal opened as a challenge") as Extract<NegativeVector, { open: "challenge" }>;
    expect(n6.sealed).toBe(successorSeal!.sealed);
    for (const [name, i, purpose] of [
      ["a factor challenge opened with another action's digest", 1, "factor"],
      ["a key challenge opened with another action's digest", 2, "key"],
    ] as const) {
      const n = byName(name) as Extract<NegativeVector, { open: "challenge" }>;
      const c = vectors.challenges[i]!;
      expect([n.sealed, n.challengeId, n.targetId, n.purpose]).toEqual([c.sealed, c.challengeId, c.targetId, purpose]);
      expect(n.actionDigest).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(n.actionDigest).not.toBe(c.actionDigest);
    }
    const envelope = byName("a message key envelope (envelope v1) presented as a challenge") as Extract<NegativeVector, { open: "challenge" }>;
    expect(b64urlDecode(envelope.sealed).length).toBe(80);
    expect(envelope.targetId).toBe(vectors.mailboxKey.keyId);
    const tag = byName("a tag over a changed label") as Extract<NegativeVector, { open: "tag" }>;
    expect(tag.tag).toBe(vectors.tags[0]!.tag);
    expect(tag.label).not.toBe(vectors.tags[0]!.recipient.label);
    const proof = byName("a device proof over another nonce") as Extract<NegativeVector, { open: "deviceProof" }>;
    expect(proof.signature).toBe(vectors.deviceProof.signature);
    expect(proof.nonce).not.toBe(vectors.deviceProof.nonce);
    expect(b64urlDecode(proof.nonce).length).toBe(32);
  });
});
