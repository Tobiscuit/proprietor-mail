// Page-side diagnostics for the browser tests (bundled into the harness; test code only).
//
// 1. A recorder: every crypto.subtle call that throws is kept, with what it was asked to do and the
//    data it was given, so a failing flow says WHICH operation failed and on WHAT input.
// 2. A probe: each primitive device-v1 and envelope v1 use, run over many fresh random inputs, with
//    the results checked for length and against the engine's own other answers (the scalar an
//    imported key reports back, the public key two ways). It reports counts, and a few failing inputs.
//
// Every key here is random and made for the run: test values, never used for mail.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  bindingKey,
  bindingTag,
  deriveFactorKey,
  factorPublicKey,
  generateMailboxKey,
  generateUnlockKey,
  newId,
  openChallenge,
  openKeySeal,
  sealKey,
  unwrapPrivateKey,
  verifyBindingTag,
  wrapPrivateKey,
} from "@proprietor/mail-crypto";

const hex = (bytes: ArrayBuffer | Uint8Array): string =>
  Array.from(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
const b64url = (bytes: Uint8Array): string => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const random = (n: number): Uint8Array<ArrayBuffer> => crypto.getRandomValues(new Uint8Array(n));
const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);

// ---- 1. The recorder ------------------------------------------------------------------------------

export interface CryptoFailure {
  method: string;
  /** What the call was asked to do: algorithm names and curves, formats, lengths, key kinds. */
  call: Record<string, unknown>;
  /** The key data or the input bytes, as hex (random test values). */
  data?: string;
  error: { name: string; message: string };
}

const failures: CryptoFailure[] = [];

function describeAlgorithm(a: unknown): unknown {
  if (typeof a === "string") return a;
  if (typeof a !== "object" || a === null) return String(a);
  const o = a as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v instanceof CryptoKey) out[k] = describeKey(v);
    else if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) out[k] = `${(v as ArrayBuffer).byteLength} bytes: ${hex(new Uint8Array(v instanceof ArrayBuffer ? v : (v as ArrayBufferView).buffer, v instanceof ArrayBuffer ? 0 : (v as ArrayBufferView).byteOffset, (v as ArrayBufferView).byteLength))}`;
    else if (typeof v === "object" && v !== null) out[k] = (v as { name?: unknown }).name ?? "object";
    else out[k] = v;
  }
  return out;
}

function describeKey(k: unknown): unknown {
  if (!(k instanceof CryptoKey)) return typeof k;
  const a = k.algorithm as unknown as Record<string, unknown>;
  return { type: k.type, extractable: k.extractable, algorithm: a.name, curve: a.namedCurve, usages: [...k.usages] };
}

function bytesOf(v: unknown): Uint8Array | null {
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  return null;
}

/** Wraps every crypto.subtle method once, to keep the calls that throw. */
export function installRecorder(): void {
  const subtle = crypto.subtle as unknown as Record<string, (...args: unknown[]) => Promise<unknown>>;
  if ((subtle as unknown as { __recorded?: boolean }).__recorded) return;
  for (const method of ["importKey", "exportKey", "generateKey", "deriveBits", "deriveKey", "wrapKey", "unwrapKey", "sign", "verify", "encrypt", "decrypt", "digest"]) {
    const original = subtle[method]!.bind(crypto.subtle);
    subtle[method] = async (...args: unknown[]) => {
      try {
        return await original(...args);
      } catch (e) {
        const call: Record<string, unknown> = {};
        let data: Uint8Array | null = null;
        if (method === "importKey") {
          call.format = args[0];
          call.algorithm = describeAlgorithm(args[2]);
          call.extractable = args[3];
          call.usages = args[4];
          data = bytesOf(args[1]);
          if (data) call.length = data.length;
          else call.jwk = Object.keys((args[1] as object) ?? {});
        } else if (method === "unwrapKey") {
          call.format = args[0];
          call.unwrapAlgorithm = describeAlgorithm(args[3]);
          call.unwrappedKeyAlgorithm = describeAlgorithm(args[4]);
          call.extractable = args[5];
          data = bytesOf(args[1]);
          if (data) call.length = data.length;
        } else if (method === "deriveBits" || method === "deriveKey") {
          call.algorithm = describeAlgorithm(args[0]);
          call.baseKey = describeKey(args[1]);
          call.lengthOrDerivedType = method === "deriveBits" ? args[2] : describeAlgorithm(args[2]);
        } else if (method === "wrapKey" || method === "exportKey") {
          call.format = args[0];
          call.key = describeKey(args[1]);
          if (method === "wrapKey") call.wrapAlgorithm = describeAlgorithm(args[3]);
        } else {
          call.algorithm = describeAlgorithm(args[0]);
          call.key = describeKey(args[1]);
        }
        failures.push({
          method,
          call,
          ...(data ? { data: hex(data) } : {}),
          error: e instanceof Error ? { name: e.name, message: e.message } : { name: "unknown", message: String(e) },
        });
        throw e;
      }
    };
  }
  (subtle as unknown as { __recorded?: boolean }).__recorded = true;
}

/** The failing calls since the last time they were taken. */
export function takeFailures(): CryptoFailure[] {
  return failures.splice(0, failures.length);
}

// ---- 2. The probe ---------------------------------------------------------------------------------

export interface ProbeLine {
  tries: number;
  /** The operation threw. */
  threw: number;
  /** It answered, but with a result of the wrong length. */
  wrongLength: number;
  /** It answered, but the answer disagrees with the engine's other answer for the same key. */
  mismatch: number;
  /** A few failing cases: what failed, and the input that made it fail. */
  examples: unknown[];
}

const X25519 = { name: "X25519" };
const PKCS8_X25519 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);
const BASE_POINT = Uint8Array.of(9, ...new Uint8Array(31));

function clamp(k: Uint8Array): Uint8Array<ArrayBuffer> {
  const c = new Uint8Array(k);
  c[0] = c[0]! & 248;
  c[31] = (c[31]! & 127) | 64;
  return c;
}

function fromB64url(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** The facts about a 32-byte value that a value-dependent failure would hinge on. */
function shape(bytes: Uint8Array): Record<string, unknown> {
  return {
    hex: hex(bytes),
    firstByte: bytes[0],
    lastByte: bytes[bytes.length - 1],
    leadingZeroBytes: bytes.findIndex((b) => b !== 0),
    trailingZeroBytes: [...bytes].reverse().findIndex((b) => b !== 0),
    topBitOfLast: (bytes[bytes.length - 1]! & 0x80) !== 0,
  };
}

const challengeSuite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

type Check = (record: (kind: "threw" | "wrongLength" | "mismatch", example: unknown) => void) => Promise<void>;

const CHECKS: Record<string, Check> = {
  // generateKey X25519, then the public key raw and the private key pkcs8 (wrapKey's form).
  async "X25519 generateKey + raw/pkcs8 export"(record) {
    const pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    if (raw.length !== 32) return record("wrongLength", { raw: hex(raw) });
    const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
    if (pkcs8.length !== 48 || hex(pkcs8.subarray(0, 16)) !== hex(PKCS8_X25519)) record("wrongLength", { pkcs8: hex(pkcs8), length: pkcs8.length });
  },
  // X25519(k, 9) by deriveBits must be the public key the engine exports for k.
  async "X25519 deriveBits with the base point"(record) {
    const pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    const scalar = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).subarray(16);
    const base = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    let bits: Uint8Array;
    try {
      bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base } as never, pair.privateKey, 256));
    } catch (e) {
      return record("threw", { error: (e as Error).name, scalar: shape(scalar), publicKey: shape(raw) });
    }
    if (bits.length !== 32) return record("wrongLength", { bits: hex(bits) });
    if (hex(bits) !== hex(raw)) record("mismatch", { derived: shape(bits), exported: shape(raw), scalar: shape(scalar) });
  },
  // A5: X25519 of the private key with its own public key.
  async "X25519 deriveBits with its own public key (A5)"(record) {
    const pair = (await crypto.subtle.generateKey(X25519, false, ["deriveBits"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    try {
      const z = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pair.publicKey } as never, pair.privateKey, 256));
      if (z.length !== 32) record("wrongLength", { z: hex(z) });
    } catch (e) {
      record("threw", { error: (e as Error).name, publicKey: shape(raw) });
    }
  },
  // A raw public key the engine produced must import again.
  async "X25519 raw import of a generated public key"(record) {
    const pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    try {
      await crypto.subtle.importKey("raw", raw, X25519, true, []);
    } catch (e) {
      record("threw", { error: (e as Error).name, publicKey: shape(raw) });
    }
  },
  // The scalar this package builds (A2, the test vectors): a clamped random scalar as PKCS #8.
  async "X25519 pkcs8 import of a clamped scalar"(record) {
    const scalar = clamp(random(32));
    const pkcs8 = new Uint8Array([...PKCS8_X25519, ...scalar]);
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8, X25519, true, ["deriveBits"]);
    } catch (e) {
      return record("threw", { error: (e as Error).name, scalar: shape(scalar) });
    }
    // The engine's own reading of the key: its JWK d must be the scalar given, x its public key.
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const d = fromB64url((jwk as JsonWebKey).d!);
    if (hex(d) !== hex(scalar)) record("mismatch", { given: shape(scalar), readBack: shape(d) });
  },
  // The same scalar, non-extractable, as deriveFactorKey imports it, then its public key.
  async "X25519 pkcs8 import, non-extractable, then deriveBits with the base point"(record) {
    const scalar = clamp(random(32));
    const pkcs8 = new Uint8Array([...PKCS8_X25519, ...scalar]);
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8, X25519, false, ["deriveBits"]);
    } catch (e) {
      return record("threw", { error: (e as Error).name, step: "import", scalar: shape(scalar) });
    }
    const extractable = await crypto.subtle.importKey("pkcs8", pkcs8, X25519, true, ["deriveBits"]);
    const x = fromB64url(((await crypto.subtle.exportKey("jwk", extractable)) as JsonWebKey).x!);
    const base = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    try {
      const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base } as never, key, 256));
      if (bits.length !== 32) record("wrongLength", { bits: hex(bits), scalar: shape(scalar) });
      else if (hex(bits) !== hex(x)) record("mismatch", { derived: shape(bits), jwkX: shape(x), scalar: shape(scalar) });
    } catch (e) {
      record("threw", { error: (e as Error).name, step: "deriveBits", scalar: shape(scalar), jwkX: shape(x) });
    }
  },
  // The edges a value-dependent bug would hide in: a clamped scalar whose first byte is zero (1 in 32
  // of random ones), as the engine imports it and reads it back.
  async "X25519 pkcs8 import of a clamped scalar whose first byte is zero"(record) {
    const scalar = clamp(random(32));
    scalar[0] = 0;
    const pkcs8 = new Uint8Array([...PKCS8_X25519, ...scalar]);
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8, X25519, true, ["deriveBits"]);
    } catch (e) {
      return record("threw", { error: (e as Error).name, step: "import", scalar: shape(scalar) });
    }
    const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
    const d = fromB64url(jwk.d!);
    if (hex(d) !== hex(scalar)) return record("mismatch", { step: "jwk d", given: shape(scalar), readBack: shape(d) });
    const base = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    try {
      const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base } as never, key, 256));
      if (hex(bits) !== hex(fromB64url(jwk.x!))) record("mismatch", { step: "public key", derived: shape(bits), jwkX: shape(fromB64url(jwk.x!)), scalar: shape(scalar) });
    } catch (e) {
      record("threw", { error: (e as Error).name, step: "deriveBits", scalar: shape(scalar) });
    }
  },
  // ...and keys whose public key starts or ends with a zero byte (about 1 in 256 each), searched for:
  // their raw export, their raw import, the base-point derivation, and a wrap round trip.
  async "X25519 keys whose public key starts or ends with a zero byte"(record) {
    for (let i = 0; i < 2048; i++) {
      const pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
      const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
      if (raw.length !== 32) return record("wrongLength", { step: "raw export", raw: hex(raw) });
      if (raw[0] !== 0 && raw[31] !== 0) continue;
      const scalar = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).subarray(16);
      try {
        await crypto.subtle.importKey("raw", raw, X25519, true, []);
      } catch (e) {
        return record("threw", { error: (e as Error).name, step: "raw import", publicKey: shape(raw), scalar: shape(scalar) });
      }
      const base = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
      try {
        const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base } as never, pair.privateKey, 256));
        if (hex(bits) !== hex(raw)) return record("mismatch", { step: "base point", derived: shape(bits), exported: shape(raw) });
      } catch (e) {
        return record("threw", { error: (e as Error).name, step: "deriveBits", publicKey: shape(raw) });
      }
      const kek = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"])) as CryptoKey;
      const iv = random(12);
      try {
        const wrapped = await crypto.subtle.wrapKey("pkcs8", pair.privateKey, kek, { name: "AES-GCM", iv });
        await crypto.subtle.unwrapKey("pkcs8", wrapped, kek, { name: "AES-GCM", iv }, X25519, false, ["deriveBits"]);
      } catch (e) {
        return record("threw", { error: (e as Error).name, step: "wrap round trip", publicKey: shape(raw) });
      }
      return;
    }
  },
  // A2 as the package does it, end to end.
  async "deriveFactorKey (A2)"(record) {
    const secret = random(32); // pragma: allowlist secret (random test values made for the probe)
    try {
      const key = await deriveFactorKey({ mailboxId: newId("mbx"), factorId: newId("wrp"), kind: "recovery", secret });
      if (factorPublicKey(key).length !== 32) record("wrongLength", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, secret: hex(secret) }); // pragma: allowlist secret (random test values made for the probe)
    }
  },
  // A5 and DeriveKeyPair: HKDF with an empty salt.
  async "HKDF deriveBits with an empty salt"(record) {
    const ikm = random(32);
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    try {
      const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: random(16) }, base, 256));
      if (bits.length !== 32) record("wrongLength", { bits: hex(bits) });
    } catch (e) {
      record("threw", { error: (e as Error).name, ikm: hex(ikm) });
    }
  },
  // A5: the binding key is HKDF into an HMAC key, then a tag.
  async "HKDF deriveKey to HMAC, then sign"(record) {
    const base = await crypto.subtle.importKey("raw", random(32), "HKDF", false, ["deriveKey"]);
    try {
      const hmac = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: random(16) }, base, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
      const tag = new Uint8Array(await crypto.subtle.sign("HMAC", hmac, random(64)));
      if (tag.length !== 32) record("wrongLength", { tag: hex(tag) });
    } catch (e) {
      record("threw", { error: (e as Error).name });
    }
  },
  // envelope v1 (D21) and A4: wrapKey and unwrapKey of an X25519 PKCS #8 key under AES-GCM.
  async "wrapKey + unwrapKey of an X25519 pkcs8 key"(record) {
    const pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    const scalar = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).subarray(16);
    const kek = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"])) as CryptoKey;
    const iv = random(12);
    const wrapped = new Uint8Array(await crypto.subtle.wrapKey("pkcs8", pair.privateKey, kek, { name: "AES-GCM", iv }));
    if (wrapped.length !== 64) return record("wrongLength", { wrapped: wrapped.length, scalar: shape(scalar) });
    let back: CryptoKey;
    try {
      back = await crypto.subtle.unwrapKey("pkcs8", wrapped, kek, { name: "AES-GCM", iv }, X25519, false, ["deriveBits"]);
    } catch (e) {
      return record("threw", { error: (e as Error).name, step: "unwrapKey", scalar: shape(scalar), publicKey: shape(raw) });
    }
    const base = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base } as never, back, 256));
    if (hex(bits) !== hex(raw)) record("mismatch", { derived: shape(bits), exported: shape(raw), scalar: shape(scalar) });
  },
  // envelope v1 wraps as the package makes and opens them (S6a's path).
  async "wrapPrivateKey + unwrapPrivateKey"(record) {
    const { privateKey, publicKey } = await generateMailboxKey();
    const mailboxId = newId("mbx");
    const secret = random(32); // pragma: allowlist secret (random test values made for the probe)
    try {
      const wrap = await wrapPrivateKey(privateKey, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
      const back = await unwrapPrivateKey(wrap, { mailboxId, secret });
      if (back.keyId !== publicKey.keyId) record("mismatch", { publicKey: shape(publicKey.publicKey) });
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, publicKey: shape(publicKey.publicKey) });
    }
  },
  // A5 as the package does it: the binding key of a mailbox key, a tag, its verification.
  async "bindingKey + bindingTag (A5)"(record) {
    const { privateKey, publicKey } = await generateMailboxKey();
    const signing = new Uint8Array([4, ...random(64)]);
    try {
      const bk = await bindingKey(privateKey, { mailboxId: newId("mbx") });
      const recipient = { kind: "device" as const, deviceId: newId("dev"), label: "Probe", signingKey: signing, unlockKey: null };
      const tag = await bindingTag(bk, recipient);
      if (!(await verifyBindingTag(bk, recipient, tag))) record("mismatch", { publicKey: shape(publicKey.publicKey) });
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, publicKey: shape(publicKey.publicKey) });
    }
  },
  // A4, X25519 KEM: a successor seal.
  async "sealKey + openKeySeal, X25519 (successor)"(record) {
    const sealed = await generateMailboxKey();
    const to = await generateMailboxKey();
    const mailboxId = newId("mbx");
    try {
      const s = await sealKey(sealed.privateKey, { mailboxId }, { kind: "successor", publicKey: to.publicKey.publicKey });
      const back = await openKeySeal({ kind: "successor", key: to.privateKey }, { mailboxId, sealedKeyId: sealed.publicKey.keyId }, s);
      if (back.keyId !== sealed.publicKey.keyId) record("mismatch", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, sealedPublic: shape(sealed.publicKey.publicKey), toPublic: shape(to.publicKey.publicKey) });
    }
  },
  // A4, X25519 KEM to a factor key (A2).
  async "sealKey + openKeySeal, X25519 (factor)"(record) {
    const sealed = await generateMailboxKey();
    const mailboxId = newId("mbx");
    const factorId = newId("wrp");
    try {
      const factor = await deriveFactorKey({ mailboxId, factorId, kind: "passkey-prf", secret: random(32) }); // pragma: allowlist secret (random test values made for the probe)
      const s = await sealKey(sealed.privateKey, { mailboxId }, { kind: "factor", factorId, publicKey: factorPublicKey(factor) });
      const back = await openKeySeal({ kind: "factor", key: factor }, { mailboxId, sealedKeyId: sealed.publicKey.keyId }, s);
      if (back.keyId !== sealed.publicKey.keyId) record("mismatch", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message });
    }
  },
  // A4, P-256 KEM to a device's unlock key.
  async "sealKey + openKeySeal, P-256 (device)"(record) {
    const sealed = await generateMailboxKey();
    const unlock = await generateUnlockKey();
    const mailboxId = newId("mbx");
    const deviceId = newId("dev");
    try {
      const s = await sealKey(sealed.privateKey, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
      const back = await openKeySeal({ kind: "device", deviceId, privateKey: unlock.privateKey, publicKey: unlock.publicKey }, { mailboxId, sealedKeyId: sealed.publicKey.keyId }, s); // pragma: allowlist secret (random test values made for the probe)
      if (back.keyId !== sealed.publicKey.keyId) record("mismatch", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, unlockPublic: hex(unlock.publicKey) });
    }
  },
  // A6: a challenge sealed as Mail seals it (written from the contract here), opened with the mailbox key.
  async "openChallenge (A6)"(record) {
    const key = await generateMailboxKey();
    const mailboxId = newId("mbx");
    const challengeId = newId("chl");
    const answer = random(32);
    try {
      const recipientPublicKey = await crypto.subtle.importKey("raw", key.publicKey.publicKey as Uint8Array<ArrayBuffer>, X25519, true, []);
      const aad = utf8(`proprietor-mail/v1/challenge|${mailboxId}|${challengeId}|session|${key.publicKey.keyId}`);
      const { enc, ct } = await challengeSuite.seal({ recipientPublicKey, info: utf8("proprietor-mail/v1/challenge") }, answer, aad);
      const sealed = b64url(new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)]));
      const got = await openChallenge(key.privateKey, { mailboxId, challengeId }, sealed);
      if (hex(got) !== hex(answer)) record("mismatch", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, publicKey: shape(key.publicKey.publicKey) });
    }
  },
};

/** Checks that search many keys per round run fewer rounds. */
const ROUND_CAP: Record<string, number> = { "X25519 keys whose public key starts or ends with a zero byte": 12 };

/** Runs every check `rounds` times; answers, per check, how often it threw, gave a wrong length, or disagreed. */
export async function runProbe(rounds: number, only?: string[]): Promise<Record<string, ProbeLine>> {
  const report: Record<string, ProbeLine> = {};
  for (const [name, check] of Object.entries(CHECKS)) {
    if (only && !only.includes(name)) continue;
    const line: ProbeLine = { tries: 0, threw: 0, wrongLength: 0, mismatch: 0, examples: [] };
    for (let i = 0; i < Math.min(rounds, ROUND_CAP[name] ?? rounds); i++) {
      line.tries += 1;
      try {
        await check((kind, example) => {
          line[kind] += 1;
          if (line.examples.length < 4) line.examples.push({ kind, ...(example as object) });
        });
      } catch (e) {
        // A step a check did not expect to fail (its setup): counted, with the recorder's account of the call.
        line.threw += 1;
        if (line.examples.length < 4) line.examples.push({ kind: "setup threw", error: (e as Error).name, message: (e as Error).message, calls: takeFailures().slice(-2) });
      }
    }
    takeFailures();
    report[name] = line;
  }
  return report;
}

export const PROBE_CHECKS = Object.keys(CHECKS);
