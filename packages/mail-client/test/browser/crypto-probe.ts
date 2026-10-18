// Page-side diagnostics for the browser tests (bundled into the harness; test code only).
//
// 1. A recorder: every crypto.subtle call that throws is kept, with what it was asked to do and the
//    data it was given, so a failing flow says WHICH operation failed and on WHAT input.
// 2. A probe: each primitive device-v1 and envelope v1 use, run over many fresh random inputs, with
//    the results checked for length and against the engine's own other answers (the scalar an
//    imported key reports back, the public key two ways). It reports counts, and a few failing inputs.
//    An "engine" check measures Web Crypto itself; a "package" check measures mail-crypto's own
//    operations, which must never fail, whatever the engine does.
//
// What the probe found, and what it now holds the engines to: WebKit's libgcrypt backend (WebKitGTK and
// WPE on Linux, and so Playwright's WebKit there; Safari's backend is CryptoKit) drops a leading zero
// byte from an X25519 scalar, WebKit bug 307095 (fixed on WebKit main on 2026-10-09, 323215@main). So
// its PKCS #8 import refuses a scalar whose first byte is zero (DataError), and its generateKey fails
// when it drew one (OperationError, 1 draw in 256). A failure with exactly that signature is counted
// as `knownEngineBug`, allowed in WebKit's engine checks only; anything else fails the probe.
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
  /** It failed with WebKit bug 307095's signature (above): the engine's known defect, not a new one. */
  knownEngineBug: number;
  /** "engine": Web Crypto itself. "package": mail-crypto's own operations, which must never fail. */
  layer: Layer;
  /** A few failing cases: what failed, and the input that made it fail. */
  examples: unknown[];
}

export type Layer = "engine" | "package";

const X25519 = { name: "X25519" };
const PKCS8_X25519 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);
const BASE_POINT = Uint8Array.of(9, ...new Uint8Array(31));

function clamp(k: Uint8Array): Uint8Array<ArrayBuffer> {
  const c = new Uint8Array(k);
  c[0] = c[0]! & 248;
  c[31] = (c[31]! & 127) | 64;
  return c;
}

/** A clamped random scalar whose first byte is zero: 1 random one in 32, the input bug 307095 refuses. */
function zeroFirstByteScalar(): Uint8Array<ArrayBuffer> {
  const scalar = clamp(random(32));
  scalar[0] = 0;
  return scalar;
}

const pkcs8Of = (scalar: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array([...PKCS8_X25519, ...scalar]);

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

/**
 * A fresh X25519 pair for a check's SETUP, drawn again after bug 307095's OperationError: the
 * generateKey check measures that bug, and a setup only needs a key.
 */
async function drawX25519Pair(extractable: boolean): Promise<CryptoKeyPair> {
  for (let attempt = 1; ; attempt++) {
    try {
      return (await crypto.subtle.generateKey(X25519, extractable, ["deriveBits"])) as CryptoKeyPair;
    } catch (e) {
      if (attempt >= 4 || (e as Error).name !== "OperationError") throw e;
    }
  }
}

/** X25519(k, 9) by deriveBits against the base point. */
async function publicKeyOf(privateKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> { // pragma: allowlist secret (a parameter type, not a value)
  const base = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: base } as never, privateKey, 256));
}

/**
 * Whether `x` is X25519(clamped, 9), by the engine's own reckoning: the clamped scalar imported as
 * PKCS #8 where the engine can; where it refuses (bug 307095), a JWK import of d with x, which WebKit
 * accepts only after checking the pair with its RFC 7748 code (CryptoKeyOKP::importJwk).
 */
async function engineAgrees(clamped: Uint8Array, x: Uint8Array): Promise<{ agrees: boolean; by: string }> {
  try {
    const key = await crypto.subtle.importKey("pkcs8", pkcs8Of(clamped), X25519, false, ["deriveBits"]);
    return { agrees: hex(await publicKeyOf(key)) === hex(x), by: "pkcs8 import of the clamped scalar" };
  } catch (e) {
    if ((e as Error).name !== "DataError" || clamped[0] !== 0) throw e;
  }
  try {
    await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", d: b64url(clamped), x: b64url(x) }, X25519, false, ["deriveBits"]);
    return { agrees: true, by: "the engine's pair check on JWK import" };
  } catch (e) {
    return { agrees: false, by: `the engine's pair check on JWK import (${(e as Error).name})` };
  }
}

/** A DataError importing a scalar whose first byte is zero: bug 307095's signature. */
const isBug307095Import = (e: unknown, scalar: Uint8Array): boolean => (e as Error).name === "DataError" && scalar[0] === 0;

const challengeSuite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

type Outcome = "threw" | "wrongLength" | "mismatch" | "knownEngineBug";
type Check = (record: (kind: Outcome, example: unknown) => void) => Promise<void>;
interface ProbeCheck {
  layer: Layer;
  run: Check;
  /** Fewer rounds, for a check that searches many keys per round. */
  rounds?: number;
}
const engine = (run: Check, rounds?: number): ProbeCheck => ({ layer: "engine", run, ...(rounds ? { rounds } : {}) });
const pkg = (run: Check): ProbeCheck => ({ layer: "package", run });

const CHECKS: Record<string, ProbeCheck> = {
  // ---- the engine: Web Crypto itself ----

  // generateKey X25519, then the public key raw and the private key pkcs8 (wrapKey's form).
  "X25519 generateKey + raw/pkcs8 export": engine(async (record) => {
    let pair: CryptoKeyPair;
    try {
      pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    } catch (e) {
      return record((e as Error).name === "OperationError" ? "knownEngineBug" : "threw", { error: (e as Error).name, step: "generateKey" });
    }
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    if (raw.length !== 32) return record("wrongLength", { raw: hex(raw) });
    const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
    if (pkcs8.length !== 48 || hex(pkcs8.subarray(0, 16)) !== hex(PKCS8_X25519)) record("wrongLength", { pkcs8: hex(pkcs8), length: pkcs8.length });
  }),
  // X25519(k, 9) by deriveBits must be the public key the engine exports for k.
  "X25519 deriveBits with the base point": engine(async (record) => {
    const pair = await drawX25519Pair(true);
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    const scalar = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).subarray(16);
    let bits: Uint8Array;
    try {
      bits = await publicKeyOf(pair.privateKey);
    } catch (e) {
      return record("threw", { error: (e as Error).name, scalar: shape(scalar), publicKey: shape(raw) });
    }
    if (bits.length !== 32) return record("wrongLength", { bits: hex(bits) });
    if (hex(bits) !== hex(raw)) record("mismatch", { derived: shape(bits), exported: shape(raw), scalar: shape(scalar) });
  }),
  // A5: X25519 of the private key with its own public key.
  "X25519 deriveBits with its own public key (A5)": engine(async (record) => {
    const pair = await drawX25519Pair(false);
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    try {
      const z = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: pair.publicKey } as never, pair.privateKey, 256));
      if (z.length !== 32) record("wrongLength", { z: hex(z) });
    } catch (e) {
      record("threw", { error: (e as Error).name, publicKey: shape(raw) });
    }
  }),
  // A raw public key the engine produced must import again.
  "X25519 raw import of a generated public key": engine(async (record) => {
    const pair = await drawX25519Pair(true);
    const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
    try {
      await crypto.subtle.importKey("raw", raw, X25519, true, []);
    } catch (e) {
      record("threw", { error: (e as Error).name, publicKey: shape(raw) });
    }
  }),
  // A clamped random scalar as PKCS #8, and the scalar the engine reports back.
  "X25519 pkcs8 import of a clamped scalar": engine(async (record) => {
    const scalar = clamp(random(32));
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8Of(scalar), X25519, true, ["deriveBits"]);
    } catch (e) {
      return record(isBug307095Import(e, scalar) ? "knownEngineBug" : "threw", { error: (e as Error).name, scalar: shape(scalar) });
    }
    // The engine's own reading of the key: its JWK d must be the scalar given.
    const jwk = await crypto.subtle.exportKey("jwk", key);
    const d = fromB64url((jwk as JsonWebKey).d!);
    if (hex(d) !== hex(scalar)) record("mismatch", { given: shape(scalar), readBack: shape(d) });
  }),
  // The same, non-extractable, then its public key.
  "X25519 pkcs8 import, non-extractable, then deriveBits with the base point": engine(async (record) => {
    const scalar = clamp(random(32));
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8Of(scalar), X25519, false, ["deriveBits"]);
    } catch (e) {
      return record(isBug307095Import(e, scalar) ? "knownEngineBug" : "threw", { error: (e as Error).name, step: "import", scalar: shape(scalar) });
    }
    const extractable = await crypto.subtle.importKey("pkcs8", pkcs8Of(scalar), X25519, true, ["deriveBits"]);
    const x = fromB64url(((await crypto.subtle.exportKey("jwk", extractable)) as JsonWebKey).x!);
    try {
      const bits = await publicKeyOf(key);
      if (bits.length !== 32) record("wrongLength", { bits: hex(bits), scalar: shape(scalar) });
      else if (hex(bits) !== hex(x)) record("mismatch", { derived: shape(bits), jwkX: shape(x), scalar: shape(scalar) });
    } catch (e) {
      record("threw", { error: (e as Error).name, step: "deriveBits", scalar: shape(scalar), jwkX: shape(x) });
    }
  }),
  // The edge bug 307095 lives on: a clamped scalar whose first byte is zero, imported and read back.
  "X25519 pkcs8 import of a clamped scalar whose first byte is zero": engine(async (record) => {
    const scalar = zeroFirstByteScalar();
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8Of(scalar), X25519, true, ["deriveBits"]);
    } catch (e) {
      return record(isBug307095Import(e, scalar) ? "knownEngineBug" : "threw", { error: (e as Error).name, step: "import", scalar: shape(scalar) });
    }
    const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
    const d = fromB64url(jwk.d!);
    if (hex(d) !== hex(scalar)) return record("mismatch", { step: "jwk d", given: shape(scalar), readBack: shape(d) });
    try {
      const bits = await publicKeyOf(key);
      if (hex(bits) !== hex(fromB64url(jwk.x!))) record("mismatch", { step: "public key", derived: shape(bits), jwkX: shape(fromB64url(jwk.x!)), scalar: shape(scalar) });
    } catch (e) {
      record("threw", { error: (e as Error).name, step: "deriveBits", scalar: shape(scalar) });
    }
  }),
  // How mail-crypto imports a key it never serializes (a factor key, A2): the three low bits, which
  // X25519 ignores, set. The import must work, and the key must be the clamped scalar's.
  "X25519 pkcs8 import of a first-byte-zero scalar with the three ignored bits set": engine(async (record) => {
    const clamped = zeroFirstByteScalar();
    const masked = new Uint8Array(clamped);
    masked[0] = 0x07;
    let key: CryptoKey;
    try {
      key = await crypto.subtle.importKey("pkcs8", pkcs8Of(masked), X25519, false, ["deriveBits"]);
    } catch (e) {
      return record("threw", { error: (e as Error).name, step: "import", scalar: shape(masked) });
    }
    const x = await publicKeyOf(key);
    if (x.length !== 32) return record("wrongLength", { x: hex(x) });
    const { agrees, by } = await engineAgrees(clamped, x);
    if (!agrees) record("mismatch", { by, scalar: shape(clamped), derived: shape(x) });
  }),
  // A wrap another engine made (OpenSSL clamps the keys it makes, so 1 in 32 start with a zero byte),
  // opened here: AES-GCM over the PKCS #8 form, then unwrapKey.
  "unwrapKey of a PKCS #8 key whose first scalar byte is zero, as another engine wraps it": engine(async (record) => {
    const clamped = zeroFirstByteScalar();
    const kek = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "unwrapKey"])) as CryptoKey;
    const iv = random(12);
    const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, pkcs8Of(clamped));
    let key: CryptoKey;
    try {
      key = await crypto.subtle.unwrapKey("pkcs8", wrapped, kek, { name: "AES-GCM", iv }, X25519, false, ["deriveBits"]);
    } catch (e) {
      return record(isBug307095Import(e, clamped) ? "knownEngineBug" : "threw", { error: (e as Error).name, step: "unwrapKey", scalar: shape(clamped) });
    }
    const x = await publicKeyOf(key);
    const { agrees, by } = await engineAgrees(clamped, x);
    if (!agrees) record("mismatch", { by, scalar: shape(clamped), derived: shape(x) });
  }),
  // Keys whose public key starts or ends with a zero byte (about 1 in 256 each), searched for: their
  // raw export, their raw import, the base-point derivation, and a wrap round trip.
  "X25519 keys whose public key starts or ends with a zero byte": engine(async (record) => {
    for (let i = 0; i < 2048; i++) {
      const pair = await drawX25519Pair(true);
      const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
      if (raw.length !== 32) return record("wrongLength", { step: "raw export", raw: hex(raw) });
      if (raw[0] !== 0 && raw[31] !== 0) continue;
      const scalar = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).subarray(16);
      try {
        await crypto.subtle.importKey("raw", raw, X25519, true, []);
      } catch (e) {
        return record("threw", { error: (e as Error).name, step: "raw import", publicKey: shape(raw), scalar: shape(scalar) });
      }
      try {
        const bits = await publicKeyOf(pair.privateKey);
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
  }, 12),
  // A5 and DeriveKeyPair: HKDF with an empty salt.
  "HKDF deriveBits with an empty salt": engine(async (record) => {
    const ikm = random(32);
    const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    try {
      const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: random(16) }, base, 256));
      if (bits.length !== 32) record("wrongLength", { bits: hex(bits) });
    } catch (e) {
      record("threw", { error: (e as Error).name, ikm: hex(ikm) });
    }
  }),
  // A5: the binding key is HKDF into an HMAC key, then a tag.
  "HKDF deriveKey to HMAC, then sign": engine(async (record) => {
    const base = await crypto.subtle.importKey("raw", random(32), "HKDF", false, ["deriveKey"]);
    try {
      const hmac = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: random(16) }, base, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
      const tag = new Uint8Array(await crypto.subtle.sign("HMAC", hmac, random(64)));
      if (tag.length !== 32) record("wrongLength", { tag: hex(tag) });
    } catch (e) {
      record("threw", { error: (e as Error).name });
    }
  }),
  // envelope v1 (D21) and A4: wrapKey and unwrapKey of an X25519 PKCS #8 key under AES-GCM.
  "wrapKey + unwrapKey of an X25519 pkcs8 key": engine(async (record) => {
    const pair = await drawX25519Pair(true);
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
    if (hex(await publicKeyOf(back)) !== hex(raw)) record("mismatch", { exported: shape(raw), scalar: shape(scalar) });
  }),

  // ---- the package: mail-crypto's own operations, which must never fail ----

  // A fresh mailbox key (enrollment, rotation).
  generateMailboxKey: pkg(async (record) => {
    try {
      const { privateKey, publicKey } = await generateMailboxKey();
      if (publicKey.publicKey.length !== 32) record("wrongLength", { publicKey: hex(publicKey.publicKey) });
      else if (privateKey.keyId !== publicKey.keyId) record("mismatch", { publicKey: shape(publicKey.publicKey) });
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message });
    }
  }),
  // A2 as the package does it, end to end (1 random secret in 32 gives a scalar whose first byte is zero).
  "deriveFactorKey (A2)": pkg(async (record) => {
    const secret = random(32); // pragma: allowlist secret (random test values made for the probe)
    try {
      const key = await deriveFactorKey({ mailboxId: newId("mbx"), factorId: newId("wrp"), kind: "recovery", secret });
      if (factorPublicKey(key).length !== 32) record("wrongLength", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, secret: hex(secret) }); // pragma: allowlist secret (random test values made for the probe)
    }
  }),
  // envelope v1 wraps as the package makes and opens them (S6a's path).
  "wrapPrivateKey + unwrapPrivateKey": pkg(async (record) => {
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
  }),
  // A5 as the package does it: the binding key of a mailbox key, a tag, its verification.
  "bindingKey + bindingTag (A5)": pkg(async (record) => {
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
  }),
  // A4, X25519 KEM: a successor seal.
  "sealKey + openKeySeal, X25519 (successor)": pkg(async (record) => {
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
  }),
  // A4, X25519 KEM to a factor key (A2).
  "sealKey + openKeySeal, X25519 (factor)": pkg(async (record) => {
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
  }),
  // A4, P-256 KEM to a device's unlock key.
  "sealKey + openKeySeal, P-256 (device)": pkg(async (record) => {
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
  }),
  // A6: a challenge sealed as Mail seals it (written from the contract here; Mail seals in workerd, so
  // the ephemeral key is drawn as a setup), opened with the mailbox key.
  "openChallenge (A6)": pkg(async (record) => {
    const key = await generateMailboxKey();
    const mailboxId = newId("mbx");
    const challengeId = newId("chl");
    const answer = random(32);
    const recipientPublicKey = await crypto.subtle.importKey("raw", key.publicKey.publicKey as Uint8Array<ArrayBuffer>, X25519, true, []);
    const aad = utf8(`proprietor-mail/v1/challenge|${mailboxId}|${challengeId}|session|${key.publicKey.keyId}`);
    const { enc, ct } = await challengeSuite.seal({ recipientPublicKey, info: utf8("proprietor-mail/v1/challenge"), ekm: await drawX25519Pair(true) }, answer, aad);
    const sealed = b64url(new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)]));
    try {
      const got = await openChallenge(key.privateKey, { mailboxId, challengeId }, sealed);
      if (hex(got) !== hex(answer)) record("mismatch", {});
    } catch (e) {
      record("threw", { error: (e as Error).name, message: (e as Error).message, publicKey: shape(key.publicKey.publicKey) });
    }
  }),
};

/** Runs every check `rounds` times; answers, per check, how often it threw, gave a wrong length, disagreed, or hit the known engine bug. */
export async function runProbe(rounds: number, only?: string[]): Promise<Record<string, ProbeLine>> {
  const report: Record<string, ProbeLine> = {};
  for (const [name, check] of Object.entries(CHECKS)) {
    if (only && !only.includes(name)) continue;
    const line: ProbeLine = { tries: 0, threw: 0, wrongLength: 0, mismatch: 0, knownEngineBug: 0, layer: check.layer, examples: [] };
    for (let i = 0; i < Math.min(rounds, check.rounds ?? rounds); i++) {
      line.tries += 1;
      try {
        await check.run((kind, example) => {
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

/**
 * The private keys this engine's generateKey makes: how many start with a zero byte (the keys bug
 * 307095 cannot open when another engine made them), and whether the engine clamps them (low three
 * bits 000, top two bits 01), sets the opposite as BoringSSL does (111 and 10), or leaves them random.
 */
export async function keyShapes(draws: number) {
  const out = { draws: 0, operationErrors: 0, firstByteZero: 0, lowThreeBits: {} as Record<string, number>, topTwoBits: {} as Record<string, number> };
  while (out.draws < draws && out.operationErrors < 64) {
    let pair: CryptoKeyPair;
    try {
      pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    } catch (e) {
      if ((e as Error).name !== "OperationError") throw e;
      out.operationErrors += 1;
      continue;
    }
    out.draws += 1;
    const scalar = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer).subarray(16);
    if (scalar[0] === 0) out.firstByteZero += 1;
    const low = (scalar[0]! & 7).toString(2).padStart(3, "0");
    const top = (scalar[31]! >> 6).toString(2).padStart(2, "0");
    out.lowThreeBits[low] = (out.lowThreeBits[low] ?? 0) + 1;
    out.topTwoBits[top] = (out.topTwoBits[top] ?? 0) + 1;
  }
  takeFailures();
  return out;
}
