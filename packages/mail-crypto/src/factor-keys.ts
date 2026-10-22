/**
 * Factor keys (contracts/device-v1.md A2). Every factor (a passkey with PRF,
 * or the recovery key) has an X25519 key pair derived from its secret, so
 * that a browser holding the mailbox key can seal a new key to a factor that
 * is not present, and Mail can check that a factor was just used without
 * ever holding its secret.
 *
 *   ikm is HKDF-SHA256 over the secret, with the factor id (UTF-8) for its
 *   salt, info ctx("factor-key", mailboxId, factorId, kind) and L = 32;
 *   (skF, pkF) is DeriveKeyPair(ikm) for DHKEM(X25519, HKDF-SHA256) (RFC 9180 §7.1.3).
 *
 * `@hpke/core`'s own `deriveKeyPair` is not used: it imports the private key
 * as extractable and leaves its PKCS #8 buffer unzeroed (read in its 1.9.0
 * source). Here skF is imported non-extractable with usage deriveBits, and
 * every byte string that held the secret, ikm or the scalar is zeroed after
 * use. A FactorPrivateKey is an opaque frozen handle, like MailboxPrivateKey:
 * the CryptoKey lives in a module-private WeakMap.
 *
 * Round 3 (A2b, D39): the same secret also gives the factor's ECDSA P-256
 * signing key, with which it signs what it authorizes (A11):
 *
 *   ikmS is HKDF-SHA256 over the secret, with the factor id for its salt,
 *   info ctx("factor-signing-key", mailboxId, factorId, kind) and L = 32;
 *   (sS, vS) is DeriveKeyPair(ikmS) for DHKEM(P-256, HKDF-SHA256) (RFC 9180
 *   §7.1.3: candidates with a counter, bitmask 0xFF, until 0 < sk < n).
 *
 * sS is imported from PKCS #8 (the scalar alone, as @hpke/common 1.10.1's
 * `Ec._deserializePkcs8Key` does) for ECDSA, non-extractable, usage sign.
 * Its public point vS cannot be read from a non-extractable key (exportKey
 * needs `extractable`; @hpke/common goes through JWK, which would put the
 * scalar in a string nothing can zero). So the scalar is imported a second
 * time for ECDH, non-extractable: ECDH against the base point G gives x of
 * sS·G (the field element RFC 6090 §6.2 converts, which is what Web Crypto's
 * ECDH deriveBits returns), y is one of the two square roots of x³ − 3x + b,
 * and the one for which a signature by sS verifies is vS. @hpke/common's own
 * fallback for this (Firefox) takes the even root, which is the wrong point
 * for about half of all keys. Every candidate, the PKCS #8 buffer and the
 * labeled ikmS are zeroed after use.
 */
import { concat, copy, utf8 } from "./bytes";
import { context } from "./envelope";
import type { WrapKind } from "./index";
import { importX25519PublicKey, importX25519Scalar, x25519PublicKeyOf } from "./keys";

const WRAP_KINDS: readonly string[] = ["passkey-prf", "recovery"] satisfies WrapKind[];

/** RFC 9180 §4: "HPKE-v1", and the KEM's suite_id = "KEM" || I2OSP(kem_id = 0x0020, 2). */
const HPKE_V1 = utf8("HPKE-v1");
const KEM_X25519_SUITE_ID = Uint8Array.of(0x4b, 0x45, 0x4d, 0x00, 0x20);
const NSK = 32;

/** RFC 9180 §4.1: suite_id = "KEM" || I2OSP(kem_id = 0x0010, 2), DHKEM(P-256, HKDF-SHA256). */
const KEM_P256_SUITE_ID = Uint8Array.of(0x4b, 0x45, 0x4d, 0x00, 0x10);
/** RFC 9180 §7.1.3: "bitmask is defined to be 0xFF for P-256". */
const P256_BITMASK = 0xff;
/** The order n of P-256's base point, big-endian: a scalar sk is accepted when 0 < sk < n. */
const P256_ORDER = Uint8Array.of(
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
);
/**
 * PKCS #8 PrivateKeyInfo of a P-256 key holding only the scalar: this prefix,
 * then the 32 bytes. The same bytes as @hpke/common 1.10.1's PKCS8_ALG_ID_P_256:
 * SEQUENCE { INTEGER 0, SEQUENCE { id-ecPublicKey, prime256v1 },
 * OCTET STRING { SEQUENCE { INTEGER 1, OCTET STRING (32) } } }.
 */
const PKCS8_P256_PREFIX = Uint8Array.of(
  0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
  0x01, 0x04, 0x20,
);
/** P-256's field prime p, coefficient b and base point G (SEC 2 / FIPS 186), for vS's y. */
const P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const P256_G = Uint8Array.of(
  0x04,
  0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
  0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
  0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
  0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
);
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };
const ECDH_P256 = { name: "ECDH", namedCurve: "P-256" };
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" };
/** What sS signs once, in this module only, to tell vS from the other point with its x; never sent or kept. */
const POINT_CHECK = utf8("proprietor-mail/v1/factor-signing-key/which-point");

type DeriveBitsParams = Parameters<SubtleCrypto["deriveBits"]>[0];

/**
 * A factor's private key in the browser: an opaque, frozen `{ factorId, kind }`
 * handle. Its X25519 key pair (the private half non-extractable, deriveBits
 * only) lives in a module-private WeakMap; a clone or a forged object is
 * refused with a TypeError.
 */
export interface FactorPrivateKey {
  readonly factorId: string;
  readonly kind: WrapKind;
}

export interface FactorMaterial {
  readonly factorId: string;
  readonly kind: WrapKind;
  /** pkF, the raw 32-byte X25519 public key Mail stores. */
  readonly publicKey: Uint8Array<ArrayBuffer>;
  /** For HPKE: skF (non-extractable) and its public CryptoKey. */
  readonly keyPair: CryptoKeyPair;
  /** A2b: sS, an ECDSA P-256 private key, non-extractable, usage sign. */
  readonly signingKey: CryptoKey; // pragma: allowlist secret (a type)
  /** A2b: vS, sS's public point, raw uncompressed (65 bytes): the factor's `signingKey` in Mail's records. */
  readonly signingPublicKey: Uint8Array<ArrayBuffer>;
}

const materials = new WeakMap<object, FactorMaterial>();

/**
 * RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(X25519, HKDF-SHA256):
 *   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
 *   sk      = LabeledExpand(dkp_prk, "sk", "", Nsk)
 * Web Crypto's HKDF is Extract then Expand, so one deriveBits with the labeled
 * ikm and the labeled info computes sk. The private key is non-extractable.
 */
export async function deriveX25519KeyPair(ikm: Uint8Array): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array<ArrayBuffer> }> { // pragma: allowlist secret (a type)
  if (!(ikm instanceof Uint8Array) || ikm.length < NSK) throw new TypeError("DeriveKeyPair needs at least 32 bytes of input keying material");
  const labeledIkm = concat(HPKE_V1, KEM_X25519_SUITE_ID, utf8("dkp_prk"), ikm);
  const labeledInfo = concat(Uint8Array.of(0, NSK), HPKE_V1, KEM_X25519_SUITE_ID, utf8("sk"));
  let sk: Uint8Array | null = null;
  try {
    const base = await crypto.subtle.importKey("raw", labeledIkm, "HKDF", false, ["deriveBits"]);
    sk = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: labeledInfo }, base, NSK * 8));
    const privateKey = await importX25519Scalar(sk, false);
    return { privateKey, publicKey: await x25519PublicKeyOf(privateKey) };
  } finally {
    labeledIkm.fill(0);
    sk?.fill(0);
  }
}

/** True when the big-endian scalar is 0 < sk < n, read without turning it into a number. */
function inP256Range(sk: Uint8Array): boolean {
  let nonZero = 0;
  for (const b of sk) nonZero |= b;
  if (nonZero === 0) return false;
  for (let i = 0; i < sk.length; i++) {
    if (sk[i]! !== P256_ORDER[i]!) return sk[i]! < P256_ORDER[i]!;
  }
  return false; // sk = n
}

function bigintOf(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bytes32(v: bigint): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function modPow(base: bigint, exponent: bigint, m: bigint): bigint {
  let result = 1n;
  let b = base % m;
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
  }
  return result;
}

/**
 * vS from the two non-extractable halves of one scalar: x from ECDH with the
 * base point, the two candidate y (p = 3 mod 4, so a root is rhs^((p+1)/4)),
 * and the point under which sS's signature verifies. All of it is public.
 */
async function p256PublicPoint(signing: CryptoKey, ecdh: CryptoKey): Promise<Uint8Array<ArrayBuffer>> { // pragma: allowlist secret (parameter types)
  const basePoint = await crypto.subtle.importKey("raw", P256_G, ECDH_P256, true, []);
  // workers-types names the peer `$public`; every runtime reads `public` (see keys.ts).
  const x = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: basePoint } as unknown as DeriveBitsParams, ecdh, 256));
  const xn = bigintOf(x);
  let rhs = ((((xn * xn) % P256_P) * xn) - 3n * xn + P256_B) % P256_P; // in (-p, p)
  if (rhs < 0n) rhs += P256_P;
  const root = modPow(rhs, (P256_P + 1n) >> 2n, P256_P);
  if ((root * root) % P256_P !== rhs) throw new Error("internal: ECDH with the base point gave no point of P-256");
  const signature = await crypto.subtle.sign(ECDSA_SHA256, signing, POINT_CHECK);
  for (const y of [root, P256_P - root]) {
    const point = concat(Uint8Array.of(0x04), x, bytes32(y));
    const candidate = await crypto.subtle.importKey("raw", point, ECDSA_P256, true, ["verify"]);
    if (await crypto.subtle.verify(ECDSA_SHA256, candidate, signature, POINT_CHECK)) return point;
  }
  throw new Error("internal: neither point with this x verifies the signing key's signature");
}

/**
 * RFC 9180 §7.1.3 DeriveKeyPair for DHKEM(P-256, HKDF-SHA256):
 *   dkp_prk = LabeledExtract("", "dkp_prk", ikm)
 *   repeat with counter = 0, 1, …, 255:
 *     bytes = LabeledExpand(dkp_prk, "candidate", I2OSP(counter, 1), Nsk); bytes[0] &= bitmask
 *   until 0 < OS2IP(bytes) < n
 * Each candidate is one Web Crypto HKDF (Extract then Expand) with the
 * labeled ikm and that counter's labeled info. The scalar becomes an ECDSA
 * P-256 key, non-extractable, usage sign; its public point is computed as
 * p256PublicPoint says. Every candidate and the PKCS #8 buffer are zeroed.
 */
export async function deriveP256SigningKey(ikm: Uint8Array): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array<ArrayBuffer> }> { // pragma: allowlist secret (a type)
  if (!(ikm instanceof Uint8Array) || ikm.length < NSK) throw new TypeError("DeriveKeyPair needs at least 32 bytes of input keying material");
  const labeledIkm = concat(HPKE_V1, KEM_P256_SUITE_ID, utf8("dkp_prk"), ikm);
  let sk: Uint8Array<ArrayBuffer> | null = null;
  let pkcs8: Uint8Array<ArrayBuffer> | null = null;
  try {
    const base = await crypto.subtle.importKey("raw", labeledIkm, "HKDF", false, ["deriveBits"]);
    for (let counter = 0; counter <= 255 && sk === null; counter++) {
      const labeledInfo = concat(Uint8Array.of(0, NSK), HPKE_V1, KEM_P256_SUITE_ID, utf8("candidate"), Uint8Array.of(counter));
      const candidate = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: labeledInfo }, base, NSK * 8));
      candidate[0] = candidate[0]! & P256_BITMASK;
      if (inP256Range(candidate)) sk = candidate;
      else candidate.fill(0);
    }
    if (sk === null) throw new Error("DeriveKeyPairError: no P-256 scalar in 256 candidates (RFC 9180 §7.1.3)");
    pkcs8 = concat(PKCS8_P256_PREFIX, sk);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, ECDSA_P256, false, ["sign"]);
    const ecdh = await crypto.subtle.importKey("pkcs8", pkcs8, ECDH_P256, false, ["deriveBits"]);
    pkcs8.fill(0);
    sk.fill(0);
    return { privateKey, publicKey: await p256PublicPoint(privateKey, ecdh) };
  } finally {
    labeledIkm.fill(0);
    sk?.fill(0);
    pkcs8?.fill(0);
  }
}

/** The factor key of `secret` (a passkey's PRF output for its wrap, or the recovery secret). */
export async function deriveFactorKey(ctx: { mailboxId: string; factorId: string; kind: WrapKind; secret: Uint8Array }): Promise<FactorPrivateKey> { // pragma: allowlist secret (a type)
  if (!WRAP_KINDS.includes(ctx.kind)) throw new TypeError(`unknown factor kind: ${String(ctx.kind)}`);
  if (!(ctx.secret instanceof Uint8Array) || ctx.secret.length !== 32) {
    throw new TypeError("a factor secret (PRF output or recovery secret) is exactly 32 bytes");
  }
  const info = context("factor-key", ctx.mailboxId, ctx.factorId, ctx.kind);
  const signingInfo = context("factor-signing-key", ctx.mailboxId, ctx.factorId, ctx.kind);
  const secret = copy(ctx.secret); // pragma: allowlist secret (a variable name, not a value)
  let ikm: Uint8Array | null = null;
  let ikmS: Uint8Array | null = null;
  try {
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    secret.fill(0);
    ikm = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(ctx.factorId), info }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
    ikmS = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(ctx.factorId), info: signingInfo }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
    const pair = await deriveX25519KeyPair(ikm);
    ikm.fill(0);
    const signing = await deriveP256SigningKey(ikmS);
    ikmS.fill(0);
    const material: FactorMaterial = {
      factorId: ctx.factorId,
      kind: ctx.kind,
      publicKey: pair.publicKey,
      keyPair: { privateKey: pair.privateKey, publicKey: await importX25519PublicKey(pair.publicKey) }, // pragma: allowlist secret (CryptoKey references)
      signingKey: signing.privateKey, // pragma: allowlist secret (a CryptoKey reference)
      signingPublicKey: signing.publicKey,
    };
    const handle: FactorPrivateKey = Object.freeze({ factorId: ctx.factorId, kind: ctx.kind }); // pragma: allowlist secret (a type annotation)
    materials.set(handle, material);
    return handle;
  } finally {
    secret.fill(0);
    ikm?.fill(0);
    ikmS?.fill(0);
  }
}

export function factorMaterialOf(key: FactorPrivateKey): FactorMaterial {
  const material = typeof key === "object" && key !== null ? materials.get(key) : undefined;
  if (!material) throw new TypeError("not a FactorPrivateKey from deriveFactorKey in this page");
  return material;
}

/** True when `key` is a FactorPrivateKey handle made in this page. */
export function isFactorKey(key: unknown): key is FactorPrivateKey {
  return typeof key === "object" && key !== null && materials.has(key);
}

/** pkF, the raw 32-byte public key Mail stores (a copy). */
export function factorPublicKey(key: FactorPrivateKey): Uint8Array<ArrayBuffer> {
  return copy(factorMaterialOf(key).publicKey);
}

/** vS, the factor's signing key as Mail lists it: a raw uncompressed P-256 point, 65 bytes (a copy). */
export function factorSigningKey(key: FactorPrivateKey): Uint8Array<ArrayBuffer> {
  return copy(factorMaterialOf(key).signingPublicKey);
}
