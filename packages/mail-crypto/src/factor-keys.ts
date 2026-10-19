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

/** The factor key of `secret` (a passkey's PRF output for its wrap, or the recovery secret). */
export async function deriveFactorKey(ctx: { mailboxId: string; factorId: string; kind: WrapKind; secret: Uint8Array }): Promise<FactorPrivateKey> { // pragma: allowlist secret (a type)
  if (!WRAP_KINDS.includes(ctx.kind)) throw new TypeError(`unknown factor kind: ${String(ctx.kind)}`);
  if (!(ctx.secret instanceof Uint8Array) || ctx.secret.length !== 32) {
    throw new TypeError("a factor secret (PRF output or recovery secret) is exactly 32 bytes");
  }
  const info = context("factor-key", ctx.mailboxId, ctx.factorId, ctx.kind);
  const secret = copy(ctx.secret); // pragma: allowlist secret (a variable name, not a value)
  let ikm: Uint8Array | null = null;
  try {
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    ikm = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(ctx.factorId), info }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
    const pair = await deriveX25519KeyPair(ikm);
    const material: FactorMaterial = {
      factorId: ctx.factorId,
      kind: ctx.kind,
      publicKey: pair.publicKey,
      keyPair: { privateKey: pair.privateKey, publicKey: await importX25519PublicKey(pair.publicKey) }, // pragma: allowlist secret (CryptoKey references)
    };
    const handle: FactorPrivateKey = Object.freeze({ factorId: ctx.factorId, kind: ctx.kind }); // pragma: allowlist secret (a type annotation)
    materials.set(handle, material);
    return handle;
  } finally {
    secret.fill(0);
    ikm?.fill(0);
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
