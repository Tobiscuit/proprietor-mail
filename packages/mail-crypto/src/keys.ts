/**
 * The mailbox key pair: X25519 through Web Crypto only.
 *
 * A MailboxPrivateKey is an opaque, frozen handle `{ keyId }`. What it stands
 * for lives in a module-private WeakMap: a NON-extractable X25519 CryptoKey
 * used for decryption, and the clamped 32-byte scalar, which only
 * wrapPrivateKey reads (an unlocked key must be re-wrappable, e.g. to enrol
 * another passkey). Nothing reaches either through a property, JSON,
 * structuredClone or postMessage; a clone or a forged `{ keyId }` is refused.
 */
import { bytesEqual, concat, copy, toHex } from "./bytes";
import type { MailboxPrivateKey, MailboxPublicKey } from "./index";

/** A plain `{ name }`: @cloudflare/workers-types has no global `Algorithm` type. */
const X25519: { name: string } = { name: "X25519" };

type DeriveBitsParams = Parameters<SubtleCrypto["deriveBits"]>[0];

/**
 * X25519 `deriveBits` parameters with the peer key under `public`, the name
 * the Secure Curves spec and every runtime use (workerd included: checked by
 * running this package in workerd 2026-09-03). @cloudflare/workers-types
 * calls the field `$public`, so the object goes through `unknown` to the
 * parameter type the ambient lib declares; the object itself is the same
 * under both.
 */
function x25519Peer(publicKey: CryptoKey): DeriveBitsParams {
  return { name: "X25519", public: publicKey } as unknown as DeriveBitsParams;
}

/** PKCS #8 PrivateKeyInfo for an X25519 key (RFC 8410): this prefix, then the 32-byte scalar. */
const PKCS8_X25519_PREFIX = Uint8Array.of(
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
);

/** u = 9, the X25519 base point (RFC 7748 §4.1): the public key is X25519(k, 9) (§6.1). */
const BASE_POINT = Uint8Array.of(9, ...new Uint8Array(31));

export interface KeyMaterial {
  readonly keyId: string;
  /** Raw X25519 public key, 32 bytes. */
  readonly publicKey: Uint8Array<ArrayBuffer>;
  /** For HPKE: a non-extractable private key and its (extractable) public key. */
  readonly keyPair: CryptoKeyPair;
  /** The clamped private scalar. Read only by wrapPrivateKey. */
  readonly scalar: Uint8Array<ArrayBuffer>;
}

const materials = new WeakMap<object, KeyMaterial>();

/** decodeScalar25519's bit operations (RFC 7748 §5), which RFC 9180 §7.1.2 applies on (de)serialization. */
export function clamp(raw: Uint8Array): Uint8Array<ArrayBuffer> {
  const k = copy(raw);
  k[0] = k[0]! & 248;
  k[31] = (k[31]! & 127) | 64;
  return k;
}

export async function keyIdOf(publicKey: Uint8Array): Promise<string> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new TypeError("an X25519 public key is exactly 32 bytes");
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", copy(publicKey)));
  return toHex(digest.subarray(0, 16));
}

/**
 * Builds a private key from a raw 32-byte X25519 private key. The input is
 * clamped first (RFC 9180 §7.1.2: DeserializePrivateKey MUST clamp its input),
 * which does not change the key: X25519 clamps the scalar before use anyway.
 */
export async function importPrivateScalar(raw: Uint8Array): Promise<MailboxPrivateKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new TypeError("an X25519 private key is exactly 32 bytes");
  const scalar = clamp(raw);
  const pkcs8 = concat(PKCS8_X25519_PREFIX, scalar);
  try {
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, X25519, false, ["deriveBits"]);
    const basePoint = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    const publicKey = new Uint8Array(await crypto.subtle.deriveBits(x25519Peer(basePoint), privateKey, 256));
    const publicCryptoKey = await crypto.subtle.importKey("raw", publicKey, X25519, true, []);
    const material: KeyMaterial = {
      keyId: await keyIdOf(publicKey),
      publicKey,
      keyPair: { privateKey, publicKey: publicCryptoKey },
      scalar,
    };
    const handle: MailboxPrivateKey = Object.freeze({ keyId: material.keyId }); // pragma: allowlist secret (a type annotation, not a secret)
    materials.set(handle, material);
    return handle;
  } finally {
    pkcs8.fill(0);
  }
}

export function materialOf(priv: MailboxPrivateKey): KeyMaterial {
  const material = typeof priv === "object" && priv !== null ? materials.get(priv) : undefined;
  if (!material) {
    throw new TypeError("not a MailboxPrivateKey from generateMailboxKey or unwrapPrivateKey in this page");
  }
  return material;
}

/** Imports an advertised public key after checking that its keyId is really its keyId. */
export async function importPublicKey(pub: MailboxPublicKey): Promise<CryptoKey> {
  const keyId = await keyIdOf(pub.publicKey);
  if (pub.keyId !== keyId) throw new TypeError("the keyId does not belong to this public key");
  return crypto.subtle.importKey("raw", copy(pub.publicKey), X25519, true, []);
}

export function publicKeyMatches(material: KeyMaterial, pub: MailboxPublicKey): boolean {
  return (
    pub.keyId === material.keyId &&
    pub.publicKey instanceof Uint8Array &&
    bytesEqual(pub.publicKey, material.publicKey)
  );
}

/**
 * True when this runtime's Web Crypto has native X25519 with every operation
 * this package uses (pkcs8 and raw import, deriveBits, generateKey, raw
 * export). There is no pure-JavaScript fallback (see the README), so a page
 * can call this before a passkey ceremony and ask for a browser update
 * instead of failing halfway through.
 */
export async function x25519Supported(): Promise<boolean> {
  try {
    const probe = clamp(new Uint8Array(32).fill(0x2a));
    const privateKey = await crypto.subtle.importKey("pkcs8", concat(PKCS8_X25519_PREFIX, probe), X25519, false, ["deriveBits"]);
    const basePoint = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    await crypto.subtle.deriveBits(x25519Peer(basePoint), privateKey, 256);
    const pair = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
    // workers-types returns ArrayBuffer | JsonWebKey for every format; "raw" is always an ArrayBuffer.
    return exported instanceof ArrayBuffer && exported.byteLength === 32;
  } catch {
    return false;
  }
}

