/**
 * The mailbox key pair: X25519 through Web Crypto only.
 *
 * A MailboxPrivateKey is an opaque, frozen handle `{ keyId }`. What it stands
 * for lives in a module-private WeakMap: an X25519 CryptoKey used for
 * decryption, with its public half. The private key is never read as bytes
 * by this module (D21, domain-model K1): a fresh key is made by
 * `generateKey`, a stored one is opened by `unwrapKey`, and a wrap is made by
 * `wrapKey`, so the scalar exists only inside Web Crypto. A key is wrappable
 * only when it was generated here (so that enrollment can wrap it) or when
 * an unlock asked for `wrappable` for that one operation; every other key is
 * non-extractable. Nothing reaches the key through a property, JSON,
 * structuredClone or postMessage; a clone or a forged `{ keyId }` is refused.
 */
import { DhkemX25519HkdfSha256 } from "@hpke/core";
import { bytesEqual, concat, copy, toHex } from "./bytes";
import type { MailboxPrivateKey, MailboxPublicKey } from "./index";

/** A plain `{ name }`: @cloudflare/workers-types has no global `Algorithm` type. */
const X25519: { name: string } = { name: "X25519" };

/*
 * One engine mishandles some X25519 keys, and the functions below work around it without changing a
 * byte of any output. WebKit's libgcrypt backend (WebKitGTK and WPE on Linux; not Safari, whose
 * backend is CryptoKit) drops a leading zero byte from an X25519 scalar: WebKit bug 307095, fixed on
 * WebKit main on 2026-10-09 (323215@main). So it refuses a PKCS #8 key whose first byte is zero
 * (DataError), which is 1 clamped scalar in 32, and its generateKey fails when it drew such a scalar
 * (OperationError), 1 draw in 256. Measured in the engine by mail-client's browser probe
 * (test/browser/webkit-probe.test.ts); what the package does about it is pinned by
 * test/engines.test.ts.
 *
 * - importX25519Scalar hands the engine a key it never serializes with the three low bits of its
 *   first byte SET. X25519 ignores those bits (RFC 7748 §5, decodeScalar25519, clears them before
 *   every use; BoringSSL sets them in every key it makes, on purpose), so it is the same key, and its
 *   first byte is never zero.
 * - generateX25519KeyPair draws again after an OperationError: a fresh key is random and nothing has
 *   kept it, so another draw loses nothing.
 *
 * A key the engine cannot hold and that is already kept elsewhere (a wrap or seal of a mailbox key
 * that another engine made with a zero first byte: WebKit on macOS and Node clamp, so 1 key in 32;
 * Firefox 1 in 256; Chromium none) cannot be helped here: its bytes exist only inside Web Crypto
 * (K1). That engine refuses it, and the unwrap fails closed.
 */

/** How many draws generateX25519KeyPair makes before an OperationError is the answer. Four in a row from the engine above: 1 chance in 2^32. */
const X25519_DRAWS = 4;

/**
 * A fresh X25519 key pair from `generateKey`, drawn again when the engine answers OperationError (at
 * most four draws in all). Any other error is thrown at once: a runtime without X25519 says
 * NotSupportedError, and that is not drawn again.
 */
export async function generateX25519KeyPair(extractable: boolean): Promise<CryptoKeyPair> {
  for (let draw = 1; ; draw++) {
    try {
      return (await crypto.subtle.generateKey(X25519, extractable, ["deriveBits"])) as CryptoKeyPair;
    } catch (e) {
      if (draw >= X25519_DRAWS || !(e instanceof DOMException && e.name === "OperationError")) throw e;
    }
  }
}

/**
 * DHKEM(X25519, HKDF-SHA256) whose ephemeral key pair, one per seal, comes from
 * generateX25519KeyPair, non-extractable (encap only derives with it and exports the public half).
 * @hpke/core's encap asks `this.generateKeyPair()` for it; everything else is @hpke/core's own.
 */
export class X25519Kem extends DhkemX25519HkdfSha256 {
  override async generateKeyPair(): Promise<CryptoKeyPair> {
    return generateX25519KeyPair(false);
  }
}

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

/** The PKCS #8 form Web Crypto exports and imports for an X25519 private key: the prefix and the scalar, 48 bytes. */
export const PKCS8_X25519_BYTES = PKCS8_X25519_PREFIX.length + 32;

/** u = 9, the X25519 base point (RFC 7748 §4.1): the public key is X25519(k, 9) (§6.1). */
const BASE_POINT = Uint8Array.of(9, ...new Uint8Array(31));

export interface KeyMaterial {
  readonly keyId: string;
  /** Raw X25519 public key, 32 bytes. */
  readonly publicKey: Uint8Array<ArrayBuffer>;
  /** For HPKE: the private key and its (extractable) public key. */
  readonly keyPair: CryptoKeyPair;
  /** True when the private CryptoKey is extractable, which only `wrapPrivateKey` relies on (K1). */
  readonly wrappable: boolean;
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

/** X25519(k, 9) with `deriveBits` against the base point: the public key of a private CryptoKey, which is never exported. */
export async function x25519PublicKeyOf(privateKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> { // pragma: allowlist secret (a parameter type, not a value)
  const basePoint = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
  return new Uint8Array(await crypto.subtle.deriveBits(x25519Peer(basePoint), privateKey, 256));
}

/** A raw X25519 public key as a CryptoKey (for HPKE, or as the peer of `deriveBits`). */
export function importX25519PublicKey(publicKey: Uint8Array): Promise<CryptoKey> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) throw new TypeError("an X25519 public key is exactly 32 bytes");
  return crypto.subtle.importKey("raw", copy(publicKey), X25519, true, []);
}

/**
 * Imports a raw 32-byte X25519 scalar as a private CryptoKey with usage
 * deriveBits, clamped first (RFC 9180 §7.1.2), and zeroes every copy of the
 * scalar this module made. The caller's buffer is the caller's to zero.
 *
 * An extractable key is one a test will wrap or seal, so it keeps the clamped
 * form envelope v1 serializes. A non-extractable key (a factor key, A2) is
 * never serialized, and is handed over with the three low bits set instead
 * (see the top of this file): the same key, never a zero first byte. Every
 * non-extractable import gets them, so nothing here depends on the value.
 */
export async function importX25519Scalar(raw: Uint8Array, extractable: boolean): Promise<CryptoKey> {
  if (!(raw instanceof Uint8Array) || raw.length !== 32) throw new TypeError("an X25519 private key is exactly 32 bytes");
  const scalar = clamp(raw);
  if (!extractable) scalar[0] = scalar[0]! | 7;
  const pkcs8 = concat(PKCS8_X25519_PREFIX, scalar);
  try {
    return await crypto.subtle.importKey("pkcs8", pkcs8, X25519, extractable, ["deriveBits"]);
  } finally {
    pkcs8.fill(0);
    scalar.fill(0);
  }
}

/**
 * Wraps a private CryptoKey (from generateKey, unwrapKey or a test import) in
 * a handle. The public key is computed as X25519(k, 9) with `deriveBits`
 * against the base point, so the private key is never exported.
 */
export async function fromPrivateCryptoKey(privateKey: CryptoKey): Promise<MailboxPrivateKey> { // pragma: allowlist secret (a parameter type, not a value)
  const publicKey = await x25519PublicKeyOf(privateKey);
  const publicCryptoKey = await crypto.subtle.importKey("raw", publicKey, X25519, true, []);
  const material: KeyMaterial = {
    keyId: await keyIdOf(publicKey),
    publicKey,
    keyPair: { privateKey, publicKey: publicCryptoKey },
    wrappable: privateKey.extractable,
  };
  const handle: MailboxPrivateKey = Object.freeze({ keyId: material.keyId }); // pragma: allowlist secret (a type annotation, not a secret)
  materials.set(handle, material);
  return handle;
}

/** A fresh key pair made inside Web Crypto: wrappable, because enrollment must wrap it, and never exported to JavaScript. */
export async function generatePrivateKey(): Promise<MailboxPrivateKey> {
  const pair = await generateX25519KeyPair(true);
  return fromPrivateCryptoKey(pair.privateKey);
}

/**
 * A private key from a raw 32-byte X25519 private key, for the test vectors
 * and tests (the browser never sees a scalar). The input is clamped first
 * (RFC 9180 §7.1.2: DeserializePrivateKey MUST clamp its input), which does
 * not change the key: X25519 clamps the scalar before use anyway.
 */
export async function importPrivateScalar(raw: Uint8Array, options?: { wrappable?: boolean }): Promise<MailboxPrivateKey> {
  return fromPrivateCryptoKey(await importX25519Scalar(raw, options?.wrappable === true));
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
 * this package uses (generateKey, pkcs8 and raw import, deriveBits, raw
 * export, and wrapKey/unwrapKey of a PKCS #8 key under AES-GCM). There is no
 * pure-JavaScript fallback (see the README), so a page can call this before
 * a passkey ceremony and ask for a browser update instead of failing halfway
 * through.
 */
export async function x25519Supported(): Promise<boolean> {
  try {
    const probe = clamp(new Uint8Array(32).fill(0x2a));
    const privateKey = await crypto.subtle.importKey("pkcs8", concat(PKCS8_X25519_PREFIX, probe), X25519, true, ["deriveBits"]);
    const basePoint = await crypto.subtle.importKey("raw", BASE_POINT, X25519, true, []);
    await crypto.subtle.deriveBits(x25519Peer(basePoint), privateKey, 256);
    const pair = await generateX25519KeyPair(true);
    const exported = await crypto.subtle.exportKey("raw", pair.publicKey);
    const kek = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"])) as CryptoKey;
    const iv = new Uint8Array(12);
    const wrapped = await crypto.subtle.wrapKey("pkcs8", privateKey, kek, { name: "AES-GCM", iv });
    const unwrapped = await crypto.subtle.unwrapKey("pkcs8", wrapped, kek, { name: "AES-GCM", iv }, X25519, false, ["deriveBits"]);
    // workers-types returns ArrayBuffer | JsonWebKey for every format; "raw" is always an ArrayBuffer.
    return (
      exported instanceof ArrayBuffer &&
      exported.byteLength === 32 &&
      wrapped.byteLength === PKCS8_X25519_BYTES + 16 &&
      unwrapped.extractable === false
    );
  } catch {
    return false;
  }
}
