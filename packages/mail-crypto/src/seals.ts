/**
 * Key seals (contracts/device-v1.md A4): a mailbox private key (X25519)
 * encrypted to one recipient public key.
 *
 *   suite  HPKE base mode; KEM DHKEM(X25519, HKDF-SHA256) 0x0020 for a factor or
 *          successor recipient, DHKEM(P-256, HKDF-SHA256) 0x0010 for a device;
 *          KDF HKDF-SHA256; AEAD export-only 0xFFFF
 *   info   ctx("key-seal", mailboxId, sealedKeyId, toKind, toId)
 *   kek    Export(UTF-8("proprietor-mail/v1/key-seal/kek"), 32), an AES-256-GCM key
 *   ct     wrapKey("pkcs8", sealedPrivateKey, kek, AES-GCM, iv, additionalData = info)
 *   bytes  0x01 || enc || iv (12) || ct (48 + 16): 109 bytes (X25519), 142 (P-256)
 *
 * The private key leaves Web Crypto only as `ct` (wrapKey) and comes back as
 * a CryptoKey (unwrapKey), so it never exists as bytes in JavaScript (D21).
 * The exported KEK is bytes for the moment it takes to import it, and is
 * zeroed then.
 *
 * Opening a P-256 seal needs the recipient's key PAIR: given a private key
 * alone, @hpke/core 1.9.0 recomputes the public key it needs for the KEM
 * context and, for a non-extractable key, picks the even-y point
 * (Ec._derivePublicKeyWithoutJwkExport, "Canonicalize sign"), which is the
 * wrong point for about half of all keys. The device's public form is kept
 * next to its private key for that reason (K5 lists it).
 */
import { CipherSuite, DhkemP256HkdfSha256, DhkemX25519HkdfSha256, ExportOnly, HkdfSha256 } from "@hpke/core";
import { base64url, concat, fromBase64url, randomBytes, utf8 } from "./bytes";
import { isDeviceUnlockKey } from "./device-keys";
import { context } from "./envelope";
import { DecryptionFailed } from "./errors";
import { factorMaterialOf, type FactorPrivateKey } from "./factor-keys";
import type { MailboxPrivateKey } from "./index";
import { fromPrivateCryptoKey, importX25519PublicKey, keyIdOf, materialOf, PKCS8_X25519_BYTES } from "./keys";

type Kem = "x25519" | "p256";

const SUITES: Record<Kem, CipherSuite> = {
  x25519: new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new ExportOnly() }),
  p256: new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new ExportOnly() }),
};
const ENC_BYTES: Record<Kem, number> = { x25519: 32, p256: 65 };
const SEAL_LEAD = 0x01;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const CT_BYTES = PKCS8_X25519_BYTES + TAG_BYTES;
const KEK_CONTEXT = utf8("proprietor-mail/v1/key-seal/kek");
const KEY_ID = /^[0-9a-f]{32}$/;
/** A plain `{ name }`: @cloudflare/workers-types has no global `Algorithm` type. */
const X25519: { name: string } = { name: "X25519" };

/** The length of a key seal to each kind of recipient (A4). */
export const KEY_SEAL_BYTES = Object.freeze({ device: 1 + 65 + IV_BYTES + CT_BYTES, factor: 1 + 32 + IV_BYTES + CT_BYTES, successor: 1 + 32 + IV_BYTES + CT_BYTES });

/** Whom a key is sealed to. A successor's toId is its own keyId, computed here from its public key. */
export type SealRecipient =
  | { kind: "device"; deviceId: string; /** The device's unlock key, a 65-byte uncompressed P-256 point. */ publicKey: Uint8Array }
  | { kind: "factor"; factorId: string; /** The factor key pkF, 32 bytes (A2). */ publicKey: Uint8Array }
  | { kind: "successor"; /** The successor mailbox key's public key, 32 bytes. */ publicKey: Uint8Array };

/** The key that opens a seal, and so names its recipient. */
export type SealOpener =
  | { kind: "device"; deviceId: string; /** The device's non-extractable ECDH P-256 unlock key. */ privateKey: CryptoKey; /** Its 65-byte public form. */ publicKey: Uint8Array } // pragma: allowlist secret (a type)
  | { kind: "factor"; key: FactorPrivateKey }
  | { kind: "successor"; key: MailboxPrivateKey };

async function importP256Public(publicKey: Uint8Array): Promise<CryptoKey> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 65 || publicKey[0] !== 0x04) {
    throw new TypeError("a device public key is a 65-byte uncompressed P-256 point");
  }
  try {
    return await crypto.subtle.importKey("raw", new Uint8Array(publicKey), { name: "ECDH", namedCurve: "P-256" }, true, []);
  } catch {
    throw new TypeError("a device public key is a point on P-256");
  }
}

async function kekOf(ctx: { export(exporterContext: Uint8Array, len: number): Promise<ArrayBuffer> }, usage: "wrapKey" | "unwrapKey"): Promise<CryptoKey> {
  const exported = new Uint8Array(await ctx.export(KEK_CONTEXT, 32));
  try {
    return await crypto.subtle.importKey("raw", exported, { name: "AES-GCM" }, false, [usage]);
  } finally {
    exported.fill(0);
  }
}

/** The seal itself, for a given suite, recipient and info: 0x01 || enc || iv || wrapKey(...). Internal; tests use it to forge. */
export async function sealWith(kem: Kem, recipientPublicKey: CryptoKey, info: Uint8Array<ArrayBuffer>, sealedPrivateKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> { // pragma: allowlist secret (a parameter type)
  const sender = await SUITES[kem].createSenderContext({ recipientPublicKey, info });
  const kek = await kekOf(sender, "wrapKey");
  const iv = randomBytes(IV_BYTES);
  const ct = new Uint8Array(await crypto.subtle.wrapKey("pkcs8", sealedPrivateKey, kek, { name: "AES-GCM", iv, additionalData: info, tagLength: 128 }));
  if (ct.length !== CT_BYTES) throw new Error("internal: a sealed X25519 PKCS #8 PrivateKeyInfo is 48 + 16 bytes");
  const enc = new Uint8Array(sender.enc);
  if (enc.length !== ENC_BYTES[kem]) throw new Error("internal: unexpected HPKE enc length");
  return concat(Uint8Array.of(SEAL_LEAD), enc, iv, ct);
}

/** Opens `bytes` under `info` with the recipient's key pair. Every failure is DecryptionFailed. Internal. */
export async function openSealWith(kem: Kem, recipientKey: CryptoKeyPair, info: Uint8Array<ArrayBuffer>, bytes: Uint8Array, extractable: boolean): Promise<CryptoKey> {
  const encBytes = ENC_BYTES[kem];
  if (!(bytes instanceof Uint8Array) || bytes.length !== 1 + encBytes + IV_BYTES + CT_BYTES || bytes[0] !== SEAL_LEAD) throw new DecryptionFailed();
  const enc = bytes.slice(1, 1 + encBytes);
  const iv = bytes.slice(1 + encBytes, 1 + encBytes + IV_BYTES);
  const ct = bytes.slice(1 + encBytes + IV_BYTES);
  let kek: CryptoKey;
  try {
    kek = await kekOf(await SUITES[kem].createRecipientContext({ recipientKey, enc, info }), "unwrapKey");
  } catch {
    throw new DecryptionFailed();
  }
  try {
    return await crypto.subtle.unwrapKey("pkcs8", ct, kek, { name: "AES-GCM", iv, additionalData: info, tagLength: 128 }, X25519, extractable, ["deriveBits"]);
  } catch (e) {
    // A runtime without X25519 is not a decryption failure; everything else (a bad tag, a malformed key) is.
    if (e instanceof DOMException && e.name === "NotSupportedError") throw e;
    throw new DecryptionFailed();
  }
}

/**
 * Seals the mailbox key `priv` to one recipient (A4). `priv` must be
 * wrappable: just generated, or opened `wrappable` for this one step after a
 * factor was used (Part C, K1′). Returns the stored form, base64url.
 */
export async function sealKey(priv: MailboxPrivateKey, ids: { mailboxId: string }, to: SealRecipient): Promise<string> {
  const material = materialOf(priv);
  if (!material.wrappable) {
    throw new TypeError("this key is decrypt-only (K1′): seal it from a key opened `wrappable` just after a factor, or from a new key");
  }
  let kem: Kem;
  let toId: string;
  let recipientPublicKey: CryptoKey;
  switch (to.kind) {
    case "device":
      kem = "p256";
      toId = to.deviceId;
      recipientPublicKey = await importP256Public(to.publicKey);
      break;
    case "factor":
      kem = "x25519";
      toId = to.factorId;
      recipientPublicKey = await importX25519PublicKey(to.publicKey);
      break;
    case "successor":
      kem = "x25519";
      toId = await keyIdOf(to.publicKey);
      recipientPublicKey = await importX25519PublicKey(to.publicKey);
      break;
    default:
      throw new TypeError(`unknown recipient kind: ${String((to as { kind?: unknown }).kind)}`);
  }
  const info = context("key-seal", ids.mailboxId, material.keyId, to.kind, toId);
  return base64url(await sealWith(kem, recipientPublicKey, info, material.keyPair.privateKey));
}

/**
 * Opens a key seal with the recipient's key (A4) and checks that it holds
 * the key it names: a seal's content is refused unless its keyId is
 * `sealedKeyId`. The key is non-extractable and decrypt-only unless
 * `wrappable` is asked for the one step that seals or wraps it again (K1′).
 * Any failure of the bytes is DecryptionFailed; a caller mistake is a
 * TypeError.
 */
export async function openKeySeal(
  by: SealOpener,
  ids: { mailboxId: string; sealedKeyId: string },
  sealed: string,
  options?: { wrappable?: boolean },
): Promise<MailboxPrivateKey> {
  if (typeof ids.sealedKeyId !== "string" || !KEY_ID.test(ids.sealedKeyId)) throw new TypeError("sealedKeyId is a keyId (32 lowercase hex digits)");
  let kem: Kem;
  let toId: string;
  let recipientKey: CryptoKeyPair;
  switch (by.kind) {
    case "device":
      if (!isDeviceUnlockKey(by.privateKey)) throw new TypeError("a device seal opens with the device's non-extractable ECDH P-256 unlock key");
      kem = "p256";
      toId = by.deviceId;
      recipientKey = { privateKey: by.privateKey, publicKey: await importP256Public(by.publicKey) }; // pragma: allowlist secret (CryptoKey references)
      break;
    case "factor":
      kem = "x25519";
      toId = by.key.factorId;
      recipientKey = factorMaterialOf(by.key).keyPair;
      break;
    case "successor":
      kem = "x25519";
      toId = materialOf(by.key).keyId;
      recipientKey = materialOf(by.key).keyPair;
      break;
    default:
      throw new TypeError(`unknown recipient kind: ${String((by as { kind?: unknown }).kind)}`);
  }
  const info = context("key-seal", ids.mailboxId, ids.sealedKeyId, by.kind, toId);
  const bytes = fromBase64url(sealed);
  if (bytes === null) throw new DecryptionFailed();
  const privateKey = await openSealWith(kem, recipientKey, info, bytes, options?.wrappable === true); // pragma: allowlist secret (a variable name)
  const handle = await fromPrivateCryptoKey(privateKey);
  if (handle.keyId !== ids.sealedKeyId) throw new DecryptionFailed("the seal holds a different key from the one it names");
  return handle;
}
