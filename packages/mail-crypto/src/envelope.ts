/**
 * The byte formats of contracts/envelope-v1.md: the HPKE key envelope and the
 * AES-256-GCM blocks, with every piece of associated data spelled out once.
 */
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { bytesEqual, concat, copy, randomBytes, utf8 } from "./bytes";
import { DecryptionFailed } from "./errors";

/** HPKE base mode, DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM (0x0020, 0x0001, 0x0002). */
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

const MESSAGE_KEY_INFO = utf8("proprietor-mail/v1/message-key");
export const KEY_ENVELOPE_BYTES = 80; // enc (32) || ct (32 + 16)
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** The leading bytes of each block: a version byte, or "PMB1" for a body object. */
export const HEADER_BLOCK = Uint8Array.of(0x01);
export const DRAFT_BLOCK = Uint8Array.of(0x01);
export const WRAP_BLOCK = Uint8Array.of(0x01);
export const BODY_OBJECT = utf8("PMB1");

/**
 * `"proprietor-mail/v1/" + label + "|" + parts.join("|")`. Ids never contain
 * "|" (they are prefix_ + Crockford base32), and one that does is refused, so
 * two different id tuples can never produce the same associated data.
 */
export function context(label: string, ...parts: string[]): Uint8Array<ArrayBuffer> {
  for (const part of parts) {
    if (typeof part !== "string" || part.length === 0 || part.includes("|")) {
      throw new TypeError(`an id must be a non-empty string without "|": ${JSON.stringify(part)}`);
    }
  }
  return utf8(`proprietor-mail/v1/${label}|${parts.join("|")}`);
}

/** Step 2: `enc || ct = HPKE.Seal(pkR, info, aad = "proprietor-mail/v1/message-key|" + mailboxId + "|" + objectId, dek)`. */
export async function sealKeyEnvelope(
  recipientPublicKey: CryptoKey,
  mailboxId: string,
  objectId: string,
  dek: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  const aad = context("message-key", mailboxId, objectId);
  const { ct, enc } = await suite.seal({ recipientPublicKey, info: MESSAGE_KEY_INFO }, copy(dek), aad);
  const envelope = concat(new Uint8Array(enc), new Uint8Array(ct));
  if (envelope.length !== KEY_ENVELOPE_BYTES) throw new Error("internal: a key envelope must be 80 bytes");
  return envelope;
}

export async function openKeyEnvelope(
  recipientKey: CryptoKeyPair,
  mailboxId: string,
  objectId: string,
  envelope: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  if (!(envelope instanceof Uint8Array) || envelope.length !== KEY_ENVELOPE_BYTES) throw new DecryptionFailed();
  try {
    const aad = context("message-key", mailboxId, objectId);
    const enc = envelope.slice(0, 32);
    const ct = envelope.slice(32);
    const dek = new Uint8Array(await suite.open({ recipientKey, enc, info: MESSAGE_KEY_INFO }, ct, aad));
    if (dek.length !== 32) throw new DecryptionFailed();
    return dek;
  } catch {
    throw new DecryptionFailed();
  }
}

export function aesKey(key: Uint8Array, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", copy(key), { name: "AES-GCM" }, false, [usage]);
}

/** `lead || iv (12) || AES-256-GCM(key, iv, aad, plaintext)`, the 16-byte tag last. */
export async function sealBlock(
  lead: Uint8Array,
  key: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }, key, plaintext);
  return concat(lead, iv, new Uint8Array(ct));
}

export async function openBlock(
  lead: Uint8Array,
  key: CryptoKey,
  aad: Uint8Array<ArrayBuffer>,
  block: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  if (block.length < lead.length + IV_BYTES + TAG_BYTES || !bytesEqual(block.subarray(0, lead.length), lead)) {
    throw new DecryptionFailed();
  }
  const iv = block.subarray(lead.length, lead.length + IV_BYTES);
  try {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 },
      key,
      block.subarray(lead.length + IV_BYTES),
    );
    return new Uint8Array(pt);
  } catch {
    throw new DecryptionFailed();
  }
}

/** Runs an opening step and turns any failure into DecryptionFailed: never an empty or partial result. */
export async function failClosed<T>(open: () => Promise<T>): Promise<T> {
  try {
    return await open();
  } catch (e) {
    throw e instanceof DecryptionFailed ? e : new DecryptionFailed();
  }
}
