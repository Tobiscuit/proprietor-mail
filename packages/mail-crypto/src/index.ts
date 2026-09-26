/**
 * @platform-mail/crypto - envelope v1 and key wrapping.
 *
 * The contract is contracts/envelope-v1.md; this file is its API in code form.
 * Until slice S1 lands, every function below throws `NotImplemented` and
 * `IMPLEMENTED` is false, so the Worker (slice S2) can compile against the real
 * signatures and inject a fake in its unit tests. S1 owns this package and may
 * add exports; it must not change a signature below without changing the
 * contract first.
 *
 * Two audiences:
 *   - the Mail Worker, which only ever SEALS (it holds public keys only);
 *   - the owner's browser, which opens, seals drafts, and wraps/unwraps the
 *     mailbox private key.
 */

import { base64url, copy, fromBase64url, randomBytes } from "./bytes";
import { crockfordEncode } from "./crockford";
import {
  aesKey,
  BODY_OBJECT,
  context,
  DRAFT_BLOCK,
  failClosed,
  HEADER_BLOCK,
  openBlock,
  openKeyEnvelope,
  sealBlock,
  sealKeyEnvelope,
} from "./envelope";
import { NotImplemented } from "./errors";
import { importPrivateScalar, importPublicKey, keyIdOf as keyIdOfPublicKey, materialOf } from "./keys";
import { parseDraft, parseHeader, serializeDraft, serializeHeader } from "./plaintext";

/** False until S1 replaces the stubs. Tests that need real crypto skip on it. */
export const IMPLEMENTED: boolean = false;

export const ENVELOPE_VERSION = 1 as const;

export { DecryptionFailed, NotImplemented, RecoveryKeyTypo } from "./errors";

// ---- Plaintext shapes (contracts/envelope-v1.md) ----------------------------

export interface Address {
  name: string;
  address: string;
}

export interface AttachmentSummary {
  filename: string;
  mimeType: string;
  size: number;
  inline: boolean;
}

/** The plaintext inside a header block. Every key is always present. */
export interface MessageHeader {
  v: 1;
  direction: "in" | "out";
  envelopeFrom: string | null;
  from: Address | null;
  to: Address[];
  cc: Address[];
  bcc: Address[];
  replyTo: Address[];
  subject: string;
  /** ISO 8601, or null when the Date header is absent or unparseable. */
  date: string | null;
  /** Without angle brackets. */
  messageId: string | null;
  inReplyTo: string | null;
  references: string[];
  /** At most 200 characters of text, whitespace collapsed. */
  snippet: string;
  attachments: AttachmentSummary[];
}

/** The plaintext inside a draft block. */
export interface Draft {
  v: 1;
  to: Address[];
  cc: Address[];
  bcc: Address[];
  subject: string;
  text: string;
  inReplyTo: string | null;
  references: string[];
  updatedAt: string;
}

// ---- Keys --------------------------------------------------------------------

export interface MailboxPublicKey {
  /** Lowercase hex of the first 16 bytes of SHA-256(publicKey). */
  keyId: string;
  /** Raw X25519 public key, 32 bytes. */
  publicKey: Uint8Array;
}

/**
 * A mailbox private key held in the browser. Opaque on purpose: S1 decides
 * whether it wraps a non-extractable CryptoKey or raw bytes behind a closure.
 * It is never serialized except inside a wrap.
 */
export interface MailboxPrivateKey {
  readonly keyId: string;
}

export type IdPrefix = "mbx" | "msg" | "drf" | "wrp";

const ID_PREFIXES: readonly string[] = ["mbx", "msg", "drf", "wrp"];
const KEY_ID = /^[0-9a-f]{32}$/;

export type WrapKind = "passkey-prf" | "recovery";

export interface KeyWrap {
  id: string;
  keyId: string;
  kind: WrapKind;
  /** base64url of 0x01 || iv || AES-256-GCM(kek, iv, aad, private key raw 32 bytes). */
  wrapped: string;
}

// ---- Sealed shapes -----------------------------------------------------------

export interface SealedMessage {
  keyId: string;
  /** base64url, 80 bytes: HPKE enc (32) || ct (48). */
  keyEnvelope: string;
  /** base64url of 0x01 || iv || ciphertext of the MessageHeader JSON. */
  header: string;
  /** "PMB1" || iv || ciphertext of the raw RFC 5322 message: the R2 object. */
  body: Uint8Array;
}

export interface SealedDraft {
  keyId: string;
  keyEnvelope: string;
  /** base64url of 0x01 || iv || ciphertext of the Draft JSON. */
  sealed: string;
}

// ---- API: both sides ---------------------------------------------------------

/** `<prefix>_<26 lowercase Crockford base32 chars of 16 random bytes>`. */
export function newId(prefix: IdPrefix): string {
  if (!ID_PREFIXES.includes(prefix)) throw new TypeError(`unknown id prefix: ${String(prefix)}`);
  return `${prefix}_${crockfordEncode(randomBytes(16), "lower")}`;
}

export async function keyIdOf(publicKey: Uint8Array): Promise<string> {
  return keyIdOfPublicKey(publicKey);
}

/** keyId in groups of four, for people to compare. */
export function fingerprint(keyId: string): string {
  if (typeof keyId !== "string" || !KEY_ID.test(keyId)) throw new TypeError("not a keyId (32 lowercase hex digits)");
  return keyId.match(/.{4}/g)!.join(" ");
}

// ---- API: the Worker (seal only) --------------------------------------------

export async function sealMessage(
  pub: MailboxPublicKey,
  ids: { mailboxId: string; messageId: string },
  header: MessageHeader,
  raw: Uint8Array,
): Promise<SealedMessage> {
  if (!(raw instanceof Uint8Array)) throw new TypeError("raw is the message's bytes (a Uint8Array)");
  const recipient = await importPublicKey(pub);
  const headerJson = serializeHeader(header);
  const headerAad = context("header", ids.mailboxId, ids.messageId);
  const bodyAad = context("body", ids.mailboxId, ids.messageId);
  const dek = randomBytes(32);
  try {
    const keyEnvelope = await sealKeyEnvelope(recipient, ids.mailboxId, ids.messageId, dek);
    const key = await aesKey(dek, "encrypt");
    return {
      keyId: pub.keyId,
      keyEnvelope: base64url(keyEnvelope),
      header: base64url(await sealBlock(HEADER_BLOCK, key, headerAad, headerJson)),
      body: await sealBlock(BODY_OBJECT, key, bodyAad, copy(raw)),
    };
  } finally {
    dek.fill(0);
  }
}

// ---- API: the browser --------------------------------------------------------

export async function generateMailboxKey(): Promise<{ publicKey: MailboxPublicKey; privateKey: MailboxPrivateKey }> {
  const scalar = randomBytes(32);
  try {
    const privateKey = await importPrivateScalar(scalar);
    const { keyId, publicKey } = materialOf(privateKey);
    return { publicKey: { keyId, publicKey: copy(publicKey) }, privateKey };
  } finally {
    scalar.fill(0);
  }
}

export async function openHeader(
  priv: MailboxPrivateKey,
  ids: { mailboxId: string; messageId: string },
  sealed: Pick<SealedMessage, "keyEnvelope" | "header">,
): Promise<MessageHeader> {
  const { keyPair } = materialOf(priv);
  return failClosed(async () => {
    const key = await openMessageKey(keyPair, ids.mailboxId, ids.messageId, sealed.keyEnvelope);
    const aad = context("header", ids.mailboxId, ids.messageId);
    return parseHeader(await openBlock(HEADER_BLOCK, key, aad, decodeBlock(sealed.header)));
  });
}

export async function openBody(
  priv: MailboxPrivateKey,
  ids: { mailboxId: string; messageId: string },
  sealed: Pick<SealedMessage, "keyEnvelope" | "body">,
): Promise<Uint8Array> {
  const { keyPair } = materialOf(priv);
  return failClosed(async () => {
    const key = await openMessageKey(keyPair, ids.mailboxId, ids.messageId, sealed.keyEnvelope);
    const aad = context("body", ids.mailboxId, ids.messageId);
    if (!(sealed.body instanceof Uint8Array)) throw new TypeError("body is a Uint8Array");
    return openBlock(BODY_OBJECT, key, aad, copy(sealed.body));
  });
}

export async function sealDraft(
  pub: MailboxPublicKey,
  ids: { mailboxId: string; draftId: string },
  draft: Draft,
): Promise<SealedDraft> {
  const recipient = await importPublicKey(pub);
  const json = serializeDraft(draft);
  const aad = context("draft", ids.mailboxId, ids.draftId);
  const dek = randomBytes(32);
  try {
    const keyEnvelope = await sealKeyEnvelope(recipient, ids.mailboxId, ids.draftId, dek);
    const key = await aesKey(dek, "encrypt");
    return {
      keyId: pub.keyId,
      keyEnvelope: base64url(keyEnvelope),
      sealed: base64url(await sealBlock(DRAFT_BLOCK, key, aad, json)),
    };
  } finally {
    dek.fill(0);
  }
}

export async function openDraft(
  priv: MailboxPrivateKey,
  ids: { mailboxId: string; draftId: string },
  sealed: SealedDraft,
): Promise<Draft> {
  const { keyPair } = materialOf(priv);
  return failClosed(async () => {
    const key = await openMessageKey(keyPair, ids.mailboxId, ids.draftId, sealed.keyEnvelope);
    const aad = context("draft", ids.mailboxId, ids.draftId);
    return parseDraft(await openBlock(DRAFT_BLOCK, key, aad, decodeBlock(sealed.sealed)));
  });
}

/** True when the private key's public half equals the advertised public key (domain-model G7). */
export async function publicKeyMatches(priv: MailboxPrivateKey, pub: MailboxPublicKey): Promise<boolean> {
  void priv, pub;
  throw new NotImplemented("publicKeyMatches");
}

/** The 32-byte `prf.eval.first` input for a passkey wrap. */
export async function prfInput(mailboxId: string, wrapId: string): Promise<Uint8Array> {
  void mailboxId, wrapId;
  throw new NotImplemented("prfInput");
}

export async function wrapPrivateKey(
  priv: MailboxPrivateKey,
  ctx: { mailboxId: string; wrapId: string; kind: WrapKind; secret: Uint8Array },
): Promise<KeyWrap> {
  void priv, ctx;
  throw new NotImplemented("wrapPrivateKey");
}

export async function unwrapPrivateKey(
  wrap: KeyWrap,
  ctx: { mailboxId: string; secret: Uint8Array },
): Promise<MailboxPrivateKey> {
  void wrap, ctx;
  throw new NotImplemented("unwrapPrivateKey");
}

/** A new 32-byte recovery secret and the 55-character display form (11 groups of 5). */
export function newRecoveryKey(): { secret: Uint8Array; display: string } {
  throw new NotImplemented("newRecoveryKey");
}

/** The 32-byte secret from its display form; throws RecoveryKeyTypo on a checksum mismatch. */
export function parseRecoveryKey(display: string): Uint8Array {
  void display;
  throw new NotImplemented("parseRecoveryKey");
}

// ---- Internals ---------------------------------------------------------------

function decodeBlock(encoded: string): Uint8Array<ArrayBuffer> {
  const bytes = fromBase64url(encoded);
  if (bytes === null) throw new TypeError("not base64url");
  return bytes;
}

/** Opens a key envelope (step 2) into an AES-256-GCM key for the blocks. */
async function openMessageKey(
  keyPair: CryptoKeyPair,
  mailboxId: string,
  objectId: string,
  keyEnvelope: string,
): Promise<CryptoKey> {
  const dek = await openKeyEnvelope(keyPair, mailboxId, objectId, decodeBlock(keyEnvelope));
  try {
    return await aesKey(dek, "decrypt");
  } finally {
    dek.fill(0);
  }
}
