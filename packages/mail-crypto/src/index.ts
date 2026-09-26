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

/** False until S1 replaces the stubs. Tests that need real crypto skip on it. */
export const IMPLEMENTED: boolean = false;

export const ENVELOPE_VERSION = 1 as const;

export class NotImplemented extends Error {
  constructor(what: string) {
    super(`@platform-mail/crypto: ${what} is not implemented yet (slice S1)`);
    this.name = "NotImplemented";
  }
}

/** An authentication tag did not verify, or a blob is malformed. Never an empty result. */
export class DecryptionFailed extends Error {
  constructor(message = "this could not be decrypted") {
    super(message);
    this.name = "DecryptionFailed";
  }
}

/** A recovery key whose checksum does not match: a typo, caught before any decryption. */
export class RecoveryKeyTypo extends Error {
  constructor(message = "that recovery key has a typo") {
    super(message);
    this.name = "RecoveryKeyTypo";
  }
}

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
  throw new NotImplemented(`newId(${prefix})`);
}

export async function keyIdOf(publicKey: Uint8Array): Promise<string> {
  void publicKey;
  throw new NotImplemented("keyIdOf");
}

/** keyId in groups of four, for people to compare. */
export function fingerprint(keyId: string): string {
  void keyId;
  throw new NotImplemented("fingerprint");
}

// ---- API: the Worker (seal only) --------------------------------------------

export async function sealMessage(
  pub: MailboxPublicKey,
  ids: { mailboxId: string; messageId: string },
  header: MessageHeader,
  raw: Uint8Array,
): Promise<SealedMessage> {
  void pub, ids, header, raw;
  throw new NotImplemented("sealMessage");
}

// ---- API: the browser --------------------------------------------------------

export async function generateMailboxKey(): Promise<{ publicKey: MailboxPublicKey; privateKey: MailboxPrivateKey }> {
  throw new NotImplemented("generateMailboxKey");
}

export async function openHeader(
  priv: MailboxPrivateKey,
  ids: { mailboxId: string; messageId: string },
  sealed: Pick<SealedMessage, "keyEnvelope" | "header">,
): Promise<MessageHeader> {
  void priv, ids, sealed;
  throw new NotImplemented("openHeader");
}

export async function openBody(
  priv: MailboxPrivateKey,
  ids: { mailboxId: string; messageId: string },
  sealed: Pick<SealedMessage, "keyEnvelope" | "body">,
): Promise<Uint8Array> {
  void priv, ids, sealed;
  throw new NotImplemented("openBody");
}

export async function sealDraft(
  pub: MailboxPublicKey,
  ids: { mailboxId: string; draftId: string },
  draft: Draft,
): Promise<SealedDraft> {
  void pub, ids, draft;
  throw new NotImplemented("sealDraft");
}

export async function openDraft(
  priv: MailboxPrivateKey,
  ids: { mailboxId: string; draftId: string },
  sealed: SealedDraft,
): Promise<Draft> {
  void priv, ids, sealed;
  throw new NotImplemented("openDraft");
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
