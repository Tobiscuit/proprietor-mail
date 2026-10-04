/**
 * The shapes of contracts/mail-client-v1.md, exactly as the stub published
 * them (slice S0c); the screens (S6b) build against these. A shape changes
 * only with the contract.
 */
import type { Address, Draft, MessageHeader } from "@proprietor/mail-crypto";

export type { Address, Draft, MessageHeader };

// ---- Shapes mirrored from MailService (contracts/mail-service-v1.md) ----

export interface KeyView {
  keyId: string;
  /** base64url of the raw 32-byte X25519 public key. */
  publicKey: string;
  createdAt: string;
  createdBy: string;
  retiredAt: string | null;
}

export interface WrapView {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  wrapped: string;
  createdAt: string;
  createdBy: string;
}

export interface MailboxView {
  id: string;
  /** The primary address. */
  address: string;
  /** Every address of the mailbox, the primary first. */
  addresses: string[];
  status: "provisioned" | "active" | "suspended" | "closed";
  displayName: string;
  keys: KeyView[];
  wraps: WrapView[];
}

export type Folder = "inbox" | "sent" | "drafts" | "archive" | "trash" | "spam";

export interface MessageItem {
  id: string;
  folder: Folder;
  direction: "in" | "out";
  receivedAt: string;
  size: number;
  seen: boolean;
  flagged: boolean;
  keyId: string;
  keyEnvelope: string;
  header: string;
}

export interface DraftRecord {
  id: string;
  keyId: string;
  keyEnvelope: string;
  sealed: string;
  updatedAt: string;
}

/** What `MailService.enroll` and `addWrap` take. */
export interface WrapInput {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  wrapped: string;
}

export interface EnrollRequest {
  publicKey: string;
  wraps: WrapInput[];
}

/** What `MailService.saveDraft` takes. */
export interface SaveDraftRequest {
  id: string;
  keyId: string;
  keyEnvelope: string;
  sealed: string;
}

// ---- Passkeys ----

export interface PasskeyOptions {
  /** Exactly the dashboard's host (spec D5). */
  rpId: string;
  /** Shown by the passkey manager: the platform's name. */
  rpName: string;
  /** Shown by the passkey manager, e.g. "Mail key — hello@example.com". */
  userName: string;
  userDisplayName: string;
  /** This device's label in Settings, e.g. "Laptop passkey". */
  label: string;
  /** Injectable for tests; default `navigator.credentials`. */
  credentials?: Pick<CredentialsContainer, "create" | "get">;
  timeoutMs?: number;
}

export type PasskeyPrompt = Pick<PasskeyOptions, "rpId" | "credentials" | "timeoutMs">;

/** A fresh unlock for the one operation that wraps the key again (K1). */
export type ReAuth = { passkey: PasskeyPrompt } | { recoveryKey: string };

// ---- Enrollment ----

export interface Enrollment {
  readonly mailboxId: string;
  readonly fingerprint: string;
  /** The display form, shown ONCE; never sent anywhere. */
  readonly recoveryKey: string;
  readonly passkey: "prf" | "none";
  /** 1-based positions among the 55 characters the owner must type back. */
  readonly recoveryCheck: { readonly positions: readonly number[] };
  confirmRecovery(characters: string): boolean;
  /** Only after confirmRecovery() returned true. */
  request(): EnrollRequest;
  /** The new key as a decrypt-only session, without another prompt. */
  unlocked(options?: UnlockOptions): UnlockedMailbox;
  discard(): void;
}

// ---- Unlocked mailbox ----

export interface UnlockOptions {
  /** Default 15 minutes without touch(); Infinity never locks on idle. */
  idleLockMs?: number;
}

export interface OpenedMessage {
  id: string;
  folder: Folder;
  direction: "in" | "out";
  receivedAt: string;
  size: number;
  seen: boolean;
  flagged: boolean;
  /** null when it could not be decrypted. */
  header: MessageHeader | null;
  undecryptable: boolean;
}

export interface OpenedDraft {
  id: string;
  updatedAt: string;
  draft: Draft | null;
  undecryptable: boolean;
}

export interface BodyAttachment {
  filename: string;
  mimeType: string;
  size: number;
  contentId: string | null;
  inline: boolean;
  content: Uint8Array;
}

export interface MailBody {
  /** The exact bytes that arrived or were sent (for "download .eml"). */
  raw: Uint8Array;
  text: string | null;
  html: string | null;
  attachments: BodyAttachment[];
}

export interface DraftInput {
  to: Address[];
  cc: Address[];
  bcc: Address[];
  subject: string;
  text: string;
  inReplyTo: string | null;
  references: string[];
}

export interface UnlockedMailbox {
  readonly mailboxId: string;
  readonly keyId: string;
  readonly fingerprint: string;
  readonly locked: boolean;
  openMessages(items: MessageItem[]): Promise<OpenedMessage[]>;
  openBody(item: MessageItem, sealedBody: Uint8Array): Promise<MailBody>;
  /** A null id makes a new draft id. */
  sealDraft(draftId: string | null, draft: DraftInput): Promise<SaveDraftRequest>;
  openDrafts(records: DraftRecord[]): Promise<OpenedDraft[]>;
  addPasskey(passkey: PasskeyOptions, reauth: ReAuth): Promise<WrapInput>;
  /** Then: addWrap(wrap), and removeWrap of the old recovery wrap. */
  replaceRecoveryKey(reauth: ReAuth): Promise<{ recoveryKey: string; wrap: WrapInput }>;
  touch(): void;
  lock(): void;
  onLock(listener: () => void): () => void;
}

// ---- Rendering: the one frame (spec D3 as amended) ----

/** A Trusted Types `TrustedHTML`. TypeScript's DOM lib has no type for it yet, so it is opaque here. */
export interface TrustedHtml {
  toString(): string;
}

export interface RenderedBody {
  readonly html: TrustedHtml | string;
  readonly remoteImagesBlocked: number;
  readonly inlineImages: number;
  dispose(): void;
}

// ---- Threads ----

export interface Thread {
  id: string;
  subject: string;
  /** Oldest first; duplicates by Message-ID merged. */
  messages: OpenedMessage[];
  /** Every mailbox address the thread's messages arrived for (domain-model G13). */
  envelopeTo: string[];
  latestAt: string;
  unread: number;
  participants: Address[];
}

// ---- Composing ----

export interface ComposeInput {
  /** One of the mailbox's addresses; omitted means the primary. */
  from?: string;
  to: Address[];
  cc: Address[];
  bcc: Address[];
  subject: string;
  text: string;
  inReplyTo: string | null;
  references: string[];
  attachments: File[];
}

/** What `MailService.send` takes (attachments as bytes). */
export interface SendRequest {
  idempotencyKey: string;
  from?: string;
  to: Address[];
  cc: Address[];
  bcc: Address[];
  subject: string;
  text: string;
  inReplyTo?: string;
  references: string[];
  attachments: { filename: string; mimeType: string; content: Uint8Array }[];
  draftId?: string;
}

// ---- The promise, as data (spec §2 Option A, §4) ----

export interface ProtectionTexts {
  optionA(operator: string): string;
  readonly metadata: readonly { what: string; where: string; why: string }[];
}
