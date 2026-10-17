/**
 * The shapes of contracts/mail-client-v1.md, as the stub published them
 * (slice S0c) and as spec 002 amends them (slice D1: kept devices,
 * contracts/device-v1.md Part B). The screens build against these. A shape
 * changes only with the contract.
 */
import type { Address, Draft, MessageHeader } from "@proprietor/mail-crypto";

export type { Address, Draft, MessageHeader };

// ---- Shapes mirrored from MailService (contracts/mail-service-v1.md) ----

// The fields spec 002 adds (device-v1 B4) are optional here: a view from a
// Mail Worker without spec 002 (a rollback, spec 002 §8) lacks them and is
// read as a mailbox whose sessions are optional, with no devices, seals or
// factor keys.

export interface KeyView {
  keyId: string;
  /** base64url of the raw 32-byte X25519 public key. */
  publicKey: string;
  createdAt: string;
  createdBy: string;
  retiredAt: string | null;
  /** A retired key's successor seal (device-v1 A4): this key sealed to the key that replaced it. */
  successor?: { keyId: string; sealed: string } | null;
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
  /** The factor's public key pkF (device-v1 A2), base64url of 32 bytes; null until the factor has one. */
  factorKey?: string | null;
  /** The factor's binding tag (A5) under tagKeyId, base64url of 32 bytes. */
  tag?: string | null;
  tagKeyId?: string | null;
}

/** A kept device as `mailbox()` lists it (device-v1 B4). */
export interface DeviceView {
  id: string;
  label: string;
  /** The ECDSA P-256 signing key, base64url of a 65-byte uncompressed point. */
  signingKey: string;
  /** The ECDH P-256 unlock key, base64url of 65 bytes; null while the device keeps none. */
  unlockKey: string | null;
  tag: string;
  tagKeyId: string;
  createdAt: string;
  createdBy: string;
  lastSeenAt: string | null;
}

/** A seal of the active key to one device or factor (device-v1 B4, M19). */
export interface SealView {
  keyId: string;
  to: { kind: "device" | "factor"; id: string };
  sealed: string;
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
  /** device-v1 B2: "optional" until the upgrade or an enrollment with factor keys, then "required" for good. */
  sessions?: "optional" | "required";
  devices?: DeviceView[];
  seals?: SealView[];
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

/**
 * What `MailService.enroll` and `addWrap` take. Once a mailbox's sessions are
 * required, a wrap also carries its factor key and its tag under the active
 * key (device-v1 B5, B7); before that, it carries neither.
 */
export interface WrapInput {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  wrapped: string;
  factorKey?: string;
  tag?: string;
  tagKeyId?: string;
}

export interface EnrollRequest {
  publicKey: string;
  wraps: WrapInput[];
  /** The browser that enrolls, when the owner said "this device is mine" (device-v1 B5). */
  device?: RegisterDeviceRequest;
}

// ---- device-v1 Part B: what the browser sends ----

/** The last argument of every session-bound MailService method (device-v1 B1). */
export interface Auth {
  /** The token from openSession(): base64url of 32 bytes. Held in memory only, never stored. */
  session?: string;
  /** A fresh factor proof, for the methods that need one. */
  factorProof?: FactorProof;
}

/** The answer to a `purpose: "factor"` challenge (device-v1 B1). */
export interface FactorProof {
  challengeId: string;
  /** base64url of the 32-byte answer. */
  answer: string;
}

/** What `MailService.challenge` takes (device-v1 B6). */
export type ChallengeRequest = { purpose: "session" } | { purpose: "factor"; factorId: string };

/** What `MailService.challenge` answers (device-v1 B6). */
export interface ChallengeView {
  id: string;
  purpose: "session" | "factor";
  /** The active key, for purpose "session". */
  keyId: string | null;
  /** The factor, for purpose "factor". */
  factorId: string | null;
  /** base64url of 32 bytes. */
  nonce: string;
  /** base64url of 80 bytes (device-v1 A6). */
  sealed: string;
  expiresAt: string;
}

/** What `MailService.openSession` takes (device-v1 B6). `device` is there only on a kept device. */
export interface OpenSessionRequest {
  challengeId: string;
  answer: string;
  device?: { id: string; signature: string };
}

/** What `MailService.openSession` answers. */
export interface OpenSessionResult {
  session: string;
  expiresAt: string;
  device: string | null;
}

/** device-v1 B7. */
export interface DeviceInput {
  id: string;
  label: string;
  signingKey: string;
  unlockKey: string | null;
  tag: string;
  tagKeyId: string;
}

/** What `MailService.registerDevice` takes: the seal is present exactly when the unlock key is. */
export interface RegisterDeviceRequest {
  device: DeviceInput;
  seal: string | null;
}

/** What `MailService.updateDevice` takes: a new unlock key with its seal and tag, or null for both (the device locked). */
export interface UpdateDeviceRequest {
  unlockKey: string | null;
  tag: string;
  tagKeyId: string;
  seal: string | null;
}

export interface RecipientRef {
  kind: "device" | "factor";
  id: string;
}

/** device-v1 B7: the new key, its successor seal, and a seal and a tag for exactly the remaining recipients. */
export interface Rotation {
  from: string;
  publicKey: string;
  successorSeal: string;
  seals: { to: RecipientRef; sealed: string }[];
  tags: { to: RecipientRef; tag: string }[];
}

/** What `MailService.removeDevice` takes. */
export interface RemoveDeviceRequest {
  deviceId: string;
  rotation: Rotation;
}

/** What `MailService.setFactorKey` takes: a seal of the active key only when the factor's wrap is of a retired key. */
export interface SetFactorKeyRequest {
  factorId: string;
  factorKey: string;
  tag: string;
  tagKeyId: string;
  seal: string | null;
}

/** What `MailService.upgrade` takes (device-v1 B5): it must name a recovery factor. */
export interface UpgradeRequest {
  factors: { id: string; factorKey: string; tag: string; tagKeyId: string }[];
}

/** A request for Mail, and what to do in this browser once Mail accepted it. */
export interface PendingChange<T> {
  readonly request: T;
  /** Call once, after Mail answered `ok: true`. Before that, nothing in this browser has changed. */
  commit(): Promise<void>;
}

// ---- Kept devices (contracts/device-v1.md Part C, K5, K6) ----

/** R3: lock after right away, 15 minutes, 1 hour, or when the dashboard's sign-in ends. */
export type LockAfter = "right-away" | "15-minutes" | "1-hour" | "sign-out";

/**
 * The one record a kept device stores per mailbox, exactly K5's fields: the
 * two non-extractable P-256 private keys and their public forms, the keyId it
 * last accepted, its lock setting, its last activity and the sign-in id it
 * was unlocked under. Never a mailbox key, a factor secret, a token or
 * decrypted content.
 */
export interface KeptDevice {
  mailboxId: string;
  deviceId: string;
  label: string;
  /** ECDSA P-256, non-extractable, sign only. */
  signingKey: CryptoKey; // pragma: allowlist secret (a field type)
  /** ECDH P-256, non-extractable, deriveBits only; null while locked or for "right-away". */
  unlockKey: CryptoKey | null;
  /** base64url of the signing key's 65-byte public point. */
  signingPublic: string;
  /** base64url of the unlock key's 65-byte public point; null exactly when unlockKey is. */
  unlockPublic: string | null;
  lastKeyId: string;
  lockAfter: LockAfter;
  /** Milliseconds since the epoch. */
  lastActiveAt: number;
  /** The dashboard's per-sign-in id it was unlocked under (D30), or null where the shell gives none. */
  signInId: string | null;
}

/** The fields an update may change; the device's identity never changes. */
export type KeptDeviceChange = Partial<Pick<KeptDevice, "unlockKey" | "unlockPublic" | "lastKeyId" | "lockAfter" | "lastActiveAt" | "signInId">>;

/**
 * Where a kept device lives: `indexedDbDeviceStore()` in a browser,
 * `memoryDeviceStore()` in tests. Every write is checked against K5, and an
 * update or a delete names the device it is for, so a stale page never
 * overwrites another page's newer record.
 */
export interface DeviceStore {
  get(mailboxId: string): Promise<KeptDevice | null>;
  put(record: KeptDevice): Promise<void>;
  /** Applies `change` to the record of `deviceId`, atomically; null when there is no such record. */
  update(mailboxId: string, deviceId: string, change: KeptDeviceChange): Promise<KeptDevice | null>;
  /** Deletes the mailbox's record, only if it is `deviceId`'s when that is given. */
  delete(mailboxId: string, deviceId?: string): Promise<void>;
}

/** What the screens may show about this browser's kept device: plain facts, no keys. */
export interface DeviceInfo {
  readonly id: string;
  readonly label: string;
  readonly lockAfter: LockAfter;
  /** True while it keeps an unlock key, i.e. opens without a prompt at its next load. */
  readonly keepsUnlocked: boolean;
}

/** Why a kept device needs a factor (resumeDevice). */
export type LockReason =
  | "right-away" // its setting keeps nothing between pages
  | "idle" // 15 minutes or 1 hour without use passed
  | "signed-out" // the dashboard's sign-in id changed
  | "locked" // locked earlier (Lock now, or a lock that fell due)
  | "no-seal"; // Mail holds no seal this device can open (it was locked at Mail, or Mail lacks spec 002)

export type ResumeResult =
  | { readonly state: "none" }
  | { readonly state: "unlocked"; readonly mailbox: UnlockedMailbox }
  | { readonly state: "locked"; readonly reason: LockReason; readonly device: DeviceInfo }
  | { readonly state: "removed" };

export interface ResumeOptions {
  store: DeviceStore;
  /** The dashboard's per-sign-in id now (D30), or null. */
  signInId: string | null;
  /** Injectable clock, milliseconds since the epoch. Default Date.now. */
  now?: () => number;
  idleLockMs?: number;
}

/** What locking did: the request to clear the unlock key at Mail, when this was a kept device that kept one. */
export interface LockResult {
  readonly updateDevice: UpdateDeviceRequest | null;
}

export interface LockEvent {
  readonly reason: "lock" | "idle" | "removed";
  /** Send it with the mail session while one is live (K6), then forget the session. */
  readonly updateDevice: UpdateDeviceRequest | null;
}

/**
 * What the browser holds for 2 minutes after a factor was used (device-v1
 * Part C, K1′): the factor's own key (A2), and a wrappable copy of the active
 * key for the one step that seals or wraps it again. It answers factor
 * challenges. After 2 minutes, or dispose(), every use throws FactorExpired.
 */
export interface FreshFactor {
  readonly factorId: string;
  readonly kind: "passkey-prf" | "recovery";
  /** Milliseconds since the epoch. */
  readonly expiresAt: number;
  readonly expired: boolean;
  /** The factor proof for `auth.factorProof`: the answer to a `purpose: "factor"` challenge for this factor. */
  answer(challenge: ChallengeView): Promise<FactorProof>;
  dispose(): void;
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
  /** Only after confirmRecovery() returned true. With `keep`, it carries the device and its seal. */
  request(): EnrollRequest;
  /** After Mail accepted request(): keeps this device in the store, when `keep` was asked. Otherwise nothing. */
  commit(): Promise<void>;
  /** The new key as a decrypt-only session, without another prompt; with `keep`, only after commit(), and bound to the device. */
  unlocked(options?: UnlockOptions): UnlockedMailbox;
  discard(): void;
}

/** startEnrollment's options: "this device is mine" makes the browser that enrolls a kept device (plan.md F12). */
export interface EnrollmentOptions {
  keep?: { store: DeviceStore; label: string; lockAfter?: LockAfter; signInId?: string | null };
  /** Injectable clock, milliseconds since the epoch. Default Date.now. */
  now?: () => number;
}

// ---- Unlocked mailbox ----

export interface UnlockOptions {
  /**
   * Default 15 minutes without touch(); Infinity never locks on idle. A kept
   * device locks after its own setting instead (15 minutes, 1 hour, or not on
   * idle for "sign-out").
   */
  idleLockMs?: number;
  /** Where this browser keeps devices. Without it nothing is kept: a shared computer. */
  store?: DeviceStore;
  /** The dashboard's per-sign-in id now (D30), or null. */
  signInId?: string | null;
  /** Injectable clock, milliseconds since the epoch. Default Date.now. */
  now?: () => number;
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
  /** The active key (it changes when this browser commits a rotation). */
  readonly keyId: string;
  readonly fingerprint: string;
  /** Every key the session holds, the active one first (G40: old mail opens after a rotation). */
  readonly keyIds: readonly string[];
  readonly locked: boolean;
  /** This browser's kept device, or null on a shared computer. */
  readonly device: DeviceInfo | null;
  /** The FreshFactor of the factor this unlock used; null after resumeDevice or enrollment. */
  readonly freshFactor: FreshFactor | null;
  openMessages(items: MessageItem[]): Promise<OpenedMessage[]>;
  openBody(item: MessageItem, sealedBody: Uint8Array): Promise<MailBody>;
  /** A null id makes a new draft id. */
  sealDraft(draftId: string | null, draft: DraftInput): Promise<SaveDraftRequest>;
  openDrafts(records: DraftRecord[]): Promise<OpenedDraft[]>;
  /** The key proof for openSession, with this device's signature on a kept device. */
  sessionProof(challenge: ChallengeView): Promise<OpenSessionRequest>;
  /** A FreshFactor for a sensitive setting: one prompt, or the recovery key. */
  reauthenticate(reauth: ReAuth): Promise<FreshFactor>;
  /** Re-checks a newer view of the same key (K3) and adopts its wraps, seals and devices. */
  refresh(view: MailboxView): Promise<void>;
  /** "This device is mine": registerDevice's request; commit() keeps the device in this browser. */
  keepThisDevice(options: { label: string; lockAfter?: LockAfter }, freshFactor: FreshFactor): Promise<PendingChange<RegisterDeviceRequest>>;
  /** A new unlock key and its seal, after a lock: updateDevice's request; commit() keeps it. */
  rekeyThisDevice(freshFactor: FreshFactor): Promise<PendingChange<UpdateDeviceRequest>>;
  /** Changes this device's lock setting at once; "right-away" drops its unlock key. */
  setLockAfter(lockAfter: LockAfter): Promise<{ updateDevice: UpdateDeviceRequest | null; needsRekey: boolean }>;
  /** removeDevice's request with the whole rotation; commit() moves this session to the new key. */
  removeDevice(view: MailboxView, deviceId: string, freshFactor: FreshFactor): Promise<PendingChange<RemoveDeviceRequest>>;
  /** The one-time upgrade (D26): factor keys and tags for the factors just used; one must be the recovery key. */
  upgradeRequest(factors: readonly FreshFactor[]): Promise<PendingChange<UpgradeRequest>>;
  /** Gives `target` its factor key; the factor proof for the call comes from `proving`, another factor. */
  setFactorKey(target: FreshFactor, proving: FreshFactor): Promise<PendingChange<SetFactorKeyRequest>>;
  /** A wrap of the active key for a new passkey (one more prompt), with its factor key once sessions are required. */
  addPasskey(passkey: PasskeyOptions, freshFactor: FreshFactor): Promise<WrapInput>;
  /** Then: addWrap(wrap), and removeWrap of the old recovery wrap, each with a factor proof. */
  replaceRecoveryKey(freshFactor: FreshFactor): Promise<{ recoveryKey: string; wrap: WrapInput }>;
  touch(): void;
  /** Lock now: drops every key at once; on a kept device, also deletes its unlock key (K6). */
  lock(): Promise<LockResult>;
  /** K7: this device was removed (DeviceRevoked): deletes its record and drops every key. */
  forget(): Promise<void>;
  onLock(listener: (event: LockEvent) => void): () => void;
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
  /** The mail session token (device-v1 B1: send carries it inside the request). */
  session?: string;
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

// ---- The promise, as data (spec 001 §2 Option A and §4; spec 002 §5) ----

export interface ProtectionTexts {
  optionA(operator: string): string;
  readonly metadata: readonly { what: string; where: string; why: string }[];
}
