/**
 * The shapes of contracts/mail-client-v1.md, as the stub published them
 * (slice S0c) and as spec 002 amends them (slice D1: kept devices,
 * contracts/device-v1.md Part B). The screens build against these. A shape
 * changes only with the contract.
 */
import type { ActionInput, Address, Draft, MessageHeader } from "@proprietor/mail-crypto";

export type { ActionInput, Address, Draft, MessageHeader };

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
  /**
   * A retired key's successor seal (device-v1 A4): this key sealed to the key that replaced it; round 3
   * (A11): with its transition, signed by the factor whose proof the rotation spent.
   */
  successor?: { keyId: string; sealed: string; signedBy?: string; signature?: string } | null;
}

/** A factor's admission (device-v1 A11): signed by its admitter and by the factor itself, base64url of 64 bytes each. */
export interface FactorAdmission {
  by: string;
  signature: string;
  selfSignature: string;
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
  /** Round 3: the factor's Ed25519 signing key vS (A2b, D44), base64url of 32 bytes. */
  signingKey?: string | null;
  /** Round 3: its admission (A11). */
  admission?: FactorAdmission | null;
  /** The factor's binding tag (A5) under tagKeyId, base64url of 32 bytes. */
  tag?: string | null;
  tagKeyId?: string | null;
}

/** Round 3 (B4, M24): a removed factor's record, kept so that the signatures it made still verify. */
export interface RemovedFactorView {
  id: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  factorKey: string;
  signingKey: string;
  admission: FactorAdmission;
  removedAt: string;
}

/** A kept device as `mailbox()` lists it (device-v1 B4). */
export interface DeviceView {
  id: string;
  label: string;
  /** The ECDSA P-256 signing key, base64url of a 65-byte uncompressed point. */
  signingKey: string;
  /** The ECDH P-256 unlock key, base64url of 65 bytes; null while the device keeps none. */
  unlockKey: string | null;
  /** Round 3 (A11): the unlock key's statement, signed by the device's own signing key; null exactly when unlockKey is. */
  unlockSignature?: string | null;
  /** Round 3 (A11): signed by the factor that admitted the device. */
  admission?: { by: string; signature: string } | null;
  tag: string;
  tagKeyId: string;
  createdAt: string;
  /** The account that kept it (M21′): a browser opens nothing of another account's device (K10). */
  createdBy: string;
  lastSeenAt: string | null;
}

/** Round 3 (B7a): set by revokeDevices (an email code), cleared by the next rotation. */
export interface RotationDueView {
  since: string;
  by: string;
  devices: string[];
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
  /** Round 3 (M24): removed factors, kept for the factor graph (A11). */
  removedFactors?: RemovedFactorView[];
  /** Round 3 (B7a, K13): a rotation that must happen before any other change. */
  rotationDue?: RotationDueView | null;
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
  /** Round 3: vS (A2b) and the admission (A11), with factorKey once sessions are required. */
  signingKey?: string;
  admission?: FactorAdmission;
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
  /** A fresh factor proof, for the methods that need one; its challenge's descriptor names this very call (round 3). */
  factorProof?: FactorProof;
  /** Round 3: a key proof bound to the call, for `upgrade`. */
  keyProof?: KeyProof;
}

/** The answer to a `purpose: "factor"` challenge (device-v1 B1). */
export interface FactorProof {
  challengeId: string;
  /** base64url of the 32-byte answer. */
  answer: string;
}

/** Round 3: the answer to a `purpose: "key"` challenge, for `upgrade` (device-v1 B1). */
export interface KeyProof {
  challengeId: string;
  answer: string;
}

/** What `MailService.challenge` takes (device-v1 B6, round 3: an action for every purpose but session, A10). */
export type ChallengeRequest =
  | { purpose: "session" }
  | { purpose: "factor"; factorId: string; action: ActionInput }
  | { purpose: "key"; action: ActionInput }
  | { purpose: "email"; action: ActionInput };

/** What `MailService.challenge` answers (device-v1 B6). */
export interface ChallengeView {
  id: string;
  purpose: "session" | "factor" | "key" | "email";
  /** The active key, for purposes "session" and "key". */
  keyId: string | null;
  /** The factor, for purpose "factor". */
  factorId: string | null;
  /** base64url of 32 bytes. */
  nonce: string;
  /** base64url of 80 bytes (device-v1 A6); null for purpose "email". */
  sealed: string | null;
  /** Round 3: base64url of the action descriptor's bytes (action-descriptor-v1), for every purpose but "session". */
  descriptor?: string | null;
  expiresAt: string;
}

/**
 * What `MailService.openSession` takes (device-v1 B6). While sessions are required, exactly one of
 * `device` (a kept device's signature) and `factorProof` (a factor proof of kind open-session, D38).
 */
export interface OpenSessionRequest {
  challengeId: string;
  answer: string;
  device?: { id: string; signature: string };
  factorProof?: FactorProof;
}

/** What `MailService.openSession` answers. */
export interface OpenSessionResult {
  session: string;
  expiresAt: string;
  device: string | null;
}

/** device-v1 B7 (round 3: the unlock key's signature and the admission, A11). */
export interface DeviceInput {
  id: string;
  label: string;
  signingKey: string;
  unlockKey: string | null;
  /** Signed by the device's own signing key; present exactly when unlockKey is. */
  unlockSignature: string | null;
  /** Signed by the factor whose proof the call spends. */
  admission: { by: string; signature: string };
  tag: string;
  tagKeyId: string;
}

/** What `MailService.registerDevice` takes: the seal is present exactly when the unlock key is. */
export interface RegisterDeviceRequest {
  device: DeviceInput;
  seal: string | null;
}

/** What `MailService.updateDevice` takes: a new unlock key with its signature, seal and tag, or null for all three (the device locked). */
export interface UpdateDeviceRequest {
  unlockKey: string | null;
  unlockSignature: string | null;
  tag: string;
  tagKeyId: string;
  seal: string | null;
}

export interface RecipientRef {
  kind: "device" | "factor";
  id: string;
}

/** device-v1 B7: the new key, its successor seal, its transition (round 3, A11), and a seal and a tag for exactly the remaining recipients. */
export interface Rotation {
  from: string;
  publicKey: string;
  successorSeal: string;
  /** Signed by the factor whose proof the call spends. */
  transition: { signedBy: string; signature: string };
  seals: { to: RecipientRef; sealed: string }[];
  tags: { to: RecipientRef; tag: string }[];
}

/** What `MailService.removeDevices` takes (round 3: replaces removeDevice; 0 to 20 devices, 0 only while a rotation is due). */
export interface RemoveDevicesRequest {
  deviceIds: string[];
  rotation: Rotation;
}

/** What `MailService.revokeDevices` takes (round 3, B7a): confirmed by an email code, attested by the dashboard. */
export interface RevokeDevicesRequest {
  deviceIds: string[];
}

/** What `MailService.removeWrap`'s confirmation digests (A10): its one argument. */
export interface RemoveWrapRequest {
  wrapId: string;
}

/** What `MailService.upgrade` takes (B5 as amended): every wrap of the mailbox, exactly once, with round 3's signing key and admission. */
export interface UpgradeRequest {
  factors: { id: string; factorKey: string; signingKey: string; admission: FactorAdmission; tag: string; tagKeyId: string }[];
}

/** A request for Mail, and what to do in this browser once Mail accepted it. */
export interface PendingChange<T> {
  readonly request: T;
  /** Call once, after Mail answered `ok: true`. Before that, nothing in this browser has changed. */
  commit(): Promise<void>;
}

/**
 * Round 3 (A10, K4, K12): what a factor proof or a key proof confirms. `action` is what
 * `MailService.challenge` takes; `labels` are the labels of the devices it names as this browser's
 * view lists them. The browser builds the descriptor it expects from these and Mail's nonce and time,
 * compares bytes, and opens the challenge with its own digest.
 */
export interface Confirmation {
  readonly action: ActionInput;
  readonly labels: Readonly<Record<string, string>>;
}

/** A PendingChange that Mail takes only with a proof bound to it: challenge with `confirmation.action`, answer with `confirmation`. */
export interface ConfirmedChange<T> extends PendingChange<T> {
  readonly confirmation: Confirmation;
}

// ---- Kept devices (contracts/device-v1.md Part C, K5, K6) ----

/** R3: lock after right away, 15 minutes, 1 hour, or when the dashboard's sign-in ends. */
export type LockAfter = "right-away" | "15-minutes" | "1-hour" | "sign-out";

/**
 * The one record a kept device stores per mailbox and account (round 3, K10), exactly K5's fields: the
 * account, the two non-extractable P-256 private keys and their public forms, the keyId it last
 * accepted, the signing key of the factor it trusts, its lock setting, its last activity and the
 * sign-in id it was unlocked under. Never a mailbox key, a factor secret, a token or decrypted content.
 */
export interface KeptDevice {
  mailboxId: string;
  /** The dashboard's account id (the capability's `sub`) of the person who kept it. */
  accountId: string;
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
  /** Round 3 (K2″, K3′): base64url of the 32-byte signing key of the factor last used on this device. */
  trustRoot: string;
  lockAfter: LockAfter;
  /** Milliseconds since the epoch. */
  lastActiveAt: number;
  /** The dashboard's per-sign-in id it was unlocked under (D34), or null where the shell gives none. */
  signInId: string | null;
}

/** The fields an update may change; the device's identity (mailbox, account, id, label, signing key) never changes. */
export type KeptDeviceChange = Partial<Pick<KeptDevice, "unlockKey" | "unlockPublic" | "lastKeyId" | "trustRoot" | "lockAfter" | "lastActiveAt" | "signInId">>;

/**
 * Where a kept device lives: `indexedDbDeviceStore()` in a browser, `memoryDeviceStore()` in tests. One
 * record per mailbox AND account (K10): every call names both, and another account's record is never
 * read, written or deleted. Every write is checked against K5, and an update or a delete names the
 * device it is for, so a stale page never overwrites another page's newer record.
 */
export interface DeviceStore {
  get(mailboxId: string, accountId: string): Promise<KeptDevice | null>;
  put(record: KeptDevice): Promise<void>;
  /** Applies `change` to the record of `deviceId`, atomically; null when there is no such record. */
  update(mailboxId: string, accountId: string, deviceId: string, change: KeptDeviceChange): Promise<KeptDevice | null>;
  /**
   * K11: in ONE readwrite transaction, reads the record, and applies `change` (which sets lastKeyId) only
   * while it still holds `expectedLastKeyId`. `swapped: false` with the record as it now is (or null)
   * when another page moved it first: the caller resumes again from that.
   */
  swapLastKeyId(mailboxId: string, accountId: string, deviceId: string, expectedLastKeyId: string, change: KeptDeviceChange & { lastKeyId: string }): Promise<{ swapped: boolean; record: KeptDevice | null }>;
  /** Deletes this account's record of the mailbox, only if it is `deviceId`'s when that is given. */
  delete(mailboxId: string, accountId: string, deviceId?: string): Promise<void>;
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
  /** Round 3 (K10): the signed-in account (the capability's `sub`); only its record is read. */
  accountId: string;
  /** The dashboard's per-sign-in id now (D34), or null. */
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
  /**
   * The factor proof for `auth.factorProof`: the answer to a `purpose: "factor"` challenge for this
   * factor, only for the action `confirmation` describes (K4, K12): the descriptor it expects is built
   * from `confirmation` and compared with Mail's bytes, and the challenge opens with its own digest.
   */
  answer(challenge: ChallengeView, confirmation: Confirmation): Promise<FactorProof>;
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
  keep?: { store: DeviceStore; accountId: string; label: string; lockAfter?: LockAfter; signInId?: string | null };
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
  /** Round 3 (K10): the signed-in account (the capability's `sub`); needed with `store`, and only its record is read. */
  accountId?: string;
  /** The dashboard's per-sign-in id now (D34), or null. */
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

/**
 * The recipients this browser does not trust (contracts/device-v1.md Part C, K3 and K9): a device or a
 * factor whose tag fails under the active key, or a factor just used whose factor key is not the one
 * Mail lists. Nothing is ever sealed to them; the screens show them, as recipients no holder of the key
 * added, and offer to remove them (removeDevice for a device, removeWrap for a factor). Ids, as the
 * view lists them.
 */
export interface FlaggedRecipients {
  readonly devices: readonly string[];
  readonly factors: readonly string[];
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
  /** K3′, K9: the recipients flagged in the key ring as this session last read it. Frozen; both lists empty when all is well. */
  readonly flagged: FlaggedRecipients;
  /** Round 3 (B7a, K13): the rotation due after an email-code revocation, or null. While set, removeDevices comes before any other change. */
  readonly rotationDue: RotationDueView | null;
  openMessages(items: MessageItem[]): Promise<OpenedMessage[]>;
  openBody(item: MessageItem, sealedBody: Uint8Array): Promise<MailBody>;
  /** A null id makes a new draft id. */
  sealDraft(draftId: string | null, draft: DraftInput): Promise<SaveDraftRequest>;
  openDrafts(records: DraftRecord[]): Promise<OpenedDraft[]>;
  /** D38: what a deviceless session's factor proof confirms: kind open-session, for this session challenge. */
  sessionConfirmation(challenge: ChallengeView): Promise<Confirmation>;
  /**
   * The key proof for openSession: with this device's signature on a kept device, or, where no device is
   * kept and sessions are required, with `factorProof` (D38: a FreshFactor's answer for sessionConfirmation).
   */
  sessionProof(challenge: ChallengeView, factorProof?: FactorProof): Promise<OpenSessionRequest>;
  /** Round 3: the key proof for upgrade, only for the action `confirmation` describes (K4). */
  keyProof(challenge: ChallengeView, confirmation: Confirmation): Promise<KeyProof>;
  /** A FreshFactor for a sensitive setting: one prompt, or the recovery key. */
  reauthenticate(reauth: ReAuth): Promise<FreshFactor>;
  /** Re-checks a newer view of the same key (K2″, K3′, flagging what fails) and adopts its wraps, seals and devices. */
  refresh(view: MailboxView): Promise<void>;
  /** "This device is mine": registerDevice's request, admitted by the FreshFactor's factor (K12); commit() keeps the device in this browser. */
  keepThisDevice(options: { label: string; lockAfter?: LockAfter }, freshFactor: FreshFactor): Promise<ConfirmedChange<RegisterDeviceRequest>>;
  /** A new unlock key, signed by the device, and its seal, after a lock: updateDevice's request; commit() keeps it. */
  rekeyThisDevice(freshFactor: FreshFactor): Promise<PendingChange<UpdateDeviceRequest>>;
  /** Changes this device's lock setting at once; "right-away" drops its unlock key. */
  setLockAfter(lockAfter: LockAfter): Promise<{ updateDevice: UpdateDeviceRequest | null; needsRekey: boolean }>;
  /**
   * removeDevices' request (D40): the devices named and every flagged device, with the whole rotation and
   * its transition, signed by the FreshFactor's factor (K12); none only while a rotation is due (K13).
   * commit() moves this session to the new key. A flagged factor is FlaggedRecipient (remove it first).
   */
  removeDevices(view: MailboxView, deviceIds: readonly string[], freshFactor: FreshFactor): Promise<ConfirmedChange<RemoveDevicesRequest>>;
  /**
   * The one-time upgrade (D26): factor keys, signing keys, admissions (A11's cycle) and tags for every
   * factor of the mailbox, each just used (B5, M20). One that is not among `factors` is MissingFactors.
   * It is confirmed by a key proof (keyProof).
   */
  upgradeRequest(factors: readonly FreshFactor[]): Promise<ConfirmedChange<UpgradeRequest>>;
  /** A wrap of the active key for a new passkey (one more prompt), with its keys and admission once sessions are required. */
  addPasskey(passkey: PasskeyOptions, freshFactor: FreshFactor): Promise<ConfirmedChange<WrapInput>>;
  /**
   * A new recovery key, shown once, and its wrap: addWrap(change.request), then removeFactor of the old
   * recovery factor, each with a factor proof. FlaggedRecipient while a factor other than a recovery
   * factor is flagged; a flagged recovery factor is replaced this way (M5′).
   */
  replaceRecoveryKey(freshFactor: FreshFactor): Promise<NewRecoveryKey>;
  /** removeWrap's confirmation: the factor goes, and its record stays among removedFactors (M24). */
  removeFactor(factorId: string): Promise<ConfirmedChange<RemoveWrapRequest>>;
  touch(): void;
  /** Lock now: drops every key at once; on a kept device, also deletes its unlock key (K6). */
  lock(): Promise<LockResult>;
  /** K7: this device was removed (DeviceRevoked): deletes this account's record and drops every key. Never on Forbidden (K10). */
  forget(): Promise<void>;
  onLock(listener: (event: LockEvent) => void): () => void;
}

/** replaceRecoveryKey's answer: the new key's display form, shown once, and the change that adds it. */
export interface NewRecoveryKey extends ConfirmedChange<WrapInput> {
  readonly recoveryKey: string;
}

/** revokeRequest's answer (B7a, F13): the email challenge's action and revokeDevices' request. */
export interface RevokeRequest {
  readonly action: ActionInput;
  readonly request: RevokeDevicesRequest;
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
  /** Shown under "How your mail is protected" whenever the mailbox has kept devices (spec 002 §5). */
  devices(operator: string): string;
  /** Spec 001 §4's rows, then the rows spec 002 §5 adds. */
  readonly metadata: readonly { what: string; where: string; why: string }[];
}
