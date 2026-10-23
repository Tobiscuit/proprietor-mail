import type { Role } from "../capability";
import type { DirectoryEntry, MailboxStatus } from "../directory/directory";
import type { FolderId } from "./folders";

/**
 * What MailService tells a Mailbox about each call: the Directory row it
 * checked (business and mailbox already matched the capability, M4) and who is
 * acting. The Mailbox applies the rest: its own identity and its policy.
 */
export interface CallContext {
  mailbox: DirectoryEntry;
  actor: { accountId: string; role: Role };
  /**
   * What the call carried for contracts/device-v1.md B1, as the caller sent
   * it: filled by MailService from the method's last argument (for `send`,
   * from `request.session`) and checked by the Mailbox (sessions.ts) against
   * what it stores. The token is never stored or logged. Absent: nothing.
   */
  auth?: CallAuth;
  /**
   * Round 3 (B7a, M22): the capability's `confirmation` claim, read strictly.
   * MailService sets it for `revokeDevices` and for no other method, so every
   * other method ignores an attestation by construction.
   */
  confirmation?: Attestation;
}

/** device-v1 B1, after MailService checked its shape (sessions.ts, parseAuth). */
export interface CallAuth {
  /** The token from openSession(), as sent: 43 base64url characters when it is one. */
  session: string | null;
  /** A factor proof: a live "factor" challenge and its answer (base64url, 32 bytes). */
  factorProof: { challengeId: string; answer: string } | null;
  /** Round 3: a key proof bound to the call (only `upgrade` takes one): a live "key" challenge and its answer. */
  keyProof: { challengeId: string; answer: string } | null;
}

/**
 * Round 3 (capability-v1 `confirmation`, action-descriptor-v1): the
 * dashboard's attestation of an email code, read strictly by the capability
 * verifier and handed to `revokeDevices` only (B7a, M22).
 */
export interface Attestation {
  method: string;
  accountId: string;
  actionKind: string;
  /** base64url SHA-256 of the descriptor of the email challenge it confirms (43 characters). */
  actionDigest: string;
  /** Whole seconds since 1970: when the dashboard checked the code. */
  at: number;
  /** The code's id, for the audit row: at most 64 characters of [A-Za-z0-9_-]. */
  codeId: string;
}

export interface KeyView {
  keyId: string;
  /** base64url of the raw 32-byte X25519 public key. */
  publicKey: string;
  createdAt: string;
  createdBy: string;
  retiredAt: string | null;
  /**
   * A retired key's successor seal (contracts/device-v1.md A4, B4): this key
   * sealed to the key that replaced it, 109 bytes base64url, with its
   * transition (round 3, A11): signed by the factor whose proof the rotation
   * spent. Null for the active key, and for a key retired before spec 002.
   */
  successor: { keyId: string; sealed: string; signedBy: string; signature: string } | null;
}

/** A factor's admission (A11): by its admitter, and countersigned by the factor itself; base64url of 64 bytes each. */
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
  /** Ciphertext: the private key wrapped on the owner's device. */
  wrapped: string;
  createdAt: string;
  createdBy: string;
  /** The factor's X25519 public key (device-v1 A2), base64url; null until the upgrade gives every factor its key. */
  factorKey: string | null;
  /** Round 3: its Ed25519 signing key (A2b, D44), base64url of 32 bytes; null while `factorKey` is. */
  signingKey: string | null;
  /** Round 3: its admission (A11); null while `factorKey` is. */
  admission: FactorAdmission | null;
  /** Its binding tag (A5), base64url, made under `tagKeyId`; null while `factorKey` is. */
  tag: string | null;
  tagKeyId: string | null;
}

/** Round 3 (B4, M24): a removed factor's record, kept (without its wrap or seals) so the signatures it made still verify. */
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

/** Round 3 (B4, B7a): the rotation an email-code revocation left due, until a removeDevices rotates. */
export interface RotationDueView {
  since: string;
  /** The account that revoked last. */
  by: string;
  /** Every device revoked since the last rotation. */
  devices: string[];
}

/** A kept device (device-v1 B4): public keys, its tag and when it last opened a session. */
export interface DeviceView {
  id: string;
  label: string;
  /** base64url of the 65-byte P-256 point (A3). */
  signingKey: string;
  /** base64url of the 65-byte P-256 point; null while the device is locked, or keeps nothing. */
  unlockKey: string | null;
  /** Round 3 (A11): the unlock key's statement signed by the device's own signing key; null exactly when `unlockKey` is. */
  unlockSignature: string | null;
  /** Round 3 (A11): signed by the factor whose proof kept the device. */
  admission: { by: string; signature: string };
  tag: string;
  tagKeyId: string;
  createdAt: string;
  /** The account that kept it (M21′): another account's page opens nothing of it (K10). */
  createdBy: string;
  lastSeenAt: string | null;
}

/** A seal of the active key to one recipient (A4). Every seal in the view is of the active key (M19). */
export interface SealView {
  keyId: string;
  to: { kind: "device" | "factor"; id: string };
  sealed: string;
}

export interface PolicyView {
  openRoles: Role[];
  sendRoles: Role[];
  assistant: "off" | "on";
  delivery: "store" | "store-and-forward";
  forwardTo: string | null;
  updatedAt: string;
  updatedBy: string;
}

export interface MailboxView {
  id: string;
  /** The primary address: the identity and the default From. */
  address: string;
  /** Every address that delivers to the mailbox, the primary first (plan.md §12). */
  addresses: string[];
  status: MailboxStatus;
  displayName: string;
  /** "optional" until the upgrade or an enrolment with factor keys; "required" from then on, for good (M13). */
  sessions: "optional" | "required";
  keys: KeyView[];
  wraps: WrapView[];
  /** Round 3 (M24): removed factors, kept for the factor graph (A11). */
  removedFactors: RemovedFactorView[];
  devices: DeviceView[];
  seals: SealView[];
  /** Round 3 (B7a): set by revokeDevices, cleared by the next rotation (removeDevices). */
  rotationDue: RotationDueView | null;
  /** Includes the delivery mode and forwarding target on every read (M10). */
  policy: PolicyView;
}

export interface MessageItem {
  id: string;
  folder: FolderId;
  direction: "in" | "out";
  receivedAt: string;
  size: number;
  seen: boolean;
  flagged: boolean;
  keyId: string;
  keyEnvelope: string;
  /** The sealed MessageHeader. */
  header: string;
}

export interface ListPage {
  items: MessageItem[];
  /** Pass as `before` for the next page; null when there is none. */
  next: string | null;
}

export interface DraftRecord {
  id: string;
  keyId: string;
  keyEnvelope: string;
  sealed: string;
  updatedAt: string;
}

export interface SendResult {
  /** The stored Sent copy; null only if SES accepted the message and storing the copy then failed. */
  messageId: string | null;
  providerMessageId: string;
}

/** What `challenge()` answers (device-v1 B6). */
export interface ChallengeView {
  id: string;
  purpose: "session" | "factor" | "key" | "email";
  /** The active key, for purposes "session" and "key"; null otherwise. */
  keyId: string | null;
  /** The factor, for purpose "factor"; null otherwise. */
  factorId: string | null;
  /** 32 bytes, base64url: what a device signs with a session challenge (A7). */
  nonce: string;
  /** enc || ct, 80 bytes, base64url (A6); null for purpose "email". */
  sealed: string | null;
  /** Round 3: base64url of the action descriptor's bytes (A10), for every purpose but "session". */
  descriptor: string | null;
  expiresAt: string;
}

/** What `openSession()` answers (B6): the token, once, and never again. */
export interface SessionView {
  /** 32 random bytes, base64url (43 characters); Mail keeps only its SHA-256 (A8). */
  session: string;
  expiresAt: string;
  /** The device whose session it is, or null. */
  device: string | null;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  /** Ids, kinds, counts and outcomes: never message content. */
  detail: Record<string, string | number | boolean | null>;
}
