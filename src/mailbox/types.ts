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
}

/** device-v1 B1, after MailService checked its shape (sessions.ts, parseAuth). */
export interface CallAuth {
  /** The token from openSession(), as sent: 43 base64url characters when it is one. */
  session: string | null;
  /** A factor proof: a live "factor" challenge and its answer (base64url, 32 bytes). */
  factorProof: { challengeId: string; answer: string } | null;
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
   * sealed to the key that replaced it, 109 bytes base64url. Null for the
   * active key, and for a key retired before spec 002.
   */
  successor: { keyId: string; sealed: string } | null;
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
  /** Its binding tag (A5), base64url, made under `tagKeyId`; null while `factorKey` is. */
  tag: string | null;
  tagKeyId: string | null;
}

/** A kept device (device-v1 B4): public keys, its tag and when it last opened a session. */
export interface DeviceView {
  id: string;
  label: string;
  /** base64url of the 65-byte P-256 point (A3). */
  signingKey: string;
  /** base64url of the 65-byte P-256 point; null while the device is locked, or keeps nothing. */
  unlockKey: string | null;
  tag: string;
  tagKeyId: string;
  createdAt: string;
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
  devices: DeviceView[];
  seals: SealView[];
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
  purpose: "session" | "factor";
  /** The active key, for a session challenge; null for a factor challenge. */
  keyId: string | null;
  /** The factor, for a factor challenge; null for a session challenge. */
  factorId: string | null;
  /** 32 bytes, base64url: what a device signs with the challenge (A7). */
  nonce: string;
  /** enc || ct, 80 bytes, base64url (A6). */
  sealed: string;
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
