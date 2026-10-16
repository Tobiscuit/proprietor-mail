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
  /** The factor's X25519 public key (device-v1 A2), base64url; null until the upgrade or `setFactorKey`. */
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

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  /** Ids, kinds, counts and outcomes: never message content. */
  detail: Record<string, string | number | boolean | null>;
}
