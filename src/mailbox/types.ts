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
  address: string;
  status: MailboxStatus;
  displayName: string;
  keys: KeyView[];
  wraps: WrapView[];
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
