import type { LogValue } from "../log";
import type { Proofs } from "../ports";

/**
 * What the key ring's modules (keyring.ts, sessions.ts, devices.ts) need from
 * the Mailbox, and nothing more: its SQLite, its transactions, its clock and
 * proofs ports, its active key and its audit log. The Mailbox builds one for
 * each call (`Mailbox.store()`); the modules reach the Durable Object only
 * through it, so the Mailbox stays the one consistency boundary.
 */
export interface MailboxStore {
  readonly mailboxId: string;
  readonly sql: SqlStorage;
  /** `storage.transactionSync`: the callback is synchronous, and everything it wrote is rolled back when it throws. */
  transaction<T>(fn: () => T): T;
  now(): Date;
  /** A new `chl_` id (device-v1 A1), from the ids port. */
  newChallengeId(): string;
  /** The contract's keyId of a raw public key (envelope v1), recomputed here: a keyId a browser claims is never trusted. */
  keyIdOf(publicKey: Uint8Array): Promise<string>;
  /** The key new mail is sealed to: the one key not retired (the Mailbox's own `activeKey()`). */
  activeKey(): { keyId: string; publicKey: Uint8Array } | null;
  /** Ids, kinds, counts and labels only (device-v1 B9): never a token, an answer, a seal or a key. */
  audit(actor: string, action: string, detail: Record<string, LogValue>): void;
  readonly proofs: Proofs;
}

export function rows<T>(sql: SqlStorage, query: string, ...args: unknown[]): T[] {
  return sql.exec(query, ...args).toArray() as T[];
}
