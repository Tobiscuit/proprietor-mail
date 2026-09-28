import type { MailboxPublicKey, MessageHeader, SealedMessage } from "@proprietor/mail-crypto";
import type { BuildOptions, BuiltMessage, ComposedMessage, RawSendRequest } from "@proprietor/mail-outbound";

/**
 * What the Mailbox needs from the outside, as narrow interfaces. Production
 * wires the real packages behind them (src/wiring.ts); unit tests inject fakes
 * into a live Mailbox object. The Mailbox never imports a package function
 * directly, so a stub that still throws `NotImplemented` cannot reach a test
 * that is not about it.
 */

/** Envelope v1, seal side only: the Worker holds public keys and nothing else (domain-model M3). */
export interface Sealer {
  seal(
    pub: MailboxPublicKey,
    ids: { mailboxId: string; messageId: string },
    header: MessageHeader,
    raw: Uint8Array,
  ): Promise<SealedMessage>;
  /** The contract's keyId of a raw public key, recomputed server-side at enrolment. */
  keyIdOf(publicKey: Uint8Array): Promise<string>;
}

/** Message ids in the contract's shape (`msg_` + 26 Crockford base32 characters). */
export interface IdSource {
  messageId(): string;
}

export interface MimeBuilder {
  build(msg: ComposedMessage, opts: BuildOptions): BuiltMessage;
}

export interface RawMailer {
  send(req: RawSendRequest): Promise<{ providerMessageId: string }>;
}

/**
 * "A new message arrived" to the business's dashboard Agent: a count, never
 * content (plan.md §1 seam 4). The dashboard will export an entrypoint
 * `MailSignals` with exactly this method, bound as MAIL_SIGNALS once the
 * dashboard ships it.
 */
export interface NewMailSignal {
  unread(event: { tenantId: string; mailboxId: string; unread: number }): Promise<void>;
}

export interface Clock {
  now(): Date;
}

export interface MailboxPorts {
  sealer: Sealer;
  ids: IdSource;
  mime: MimeBuilder;
  mailer: RawMailer;
  signal: NewMailSignal;
  clock: Clock;
}
