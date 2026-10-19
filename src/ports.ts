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

/** Ids in the contracts' shape: `msg_` (envelope v1) and `chl_` (device-v1 A1), each + 26 Crockford base32 characters. */
export interface IdSource {
  messageId(): string;
  challengeId(): string;
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
  unread(event: { businessId: string; mailboxId: string; unread: number }): Promise<void>;
}

export interface Clock {
  now(): Date;
}

/**
 * contracts/device-v1.md A6 and A7, Mail's side only
 * (@proprietor/mail-crypto, src/proofs.ts): a challenge sealed to a public
 * key, with the answer Mail hashes and forgets, and a device's signature
 * verified with its public signing key. Mail holds nothing that opens a
 * challenge or makes a signature.
 */
export interface Proofs {
  sealChallenge(
    target: { publicKey: Uint8Array },
    ids: { mailboxId: string; challengeId: string; purpose: "session" | "factor"; targetId: string },
  ): Promise<{ sealed: string; answer: Uint8Array }>;
  verifyDeviceProof(
    signingKey: Uint8Array, // pragma: allowlist secret (a type annotation: a public P-256 point)
    ids: { mailboxId: string; deviceId: string; challengeId: string; nonce: Uint8Array },
    signature: Uint8Array,
  ): Promise<boolean>;
}

export interface MailboxPorts {
  sealer: Sealer;
  ids: IdSource;
  mime: MimeBuilder;
  mailer: RawMailer;
  signal: NewMailSignal;
  clock: Clock;
  proofs: Proofs;
}
