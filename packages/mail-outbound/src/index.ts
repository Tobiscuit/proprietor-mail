/**
 * @platform-mail/outbound - turn a composed message into MIME and hand it to
 * Amazon SES (API v2, raw content).
 *
 * This file is the API in code form (specs/001-inbox-module/plan.md §6).
 * Until slice S3 lands every function throws `NotImplemented` and
 * `IMPLEMENTED` is false; the Worker (slice S2) compiles against these
 * signatures and injects fakes in its unit tests. S3 owns this package and may
 * add exports; it must not change a signature below without changing the plan
 * first.
 *
 * No bindings, no Node APIs: fetch and Web Crypto only, so it runs unchanged in
 * a Worker and in Node's test runner.
 */

/** False until S3 replaces the stubs. */
export const IMPLEMENTED: boolean = false;

export class NotImplemented extends Error {
  constructor(what: string) {
    super(`@platform-mail/outbound: ${what} is not implemented yet (slice S3)`);
    this.name = "NotImplemented";
  }
}

export interface Address {
  name?: string;
  address: string;
}

export interface OutgoingAttachment {
  filename: string;
  mimeType: string;
  content: Uint8Array;
  inline?: boolean;
  contentId?: string;
}

export interface ComposedMessage {
  /** Set by the Mailbox from its own address; never taken from a request. */
  from: Address;
  to: Address[];
  cc?: Address[];
  /** Goes into the SMTP envelope only, never into a header. */
  bcc?: Address[];
  replyTo?: Address[];
  subject: string;
  text: string;
  html?: string;
  /** Bare id, no angle brackets. */
  inReplyTo?: string;
  references?: string[];
  attachments?: OutgoingAttachment[];
}

export interface BuiltMessage {
  /** The RFC 5322 message, CRLF line endings: exactly what SES receives and what the Sent copy seals. */
  raw: Uint8Array;
  /** The Message-ID it carries, without angle brackets. */
  messageId: string;
  /** to + cc + bcc, lower-cased and de-duplicated: the SMTP envelope recipients. */
  recipients: string[];
}

export interface BuildOptions {
  /** The domain after "@" in the Message-ID: the mailbox's own domain. */
  messageIdDomain: string;
  /** Injected for tests. */
  now?: Date;
  /** Injected for tests; defaults to crypto.getRandomValues. */
  random?: (length: number) => Uint8Array;
}

export const LIMITS = {
  /** Recipients per message across to, cc and bcc (domain-model M7). */
  maxRecipients: 50,
  /** v1's ceiling for a whole raw message; S3 confirms SES's own limit and keeps this at or below it. */
  maxRawBytes: 10 * 1024 * 1024,
} as const;

/** A message that cannot be built: header injection, too many recipients, too large. */
export class InvalidMessage extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidMessage";
  }
}

export function buildMime(msg: ComposedMessage, opts: BuildOptions): BuiltMessage {
  void msg, opts;
  throw new NotImplemented("buildMime");
}

export interface SesCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  /** Only for temporary (STS) credentials. */
  sessionToken?: string;
  region: string;
}

export interface RawSendRequest {
  raw: Uint8Array;
  /** Must equal the From header's address; SES authorizes on it (ses:FromAddress). */
  fromAddress: string;
  recipients: string[];
  configurationSet: string;
  /** The SES tenant of the business (spec D7); omitted until the tenant exists. */
  tenantName?: string;
}

export interface RawMailer {
  send(req: RawSendRequest): Promise<{ providerMessageId: string }>;
}

/** SES refused or failed. `retryable` is true only for throttling and 5xx. */
export class SendRejected extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly retryable: boolean,
  ) {
    super(message);
    this.name = "SendRejected";
  }
}

export function sesRawMailer(
  creds: SesCredentials,
  opts?: { fetch?: typeof fetch; timeoutMs?: number },
): RawMailer {
  void creds, opts;
  throw new NotImplemented("sesRawMailer");
}
