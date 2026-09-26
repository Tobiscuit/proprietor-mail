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

import { CRLF, hex } from "./encoding";
import { MAX_HARD_LINE, assemble, newBoundary } from "./mime";

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

/**
 * The message as RFC 5322 + MIME, 7-bit and CRLF throughout, every line within
 * 76 characters (998 at most, for an unbreakable address or id). Throws
 * `InvalidMessage` before building anything when a header input holds CR, LF
 * or NUL, an address or id is malformed, or a limit in `LIMITS` is passed.
 * Error messages name the field, never its value: callers log them.
 */
export function buildMime(msg: ComposedMessage, opts: BuildOptions): BuiltMessage {
  const now = opts.now ?? new Date();
  if (Number.isNaN(now.getTime())) throw new InvalidMessage("the clock gave an invalid date");
  checkHeaderValue(opts.messageIdDomain, "messageIdDomain");
  if (!DOMAIN.test(opts.messageIdDomain)) throw new InvalidMessage("messageIdDomain is not a domain name");

  const to = msg.to ?? [];
  const cc = msg.cc ?? [];
  const bcc = msg.bcc ?? [];
  const replyTo = msg.replyTo ?? [];
  checkMailbox(msg.from, "from");
  to.forEach((a, i) => checkMailbox(a, `to[${i}]`));
  cc.forEach((a, i) => checkMailbox(a, `cc[${i}]`));
  bcc.forEach((a, i) => checkMailbox(a, `bcc[${i}]`));
  replyTo.forEach((a, i) => checkMailbox(a, `replyTo[${i}]`));
  checkHeaderValue(msg.subject, "subject");
  if (msg.inReplyTo !== undefined) checkId(msg.inReplyTo, "inReplyTo");
  (msg.references ?? []).forEach((r, i) => checkId(r, `references[${i}]`));
  const attachments = msg.attachments ?? [];
  attachments.forEach(checkAttachment);

  const recipients = [...new Set([...to, ...cc, ...bcc].map((a) => a.address.toLowerCase()))];
  if (recipients.length === 0) throw new InvalidMessage("the message has no recipients");
  if (recipients.length > LIMITS.maxRecipients) {
    throw new InvalidMessage(`too many recipients: ${recipients.length} (at most ${LIMITS.maxRecipients})`);
  }

  // Encoding never shrinks content, so this bound is safe and avoids encoding
  // megabytes only to throw them away. (UTF-16 length ≤ UTF-8 byte length.)
  const contentFloor =
    msg.text.length + (msg.html?.length ?? 0) + attachments.reduce((sum, a) => sum + a.content.byteLength, 0);
  if (contentFloor > LIMITS.maxRawBytes) {
    throw new InvalidMessage(`message too large: its content alone is over ${LIMITS.maxRawBytes} bytes`);
  }

  const random = opts.random ?? ((length: number) => crypto.getRandomValues(new Uint8Array(length)));
  const messageId = `${hex(random(16))}@${opts.messageIdDomain}`;
  const text = assemble({
    msg: { ...msg, to, cc, bcc, replyTo, attachments },
    messageId,
    date: now,
    newBoundary: () => newBoundary(random),
  });

  const raw = new TextEncoder().encode(text);
  if (raw.byteLength > LIMITS.maxRawBytes) {
    throw new InvalidMessage(`message too large: ${raw.byteLength} bytes encoded (at most ${LIMITS.maxRawBytes})`);
  }
  if (longestLine(text) > MAX_HARD_LINE) {
    throw new InvalidMessage(`a line would be longer than ${MAX_HARD_LINE} characters (an address or id is too long)`);
  }
  return { raw, messageId, recipients };
}

// ── validation ───────────────────────────────────────────────────────────

/** CR and LF end a header line, and NUL ends a C string in whatever reads it next. */
const HEADER_BREAKERS = /[\r\n\u0000]/;

function checkHeaderValue(value: string, field: string): void {
  if (typeof value !== "string") throw new InvalidMessage(`${field} is not a string`);
  if (HEADER_BREAKERS.test(value)) throw new InvalidMessage(`header injection: CR, LF or NUL in ${field}`);
}

const ATEXT = "A-Za-z0-9!#$%&'*+/=?^_`{|}~-";
const LOCAL_PART = new RegExp(`^[${ATEXT}]+(?:\\.[${ATEXT}]+)*$`);
const LABEL = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?";
/** An ASCII host name; an internationalized domain must arrive as punycode. */
const DOMAIN = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})*$`);

/**
 * A bare addr-spec with a dot-atom local part (RFC 5322 §3.4.1) and an ASCII
 * domain. Strict on purpose: SES does not support SMTPUTF8, so a non-ASCII
 * local part cannot be delivered and a non-ASCII domain must be punycode
 * (API_Destination); and anything outside this grammar - a quote, a comma, an
 * angle bracket - could change the meaning of the header it is written into.
 */
export function isAddress(value: string): boolean {
  if (typeof value !== "string" || value.length > 254) return false;
  const at = value.lastIndexOf("@");
  if (at <= 0) return false;
  const local = value.slice(0, at);
  return local.length <= 64 && LOCAL_PART.test(local) && DOMAIN.test(value.slice(at + 1));
}

function checkMailbox(a: Address, field: string): void {
  if (a === null || typeof a !== "object") throw new InvalidMessage(`${field} is not an address`);
  checkHeaderValue(a.address, `${field}.address`);
  if (a.name !== undefined) checkHeaderValue(a.name, `${field}.name`);
  if (!isAddress(a.address)) throw new InvalidMessage(`${field}.address is not a valid email address`);
}

/** A bare msg-id (or Content-ID): printable ASCII without space, "<" or ">". */
const MSG_ID = /^[\x21-\x3b\x3d\x3f-\x7e]+$/;

function checkId(value: string, field: string): void {
  checkHeaderValue(value, field);
  if (!MSG_ID.test(value)) throw new InvalidMessage(`${field} is not a bare message id (no angle brackets or spaces)`);
}

/** RFC 6838 §4.2 restricted-name, twice. */
const MEDIA_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}$/;

function checkAttachment(a: OutgoingAttachment, i: number): void {
  const field = `attachments[${i}]`;
  checkHeaderValue(a.filename, `${field}.filename`);
  checkHeaderValue(a.mimeType, `${field}.mimeType`);
  if (!MEDIA_TYPE.test(a.mimeType)) throw new InvalidMessage(`${field}.mimeType is not a media type`);
  // RFC 2045 §6.4: a multipart or message entity may not be base64-encoded
  if (/^(?:multipart|message)\//i.test(a.mimeType)) {
    throw new InvalidMessage(`${field}.mimeType cannot be sent as an attachment (multipart and message types)`);
  }
  if (a.contentId !== undefined) checkId(a.contentId, `${field}.contentId`);
  if (!(a.content instanceof Uint8Array)) throw new InvalidMessage(`${field}.content is not a Uint8Array`);
}

function longestLine(text: string): number {
  let longest = 0;
  let start = 0;
  for (let end = text.indexOf(CRLF); end !== -1; end = text.indexOf(CRLF, start)) {
    longest = Math.max(longest, end - start);
    start = end + 2;
  }
  return Math.max(longest, text.length - start);
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
