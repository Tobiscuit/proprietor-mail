/**
 * @platform-mail/outbound - turn a composed message into MIME and hand it to
 * Amazon SES (API v2, raw content).
 *
 * This file is the API in code form (specs/001-inbox-module/plan.md §6).
 * Slice S3 implemented it (README.md has the SES facts it rests on); the
 * Worker (slice S2) compiles against these signatures and injects fakes in its
 * unit tests. A signature below does not change without changing the plan
 * first.
 *
 * No bindings, no Node APIs: fetch and Web Crypto only, so it runs unchanged in
 * a Worker and in Node's test runner.
 */

import { AwsClient } from "aws4fetch";
import { CRLF, base64, hex } from "./encoding";
import { MAX_HARD_LINE, assemble, newBoundary } from "./mime";

/** True since S3: buildMime and sesRawMailer are real. */
export const IMPLEMENTED: boolean = true;

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
  /**
   * Recipients per message across to, cc and bcc (domain-model M7). SES's own
   * cap is the same: "Maximum number of recipients per message: 50 recipients
   * per message. A recipient is any "To", "CC", or "BCC" address."
   * (https://docs.aws.amazon.com/ses/latest/dg/quotas.html, checked 2026-09-26)
   */
  maxRecipients: 50,
  /**
   * v1's ceiling for a whole raw message. SES's own: "Using the SES v2 API or
   * SMTP - Maximum message size (including attachments): 40 MB per message
   * (after base64 encoding)" (same page, checked 2026-09-26). 10 MiB of raw
   * message is 13,981,016 bytes of base64, under 40 MB however it is counted;
   * and "Messages larger than 10MB are subject to bandwidth throttling".
   */
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
  if (typeof msg.text !== "string") throw new InvalidMessage("text is not a string");
  if (msg.html !== undefined && typeof msg.html !== "string") throw new InvalidMessage("html is not a string");
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

/**
 * SES API v2 `SendEmail` with raw content: one SigV4-signed POST per message
 * (aws4fetch signs; the injectable fetch sends, so tests see exactly what
 * would leave the machine). It never retries on its own: a retry after a 5xx
 * or a timeout can deliver a message twice, so that decision belongs to the
 * caller, which holds the idempotency key (M7).
 *
 * Throws `InvalidMessage` before any request for an unusable request, and
 * `SendRejected` for everything that happens after: SES's answer (code from
 * `x-amzn-errortype`, `retryable` only for throttling and 5xx), a timeout or a
 * network failure (status 0, not retryable: SES may have accepted the message).
 */
export function sesRawMailer(
  creds: SesCredentials,
  opts?: { fetch?: typeof fetch; timeoutMs?: number },
): RawMailer {
  const { accessKeyId, secretAccessKey, sessionToken, region } = creds;
  if (!AWS_REGION.test(region)) throw new TypeError("sesRawMailer: region must be an AWS region name such as us-east-1");
  // "ses" is the signing name in SES v2's service model (aws.auth#sigv4); the
  // host prefix is "email". retries: 0 because this package never retries.
  const aws = new AwsClient({ accessKeyId, secretAccessKey, sessionToken, region, service: "ses", retries: 0 });
  const endpoint = `https://email.${region}.amazonaws.com/v2/email/outbound-emails`;
  const send: typeof fetch = opts?.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return {
    async send(req: RawSendRequest): Promise<{ providerMessageId: string }> {
      checkRawSendRequest(req);
      // API_SendEmail request syntax; API_RawMessage: Data is the whole message,
      // base64-encoded on the HTTPS interface. With raw content Destination is
      // only the SMTP envelope ("the addresses you specify in the Source and
      // Destinations parameters define the envelope sender and recipients",
      // send-email-raw); every recipient goes in BccAddresses so that nothing,
      // even a future SES change, could turn an envelope recipient into a header.
      const body = JSON.stringify({
        FromEmailAddress: req.fromAddress,
        Destination: { BccAddresses: [...req.recipients] },
        Content: { Raw: { Data: base64(req.raw) } },
        ConfigurationSetName: req.configurationSet,
        ...(req.tenantName !== undefined ? { TenantName: req.tenantName } : {}),
      });
      const signed = await aws.sign(endpoint, { method: "POST", headers: { "content-type": "application/json" }, body });

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        let answer: Response;
        let text: string;
        try {
          answer = await send(signed.url, { method: signed.method, headers: signed.headers, body, signal: controller.signal });
          text = await answer.text();
        } catch (err) {
          if (controller.signal.aborted) {
            throw new SendRejected(
              `SES did not answer within ${timeoutMs} ms; the message may or may not have been accepted`,
              0,
              "Timeout",
              false,
            );
          }
          const reason = err instanceof Error ? `${err.name}: ${err.message}` : "unknown error";
          throw new SendRejected(`could not reach SES (${redact(reason)})`, 0, "NetworkError", false);
        }
        if (answer.ok) return accepted(answer.status, text);
        throw rejected(answer, text);
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

// ── SES details ──────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 15_000;

/** us-east-1, eu-west-2, ap-southeast-5, us-gov-west-1: letters, a hyphen, digits. Goes into the host name. */
const AWS_REGION = /^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$/;

/**
 * Configuration set names: "up to 64 alphanumeric characters … hyphens (-)
 * and underscores (_)" (SES quotas page). Tenant names: "up to 64
 * alphanumeric characters, including letters, numbers, hyphens (-) and
 * underscores (_) only" (TenantName in the SES v2 service model).
 */
const SES_NAME = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * SendEmail's throttling errors: TooManyRequestsException (HTTP 429,
 * API_SendEmail) and ThrottlingException (HTTP 400, CommonErrors; the
 * developer guide: "exceeding sending limits results in a ThrottlingException
 * error"). No SES v2 error carries Smithy's @retryable trait, so this list
 * and 5xx are the whole retry policy.
 */
const THROTTLING = new Set(["TooManyRequestsException", "ThrottlingException"]);

function checkRawSendRequest(req: RawSendRequest): void {
  if (!req.raw || req.raw.byteLength === 0) throw new InvalidMessage("the raw message is empty");
  if (req.raw.byteLength > LIMITS.maxRawBytes) {
    throw new InvalidMessage(`message too large: ${req.raw.byteLength} bytes (at most ${LIMITS.maxRawBytes})`);
  }
  if (!isAddress(req.fromAddress)) throw new InvalidMessage("fromAddress is not a bare email address");
  if (!Array.isArray(req.recipients) || req.recipients.length === 0) throw new InvalidMessage("the message has no recipients");
  if (req.recipients.length > LIMITS.maxRecipients) {
    throw new InvalidMessage(`too many recipients: ${req.recipients.length} (at most ${LIMITS.maxRecipients})`);
  }
  req.recipients.forEach((r, i) => {
    if (!isAddress(r)) throw new InvalidMessage(`recipients[${i}] is not a valid email address`);
  });
  if (!SES_NAME.test(req.configurationSet)) throw new InvalidMessage("configurationSet is not an SES configuration set name");
  if (req.tenantName !== undefined && !SES_NAME.test(req.tenantName)) throw new InvalidMessage("tenantName is not an SES tenant name");
}

function accepted(status: number, text: string): { providerMessageId: string } {
  const id = parseJson(text)?.MessageId;
  if (typeof id === "string" && id !== "") return { providerMessageId: id };
  throw new SendRejected(
    `SES answered ${status} without a MessageId; the message may have been accepted, so it must not be resent automatically`,
    status,
    "MalformedResponse",
    false,
  );
}

function rejected(answer: Response, text: string): SendRejected {
  const body = parseJson(text) ?? {};
  const code = errorCode(answer.headers.get("x-amzn-errortype") ?? stringField(body.__type) ?? stringField(body.code));
  const detail = stringField(body.message) ?? stringField(body.Message);
  const retryable = answer.status === 429 || answer.status >= 500 || THROTTLING.has(code);
  return new SendRejected(
    `SES SendEmail failed: HTTP ${answer.status} ${code}${detail ? `: ${redact(detail)}` : ""}`,
    answer.status,
    code,
    retryable,
  );
}

/**
 * The restJson1 error type, sanitized as the Smithy spec says clients should:
 * "If a : character is present, then take only the contents before the first
 * : character … If a # character is present, then take only the contents
 * after the first # character" (aws-restjson1-protocol, error serialization).
 */
function errorCode(value: string | undefined): string {
  if (!value) return "UnknownError";
  let code = value;
  const colon = code.indexOf(":");
  if (colon >= 0) code = code.slice(0, colon);
  const hash = code.indexOf("#");
  if (hash >= 0) code = code.slice(hash + 1);
  code = code.trim();
  return /^[A-Za-z0-9_.-]{1,128}$/.test(code) ? code : "UnknownError";
}

function parseJson(text: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === "object" ? (value as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}

const stringField = (value: unknown): string | undefined => (typeof value === "string" && value !== "" ? value : undefined);

/**
 * SES's explanations name addresses ("… failed the check in region US-EAST-1:
 * ana@example.com"), and SendRejected messages end up in logs, which carry no
 * addresses (spec D8). Keep the explanation, drop the addresses.
 */
function redact(detail: string): string {
  return detail
    .replace(/[^\s<>()[\]{},;:"']+@[^\s<>()[\]{},;:"']+/g, "[address]")
    .replace(/[\r\n\t]+/g, " ")
    .slice(0, 300);
}
