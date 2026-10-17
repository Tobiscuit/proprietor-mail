/**
 * The send form (contracts/mail-client-v1.md "Drafts and sending", spec
 * D22): the browser builds `FormData` with a JSON part and one `File` per
 * attachment; the server side of the route decodes it, checks the limits
 * and returns exactly what `MailService.send` takes. Both are pure.
 *
 * Spec 002 (D29, device-v1 B1): `send` carries its mail session inside the
 * request, as `request.session`, so the dashboard's send route hands it on
 * unchanged. Its shape is checked here (base64url of 32 bytes); its value is
 * Mail's to judge, and it is never stored or logged on the way.
 */
import type { Address } from "@proprietor/mail-crypto";
import { ADDRESS } from "./compose";
import { InvalidSendForm } from "./errors";
import type { ComposeInput, SendRequest } from "./types";

/**
 * The Worker's limits (packages/mail-outbound LIMITS, src/mailbox/mailbox.ts
 * parseSendRequest), mirrored so that a refusal happens before the upload;
 * maxFormBytes is the route's hard cap (spec D22). A test keeps them equal.
 */
export const SEND_LIMITS = {
  maxRecipients: 50,
  maxRawBytes: 10 * 1024 * 1024,
  maxFormBytes: 25 * 1024 * 1024,
  maxSubjectChars: 998,
  maxTextChars: 5_000_000,
  maxReferences: 20,
  maxNameChars: 255,
  maxFilenameChars: 255,
} as const;

const IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{1,200}$/;
/** A mail session token: base64url of 32 bytes, 43 characters, the last of which carries 2 zero bits. */
const SESSION_TOKEN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/; // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
const DRAFT_ID = /^drf_[0-9a-hjkmnp-tv-z]{26}$/;
const BARE_ID = /^[^\s<>\u0000-\u001f\u007f]{1,998}$/;
const SINGLE_LINE = /^[^\r\n\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]*$/;

const REQUEST_FIELD = "request";
const ATTACHMENT_FIELD = "attachment";

function refuse(what: string): never {
  throw new InvalidSendForm(`invalid ${what}`);
}

function text(value: unknown, what: string, max: number, singleLine: boolean): string {
  if (typeof value !== "string" || value.length > max || (singleLine && !SINGLE_LINE.test(value))) refuse(what);
  return value;
}

function addressList(value: unknown, what: string): Address[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > SEND_LIMITS.maxRecipients) refuse(what);
  return value.map((a, i) => {
    if (typeof a !== "object" || a === null) refuse(`${what} ${i + 1}`);
    const { name, address } = a as { name?: unknown; address?: unknown };
    const n = text(name ?? "", `${what} ${i + 1} name`, SEND_LIMITS.maxNameChars, true);
    if (typeof address !== "string" || !ADDRESS.test(address)) refuse(`${what} ${i + 1} address`);
    return { name: n, address };
  });
}

interface Fields {
  idempotencyKey: string;
  session?: string;
  from?: string;
  to: Address[];
  cc: Address[];
  bcc: Address[];
  subject: string;
  text: string;
  inReplyTo?: string;
  references: string[];
  draftId?: string;
}

/** The checks both sides make on the fields; attachments are checked where their bytes are. */
function checkFields(r: Record<string, unknown>): Fields {
  const idempotencyKey = typeof r.idempotencyKey === "string" && IDEMPOTENCY_KEY.test(r.idempotencyKey) ? r.idempotencyKey : refuse("idempotency key");
  const to = addressList(r.to, "to");
  const cc = addressList(r.cc, "cc");
  const bcc = addressList(r.bcc, "bcc");
  if (to.length === 0) throw new InvalidSendForm("at least one recipient in to is required");
  if (to.length + cc.length + bcc.length > SEND_LIMITS.maxRecipients) throw new InvalidSendForm(`at most ${SEND_LIMITS.maxRecipients} recipients`);
  const fields: Fields = {
    idempotencyKey,
    to,
    cc,
    bcc,
    subject: text(r.subject ?? "", "subject", SEND_LIMITS.maxSubjectChars, true),
    text: text(r.text ?? "", "text", SEND_LIMITS.maxTextChars, false),
    references: (() => {
      if (r.references === undefined) return [];
      if (!Array.isArray(r.references) || r.references.length > SEND_LIMITS.maxReferences) refuse("references");
      return r.references.map((x) => (typeof x === "string" && BARE_ID.test(x) ? x : refuse("reference")));
    })(),
  };
  if (r.session !== undefined && r.session !== null) {
    fields.session = typeof r.session === "string" && SESSION_TOKEN.test(r.session) ? r.session : refuse("mail session");
  }
  if (r.from !== undefined && r.from !== null) {
    if (typeof r.from !== "string" || !ADDRESS.test(r.from)) refuse("from");
    fields.from = r.from.toLowerCase();
  }
  if (r.inReplyTo !== undefined && r.inReplyTo !== null) {
    fields.inReplyTo = typeof r.inReplyTo === "string" && BARE_ID.test(r.inReplyTo) ? r.inReplyTo : refuse("in-reply-to");
  }
  if (r.draftId !== undefined && r.draftId !== null) {
    fields.draftId = typeof r.draftId === "string" && DRAFT_ID.test(r.draftId) ? r.draftId : refuse("draft id");
  }
  return fields;
}

function checkSize(textChars: number, attachmentBytes: number): void {
  // UTF-16 length ≤ UTF-8 byte length, and encoding never shrinks content: the Worker's own floor.
  if (textChars + attachmentBytes > SEND_LIMITS.maxRawBytes) throw new InvalidSendForm("the message is too large");
}

function attachmentMeta(value: unknown, i: number): { filename: string; mimeType: string } {
  if (typeof value !== "object" || value === null) refuse(`attachment ${i + 1}`);
  const { filename, mimeType } = value as { filename?: unknown; mimeType?: unknown };
  return {
    filename: text(filename, `attachment ${i + 1} filename`, SEND_LIMITS.maxFilenameChars, true) || refuse(`attachment ${i + 1} filename`),
    mimeType: text(mimeType, `attachment ${i + 1} type`, 255, true) || "application/octet-stream",
  };
}

/**
 * Browser side of the send route: `request` (JSON) plus one `attachment` File
 * per attachment, in order. `session` is the mail session token (device-v1
 * B1), once the mailbox has sessions.
 */
export function encodeSendForm(compose: ComposeInput, options: { idempotencyKey: string; draftId?: string; session?: string }): FormData {
  if (options.session !== undefined && (typeof options.session !== "string" || !SESSION_TOKEN.test(options.session))) refuse("mail session");
  const fields = checkFields({
    idempotencyKey: options.idempotencyKey,
    session: options.session,
    from: compose.from,
    to: compose.to,
    cc: compose.cc,
    bcc: compose.bcc,
    subject: compose.subject,
    text: compose.text,
    inReplyTo: compose.inReplyTo,
    references: compose.references,
    draftId: options.draftId,
  });
  const files = compose.attachments ?? [];
  if (!Array.isArray(files) || files.some((f) => !(f instanceof File))) refuse("attachments (File objects)");
  const attachments = files.map((f, i) => attachmentMeta({ filename: f.name || `attachment-${i + 1}`, mimeType: f.type || "application/octet-stream" }, i));
  checkSize(fields.text.length, files.reduce((n, f) => n + f.size, 0));
  const form = new FormData();
  form.set(REQUEST_FIELD, JSON.stringify({ ...fields, attachments }));
  files.forEach((f, i) => form.append(ATTACHMENT_FIELD, f, attachments[i]!.filename));
  return form;
}

/** Server side of the send route: checks a form it did not build and returns exactly what MailService.send takes. */
export async function decodeSendForm(form: FormData): Promise<SendRequest> {
  if (!(form instanceof FormData)) refuse("form");
  const raw = form.get(REQUEST_FIELD);
  if (typeof raw !== "string") refuse("request part");
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    refuse("request part (not JSON)");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) refuse("request part");
  const r = parsed as Record<string, unknown>;
  const fields = checkFields(r);
  const metas = Array.isArray(r.attachments) ? r.attachments.map(attachmentMeta) : r.attachments === undefined ? [] : refuse("attachments");
  const parts = form.getAll(ATTACHMENT_FIELD);
  if (parts.length !== metas.length) throw new InvalidSendForm("the attachment parts do not match the request");
  let total = raw.length;
  const attachments: SendRequest["attachments"] = [];
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (!(part instanceof File)) refuse(`attachment ${i + 1} (not a file part)`);
    total += part.size;
    if (total > SEND_LIMITS.maxFormBytes) throw new InvalidSendForm("the message is too large");
    attachments.push({ filename: metas[i]!.filename, mimeType: metas[i]!.mimeType, content: new Uint8Array(await part.arrayBuffer()) });
  }
  checkSize(fields.text.length, attachments.reduce((n, a) => n + a.content.byteLength, 0));
  const request: SendRequest = {
    idempotencyKey: fields.idempotencyKey,
    ...(fields.session !== undefined ? { session: fields.session } : {}),
    ...(fields.from !== undefined ? { from: fields.from } : {}),
    to: fields.to,
    cc: fields.cc,
    bcc: fields.bcc,
    subject: fields.subject,
    text: fields.text,
    ...(fields.inReplyTo !== undefined ? { inReplyTo: fields.inReplyTo } : {}),
    references: fields.references,
    attachments,
    ...(fields.draftId !== undefined ? { draftId: fields.draftId } : {}),
  };
  return request;
}
