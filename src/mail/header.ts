import type { Address, AttachmentSummary, MessageHeader } from "@proprietor/mail-crypto";
import PostalMime, { type Address as ParsedAddress, type Email } from "postal-mime";
import { stripHtmlToText } from "./html-text";

/**
 * The plaintext MessageHeader that gets sealed (contracts/envelope-v1.md):
 * every key always present, the snippet at most 200 characters, the JSON at
 * most 64 KiB. Built in the Worker's memory, sealed, and forgotten; this module
 * never logs and never stores.
 */

export const MAX_HEADER_BYTES = 64 * 1024;
export const SNIPPET_CHARS = 200;
const KEEP_REFERENCES = 20;

/**
 * The parser's limits, tighter than postal-mime's defaults (2 MiB of header
 * lines, 10,000 parts, nesting 256 deep, 10,000 forwarded addresses; checked
 * on 4.1.3). Each is far beyond any real message and bounds the work an
 * arriving message can ask of the Worker's CPU budget. Past any of them the
 * parser throws, and the caller still stores the message, with an empty
 * header: a message built to exhaust the parser is kept, not retried forever.
 */
const PARSE_LIMITS = {
  maxHeadersSize: 256 * 1024,
  maxPartCount: 1000,
  maxNestingDepth: 32,
  maxForwardedAddresses: 1000,
} as const;

/** The parsed message, or null when the parser gives up (the message is then stored with an empty header). */
export async function parseMessage(raw: Uint8Array): Promise<Email | null> {
  try {
    return await PostalMime.parse(raw, { ...PARSE_LIMITS, attachmentEncoding: "arraybuffer" });
  } catch {
    return null;
  }
}

function addressesOf(list: ParsedAddress[] | undefined): Address[] {
  const out: Address[] = [];
  for (const entry of list ?? []) {
    if (entry.group !== undefined) {
      for (const member of entry.group) out.push({ name: member.name ?? "", address: member.address ?? "" });
    } else {
      out.push({ name: entry.name ?? "", address: entry.address ?? "" });
    }
  }
  return out;
}

function firstAddress(entry: ParsedAddress | undefined): Address | null {
  return addressesOf(entry === undefined ? undefined : [entry])[0] ?? null;
}

/** Message ids without angle brackets: every `<…>` token, or whitespace-separated words when there are none. */
function messageIds(value: string | undefined): string[] {
  if (value === undefined) return [];
  const bracketed = [...value.matchAll(/<([^<>]*)>/g)].map((m) => (m[1] ?? "").trim()).filter((id) => id !== "");
  if (bracketed.length > 0) return bracketed;
  return value.split(/\s+/).filter((id) => id !== "");
}

/** postal-mime gives an ISO string when the Date header parses, and the raw value otherwise. */
function isoDate(value: string | undefined): string | null {
  if (value === undefined) return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

/** Whitespace collapsed, at most 200 characters (code points, so no surrogate pair is split). */
export function snippetOf(text: string | undefined): string {
  const collapsed = (text ?? "").replace(/\s+/g, " ").trim();
  return Array.from(collapsed).slice(0, SNIPPET_CHARS).join("");
}

function byteLength(content: ArrayBuffer | Uint8Array | string): number {
  return typeof content === "string" ? new TextEncoder().encode(content).length : content.byteLength;
}

/** The SMTP envelope of an arriving message, as Email Routing hands it over. */
export interface Envelope {
  /** MAIL FROM. */
  from: string;
  /** RCPT TO: the one of the mailbox's addresses this copy arrived for (plan.md §12). */
  to: string;
}

/**
 * The header of an arriving message. `parsed` is null when the parser gave up.
 * The envelope is trusted over any header the sender wrote: `envelopeTo` is
 * what lets the browser merge the copies of one message sent to two of the
 * mailbox's addresses, and reply from the address it arrived at (G13).
 */
export function inboundHeader(parsed: Email | null, envelope: Envelope): MessageHeader {
  const header: MessageHeader = {
    v: 1,
    direction: "in",
    envelopeFrom: envelope.from,
    envelopeTo: envelope.to,
    from: firstAddress(parsed?.from),
    to: addressesOf(parsed?.to),
    cc: addressesOf(parsed?.cc),
    // Sent copies only (the contract): arriving mail never names its Bcc recipients.
    bcc: [],
    replyTo: addressesOf(parsed?.replyTo),
    subject: parsed?.subject ?? "",
    date: isoDate(parsed?.date),
    messageId: messageIds(parsed?.messageId)[0] ?? null,
    inReplyTo: messageIds(parsed?.inReplyTo)[0] ?? null,
    references: messageIds(parsed?.references),
    // postal-mime leaves `text` unset for an HTML-only message (still so in 4.1.3).
    snippet: snippetOf(parsed?.text ?? (parsed?.html === undefined ? undefined : stripHtmlToText(parsed.html))),
    attachments: (parsed?.attachments ?? []).map(
      (a): AttachmentSummary => ({
        filename: a.filename ?? "",
        mimeType: a.mimeType,
        size: byteLength(a.content),
        inline: a.disposition === "inline",
      }),
    ),
  };
  return fitHeader(header);
}

export interface OutboundHeaderInput {
  from: Address;
  to: { name?: string; address: string }[];
  cc?: { name?: string; address: string }[];
  bcc?: { name?: string; address: string }[];
  subject: string;
  text: string;
  date: Date;
  messageId: string;
  inReplyTo?: string;
  references?: string[];
  attachments?: { filename: string; mimeType: string; content: Uint8Array; inline?: boolean }[];
}

/** The header of the Sent copy: direction out, from the mailbox, bcc kept, no envelope sender or recipient. */
export function outboundHeader(input: OutboundHeaderInput): MessageHeader {
  const list = (a: { name?: string; address: string }[] | undefined): Address[] =>
    (a ?? []).map((x) => ({ name: x.name ?? "", address: x.address }));
  return fitHeader({
    v: 1,
    direction: "out",
    envelopeFrom: null,
    envelopeTo: null,
    from: { name: input.from.name, address: input.from.address },
    to: list(input.to),
    cc: list(input.cc),
    bcc: list(input.bcc),
    replyTo: [],
    subject: input.subject,
    date: input.date.toISOString(),
    messageId: input.messageId,
    inReplyTo: input.inReplyTo ?? null,
    references: input.references ?? [],
    snippet: snippetOf(input.text),
    attachments: (input.attachments ?? []).map((a) => ({
      filename: a.filename,
      mimeType: a.mimeType,
      size: a.content.byteLength,
      inline: a.inline === true,
    })),
  });
}

const sizeOf = (h: MessageHeader) => new TextEncoder().encode(JSON.stringify(h)).length;
const clip = (text: string, n: number) => Array.from(text).slice(0, n).join("");

/**
 * The 64 KiB ceiling, in the contract's order: `references` keeps its last 20
 * entries, then `snippet` is shortened, then (envelope-v1 amendment,
 * 2026-09-26) the minimal header. Nothing is lost either way: the full headers
 * stay inside the sealed raw message.
 */
export function fitHeader(header: MessageHeader): MessageHeader {
  if (sizeOf(header) <= MAX_HEADER_BYTES) return header;

  const trimmed: MessageHeader = { ...header, references: header.references.slice(-KEEP_REFERENCES) };
  if (sizeOf(trimmed) <= MAX_HEADER_BYTES) return trimmed;

  const chars = Array.from(trimmed.snippet);
  for (let n = chars.length - 1; n >= 0; n--) {
    const shorter = { ...trimmed, snippet: chars.slice(0, n).join("") };
    if (sizeOf(shorter) <= MAX_HEADER_BYTES) return shorter;
  }
  return minimalHeader(header);
}

/**
 * The header for mail whose full header cannot fit (thousands of recipients or
 * attachments), as the contract defines it: the same v, direction,
 * envelopeFrom, envelopeTo, date, messageId and inReplyTo; `from` only if its JSON is
 * under 1 KiB; every list emptied; the subject cut to 200 characters; no
 * snippet. It is also what the Worker retries with when `sealMessage` throws
 * RangeError. The kept strings are additionally bounded to 998 characters, the
 * RFC 5322 line length, so that even a pathological Message-ID cannot make the
 * minimal header too large.
 */
export function minimalHeader(header: MessageHeader): MessageHeader {
  const line = (value: string | null) => (value === null ? null : clip(value, 998));
  const fromFits = header.from !== null && new TextEncoder().encode(JSON.stringify(header.from)).length < 1024;
  return {
    v: 1,
    direction: header.direction,
    envelopeFrom: line(header.envelopeFrom),
    envelopeTo: line(header.envelopeTo),
    from: fromFits ? header.from : null,
    to: [],
    cc: [],
    bcc: [],
    replyTo: [],
    subject: clip(header.subject, 200),
    date: header.date,
    messageId: line(header.messageId),
    inReplyTo: line(header.inReplyTo),
    references: [],
    snippet: "",
    attachments: [],
  };
}
