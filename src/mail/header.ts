import type { Address, AttachmentSummary, MessageHeader } from "@platform-mail/crypto";
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
 * postal-mime 3.0.1 would read up to 2 MiB of header lines. A quarter of a
 * MiB is far beyond any real message and bounds the work an arriving message
 * can ask for. Past it, the parser throws, and the message is still stored
 * (with an empty header) by the caller.
 */
const MAX_HEADERS_SIZE = 256 * 1024;

/** The parsed message, or null when the parser gives up (the message is then stored with an empty header). */
export async function parseMessage(raw: Uint8Array): Promise<Email | null> {
  try {
    return await PostalMime.parse(raw, { maxHeadersSize: MAX_HEADERS_SIZE, attachmentEncoding: "arraybuffer" });
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

/** The header of an arriving message. `parsed` is null when the parser gave up. */
export function inboundHeader(parsed: Email | null, envelopeFrom: string): MessageHeader {
  const header: MessageHeader = {
    v: 1,
    direction: "in",
    envelopeFrom,
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
    // postal-mime 3.0.1 leaves `text` unset for an HTML-only message.
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

/** The header of the Sent copy: direction out, from the mailbox, bcc kept, no envelope sender. */
export function outboundHeader(input: OutboundHeaderInput): MessageHeader {
  const list = (a: { name?: string; address: string }[] | undefined): Address[] =>
    (a ?? []).map((x) => ({ name: x.name ?? "", address: x.address }));
  return fitHeader({
    v: 1,
    direction: "out",
    envelopeFrom: null,
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
const clip = (s: string, n: number) => Array.from(s).slice(0, n).join("");

/**
 * The 64 KiB ceiling. The contract's two steps first: `references` keeps its
 * last 20 entries, then `snippet` is shortened. If a pathological message is
 * still larger (a 100 KB subject, thousands of recipients), every other string
 * and list is bounded by a limit that halves until the header fits. The
 * contract does not say what gives way in that case (reported as a gap); no
 * mail is lost either way, because the raw message is sealed in full and the
 * browser can parse it again.
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

  for (let limit = 1024; ; limit = Math.max(1, Math.floor(limit / 2))) {
    const address = (a: Address): Address => ({ name: clip(a.name, limit), address: clip(a.address, limit) });
    const bounded: MessageHeader = {
      ...trimmed,
      snippet: "",
      envelopeFrom: trimmed.envelopeFrom === null ? null : clip(trimmed.envelopeFrom, limit),
      from: trimmed.from === null ? null : address(trimmed.from),
      to: trimmed.to.slice(0, limit).map(address),
      cc: trimmed.cc.slice(0, limit).map(address),
      bcc: trimmed.bcc.slice(0, limit).map(address),
      replyTo: trimmed.replyTo.slice(0, limit).map(address),
      subject: clip(trimmed.subject, limit),
      messageId: trimmed.messageId === null ? null : clip(trimmed.messageId, limit),
      inReplyTo: trimmed.inReplyTo === null ? null : clip(trimmed.inReplyTo, limit),
      references: trimmed.references.map((r) => clip(r, limit)),
      attachments: trimmed.attachments
        .slice(0, limit)
        .map((a) => ({ ...a, filename: clip(a.filename, limit), mimeType: clip(a.mimeType, limit) })),
    };
    if (sizeOf(bounded) <= MAX_HEADER_BYTES || limit === 1) return bounded;
  }
}
