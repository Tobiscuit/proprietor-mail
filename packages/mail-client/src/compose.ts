/**
 * Compose helpers (contracts/mail-client-v1.md "Drafts and sending"):
 * reply, reply-all, forward, and the address list the owner types.
 */
import type { Address } from "@proprietor/mail-crypto";
import type { ComposeInput, MailBody, MailboxView, OpenedMessage } from "./types";

/** One part of an address: no whitespace, `@`, `<`, `>`, `"`, `(`, `)`, `,`, `;`, `:`, `[`, `]` or `\`. */
const ADDRESS_PART = /^[^\s@<>"(),;:[\]\\]+$/;

/**
 * RFC 5322's practical shape: no whitespace or specials around one `@`, and a
 * dot inside the domain (neither its first nor its last character). The same
 * set as the single pattern S6a used, checked in linear time: that pattern
 * backtracked polynomially (CodeQL js/polynomial-redos), and decodeSendForm
 * runs it on the server over strings a form supplies.
 */
export function isAddress(value: string): boolean {
  if (typeof value !== "string") return false;
  const at = value.indexOf("@");
  if (at < 1 || at !== value.lastIndexOf("@")) return false;
  const domain = value.slice(at + 1);
  if (!ADDRESS_PART.test(value.slice(0, at)) || !ADDRESS_PART.test(domain)) return false;
  const dot = domain.indexOf(".", 1);
  return dot !== -1 && dot < domain.length - 1;
}
/** The last 20 references are kept, as the envelope keeps them in a header. */
const MAX_REFERENCES = 20;

function formatAddress(a: Address): string {
  return a.name ? `${a.name} <${a.address}>` : a.address;
}

function same(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

function isOwn(mailbox: Pick<MailboxView, "addresses">, address: string): boolean {
  return mailbox.addresses.some((own) => same(own, address));
}

/** Which of the mailbox's addresses answers: the one the message arrived at, else one it was addressed to, else the primary. */
function fromFor(message: OpenedMessage, mailbox: Pick<MailboxView, "address" | "addresses">): string {
  const h = message.header!;
  const candidates = message.direction === "out" ? [h.from?.address ?? ""] : [h.envelopeTo ?? "", ...h.to.map((a) => a.address), ...h.cc.map((a) => a.address)];
  for (const c of candidates) {
    const own = mailbox.addresses.find((a) => same(a, c));
    if (own) return own;
  }
  return mailbox.address;
}

function dedupe(list: Address[], exclude: (address: string) => boolean): Address[] {
  const out: Address[] = [];
  for (const a of list) {
    if (exclude(a.address) || out.some((o) => same(o.address, a.address))) continue;
    out.push(a);
  }
  return out;
}

function withPrefix(prefix: "Re" | "Fwd", subject: string): string {
  const pattern = prefix === "Re" ? /^\s*re\s*:/i : /^\s*fwd?\s*:/i;
  return pattern.test(subject) ? subject : `${prefix}: ${subject}`;
}

function quoted(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => `> ${line}`)
    .join("\n");
}

function textOf(message: OpenedMessage, body: MailBody | null): string {
  return body?.text ?? message.header!.snippet;
}

function requireHeader(message: OpenedMessage): void {
  if (message.header === null) throw new TypeError("a message that could not be decrypted cannot be answered or forwarded");
}

function references(message: OpenedMessage): string[] {
  const h = message.header!;
  const all = [...h.references, ...(h.messageId ? [h.messageId] : [])];
  const unique = all.filter((r, i) => all.indexOf(r) === i);
  return unique.slice(-MAX_REFERENCES);
}

export function replyTo(message: OpenedMessage, body: MailBody | null, mailbox: Pick<MailboxView, "address" | "addresses">, mode: "reply" | "reply-all"): ComposeInput {
  requireHeader(message);
  const h = message.header!;
  const own = (address: string) => isOwn(mailbox, address);
  let to: Address[];
  let cc: Address[];
  if (message.direction === "out") {
    to = dedupe(h.to, () => false);
    cc = mode === "reply-all" ? dedupe(h.cc, (a) => own(a) || to.some((t) => same(t.address, a))) : [];
  } else {
    const sender = h.replyTo.length > 0 ? h.replyTo : h.from ? [h.from] : [];
    to = mode === "reply-all" ? dedupe([...sender, ...h.to], own) : dedupe(sender, () => false);
    cc = mode === "reply-all" ? dedupe(h.cc, (a) => own(a) || to.some((t) => same(t.address, a))) : [];
  }
  const who = h.from ? formatAddress(h.from) : "they";
  const when = h.date ? h.date.slice(0, 10) : "an unknown date";
  return {
    from: fromFor(message, mailbox),
    to,
    cc,
    bcc: [],
    subject: withPrefix("Re", h.subject),
    text: `\n\nOn ${when}, ${who} wrote:\n${quoted(textOf(message, body))}`,
    inReplyTo: h.messageId,
    references: references(message),
    attachments: [],
  };
}

export function forwardOf(message: OpenedMessage, body: MailBody | null, mailbox: Pick<MailboxView, "address" | "addresses">): ComposeInput {
  requireHeader(message);
  const h = message.header!;
  const lines = [
    "---------- Forwarded message ----------",
    `From: ${h.from ? formatAddress(h.from) : ""}`,
    `Date: ${h.date ?? ""}`,
    `Subject: ${h.subject}`,
    `To: ${h.to.map(formatAddress).join(", ")}`,
    ...(h.cc.length > 0 ? [`Cc: ${h.cc.map(formatAddress).join(", ")}`] : []),
  ];
  return {
    from: fromFor(message, mailbox),
    to: [],
    cc: [],
    bcc: [],
    subject: withPrefix("Fwd", h.subject),
    text: `\n\n${lines.join("\n")}\n\n${textOf(message, body)}`,
    inReplyTo: null,
    references: [],
    attachments: (body?.attachments ?? []).map((a) => new File([a.content as BlobPart], a.filename, { type: a.mimeType })),
  };
}

/** Splits on commas, semicolons and line breaks outside quotes and angle brackets. */
function tokens(input: string): string[] {
  const out: string[] = [];
  let current = "";
  let inQuotes = false;
  let inAngle = false;
  for (const ch of input) {
    if (ch === '"' && !inAngle) inQuotes = !inQuotes;
    else if (ch === "<" && !inQuotes) inAngle = true;
    else if (ch === ">" && !inQuotes) inAngle = false;
    if ((ch === "," || ch === ";" || ch === "\n" || ch === "\r") && !inQuotes && !inAngle) {
      out.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  out.push(current);
  return out.map((t) => t.trim()).filter((t) => t.length > 0);
}

/**
 * `"quoted name" <address>` or `name <address>`. The unquoted name is taken
 * whole and trimmed after, so no whitespace can belong to two parts of the
 * pattern (S6a's lazy name followed by \s* backtracked polynomially on runs of
 * spaces); the names it reads are the same.
 */
const NAMED = /^(?:"((?:[^"\\]|\\.)*)"\s*|([^<]*))<([^<>]*)>$/;

export function parseAddressList(input: string): { addresses: Address[]; invalid: string[] } {
  const addresses: Address[] = [];
  const invalid: string[] = [];
  for (const token of tokens(String(input))) {
    const named = NAMED.exec(token);
    const name = named ? (named[1] !== undefined ? named[1].replace(/\\(.)/g, "$1") : named[2]!.trim()) : "";
    const address = named ? named[3]!.trim() : token;
    if (isAddress(address)) addresses.push({ name, address });
    else invalid.push(token);
  }
  return { addresses, invalid };
}
