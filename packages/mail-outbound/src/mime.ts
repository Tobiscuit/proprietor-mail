/**
 * Assembles an RFC 5322 / MIME message from input that buildMime has already
 * validated. Nothing here throws on content: every choice is an encoding
 * decision, and every value leaves as 7-bit ASCII.
 *
 * Shapes:
 *   text only            text/plain
 *   text + html          multipart/alternative [text/plain, text/html]
 *   any attachment       multipart/mixed [body, attachment…]
 *   inline + Content-ID  the html becomes multipart/related [text/html, inline…]
 *                        (RFC 2387), so a client that shows the text/plain
 *                        alternative never sees the images, and one that
 *                        shows the html resolves its cid: references.
 *
 * Boundaries are "=_" + hex. Neither quoted-printable nor base64 output can
 * contain "=_" ("=" is always followed by two hex digits or a line break in
 * QP, and "_" is not a base64 character), so no body line can ever start with
 * a delimiter, whatever the content.
 */

import type { Address, ComposedMessage, OutgoingAttachment } from "./index";
import {
  CRLF,
  MAX_LINE,
  base64,
  base64Length,
  encodedWords,
  foldHeader,
  foldUnstructured,
  hex,
  quotedPrintable,
  rfc2231Params,
  rfc5322Date,
} from "./encoding";

/** RFC 5322 §2.1.1: the hard limit for a line, CRLF excluded. */
export const MAX_HARD_LINE = 998;

const PRINTABLE = /^[\x20-\x7e]*$/;
/** Longest quoted display name that still fits a first line after "Reply-To: ". */
const MAX_QUOTED_NAME = MAX_LINE - "Reply-To: ".length;

interface Part {
  /** Header lines, each ending in CRLF. */
  header: string;
  body: string;
}

interface Leaf extends Part {
  transferEncoding: "quoted-printable" | "base64";
}

export interface AssembleInput {
  msg: ComposedMessage;
  /** Without angle brackets. */
  messageId: string;
  date: Date;
  /** Called once per multipart, outermost first. */
  newBoundary: () => string;
}

export function newBoundary(random: (length: number) => Uint8Array): string {
  return `=_${hex(random(12))}`;
}

export function assemble({ msg, messageId, date, newBoundary }: AssembleInput): string {
  const attachments = msg.attachments ?? [];
  const html = msg.html;
  const related = html === undefined ? [] : attachments.filter((a) => a.inline === true && a.contentId !== undefined);
  const others = attachments.filter((a) => !related.includes(a));

  // Drawn outermost first, so a fake randomness source gives predictable names.
  const mixedBoundary = attachments.length > 0 ? newBoundary() : "";
  const alternativeBoundary = html !== undefined ? newBoundary() : "";
  const relatedBoundary = related.length > 0 ? newBoundary() : "";

  let body: Part = textPart("plain", msg.text);
  if (html !== undefined) {
    let htmlPart: Part = textPart("html", html);
    if (related.length > 0) {
      htmlPart = multipart("related", relatedBoundary, [htmlPart, ...related.map(attachmentPart)], ['type="text/html"']);
    }
    body = multipart("alternative", alternativeBoundary, [body, htmlPart]);
  }
  if (attachments.length > 0) body = multipart("mixed", mixedBoundary, [body, ...others.map(attachmentPart)]);

  const header =
    `Date: ${rfc5322Date(date)}${CRLF}` +
    addressHeader("From", [msg.from]) +
    (msg.to.length > 0 ? addressHeader("To", msg.to) : `To: undisclosed-recipients:;${CRLF}`) +
    (msg.cc?.length ? addressHeader("Cc", msg.cc) : "") +
    (msg.replyTo?.length ? addressHeader("Reply-To", msg.replyTo) : "") +
    subjectHeader(msg.subject) +
    foldHeader("Message-ID", [`<${messageId}>`]) +
    (msg.inReplyTo !== undefined ? foldHeader("In-Reply-To", [`<${msg.inReplyTo}>`]) : "") +
    (msg.references?.length ? foldHeader("References", msg.references.map((r) => `<${r}>`)) : "") +
    `MIME-Version: 1.0${CRLF}`;

  return header + body.header + CRLF + body.body + ending(body);
}

/**
 * Make the message end with CRLF without changing what it says: a multipart
 * body gets an empty epilogue; a quoted-printable body that does not already
 * end in a line break gets a soft one ("=" CRLF, which decodes to nothing);
 * trailing CRLF after base64 is ignored by decoders.
 */
function ending(part: Part): string {
  if (!("transferEncoding" in part)) return CRLF;
  if (part.body === "" || part.body.endsWith(CRLF)) return "";
  return (part as Leaf).transferEncoding === "quoted-printable" ? `=${CRLF}` : CRLF;
}

// ── header fields ────────────────────────────────────────────────────────

/**
 * Printable ASCII goes out as a quoted-string, the way the portfolio's
 * contact form writes names (a name with "<" or "," in it stays one name).
 * Anything a quoted-string would need escapes for, anything that looks like an
 * encoded-word, anything long and anything non-ASCII goes out as RFC 2047
 * encoded-words (§5(3): allowed in place of a word in a display name).
 */
function displayName(name: string): string[] {
  if (PRINTABLE.test(name) && !/["\\]/.test(name) && !name.includes("=?") && name.length + 2 <= MAX_QUOTED_NAME) {
    return [`"${name}"`];
  }
  return encodedWords(name);
}

function addressHeader(field: string, list: readonly Address[]): string {
  const tokens: string[] = [];
  list.forEach((a, i) => {
    const mailbox = a.name ? [...displayName(a.name), `<${a.address}>`] : [a.address];
    if (i < list.length - 1) mailbox[mailbox.length - 1] += ",";
    tokens.push(...mailbox);
  });
  return foldHeader(field, tokens);
}

function subjectHeader(subject: string): string {
  if (PRINTABLE.test(subject) && !subject.includes("=?")) {
    const folded = foldUnstructured("Subject", subject);
    if (folded.split(CRLF).every((line) => line.length <= MAX_HARD_LINE)) return folded;
  }
  return foldHeader("Subject", encodedWords(subject));
}

/** `value; p1; p2` as tokens for foldHeader. */
function withParams(value: string, params: readonly string[]): string[] {
  const all = [value, ...params];
  return all.map((token, i) => (i < all.length - 1 ? `${token};` : token));
}

// ── parts ────────────────────────────────────────────────────────────────

const utf8 = new TextEncoder();

/**
 * Quoted-printable unless base64 is shorter (mostly non-Latin text); both
 * carry CRLF line breaks, both keep every line within 76.
 */
function textPart(subtype: "plain" | "html", content: string): Leaf {
  const qp = quotedPrintable(content);
  const bytes = utf8.encode(content.replace(/\r\n|\r|\n/g, CRLF));
  const useBase64 = qp.length > base64Length(bytes.length, MAX_LINE);
  const transferEncoding = useBase64 ? "base64" : "quoted-printable";
  return {
    header: `Content-Type: text/${subtype}; charset=utf-8${CRLF}Content-Transfer-Encoding: ${transferEncoding}${CRLF}`,
    body: useBase64 ? base64(bytes, MAX_LINE) : qp,
    transferEncoding,
  };
}

function attachmentPart(a: OutgoingAttachment): Leaf {
  const name = a.filename === "" ? [] : rfc2231Params("name", a.filename);
  const filename = a.filename === "" ? [] : rfc2231Params("filename", a.filename);
  return {
    header:
      foldHeader("Content-Type", withParams(a.mimeType.toLowerCase(), name)) +
      `Content-Transfer-Encoding: base64${CRLF}` +
      foldHeader("Content-Disposition", withParams(a.inline === true ? "inline" : "attachment", filename)) +
      (a.contentId !== undefined ? foldHeader("Content-ID", [`<${a.contentId}>`]) : ""),
    body: base64(a.content, MAX_LINE),
    transferEncoding: "base64",
  };
}

/** RFC 2046 §5.1.1: parts between delimiters; the CRLF before each delimiter belongs to the delimiter. */
function multipart(subtype: "mixed" | "alternative" | "related", boundary: string, parts: readonly Part[], params: readonly string[] = []): Part {
  return {
    header: foldHeader("Content-Type", withParams(`multipart/${subtype}`, [...params, `boundary="${boundary}"`])),
    body: parts.map((p) => `--${boundary}${CRLF}${p.header}${CRLF}${p.body}`).join(CRLF) + `${CRLF}--${boundary}--`,
  };
}
