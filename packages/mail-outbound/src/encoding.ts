/**
 * The encoders buildMime needs, each written against its RFC: base64
 * (RFC 4648), quoted-printable (RFC 2045 §6.7), encoded-words (RFC 2047),
 * parameter values (RFC 2231), header folding (RFC 5322 §2.2.3) and the date
 * (RFC 5322 §3.3). Pure functions over strings and bytes; no Node APIs.
 *
 * Every function here returns 7-bit ASCII, and every line it writes is at most
 * MAX_LINE characters unless a single unbreakable token is longer.
 */

export const CRLF = "\r\n";

/**
 * The folding target for every line this package writes. RFC 5322 §2.1.1
 * asks for 78; RFC 2047 §2 limits a line that carries an encoded-word to 76;
 * RFC 2045 §6.7 limits a quoted-printable line to 76. One number for all three.
 */
export const MAX_LINE = 76;

const utf8 = new TextEncoder();
/** Only ever fed ASCII bytes, so UTF-8 decoding is exact. */
const ascii = new TextDecoder();

const HEX = "0123456789abcdef";

/** Lower-case hex, for Message-IDs and boundaries. */
export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += HEX[b >>> 4]! + HEX[b & 15]!;
  return out;
}

// ── base64 (RFC 4648 §4) ─────────────────────────────────────────────────

const B64 = Uint8Array.from("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", (c) => c.charCodeAt(0));
const PAD = 0x3d; // "="

function base64Codes(bytes: Uint8Array): Uint8Array {
  const n = bytes.length;
  const out = new Uint8Array(Math.ceil(n / 3) * 4);
  let i = 0;
  let o = 0;
  for (; i + 2 < n; i += 3) {
    const v = (bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!;
    out[o++] = B64[v >>> 18]!;
    out[o++] = B64[(v >>> 12) & 63]!;
    out[o++] = B64[(v >>> 6) & 63]!;
    out[o++] = B64[v & 63]!;
  }
  if (i < n) {
    const two = i + 1 < n;
    const v = (bytes[i]! << 16) | (two ? bytes[i + 1]! << 8 : 0);
    out[o++] = B64[v >>> 18]!;
    out[o++] = B64[(v >>> 12) & 63]!;
    out[o++] = two ? B64[(v >>> 6) & 63]! : PAD;
    out[o++] = PAD;
  }
  return out;
}

/** Standard base64 with padding; with `lineLength`, lines of that length joined by CRLF (no trailing CRLF). */
export function base64(bytes: Uint8Array, lineLength = 0): string {
  const flat = base64Codes(bytes);
  if (lineLength <= 0 || flat.length <= lineLength) return ascii.decode(flat);
  const lines = Math.ceil(flat.length / lineLength);
  const out = new Uint8Array(flat.length + (lines - 1) * 2);
  let o = 0;
  for (let l = 0; l < lines; l++) {
    if (l > 0) {
      out[o++] = 13;
      out[o++] = 10;
    }
    const chunk = flat.subarray(l * lineLength, (l + 1) * lineLength);
    out.set(chunk, o);
    o += chunk.length;
  }
  return ascii.decode(out);
}

/** Length of base64(bytes of length n, lineLength), without encoding anything. */
export function base64Length(n: number, lineLength: number): number {
  const chars = Math.ceil(n / 3) * 4;
  return chars === 0 ? 0 : chars + (Math.ceil(chars / lineLength) - 1) * 2;
}

// ── quoted-printable (RFC 2045 §6.7) ─────────────────────────────────────

const escape = (b: number) => "=" + "0123456789ABCDEF"[b >>> 4]! + "0123456789ABCDEF"[b & 15]!;

/**
 * Text → UTF-8 → quoted-printable. Every line break in the text (CRLF, CR or
 * LF) becomes a CRLF hard break (rule 4). "=" and every byte outside 33–126
 * is escaped (rules 1–2), except space and tab, which stay literal unless they
 * end a line (rule 3). Lines longer than 76 get soft breaks ("=" + CRLF) that
 * never split an escape (rule 5).
 */
export function quotedPrintable(text: string): string {
  return text.split(/\r\n|\r|\n/).map(quotedPrintableLine).join(CRLF);
}

function quotedPrintableLine(line: string): string {
  const bytes = utf8.encode(line);
  const out: string[] = [];
  let current = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    const whitespace = b === 0x20 || b === 0x09;
    const literal = whitespace ? i < bytes.length - 1 : b >= 0x21 && b <= 0x7e && b !== 0x3d;
    const token = literal ? String.fromCharCode(b) : escape(b);
    // leave room for the "=" of a soft break
    if (current.length + token.length > MAX_LINE - 1) {
      out.push(current + "=");
      current = "";
    }
    current += token;
  }
  out.push(current);
  return out.join(CRLF);
}

// ── encoded-words (RFC 2047) ─────────────────────────────────────────────

/**
 * Bytes of UTF-8 per encoded-word: 39 bytes are 52 base64 characters, so a
 * word is 64 characters long ("=?UTF-8?B?" + 52 + "?="). That fits on a first
 * line after the longest header name we fold ("Reply-To: ", 10) within the
 * 76 that RFC 2047 §2 allows, and within the 75 it allows for one word.
 */
const WORD_BYTES = 39;

/**
 * Text as B-encoded UTF-8 encoded-words. Each word holds whole characters
 * (RFC 2047 §5: "Each 'encoded-word' MUST represent an integral number of
 * characters"); decoders join adjacent words and drop the space between them
 * (§6.2), so the words may be folded apart. Returns [] for "".
 */
export function encodedWords(text: string): string[] {
  const words: string[] = [];
  let chunk: number[] = [];
  for (const ch of text) {
    const bytes = utf8.encode(ch);
    if (chunk.length > 0 && chunk.length + bytes.length > WORD_BYTES) {
      words.push(encodedWord(chunk));
      chunk = [];
    }
    for (const b of bytes) chunk.push(b);
  }
  if (chunk.length > 0) words.push(encodedWord(chunk));
  return words;
}

const encodedWord = (bytes: number[]) => `=?UTF-8?B?${base64(Uint8Array.from(bytes))}?=`;

// ── header folding (RFC 5322 §2.2.3) ─────────────────────────────────────

/**
 * `Name: token token …` + CRLF, folded before a token whenever the line would
 * pass MAX_LINE. The first token always shares the first line, so no header
 * starts with an empty line. Use it for structured fields, where the space
 * between tokens is a place the grammar allows folding white space.
 */
export function foldHeader(name: string, tokens: readonly string[]): string {
  const lines: string[] = [];
  let line = `${name}:`;
  tokens.forEach((token, i) => {
    if (i === 0 || line.length + 1 + token.length <= MAX_LINE) {
      line += ` ${token}`;
    } else {
      lines.push(line);
      line = ` ${token}`;
    }
  });
  lines.push(line);
  return lines.join(CRLF) + CRLF;
}

/**
 * An unstructured field (Subject) whose value is printable ASCII: folded only
 * by inserting CRLF before existing white space, so unfolding gives back the
 * value exactly. A run of white space is never left alone on a line.
 */
export function foldUnstructured(name: string, value: string): string {
  if (value === "") return `${name}:${CRLF}`;
  const pieces = value.match(/[ \t]*[^ \t]+|[ \t]+$/g) ?? [value];
  const lines: string[] = [];
  let line = `${name}: ${pieces[0]}`;
  for (const piece of pieces.slice(1)) {
    if (line.length + piece.length <= MAX_LINE || !/[^ \t]/.test(piece)) {
      line += piece;
    } else {
      lines.push(line);
      line = piece;
    }
  }
  lines.push(line);
  return lines.join(CRLF) + CRLF;
}

// ── MIME parameters (RFC 2045 §5.1, RFC 2231) ────────────────────────────

/** RFC 2231 attribute-char: US-ASCII except SPACE, CTLs, "*", "'", "%" and tspecials. */
const ATTRIBUTE_CHAR = /^[A-Za-z0-9!#$&+\-.^_`{|}~]$/;

function percentEncode(ch: string): string {
  if (ATTRIBUTE_CHAR.test(ch)) return ch;
  let out = "";
  for (const b of utf8.encode(ch)) out += "%" + "0123456789ABCDEF"[b >>> 4]! + "0123456789ABCDEF"[b & 15]!;
  return out;
}

/**
 * A parameter (`filename`, `name`) as one or more `attr=value` tokens.
 * Short printable ASCII without `"` or `\` becomes a quoted-string; anything
 * else is percent-encoded UTF-8 per RFC 2231 §4, split into numbered sections
 * (§3) of whole characters so that each fits a folded line with its ";".
 */
export function rfc2231Params(name: string, value: string): string[] {
  const quoted = `${name}="${value}"`;
  // " " + token + ";" must fit a line
  const budget = MAX_LINE - 2;
  if (/^[\x20-\x7e]*$/.test(value) && !/["\\]/.test(value) && quoted.length <= budget) return [quoted];

  const head = (i: number) => `${name}*${i}*=${i === 0 ? "UTF-8''" : ""}`;
  const sections: string[] = [];
  let current = "";
  for (const ch of value) {
    const unit = percentEncode(ch);
    if (current !== "" && head(sections.length).length + current.length + unit.length > budget) {
      sections.push(head(sections.length) + current);
      current = "";
    }
    current += unit;
  }
  if (sections.length === 0) return [`${name}*=UTF-8''${current}`];
  sections.push(head(sections.length) + current);
  return sections;
}

// ── date (RFC 5322 §3.3) ─────────────────────────────────────────────────

const DAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** `Sat, 26 Sep 2026 15:04:05 +0000`: always UTC, seconds precision. */
export function rfc5322Date(date: Date): string {
  const two = (n: number) => String(n).padStart(2, "0");
  return (
    `${DAYS[date.getUTCDay()]}, ${two(date.getUTCDate())} ${MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()} ` +
    `${two(date.getUTCHours())}:${two(date.getUTCMinutes())}:${two(date.getUTCSeconds())} +0000`
  );
}
