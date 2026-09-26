import PostalMime, { type Address as ParsedAddress, type Email } from "postal-mime";
import { describe, expect, it } from "vitest";
import { buildMime, type Address, type BuiltMessage, type ComposedMessage, type OutgoingAttachment } from "../src/index";
import { ALTERNATIVE, MIXED, NOW, TEXT_ONLY, counterRandom, utf8 } from "./fixtures";

/**
 * Round-trip property: whatever buildMime writes, postal-mime (the parser the
 * Mail Worker uses for inbound mail) reads back to the same fields.
 */

const nl = (s: string | undefined) => (s ?? "").replace(/\r\n?/g, "\n");
const mailbox = (a: Address) => ({ name: a.name ?? "", address: a.address });

/**
 * A known postal-mime 3.0.1 quirk, not a builder bug: its quoted-printable
 * decoder ends every line that is not soft-broken with "\n", including the
 * last line before a multipart delimiter, so it keeps the CRLF that RFC 2046
 * §5.1.1 attaches to the delimiter ("the CRLF preceding the boundary delimiter
 * line is conceptually attached to the boundary"). A quoted-printable text part
 * inside a multipart therefore reads back with exactly one extra "\n".
 * Single-part messages and base64 parts read back exactly.
 */
function withoutDelimiterNewline(msg: ComposedMessage, built: BuiltMessage, subtype: "plain" | "html", parsed: string): string {
  const multipart = msg.html !== undefined || (msg.attachments?.length ?? 0) > 0;
  const raw = new TextDecoder().decode(built.raw);
  const encoding = new RegExp(`Content-Type: text/${subtype}; charset=utf-8\\r\\nContent-Transfer-Encoding: (\\S+)`).exec(raw)?.[1];
  if (!multipart || encoding !== "quoted-printable") return parsed;
  expect(parsed.endsWith("\n")).toBe(true);
  return parsed.slice(0, -1);
}

function expectRoundTrip(msg: ComposedMessage, built: BuiltMessage, parsed: Email, now: Date) {
  expect(parsed.from).toEqual(mailbox(msg.from));
  if (msg.to.length) {
    expect(parsed.to).toEqual(msg.to.map(mailbox));
  } else {
    // no To: the builder writes the empty group "undisclosed-recipients:;"
    expect(parsed.to?.flatMap((a: ParsedAddress) => ("group" in a && a.group ? a.group : [a]))).toEqual([]);
  }
  expect(parsed.cc ?? []).toEqual((msg.cc ?? []).map(mailbox));
  expect(parsed.replyTo ?? []).toEqual((msg.replyTo ?? []).map(mailbox));
  expect(parsed.bcc).toBeUndefined();
  expect(parsed.subject ?? "").toBe(msg.subject);
  expect(parsed.messageId).toBe(`<${built.messageId}>`);
  expect(parsed.inReplyTo).toBe(msg.inReplyTo === undefined ? undefined : `<${msg.inReplyTo}>`);
  expect(parsed.references).toBe(msg.references?.length ? msg.references.map((r) => `<${r}>`).join(" ") : undefined);
  expect(parsed.date).toBe(new Date(Math.floor(now.getTime() / 1000) * 1000).toISOString());
  expect(withoutDelimiterNewline(msg, built, "plain", nl(parsed.text))).toBe(nl(msg.text));
  if (msg.html !== undefined) expect(withoutDelimiterNewline(msg, built, "html", nl(parsed.html))).toBe(nl(msg.html));

  const key = (filename: string | null, cid: string | undefined) => `${filename}\u0000${cid ?? ""}`;
  const want = (msg.attachments ?? [])
    .map((a: OutgoingAttachment) => ({
      // no filename is written as no name parameter, which parses back as null
      key: key(a.filename === "" ? null : a.filename, a.contentId === undefined ? undefined : `<${a.contentId}>`),
      mimeType: a.mimeType.toLowerCase(),
      disposition: a.inline ? "inline" : "attachment",
      content: Array.from(a.content),
    }))
    .sort((x, y) => x.key.localeCompare(y.key));
  const got = parsed.attachments
    .map((a) => ({
      key: key(a.filename, a.contentId),
      mimeType: a.mimeType,
      disposition: a.disposition,
      content: Array.from(new Uint8Array(a.content as ArrayBuffer)),
    }))
    .sort((x, y) => x.key.localeCompare(y.key));
  expect(got).toEqual(want);
}

async function roundTrip(msg: ComposedMessage, now = NOW) {
  const built = buildMime(msg, { messageIdDomain: "operator.example", now, random: counterRandom() });
  const parsed = await PostalMime.parse(built.raw);
  expectRoundTrip(msg, built, parsed, now);
  return { built, parsed };
}

describe("round trip through postal-mime", () => {
  it.each([
    ["text-only", TEXT_ONLY],
    ["alternative", ALTERNATIVE],
    ["mixed", MIXED],
  ] as const)("golden input %s", async (_name, msg) => {
    await roundTrip(msg);
  });

  it("marks the inline image as related and keeps its Content-ID", async () => {
    const { parsed } = await roundTrip(MIXED);
    const logo = parsed.attachments.find((a) => a.filename === "logo.png");
    expect(logo?.related).toBe(true);
    expect(logo?.contentId).toBe("<logo.0001@operator.example>");
  });

  it("handles the awkward cases one by one", async () => {
    const cases: ComposedMessage[] = [
      // bcc only: no To header in the recipient list, an empty group instead
      { from: { address: "hello@operator.example" }, to: [], bcc: [{ address: "x@example.com" }], subject: "b", text: "" },
      // names that must not be sent as quoted strings
      {
        from: { name: 'Say "hi" \\ =?x?= (c)', address: "hello@operator.example" },
        to: [{ name: "A".repeat(300), address: "a@example.com" }, { name: "Nguyễn Văn Anh", address: "b@example.com" }],
        subject: "=?utf-8?q?not_an_encoded_word?=",
        text: "x",
      },
      // a subject that is one 1000-character word, and one with runs of spaces
      { from: { address: "hello@operator.example" }, to: [{ address: "a@example.com" }], subject: "y".repeat(1000), text: "" },
      { from: { address: "hello@operator.example" }, to: [{ address: "a@example.com" }], subject: "a  b   c\td", text: "" },
      // bodies: long lines, trailing whitespace, dots, "From ", no final newline, CRLF input
      {
        from: { address: "hello@operator.example" },
        to: [{ address: "a@example.com" }],
        subject: "body",
        text: `${"long ".repeat(400)}\n.\nFrom here \t\n=\r\nend without newline`,
        html: `<p>${"é".repeat(2000)}</p>`,
      },
      // mostly non-ASCII text goes out as base64 and still round-trips
      { from: { address: "hello@operator.example" }, to: [{ address: "a@example.com" }], subject: "中文", text: "中文内容".repeat(200) },
      // attachments: every byte value, a long non-ASCII name, a quoted name, an inline image without html
      {
        from: { address: "hello@operator.example" },
        to: [{ address: "a@example.com" }],
        subject: "files",
        text: "see attached",
        attachments: [
          { filename: "bytes.bin", mimeType: "application/octet-stream", content: new Uint8Array(256).map((_, i) => i) },
          { filename: `${"ünïcödé ".repeat(20)}.pdf`, mimeType: "Application/PDF", content: utf8("pdf") },
          { filename: 'quote " and ; semicolon.txt', mimeType: "text/plain", content: utf8("t") },
          { filename: "pixel.gif", mimeType: "image/gif", content: utf8("GIF89a"), inline: true, contentId: "px@operator.example" },
          { filename: "", mimeType: "application/octet-stream", content: new Uint8Array(0) },
        ],
      },
    ];
    for (const msg of cases) await roundTrip(msg);
  });

  it("holds for 300 generated messages", async () => {
    const rng = mulberry32(0x5eed);
    for (let i = 0; i < 300; i++) {
      const msg = randomMessage(rng);
      try {
        await roundTrip(msg, new Date(Date.UTC(2026, 0, 1) + Math.floor(rng() * 3e10)));
      } catch (err) {
        throw new Error(`generated message #${i} did not round-trip: ${JSON.stringify(msg).slice(0, 400)}`, { cause: err });
      }
    }
  });
});

// ── generator ────────────────────────────────────────────────────────────

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = <T>(rng: () => number, xs: readonly T[]): T => xs[Math.floor(rng() * xs.length)]!;
const int = (rng: () => number, max: number) => Math.floor(rng() * (max + 1));

const NAMES = [
  undefined,
  "",
  "Ana",
  "O'Brien, Pat",
  'Quote "me"',
  "Back\\slash",
  "Ana Pérez",
  "Nguyễn Thị Minh Khai",
  "山田 太郎",
  "محمد",
  "😀 Emoji Person 🎉",
  "=?utf-8?B?Zm9v?=",
  "x".repeat(90),
  "Долгое имя ".repeat(12).trim(),
];

const PIECES = ["hello", "Grüße", "中文", "😀", "=", "?", "_", " ", "  ", "\t", "—", "a".repeat(80), "Re:", ".", "<b>"];

function randomText(rng: () => number, maxPieces: number, allowNewlines: boolean): string {
  let s = "";
  const n = int(rng, maxPieces);
  for (let i = 0; i < n; i++) {
    s += pick(rng, PIECES);
    if (allowNewlines && rng() < 0.15) s += pick(rng, ["\n", "\r\n", " \n", "\n\n", "\nFrom me\n", "\n.\n"]);
  }
  return s;
}

function randomAddress(rng: () => number, i: number): Address {
  const name = pick(rng, NAMES);
  const address = `${pick(rng, ["a", "b.c", "d+tag", "e_f", "O'Hara"])}${i}@${pick(rng, ["example.com", "mail.example.org", "xn--bcher-kva.example"])}`;
  return name === undefined ? { address } : { name, address };
}

function randomMessage(rng: () => number): ComposedMessage {
  let n = 0;
  const list = (max: number, min = 0) => Array.from({ length: min + int(rng, max - min) }, () => randomAddress(rng, n++));
  const subject = randomText(rng, 12, false).trim();
  const msg: ComposedMessage = {
    from: randomAddress(rng, n++),
    to: list(3, 1),
    cc: list(2),
    bcc: list(2),
    replyTo: list(1),
    subject,
    text: randomText(rng, 60, true),
  };
  if (rng() < 0.5) msg.html = `<div>${randomText(rng, 60, true)}</div>`;
  if (rng() < 0.3) msg.inReplyTo = `in-${int(rng, 1e6)}@mail.example.com`;
  if (rng() < 0.3) msg.references = Array.from({ length: 1 + int(rng, 12) }, (_, k) => `ref${k}.${int(rng, 1e9)}@mail.example.com`);
  if (rng() < 0.5) {
    msg.attachments = Array.from({ length: 1 + int(rng, 2) }, (_, k) => {
      const inline = msg.html !== undefined && rng() < 0.4;
      const content = new Uint8Array(int(rng, 3000)).map(() => int(rng, 255));
      const base = `${k}-${randomText(rng, 4, false).replace(/[\t]/g, " ").trim() || "file"}`;
      return inline
        ? { filename: `${base}.png`, mimeType: "image/png", content, inline: true, contentId: `img${k}.${int(rng, 1e6)}@operator.example` }
        : { filename: `${base}.bin`, mimeType: pick(rng, ["application/pdf", "application/octet-stream", "image/jpeg"]), content };
    });
  }
  return msg;
}
