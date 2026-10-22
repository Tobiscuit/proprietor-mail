import { describe, expect, it } from "vitest";
import {
  MAX_HEADER_BYTES,
  fitHeader,
  inboundHeader,
  minimalHeader,
  outboundHeader,
  parseMessage,
} from "../src/mail/header";

// contracts/envelope-v1.md, "MessageHeader": the keys, in the contract's order.
const HEADER_KEYS = [
  "v",
  "direction",
  "envelopeFrom",
  "envelopeTo",
  "from",
  "to",
  "cc",
  "bcc",
  "replyTo",
  "subject",
  "date",
  "messageId",
  "inReplyTo",
  "references",
  "snippet",
  "attachments",
];

const crlf = (lines: string[]) => new TextEncoder().encode(lines.join("\r\n"));
const byteLength = (h: unknown) => new TextEncoder().encode(JSON.stringify(h)).length;

const FULL = crlf([
  'From: "Ana Ruiz" <ana@example.com>',
  "To: Hello <hello@example.com>, Team: bob@example.org, carol@example.org;",
  "Cc: dan@example.net",
  "Reply-To: replies@example.com",
  "Subject: =?UTF-8?Q?Kitchen_remodel_quote_=E2=80=94_Z=C3=BCrich?=",
  "Date: Sat, 26 Sep 2026 15:04:05 +0000",
  "Message-ID: <abc@example.com>",
  "In-Reply-To: <parent@example.com>",
  "References: <root@example.com>\r\n <parent@example.com>",
  "MIME-Version: 1.0",
  'Content-Type: multipart/mixed; boundary="b1"',
  "",
  "--b1",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Hi   there,\r\n\r\nwe'd like\ta quote for the kitchen.",
  "--b1",
  'Content-Type: application/pdf; name="plan.pdf"',
  'Content-Disposition: attachment; filename="plan.pdf"',
  "Content-Transfer-Encoding: base64",
  "",
  "JVBERi0xLjQK",
  "--b1",
  "Content-Type: image/png",
  "Content-Disposition: inline",
  "Content-ID: <logo@x>",
  "Content-Transfer-Encoding: base64",
  "",
  "iVBORw0KGgo=",
  "--b1--",
  "",
]);

describe("MessageHeader for an arriving message (contracts/envelope-v1.md)", () => {
  it("has every key, in the contract's order, with the values parsed", async () => {
    const header = inboundHeader(await parseMessage(FULL), { from: "bounce@x.example", to: "hello@example.com" });
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toEqual({
      v: 1,
      direction: "in",
      envelopeFrom: "bounce@x.example",
      envelopeTo: "hello@example.com",
      from: { name: "Ana Ruiz", address: "ana@example.com" },
      // A group is flattened into its members.
      to: [
        { name: "Hello", address: "hello@example.com" },
        { name: "", address: "bob@example.org" },
        { name: "", address: "carol@example.org" },
      ],
      cc: [{ name: "", address: "dan@example.net" }],
      bcc: [],
      replyTo: [{ name: "", address: "replies@example.com" }],
      subject: "Kitchen remodel quote — Zürich",
      date: "2026-09-26T15:04:05.000Z",
      messageId: "abc@example.com",
      inReplyTo: "parent@example.com",
      references: ["root@example.com", "parent@example.com"],
      snippet: "Hi there, we'd like a quote for the kitchen.",
      attachments: [
        { filename: "plan.pdf", mimeType: "application/pdf", size: 9, inline: false },
        { filename: "", mimeType: "image/png", size: 8, inline: true },
      ],
    });
  });

  it("keeps bcc empty for arriving mail, even when a Bcc header is present", async () => {
    const header = inboundHeader(
      await parseMessage(crlf(["From: a@b.test", "To: c@d.test", "Bcc: hidden@e.test", "Subject: s", "", "body"])),
      { from: "a@b.test", to: "hello@example.com" },
    );
    expect(header.bcc).toEqual([]);
  });

  it("uses null and empty values for what is absent, and null for an unparseable Date", async () => {
    const header = inboundHeader(await parseMessage(crlf(["Date: sometime soon", "", "just a body"])), { from: "x@y.test", to: "hello@example.com" });
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toMatchObject({
      from: null,
      to: [],
      subject: "",
      date: null,
      messageId: null,
      inReplyTo: null,
      references: [],
      snippet: "just a body",
      attachments: [],
    });
  });

  it("stores whatever parsed when the parser gives up: never loses mail to a parser", () => {
    const header = inboundHeader(null, { from: "sender@x.test", to: "hello@example.com" });
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toMatchObject({ direction: "in", envelopeFrom: "sender@x.test", envelopeTo: "hello@example.com", subject: "", snippet: "", from: null });
  });

  it("returns null, rather than throwing, when postal-mime refuses a message", async () => {
    // postal-mime throws past maxHeadersSize; the Worker's parse sets 256 KiB.
    const hugeHeader = crlf([`X-Filler: ${"a".repeat(300 * 1024)}`, "Subject: s", "", "body"]);
    expect(await parseMessage(hugeHeader)).toBeNull();
  });

  it("returns null past the Worker's part and nesting limits, and parses just inside them", async () => {
    const multipart = (parts: number) =>
      crlf([
        "Subject: many parts",
        'Content-Type: multipart/mixed; boundary="b"',
        "",
        ...Array.from({ length: parts }, (_, i) => ["--b", "Content-Type: text/plain", "", `part ${i}`]).flat(),
        "--b--",
      ]);
    // The multipart itself counts as a part, so 999 children make 1000.
    expect(await parseMessage(multipart(999))).not.toBeNull();
    expect(await parseMessage(multipart(1000))).toBeNull();

    const nested = (depth: number) => {
      const lines = ["Subject: deep"];
      for (let i = 0; i < depth; i++) lines.push(`Content-Type: multipart/mixed; boundary="n${i}"`, "", `--n${i}`);
      lines.push("Content-Type: text/plain", "", "core");
      for (let i = depth - 1; i >= 0; i--) lines.push(`--n${i}--`);
      return crlf(lines);
    };
    expect(await parseMessage(nested(20))).not.toBeNull();
    expect(await parseMessage(nested(40))).toBeNull();
  });

  it("makes the snippet from the text body: at most 200 characters, whitespace collapsed", async () => {
    const long = "word ".repeat(100) + "tail";
    const header = inboundHeader(await parseMessage(crlf(["Subject: s", "", long])), { from: "a@b.test", to: "hello@example.com" });
    expect([...header.snippet].length).toBe(200);
    expect(header.snippet).not.toMatch(/\s{2,}/);
  });

  it("counts the snippet in characters, not UTF-16 units: no split surrogate pair", async () => {
    const body = "😀".repeat(250);
    const header = inboundHeader(await parseMessage(crlf(["Content-Type: text/plain; charset=utf-8", "", body])), { from: "a@b.test", to: "hello@example.com" });
    expect([...header.snippet]).toHaveLength(200);
    expect(header.snippet).toBe("😀".repeat(200));
  });

  it("makes the snippet from HTML when there is no text part", async () => {
    const header = inboundHeader(
      await parseMessage(crlf(["Content-Type: text/html; charset=utf-8", "", "<p>Hello <b>there</b></p><p>friend</p>"])),
      { from: "a@b.test", to: "hello@example.com" },
    );
    expect(header.snippet).toMatch(/^Hello there\s?friend$/);
  });
});

describe("the 64 KiB ceiling", () => {
  it("keeps the last 20 references when there are too many", async () => {
    const refs = Array.from({ length: 5000 }, (_, i) => `<ref-${i}-${"x".repeat(20)}@example.com>`).join(" ");
    const header = inboundHeader(await parseMessage(crlf([`References: ${refs}`, "Subject: s", "", "b"])), { from: "a@b.test", to: "hello@example.com" });
    expect(byteLength(header)).toBeLessThanOrEqual(MAX_HEADER_BYTES);
    expect(header.references).toHaveLength(20);
    expect(header.references.at(-1)).toBe(`ref-4999-${"x".repeat(20)}@example.com`);
  });

  it("leaves a header that already fits exactly as it is", async () => {
    const header = inboundHeader(await parseMessage(FULL), { from: "a@b.test", to: "hello@example.com" });
    expect(fitHeader(header)).toBe(header);
  });

  it("falls back to the contract's minimal header when references and snippet are not enough (a few thousand To:)", async () => {
    // Under the parser's 256 KiB header bound, far over the 64 KiB header ceiling.
    const many = Array.from({ length: 3000 }, (_, i) => `u${i}@example-${"d".repeat(20)}.com`).join(", ");
    const raw = crlf([
      'From: "Ana" <ana@example.com>',
      `To: ${many}`,
      `Subject: ${"s".repeat(300)}`,
      "Date: Sat, 26 Sep 2026 15:04:05 +0000",
      "Message-ID: <big@example.com>",
      "In-Reply-To: <parent@x>",
      "",
      "b",
    ]);
    const header = inboundHeader(await parseMessage(raw), { from: "a@b.test", to: "hello@example.com" });
    expect(byteLength(header)).toBeLessThanOrEqual(MAX_HEADER_BYTES);
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toEqual({
      v: 1,
      direction: "in",
      envelopeFrom: "a@b.test",
      // Kept by the minimal header: which address the message arrived for is not content the raw message repeats.
      envelopeTo: "hello@example.com",
      from: { name: "Ana", address: "ana@example.com" },
      to: [],
      cc: [],
      bcc: [],
      replyTo: [],
      subject: "s".repeat(200),
      date: "2026-09-26T15:04:05.000Z",
      messageId: "big@example.com",
      inReplyTo: "parent@x",
      references: [],
      snippet: "",
      attachments: [],
    });
  });

  it("the minimal header drops a `from` whose JSON is 1 KiB or more", () => {
    const header = minimalHeader({
      v: 1, direction: "in", envelopeFrom: null, envelopeTo: null, from: { name: "n".repeat(2000), address: "a@b.test" }, to: [], cc: [], bcc: [],
      replyTo: [], subject: "", date: null, messageId: null, inReplyTo: null, references: [], snippet: "", attachments: [],
    });
    expect(header.from).toBeNull();
  });
});

describe("MessageHeader for a Sent copy", () => {
  it("is direction out, from the mailbox, with bcc kept and no envelope sender or recipient", () => {
    const header = outboundHeader({
      from: { name: "Example", address: "hello@example.com" },
      to: [{ address: "ana@example.com" }],
      cc: [{ name: "Bob", address: "bob@example.org" }],
      bcc: [{ address: "archive@example.net" }],
      subject: "Re: Kitchen",
      text: "Thanks,\n\n  see you   Monday.",
      date: new Date("2026-09-26T16:00:00.000Z"),
      messageId: "msg-1@example.com",
      inReplyTo: "abc@example.com",
      references: ["root@x", "abc@example.com"],
      attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", content: new Uint8Array(1234) }],
    });
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toEqual({
      v: 1,
      direction: "out",
      envelopeFrom: null,
      envelopeTo: null,
      from: { name: "Example", address: "hello@example.com" },
      to: [{ name: "", address: "ana@example.com" }],
      cc: [{ name: "Bob", address: "bob@example.org" }],
      bcc: [{ name: "", address: "archive@example.net" }],
      replyTo: [],
      subject: "Re: Kitchen",
      date: "2026-09-26T16:00:00.000Z",
      messageId: "msg-1@example.com",
      inReplyTo: "abc@example.com",
      references: ["root@x", "abc@example.com"],
      snippet: "Thanks, see you Monday.",
      attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", size: 1234, inline: false }],
    });
  });
});
