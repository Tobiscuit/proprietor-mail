import { describe, expect, it } from "vitest";
import {
  MAX_HEADER_BYTES,
  fitHeader,
  inboundHeader,
  outboundHeader,
  parseMessage,
} from "../src/mail/header";

// contracts/envelope-v1.md, "MessageHeader": the keys, in the contract's order.
const HEADER_KEYS = [
  "v",
  "direction",
  "envelopeFrom",
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
  "To: Hello <hello@operator.example>, Team: bob@example.org, carol@example.org;",
  "Cc: dan@example.net",
  "Reply-To: replies@example.com",
  "Subject: =?UTF-8?Q?Kitchen_remodel_quote_=E2=80=94_Z=C3=BCrich?=",
  "Date: Sat, 26 Sep 2026 15:04:05 +0000",
  "Message-ID: <abc@example.com>",
  "In-Reply-To: <parent@operator.example>",
  "References: <root@operator.example>\r\n <parent@operator.example>",
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
    const header = inboundHeader(await parseMessage(FULL), "bounce@x.example");
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toEqual({
      v: 1,
      direction: "in",
      envelopeFrom: "bounce@x.example",
      from: { name: "Ana Ruiz", address: "ana@example.com" },
      // A group is flattened into its members.
      to: [
        { name: "Hello", address: "hello@operator.example" },
        { name: "", address: "bob@example.org" },
        { name: "", address: "carol@example.org" },
      ],
      cc: [{ name: "", address: "dan@example.net" }],
      bcc: [],
      replyTo: [{ name: "", address: "replies@example.com" }],
      subject: "Kitchen remodel quote — Zürich",
      date: "2026-09-26T15:04:05.000Z",
      messageId: "abc@example.com",
      inReplyTo: "parent@operator.example",
      references: ["root@operator.example", "parent@operator.example"],
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
      "a@b.test",
    );
    expect(header.bcc).toEqual([]);
  });

  it("uses null and empty values for what is absent, and null for an unparseable Date", async () => {
    const header = inboundHeader(await parseMessage(crlf(["Date: sometime soon", "", "just a body"])), "x@y.test");
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
    const header = inboundHeader(null, "sender@x.test");
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toMatchObject({ direction: "in", envelopeFrom: "sender@x.test", subject: "", snippet: "", from: null });
  });

  it("returns null, rather than throwing, when postal-mime refuses a message", async () => {
    // postal-mime 3.0.1 throws past maxHeadersSize; the Worker's parse sets 256 KiB.
    const hugeHeader = crlf([`X-Filler: ${"a".repeat(300 * 1024)}`, "Subject: s", "", "body"]);
    expect(await parseMessage(hugeHeader)).toBeNull();
  });

  it("makes the snippet from the text body: at most 200 characters, whitespace collapsed", async () => {
    const long = "word ".repeat(100) + "tail";
    const header = inboundHeader(await parseMessage(crlf(["Subject: s", "", long])), "a@b.test");
    expect([...header.snippet].length).toBe(200);
    expect(header.snippet).not.toMatch(/\s{2,}/);
  });

  it("counts the snippet in characters, not UTF-16 units: no split surrogate pair", async () => {
    const body = "😀".repeat(250);
    const header = inboundHeader(await parseMessage(crlf(["Content-Type: text/plain; charset=utf-8", "", body])), "a@b.test");
    expect([...header.snippet]).toHaveLength(200);
    expect(header.snippet).toBe("😀".repeat(200));
  });

  it("makes the snippet from HTML when there is no text part", async () => {
    const header = inboundHeader(
      await parseMessage(crlf(["Content-Type: text/html; charset=utf-8", "", "<p>Hello <b>there</b></p><p>friend</p>"])),
      "a@b.test",
    );
    expect(header.snippet).toMatch(/^Hello there\s?friend$/);
  });
});

describe("the 64 KiB ceiling", () => {
  it("keeps the last 20 references when there are too many", async () => {
    const refs = Array.from({ length: 5000 }, (_, i) => `<ref-${i}-${"x".repeat(20)}@example.com>`).join(" ");
    const header = inboundHeader(await parseMessage(crlf([`References: ${refs}`, "Subject: s", "", "b"])), "a@b.test");
    expect(byteLength(header)).toBeLessThanOrEqual(MAX_HEADER_BYTES);
    expect(header.references).toHaveLength(20);
    expect(header.references.at(-1)).toBe(`ref-4999-${"x".repeat(20)}@example.com`);
  });

  it("leaves a header that already fits exactly as it is", async () => {
    const header = inboundHeader(await parseMessage(FULL), "a@b.test");
    expect(fitHeader(header)).toBe(header);
  });

  it("stays under the ceiling whatever the message holds (a contract gap: the fields beyond references and snippet)", async () => {
    // Under the parser's 256 KiB header bound, far over the 64 KiB header ceiling.
    const many = Array.from({ length: 1500 }, (_, i) => `user${i}@example-${"d".repeat(30)}.com`).join(", ");
    const raw = crlf([`To: ${many}`, `Cc: ${many}`, `Subject: ${"s".repeat(50_000)}`, "", "b"]);
    const header = inboundHeader(await parseMessage(raw), "a@b.test");
    expect(byteLength(header)).toBeLessThanOrEqual(MAX_HEADER_BYTES);
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header.to.length).toBeGreaterThan(0);
  });
});

describe("MessageHeader for a Sent copy", () => {
  it("is direction out, from the mailbox, with bcc kept and no envelope sender", () => {
    const header = outboundHeader({
      from: { name: "Operator", address: "hello@operator.example" },
      to: [{ address: "ana@example.com" }],
      cc: [{ name: "Bob", address: "bob@example.org" }],
      bcc: [{ address: "archive@example.net" }],
      subject: "Re: Kitchen",
      text: "Thanks,\n\n  see you   Monday.",
      date: new Date("2026-09-26T16:00:00.000Z"),
      messageId: "msg-1@operator.example",
      inReplyTo: "abc@example.com",
      references: ["root@x", "abc@example.com"],
      attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", content: new Uint8Array(1234) }],
    });
    expect(Object.keys(header)).toEqual(HEADER_KEYS);
    expect(header).toEqual({
      v: 1,
      direction: "out",
      envelopeFrom: null,
      from: { name: "Operator", address: "hello@operator.example" },
      to: [{ name: "", address: "ana@example.com" }],
      cc: [{ name: "Bob", address: "bob@example.org" }],
      bcc: [{ name: "", address: "archive@example.net" }],
      replyTo: [],
      subject: "Re: Kitchen",
      date: "2026-09-26T16:00:00.000Z",
      messageId: "msg-1@operator.example",
      inReplyTo: "abc@example.com",
      references: ["root@x", "abc@example.com"],
      snippet: "Thanks, see you Monday.",
      attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", size: 1234, inline: false }],
    });
  });
});
