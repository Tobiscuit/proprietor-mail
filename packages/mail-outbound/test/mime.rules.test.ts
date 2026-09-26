import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  InvalidMessage,
  LIMITS,
  buildMime,
  type BuildOptions,
  type ComposedMessage,
} from "../src/index";
import { ALTERNATIVE, MIXED, TEXT_ONLY, counterRandom, goldenOptions, utf8 } from "./fixtures";

const text = (raw: Uint8Array) => new TextDecoder().decode(raw);
const headerBlock = (raw: string) => raw.slice(0, raw.indexOf("\r\n\r\n") + 2);

const base: ComposedMessage = {
  from: { name: "Mailbox", address: "hello@operator.example" },
  to: [{ address: "ana@example.com" }],
  subject: "Hello",
  text: "Hi.\n",
};

function expectInvalid(msg: ComposedMessage, opts: BuildOptions = goldenOptions()): InvalidMessage {
  let caught: unknown;
  try {
    buildMime(msg, opts);
  } catch (err) {
    caught = err;
  }
  expect(caught).toBeInstanceOf(InvalidMessage);
  return caught as InvalidMessage;
}

describe("buildMime: wire format invariants", () => {
  const shapes = [TEXT_ONLY, ALTERNATIVE, MIXED, { ...base, text: "é".repeat(5000) + "\n" + "x".repeat(3000) }];

  it.each(shapes.map((m, i) => [i, m] as const))("shape %i: CRLF only, 7-bit only, lines within limits", (_i, msg) => {
    const raw = buildMime(msg, goldenOptions()).raw;
    expect(raw.every((b) => b < 0x80)).toBe(true);
    const s = text(raw);
    expect(s.endsWith("\r\n")).toBe(true);
    expect(/\r(?!\n)|(?<!\r)\n/.test(s)).toBe(false);
    for (const line of s.split("\r\n")) {
      expect(line.length).toBeLessThanOrEqual(998);
      // everything this builder writes, headers and encoded bodies alike, stays within 76
      expect(line.length).toBeLessThanOrEqual(76);
    }
  });

  it("writes the Date and a Message-ID from the injected clock and randomness", () => {
    const built = buildMime(base, { messageIdDomain: "operator.example", now: new Date("2027-02-03T04:05:06Z"), random: counterRandom(0xf0) });
    const headers = headerBlock(text(built.raw));
    expect(headers).toContain("Date: Wed, 03 Feb 2027 04:05:06 +0000\r\n");
    expect(built.messageId).toBe("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff@operator.example");
    expect(headers).toContain(`Message-ID: <${built.messageId}>\r\n`);
    expect(headers).toContain("MIME-Version: 1.0\r\n");
  });

  it("defaults to the real clock and crypto.getRandomValues", () => {
    const before = Date.now();
    const a = buildMime(base, { messageIdDomain: "operator.example" });
    const b = buildMime(base, { messageIdDomain: "operator.example" });
    expect(a.messageId).toMatch(/^[0-9a-f]{32}@operator\.dev$/);
    expect(a.messageId).not.toBe(b.messageId);
    const date = /^Date: (.+)$/m.exec(text(a.raw))![1]!;
    expect(Math.abs(Date.parse(date) - before)).toBeLessThan(5000);
  });

  it("puts inline images with a Content-ID into multipart/related under the HTML", () => {
    const s = text(buildMime(MIXED, goldenOptions()).raw);
    expect(s).toContain('Content-Type: multipart/related; type="text/html";');
    expect(s).toContain("Content-ID: <logo.0001@operator.example>\r\n");
    expect(s).toContain("Content-Disposition: inline; filename=\"logo.png\"\r\n");
  });

  it("keeps an inline attachment without HTML in multipart/mixed", () => {
    const s = text(
      buildMime(
        { ...base, attachments: [{ filename: "a.png", mimeType: "image/png", content: utf8("x"), inline: true, contentId: "a@x.example" }] },
        goldenOptions(),
      ).raw,
    );
    expect(s).toContain("Content-Type: multipart/mixed;");
    expect(s).not.toContain("multipart/related");
    expect(s).toContain("Content-Disposition: inline;");
  });

  it("writes To: undisclosed-recipients:; when there is no To", () => {
    const s = text(buildMime({ ...base, to: [], bcc: [{ address: "x@example.com" }] }, goldenOptions()).raw);
    expect(headerBlock(s)).toContain("To: undisclosed-recipients:;\r\n");
  });
});

describe("buildMime: Bcc", () => {
  it("puts Bcc recipients in the envelope and nowhere in the message", () => {
    const msg: ComposedMessage = {
      ...base,
      bcc: [
        { name: "Secret Name", address: "Secret-Bcc@Example.com" },
        { name: "Zoë Hidden", address: "zoe.hidden@example.org" },
      ],
    };
    const built = buildMime(msg, goldenOptions());
    const s = text(built.raw).toLowerCase();
    expect(s).not.toMatch(/^bcc:/m);
    for (const needle of ["secret-bcc", "secret name", "zoe.hidden", "hidden"]) expect(s).not.toContain(needle);
    // and not in encoded form either
    expect(text(built.raw)).not.toContain(Buffer.from("Zoë Hidden", "utf8").toString("base64").slice(0, 12));
    expect(built.recipients).toEqual(["ana@example.com", "secret-bcc@example.com", "zoe.hidden@example.org"]);
  });
});

describe("buildMime: recipients", () => {
  it("lower-cases and de-duplicates across to, cc and bcc, keeping first-seen order", () => {
    const built = buildMime(
      {
        ...base,
        to: [{ address: "A@Example.com" }, { address: "b@example.com" }],
        cc: [{ address: "a@example.com" }, { address: "C@example.com" }],
        bcc: [{ address: "B@EXAMPLE.COM" }],
      },
      goldenOptions(),
    );
    expect(built.recipients).toEqual(["a@example.com", "b@example.com", "c@example.com"]);
    // headers keep the addresses as written
    expect(text(built.raw)).toContain("To: A@Example.com, b@example.com\r\n");
  });

  it(`accepts ${LIMITS.maxRecipients} recipients and refuses ${LIMITS.maxRecipients + 1}`, () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => ({ address: `r${i}@example.com` }));
    expect(buildMime({ ...base, to: many(20), cc: [], bcc: many(LIMITS.maxRecipients).slice(20) }, goldenOptions()).recipients).toHaveLength(
      LIMITS.maxRecipients,
    );
    const err = expectInvalid({ ...base, to: many(LIMITS.maxRecipients + 1) });
    expect(err.message).toMatch(/recipients/);
    // duplicates count once
    expect(buildMime({ ...base, to: [...many(LIMITS.maxRecipients), ...many(10)] }, goldenOptions()).recipients).toHaveLength(
      LIMITS.maxRecipients,
    );
  });

  it("refuses a message with no recipient at all", () => {
    expectInvalid({ ...base, to: [] });
  });
});

describe("buildMime: size", () => {
  const attach = (bytes: number) => ({ filename: "big.bin", mimeType: "application/octet-stream", content: new Uint8Array(bytes) });

  it("builds a message just under LIMITS.maxRawBytes", () => {
    const built = buildMime({ ...base, attachments: [attach(7 * 1024 * 1024)] }, goldenOptions());
    expect(built.raw.byteLength).toBeLessThanOrEqual(LIMITS.maxRawBytes);
  });

  it("refuses a message whose encoded size is over LIMITS.maxRawBytes", () => {
    // 7.75 MiB of content is under the limit, its base64 is over it
    const err = expectInvalid({ ...base, attachments: [attach(7.75 * 1024 * 1024)] });
    expect(err.message).toMatch(/too large/);
  });

  it("refuses early when the content alone is over the limit", () => {
    expectInvalid({ ...base, attachments: [attach(LIMITS.maxRawBytes + 1)] });
  });
});

describe("buildMime: header injection and malformed input", () => {
  type Mutator = (m: ComposedMessage) => void;
  const PAYLOADS = ["\r", "\n", "\u0000", "\r\nBcc: victim@example.com"];
  const withAttachment = (): ComposedMessage => ({
    ...base,
    html: "<p>x</p>",
    cc: [{ name: "C", address: "c@example.com" }],
    bcc: [{ name: "B", address: "b@example.com" }],
    replyTo: [{ name: "R", address: "r@example.com" }],
    inReplyTo: "parent@mail.example.com",
    references: ["root@mail.example.com"],
    attachments: [{ filename: "a.png", mimeType: "image/png", content: utf8("x"), inline: true, contentId: "a@operator.example" }],
  });
  const fields: [string, (p: string) => Mutator][] = [
    ["from.name", (p) => (m) => (m.from = { ...m.from, name: `x${p}y` })],
    ["from.address", (p) => (m) => (m.from = { ...m.from, address: `x${p}@operator.example` })],
    ["to[0].name", (p) => (m) => (m.to = [{ name: `x${p}y`, address: "ana@example.com" }])],
    ["to[0].address", (p) => (m) => (m.to = [{ address: `ana@example.com${p}` }])],
    ["cc[0].name", (p) => (m) => (m.cc = [{ name: `x${p}y`, address: "c@example.com" }])],
    ["cc[0].address", (p) => (m) => (m.cc = [{ address: `c${p}@example.com` }])],
    ["bcc[0].name", (p) => (m) => (m.bcc = [{ name: `x${p}y`, address: "b@example.com" }])],
    ["bcc[0].address", (p) => (m) => (m.bcc = [{ address: `b@example.com${p}` }])],
    ["replyTo[0].name", (p) => (m) => (m.replyTo = [{ name: `x${p}y`, address: "r@example.com" }])],
    ["replyTo[0].address", (p) => (m) => (m.replyTo = [{ address: `r${p}@example.com` }])],
    ["subject", (p) => (m) => (m.subject = `Hello${p}World`)],
    ["inReplyTo", (p) => (m) => (m.inReplyTo = `parent${p}@mail.example.com`)],
    ["references[0]", (p) => (m) => (m.references = [`root${p}@mail.example.com`])],
    ["attachments[0].filename", (p) => (m) => (m.attachments![0] = { ...m.attachments![0]!, filename: `a${p}.png` })],
    ["attachments[0].mimeType", (p) => (m) => (m.attachments![0] = { ...m.attachments![0]!, mimeType: `image/png${p}` })],
    ["attachments[0].contentId", (p) => (m) => (m.attachments![0] = { ...m.attachments![0]!, contentId: `a${p}@operator.example` })],
  ];

  it("the unmodified message is valid", () => {
    expect(() => buildMime(withAttachment(), goldenOptions())).not.toThrow();
  });

  for (const [field, mutate] of fields) {
    it(`refuses CR, LF or NUL in ${field}, without echoing the value`, () => {
      for (const payload of PAYLOADS) {
        const msg = withAttachment();
        mutate(payload)(msg);
        const err = expectInvalid(msg);
        expect(err.message).not.toContain("victim");
        expect(err.message).not.toMatch(/[\r\n\u0000]/);
      }
    });
  }

  it("refuses CR, LF or NUL in the Message-ID domain", () => {
    for (const payload of PAYLOADS) expectInvalid(base, { ...goldenOptions(), messageIdDomain: `operator.example${payload}` });
  });

  it.each([
    "no-at-sign",
    "a@",
    "@example.com",
    "a b@example.com",
    "a@b@example.com",
    "<a@example.com>",
    "a@example.com>, <victim@example.com",
    "a@example.com,victim@example.com",
    '"quoted local"@example.com',
    "ä@example.com",
    "a@exämple.com",
    "a@-example.com",
    "a@example..com",
    ".a@example.com",
    `${"x".repeat(65)}@example.com`,
  ])("refuses the address %j", (address) => {
    const err = expectInvalid({ ...base, to: [{ address }] });
    expect(err.message).not.toContain(address);
  });

  it.each(["", "<parent@x.example>", "has space@x.example", "a>b@x.example"])("refuses the message id %j", (id) => {
    expectInvalid({ ...base, inReplyTo: id });
    expectInvalid({ ...base, references: [id] });
  });

  it.each(["", "pdf", "text/plain; charset=x", "image/", "multipart/mixed", "message/rfc822", 'a/b"c'])(
    "refuses the attachment type %j",
    (mimeType) => {
      expectInvalid({ ...base, attachments: [{ filename: "a", mimeType, content: utf8("x") }] });
    },
  );

  it.each(["", "a b@x", "<a@x>"])("refuses the Content-ID %j", (contentId) => {
    expectInvalid({ ...base, attachments: [{ filename: "a", mimeType: "image/png", content: utf8("x"), inline: true, contentId }] });
  });

  it.each(["", "bad domain", "a..b", "-a.example", "exämple.com"])("refuses the Message-ID domain %j", (messageIdDomain) => {
    expectInvalid(base, { ...goldenOptions(), messageIdDomain });
  });

  it("refuses a body that is not a string (input from RPC is not trusted to match the types)", () => {
    expectInvalid({ ...base, text: undefined as unknown as string });
    expectInvalid({ ...base, html: 42 as unknown as string });
  });

  it("refuses an invalid clock", () => {
    expectInvalid(base, { ...goldenOptions(), now: new Date(Number.NaN) });
  });
});
