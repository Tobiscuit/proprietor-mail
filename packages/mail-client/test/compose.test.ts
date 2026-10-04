// replyTo, forwardOf and parseAddressList (contracts/mail-client-v1.md "Drafts and sending").
import { describe, expect, test } from "vitest";
import { forwardOf, parseAddressList, replyTo, type MailBody } from "../src/index";
import { opened } from "./support";

const mailbox = { address: "hello@example.com", addresses: ["hello@example.com", "team@example.com"] };

const arrived = opened({
  subject: "Kitchen remodel",
  messageId: "k1@example.com",
  references: ["k0@example.com"],
  envelopeTo: "team@example.com",
  date: "2026-09-26T15:04:05.000Z",
  from: { name: "Ana Ruiz", address: "ana@example.com" },
  to: [{ name: "", address: "team@example.com" }, { name: "Bo", address: "bo@example.org" }],
  cc: [{ name: "", address: "hello@example.com" }, { name: "Cy", address: "cy@example.net" }],
  replyTo: [],
  snippet: "We'd like a quote",
});

const body: MailBody = {
  raw: new Uint8Array(0),
  text: "We'd like a quote\nfor the kitchen.",
  html: null,
  attachments: [
    { filename: "plan.pdf", mimeType: "application/pdf", size: 3, contentId: null, inline: false, content: new Uint8Array([1, 2, 3]) },
    { filename: "logo.png", mimeType: "image/png", size: 1, contentId: "logo@example.com", inline: true, content: new Uint8Array([9]) },
  ],
};

describe("replyTo", () => {
  test("reply: to the sender, from the address the message arrived at, Re: once, quoted text, threading headers", () => {
    const compose = replyTo(arrived, body, mailbox, "reply");
    expect(compose.from).toBe("team@example.com");
    expect(compose.to).toEqual([{ name: "Ana Ruiz", address: "ana@example.com" }]);
    expect(compose.cc).toEqual([]);
    expect(compose.bcc).toEqual([]);
    expect(compose.subject).toBe("Re: Kitchen remodel");
    expect(compose.text).toBe("\n\nOn 2026-09-26, Ana Ruiz <ana@example.com> wrote:\n> We'd like a quote\n> for the kitchen.");
    expect(compose.inReplyTo).toBe("k1@example.com");
    expect(compose.references).toEqual(["k0@example.com", "k1@example.com"]);
    expect(compose.attachments).toEqual([]);
  });

  test("Reply-To wins over From; Re: is not doubled; the snippet stands in when there is no body", () => {
    const withReplyTo = opened({ subject: "RE: Kitchen remodel", messageId: "k2@example.com", replyTo: [{ name: "Desk", address: "desk@example.com" }], from: { name: "Ana", address: "ana@example.com" }, snippet: "Snip" });
    const compose = replyTo(withReplyTo, null, mailbox, "reply");
    expect(compose.to).toEqual([{ name: "Desk", address: "desk@example.com" }]);
    expect(compose.subject).toBe("RE: Kitchen remodel");
    expect(compose.text).toContain("> Snip");
  });

  test("reply-all: everyone but the mailbox's own addresses, without duplicates", () => {
    const compose = replyTo(arrived, body, mailbox, "reply-all");
    expect(compose.to).toEqual([
      { name: "Ana Ruiz", address: "ana@example.com" },
      { name: "Bo", address: "bo@example.org" },
    ]);
    expect(compose.cc).toEqual([{ name: "Cy", address: "cy@example.net" }]);
  });

  test("from falls back to the primary when the message did not arrive at one of the mailbox's addresses", () => {
    const forwarded = opened({ subject: "Hi", messageId: "f@example.com", envelopeTo: "old@example.org", to: [{ name: "", address: "old@example.org" }] });
    expect(replyTo(forwarded, null, mailbox, "reply").from).toBe("hello@example.com");
  });

  test("replying to a Sent copy goes to its recipients, from the address it was sent as", () => {
    const sent = opened({ direction: "out", subject: "Our quote", messageId: "s@example.com", envelopeFrom: null, envelopeTo: null, from: { name: "Team", address: "team@example.com" }, to: [{ name: "Ana", address: "ana@example.com" }], cc: [{ name: "Bo", address: "bo@example.org" }] });
    const reply = replyTo(sent, null, mailbox, "reply");
    expect(reply.from).toBe("team@example.com");
    expect(reply.to).toEqual([{ name: "Ana", address: "ana@example.com" }]);
    expect(reply.cc).toEqual([]);
    expect(replyTo(sent, null, mailbox, "reply-all").cc).toEqual([{ name: "Bo", address: "bo@example.org" }]);
  });

  test("a message without a header cannot be answered", () => {
    expect(() => replyTo(opened({ subject: "" }, { header: null, undecryptable: true }), null, mailbox, "reply")).toThrow(TypeError);
  });
});

describe("forwardOf", () => {
  test("Fwd: once, the forwarded block, the attachments as Files, no threading headers", () => {
    const compose = forwardOf(arrived, body, mailbox);
    expect(compose.from).toBe("team@example.com");
    expect(compose.to).toEqual([]);
    expect(compose.subject).toBe("Fwd: Kitchen remodel");
    expect(compose.text).toBe(
      "\n\n---------- Forwarded message ----------\nFrom: Ana Ruiz <ana@example.com>\nDate: 2026-09-26T15:04:05.000Z\nSubject: Kitchen remodel\nTo: team@example.com, Bo <bo@example.org>\nCc: hello@example.com, Cy <cy@example.net>\n\nWe'd like a quote\nfor the kitchen.",
    );
    expect(compose.inReplyTo).toBeNull();
    expect(compose.references).toEqual([]);
    expect(compose.attachments.map((f) => [f.name, f.type, f.size])).toEqual([
      ["plan.pdf", "application/pdf", 3],
      ["logo.png", "image/png", 1],
    ]);
    expect(forwardOf(opened({ subject: "Fwd: x", messageId: "x@example.com" }), null, mailbox).subject).toBe("Fwd: x");
  });
});

describe("parseAddressList", () => {
  test("names, quoted names, bare addresses; commas, semicolons and newlines separate", () => {
    const { addresses, invalid } = parseAddressList('Ana Ruiz <ana@example.com>, "Ruiz, Bo" <bo@example.org>;\ncy@example.net\n<dy@example.net>');
    expect(addresses).toEqual([
      { name: "Ana Ruiz", address: "ana@example.com" },
      { name: "Ruiz, Bo", address: "bo@example.org" },
      { name: "", address: "cy@example.net" },
      { name: "", address: "dy@example.net" },
    ]);
    expect(invalid).toEqual([]);
  });

  test("what is not an address is listed as invalid, and nothing is silently dropped", () => {
    const { addresses, invalid } = parseAddressList("ana@example.com, not an address, <>, Bo <bo@>, ok@example.org");
    expect(addresses.map((a) => a.address)).toEqual(["ana@example.com", "ok@example.org"]);
    expect(invalid).toEqual(["not an address", "<>", "Bo <bo@>"]);
    expect(parseAddressList("")).toEqual({ addresses: [], invalid: [] });
  });
});
