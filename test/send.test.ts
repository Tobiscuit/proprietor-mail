import { SendRejected } from "@proprietor/mail-outbound";
import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { base64urlFromBytes } from "./support/capability-tokens";
import { testId } from "./support/ids";
import { capFor, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

const mail = () => exports.MailService;

function request(over: Record<string, unknown> = {}) {
  return {
    idempotencyKey: `send-${crypto.randomUUID()}`,
    to: [{ name: "Ana Ruiz", address: "ana@example.com" }],
    subject: "Your quote",
    text: "Hi Ana,\n\nthe quote is attached.",
    ...over,
  };
}

async function sentRows(mb: TestMailbox) {
  return runInDurableObject(mb.stub, (_i, state) =>
    state.storage.sql.exec("SELECT id, folder_id, direction, seen, size, body_key FROM messages WHERE folder_id = 'sent'").toArray(),
  );
}

async function sendsRows(mb: TestMailbox) {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec("SELECT * FROM sends").toArray());
}

describe("M6: only the owner sends, and always as one of the mailbox's addresses", () => {
  it("builds From from the primary address and the display name by default, and SES authorizes on that address", async () => {
    const mb = await provisionMailbox();
    valueOf(await mail().setPolicy(await capFor(mb), { displayName: "Example" }));
    valueOf(await mail().send(await capFor(mb), request()));
    expect(mb.ports.mime.built[0]!.msg.from).toEqual({ name: "Example", address: mb.address });
    expect(mb.ports.mailer.sent[0]!.fromAddress).toBe(mb.address);
  });

  it("sends as another of the mailbox's addresses when `from` names one (plan.md §12, D14): MIME, SES, Message-ID domain and the Sent copy", async () => {
    const mb = await provisionMailbox({ addresses: [`team.${testId("mbx").slice(4, 12)}@other.test`] });
    const alias = mb.addresses[1]!;
    valueOf(await mail().setPolicy(await capFor(mb), { displayName: "Example" }));
    const result = valueOf(await mail().send(await capFor(mb), request({ from: alias.toUpperCase() })));
    expect(mb.ports.mime.built[0]!.msg.from).toEqual({ name: "Example", address: alias });
    expect(mb.ports.mime.built[0]!.opts.messageIdDomain).toBe("other.test");
    expect(mb.ports.mailer.sent[0]!.fromAddress).toBe(alias);
    expect(mb.ports.sealer.sealed.at(-1)!.header).toMatchObject({ direction: "out", from: { name: "Example", address: alias } });
    expect(result.messageId).not.toBeNull();
  });

  it("refuses a `from` outside the mailbox's addresses: nothing is sent, and the idempotency key is not spent", async () => {
    const mb = await provisionMailbox();
    const outside = request({ from: "ceo@bank.example", idempotencyKey: "k-from" });
    expect(refusalOf(await mail().send(await capFor(mb), outside))).toEqual({ name: "InvalidRequest", message: "invalid request: from is not one of the mailbox's addresses" });
    expect(mb.ports.mailer.sent).toEqual([]);
    expect(await sendsRows(mb)).toEqual([]);
    // The same key then sends, once, from the primary.
    valueOf(await mail().send(await capFor(mb), request({ idempotencyKey: "k-from" })));
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("refuses a `from` that is not an address, or a Reply-To, and sends nothing", async () => {
    const mb = await provisionMailbox();
    for (const field of [{ from: { address: mb.address } }, { from: "not an address" }, { replyTo: [{ address: "x@evil.example" }] }]) {
      expect(refusalOf(await mail().send(await capFor(mb), request(field)))).toMatchObject({ name: "InvalidRequest" });
    }
    expect(mb.ports.mailer.sent).toEqual([]);
  });

  it("uses the SES tenant and configuration set from the Directory row", async () => {
    const mb = await provisionMailbox();
    valueOf(await mail().send(await capFor(mb), request()));
    expect(mb.ports.mailer.sent[0]).toMatchObject({ configurationSet: "send-test-mail", tenantName: "client-test" });
    expect(mb.ports.mailer.sent[0]!.recipients).toEqual(["ana@example.com"]);
  });

  it("answers MailboxNotActive for a suspended mailbox", async () => {
    const mb = await provisionMailbox({ status: "suspended" });
    expect(await mail().send(await capFor(mb), request())).toEqual({ ok: false, error: { name: "MailboxNotActive", message: "this mailbox is not active" } });
  });

  it("does not send from a mailbox with no SES configuration set", async () => {
    const mb = await provisionMailbox({ sesConfigurationSet: null });
    expect(await mail().send(await capFor(mb), request())).toEqual({ ok: false, error: { name: "SendFailed", message: "sending failed", retryable: false } });
    expect(mb.ports.mailer.sent).toEqual([]);
  });
});

describe("M7: sending is bounded and idempotent", () => {
  it("allows 50 recipients across to, cc and bcc, and refuses 51", async () => {
    const mb = await provisionMailbox();
    const people = (n: number, tag: string) => Array.from({ length: n }, (_, i) => ({ address: `${tag}${i}@example.com` }));
    valueOf(await mail().send(await capFor(mb), request({ to: people(20, "t"), cc: people(20, "c"), bcc: people(10, "b") })));
    const refusal = refusalOf(await mail().send(await capFor(mb), request({ to: people(20, "t"), cc: people(20, "c"), bcc: people(11, "b") })));
    expect(refusal).toEqual({ name: "InvalidRequest", message: "invalid request: at most 50 recipients" });
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("answers RateLimited on the 21st send in an hour, with retryAfterSeconds crossing RPC", async () => {
    const mb = await provisionMailbox();
    for (let i = 0; i < 20; i++) {
      valueOf(await mail().send(await capFor(mb), request()));
      mb.ports.clock.advance(60 * 1000);
    }
    // The first send leaves the hour 20 minutes from now.
    expect(await mail().send(await capFor(mb), request())).toEqual({
      ok: false,
      error: { name: "RateLimited", message: "send rate limit reached", retryAfterSeconds: 40 * 60 },
    });
    expect(mb.ports.mailer.sent).toHaveLength(20);
    mb.ports.clock.advance(40 * 60 * 1000);
    valueOf(await mail().send(await capFor(mb), request()));
    expect(mb.ports.mailer.sent).toHaveLength(21);
  });

  it("answers RateLimited on the 101st send in a day", async () => {
    const mb = await provisionMailbox();
    for (let i = 0; i < 100; i++) {
      valueOf(await mail().send(await capFor(mb), request()));
      mb.ports.clock.advance(4 * 60 * 1000); // 15 an hour: never the hourly limit
    }
    expect(refusalOf(await mail().send(await capFor(mb), request()))).toMatchObject({ name: "RateLimited" });
    expect(mb.ports.mailer.sent).toHaveLength(100);
  });

  it("sends once for a repeated idempotency key and returns the first result", async () => {
    const mb = await provisionMailbox();
    const req = request();
    const first = await mail().send(await capFor(mb), req);
    const again = await mail().send(await capFor(mb), req);
    expect(first.ok).toBe(true);
    expect(again).toEqual(first);
    expect(mb.ports.mailer.sent).toHaveLength(1);
    expect(await sentRows(mb)).toHaveLength(1);
  });
});

describe("the Sent copy", () => {
  it("is the exact bytes handed to SES, sealed with a direction-out header, stored in Sent as read", async () => {
    const mb = await provisionMailbox();
    const result = valueOf(
      await mail().send(
        await capFor(mb),
        request({
        cc: [{ address: "bob@example.org" }],
        bcc: [{ address: "archive@example.net" }],
        inReplyTo: "abc@example.com",
        references: ["root@x", "abc@example.com"],
          attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", content: new Uint8Array(1234) }],
        }),
      ),
    );
    const handedToSes = mb.ports.mailer.sent[0]!.raw;
    const sealed = mb.ports.sealer.sealed.at(-1)!;
    expect(sealed.raw).toEqual(handedToSes);
    expect(sealed.ids).toEqual({ mailboxId: mb.id, messageId: result.messageId });
    expect(sealed.header).toMatchObject({
      direction: "out",
      envelopeFrom: null,
      from: { address: mb.address },
      to: [{ name: "Ana Ruiz", address: "ana@example.com" }],
      cc: [{ name: "", address: "bob@example.org" }],
      bcc: [{ name: "", address: "archive@example.net" }],
      subject: "Your quote",
      inReplyTo: "abc@example.com",
      references: ["root@x", "abc@example.com"],
      snippet: "Hi Ana, the quote is attached.",
      attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", size: 1234, inline: false }],
    });
    expect(await sentRows(mb)).toEqual([
      { id: result.messageId, folder_id: "sent", direction: "out", seen: 1, size: handedToSes.byteLength, body_key: `mbx/${mb.id}/msg/${result.messageId}` },
    ]);
    expect(await env.MAIL.head(`mbx/${mb.id}/msg/${result.messageId}`)).not.toBeNull();
    expect(await sendsRows(mb)).toEqual([
      expect.objectContaining({ message_id: result.messageId, provider_message_id: result.providerMessageId }),
    ]);
  });

  it("carries the Message-ID recipients see: SES replaces the built one (S3 finding, us-east-1)", async () => {
    const mb = await provisionMailbox();
    const result = valueOf(await mail().send(await capFor(mb), request()));
    expect(mb.ports.sealer.sealed.at(-1)!.header.messageId).toBe(`${result.providerMessageId}@email.amazonses.com`);
  });

  it("deletes the draft it was sent from", async () => {
    const mb = await provisionMailbox();
    const draftId = testId("drf");
    valueOf(
      await mail().saveDraft(await capFor(mb), {
        id: draftId,
        keyId: mb.key!.keyId,
        keyEnvelope: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(80))),
        sealed: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(64))),
      }),
    );
    valueOf(await mail().send(await capFor(mb), request({ draftId })));
    expect(valueOf(await mail().drafts(await capFor(mb)))).toEqual([]);
  });

  it("still reports the send when storing the Sent copy fails: the message is already out", async () => {
    const mb = await provisionMailbox();
    const realSeal = mb.ports.sealer.seal.bind(mb.ports.sealer);
    mb.ports.sealer.seal = async () => {
      throw new Error("sealing broke");
    };
    const result = await mail().send(await capFor(mb), request());
    mb.ports.sealer.seal = realSeal;
    expect(result).toEqual({ ok: true, value: { messageId: null, providerMessageId: "ses-1" } });
    expect(valueOf(await mail().audit(await capFor(mb), {}))[0]).toMatchObject({ action: "sent-copy-not-stored" });
  });
});

describe("when SES says no", () => {
  it("throttling or 5xx: SendFailed{retryable: true}, and the key is free to send again", async () => {
    const mb = await provisionMailbox();
    const req = request();
    mb.ports.mailer.failWith = new SendRejected("throttled", 429, "TooManyRequestsException", true);
    expect(await mail().send(await capFor(mb), req)).toEqual({
      ok: false,
      error: { name: "SendFailed", message: "sending failed; it may be retried", retryable: true },
    });
    mb.ports.mailer.failWith = undefined;
    valueOf(await mail().send(await capFor(mb), req));
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("a definite refusal: SendFailed{retryable: false}", async () => {
    const mb = await provisionMailbox();
    mb.ports.mailer.failWith = new SendRejected("not authorized", 403, "AccessDeniedException", false);
    expect(refusalOf(await mail().send(await capFor(mb), request()))).toEqual({ name: "SendFailed", message: "sending failed", retryable: false });
  });

  it("an unknown outcome (status 0: timeout, network, 2xx without an id): recorded, and NEVER sent again under that key", async () => {
    const mb = await provisionMailbox();
    const req = request();
    mb.ports.mailer.failWith = new SendRejected("timed out", 0, "Timeout", false);
    expect(refusalOf(await mail().send(await capFor(mb), req))).toMatchObject({ name: "SendFailed", retryable: false });
    mb.ports.mailer.failWith = undefined;
    mb.ports.clock.advance(24 * 60 * 60 * 1000);
    expect(refusalOf(await mail().send(await capFor(mb), req))).toMatchObject({ name: "SendFailed", retryable: false });
    expect(mb.ports.mailer.sent).toEqual([]);
    expect(mb.ports.trace.filter((t) => t === "ses")).toHaveLength(1);
    expect(valueOf(await mail().audit(await capFor(mb), {}))[0]).toMatchObject({ action: "send-outcome-unknown" });
  });

  it("a message the MIME builder refuses: InvalidRequest, nothing sent", async () => {
    const mb = await provisionMailbox();
    const invalid = new Error("header injection");
    invalid.name = "InvalidMessage";
    mb.ports.mime.failWith = invalid;
    expect(refusalOf(await mail().send(await capFor(mb), request()))).toEqual({ name: "InvalidRequest", message: "invalid request: the message could not be built" });
    expect(mb.ports.mailer.sent).toEqual([]);
    expect(await sendsRows(mb)).toEqual([]);
  });
});
