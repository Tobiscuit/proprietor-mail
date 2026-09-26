import { SendRejected } from "@platform-mail/outbound";
import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { base64urlFromBytes } from "./support/capability-tokens";
import { testId } from "./support/ids";
import { capFor, provisionMailbox, rejectionOf, type TestMailbox } from "./support/mailbox";

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

describe("M6: only the owner sends, and always as the mailbox", () => {
  it("builds From from the mailbox's address and display name, and SES authorizes on that address", async () => {
    const mb = await provisionMailbox();
    await mail().setPolicy(await capFor(mb), { displayName: "Operator" });
    await mail().send(await capFor(mb), request());
    expect(mb.ports.mime.built[0]!.msg.from).toEqual({ name: "Operator", address: mb.address });
    expect(mb.ports.mailer.sent[0]!.fromAddress).toBe(mb.address);
  });

  it("refuses a request that tries to choose From (or Reply-To), and sends nothing", async () => {
    const mb = await provisionMailbox();
    for (const field of [{ from: { address: "ceo@bank.example" } }, { replyTo: [{ address: "x@evil.example" }] }]) {
      expect(await rejectionOf(mail().send(await capFor(mb), request(field)))).toMatchObject({ name: "InvalidRequest" });
    }
    expect(mb.ports.mailer.sent).toEqual([]);
  });

  it("uses the SES tenant and configuration set from the Directory row", async () => {
    const mb = await provisionMailbox();
    await mail().send(await capFor(mb), request());
    expect(mb.ports.mailer.sent[0]).toMatchObject({ configurationSet: "send-test-mail", tenantName: "client-test" });
    expect(mb.ports.mailer.sent[0]!.recipients).toEqual(["ana@example.com"]);
  });

  it("answers MailboxNotActive for a suspended mailbox", async () => {
    const mb = await provisionMailbox({ status: "suspended" });
    expect(await rejectionOf(mail().send(await capFor(mb), request()))).toMatchObject({ name: "MailboxNotActive" });
  });

  it("does not send from a mailbox with no SES configuration set", async () => {
    const mb = await provisionMailbox({ sesConfigurationSet: null });
    expect(await rejectionOf(mail().send(await capFor(mb), request()))).toMatchObject({ name: "SendFailed", retryable: false });
    expect(mb.ports.mailer.sent).toEqual([]);
  });
});

describe("M7: sending is bounded and idempotent", () => {
  it("allows 50 recipients across to, cc and bcc, and refuses 51", async () => {
    const mb = await provisionMailbox();
    const people = (n: number, tag: string) => Array.from({ length: n }, (_, i) => ({ address: `${tag}${i}@example.com` }));
    await mail().send(await capFor(mb), request({ to: people(20, "t"), cc: people(20, "c"), bcc: people(10, "b") }));
    const err = await rejectionOf(mail().send(await capFor(mb), request({ to: people(20, "t"), cc: people(20, "c"), bcc: people(11, "b") })));
    expect(err).toMatchObject({ name: "InvalidRequest" });
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("answers RateLimited on the 21st send in an hour, with retryAfterSeconds crossing RPC", async () => {
    const mb = await provisionMailbox();
    for (let i = 0; i < 20; i++) {
      await mail().send(await capFor(mb), request());
      mb.ports.clock.advance(60 * 1000);
    }
    const err = await rejectionOf(mail().send(await capFor(mb), request()));
    expect(err.name).toBe("RateLimited");
    // The first send leaves the hour 20 minutes from now.
    expect(err.retryAfterSeconds).toBe(40 * 60);
    expect(mb.ports.mailer.sent).toHaveLength(20);
    mb.ports.clock.advance(40 * 60 * 1000);
    await mail().send(await capFor(mb), request());
    expect(mb.ports.mailer.sent).toHaveLength(21);
  });

  it("answers RateLimited on the 101st send in a day", async () => {
    const mb = await provisionMailbox();
    for (let i = 0; i < 100; i++) {
      await mail().send(await capFor(mb), request());
      mb.ports.clock.advance(4 * 60 * 1000); // 15 an hour: never the hourly limit
    }
    const err = await rejectionOf(mail().send(await capFor(mb), request()));
    expect(err).toMatchObject({ name: "RateLimited" });
    expect(mb.ports.mailer.sent).toHaveLength(100);
  });

  it("sends once for a repeated idempotency key and returns the first result", async () => {
    const mb = await provisionMailbox();
    const req = request();
    const first = await mail().send(await capFor(mb), req);
    const again = await mail().send(await capFor(mb), req);
    expect(again).toEqual(first);
    expect(mb.ports.mailer.sent).toHaveLength(1);
    expect(await sentRows(mb)).toHaveLength(1);
  });
});

describe("the Sent copy", () => {
  it("is the exact bytes handed to SES, sealed with a direction-out header, stored in Sent as read", async () => {
    const mb = await provisionMailbox();
    const result = await mail().send(
      await capFor(mb),
      request({
        cc: [{ address: "bob@example.org" }],
        bcc: [{ address: "archive@example.net" }],
        inReplyTo: "abc@example.com",
        references: ["root@x", "abc@example.com"],
        attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", content: new Uint8Array(1234) }],
      }),
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
    const result = await mail().send(await capFor(mb), request());
    expect(mb.ports.sealer.sealed.at(-1)!.header.messageId).toBe(`${result.providerMessageId}@email.amazonses.com`);
  });

  it("deletes the draft it was sent from", async () => {
    const mb = await provisionMailbox();
    const draftId = testId("drf");
    await mail().saveDraft(await capFor(mb), {
      id: draftId,
      keyId: mb.key!.keyId,
      keyEnvelope: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(80))),
      sealed: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(64))),
    });
    await mail().send(await capFor(mb), request({ draftId }));
    expect(await mail().drafts(await capFor(mb))).toEqual([]);
  });

  it("still reports the send when storing the Sent copy fails: the message is already out", async () => {
    const mb = await provisionMailbox();
    const realSeal = mb.ports.sealer.seal.bind(mb.ports.sealer);
    mb.ports.sealer.seal = async () => {
      throw new Error("sealing broke");
    };
    const result = await mail().send(await capFor(mb), request());
    mb.ports.sealer.seal = realSeal;
    expect(result).toEqual({ messageId: null, providerMessageId: "ses-1" });
    expect((await mail().audit(await capFor(mb), {}))[0]).toMatchObject({ action: "sent-copy-not-stored" });
  });
});

describe("when SES says no", () => {
  it("throttling or 5xx: SendFailed{retryable: true}, and the key is free to send again", async () => {
    const mb = await provisionMailbox();
    const req = request();
    mb.ports.mailer.failWith = new SendRejected("throttled", 429, "TooManyRequestsException", true);
    expect(await rejectionOf(mail().send(await capFor(mb), req))).toMatchObject({ name: "SendFailed", retryable: true });
    mb.ports.mailer.failWith = undefined;
    await mail().send(await capFor(mb), req);
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("a definite refusal: SendFailed{retryable: false}", async () => {
    const mb = await provisionMailbox();
    mb.ports.mailer.failWith = new SendRejected("not authorized", 403, "AccessDeniedException", false);
    expect(await rejectionOf(mail().send(await capFor(mb), request()))).toMatchObject({ name: "SendFailed", retryable: false });
  });

  it("an unknown outcome (status 0: timeout, network, 2xx without an id): recorded, and NEVER sent again under that key", async () => {
    const mb = await provisionMailbox();
    const req = request();
    mb.ports.mailer.failWith = new SendRejected("timed out", 0, "Timeout", false);
    expect(await rejectionOf(mail().send(await capFor(mb), req))).toMatchObject({ name: "SendFailed", retryable: false });
    mb.ports.mailer.failWith = undefined;
    mb.ports.clock.advance(24 * 60 * 60 * 1000);
    expect(await rejectionOf(mail().send(await capFor(mb), req))).toMatchObject({ name: "SendFailed", retryable: false });
    expect(mb.ports.mailer.sent).toEqual([]);
    expect(mb.ports.trace.filter((t) => t === "ses")).toHaveLength(1);
    expect((await mail().audit(await capFor(mb), {}))[0]).toMatchObject({ action: "send-outcome-unknown" });
  });

  it("a message the MIME builder refuses: InvalidRequest, nothing sent", async () => {
    const mb = await provisionMailbox();
    const invalid = new Error("header injection");
    invalid.name = "InvalidMessage";
    mb.ports.mime.failWith = invalid;
    expect(await rejectionOf(mail().send(await capFor(mb), request()))).toMatchObject({ name: "InvalidRequest" });
    expect(mb.ports.mailer.sent).toEqual([]);
    expect(await sendsRows(mb)).toEqual([]);
  });
});
