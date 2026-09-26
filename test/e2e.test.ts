import * as mailCrypto from "@platform-mail/crypto";
import * as outbound from "@platform-mail/outbound";
import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import PostalMime from "postal-mime";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Mailbox } from "../src/mailbox/mailbox";
import type { MailboxPorts } from "../src/ports";
import { productionPorts } from "../src/wiring";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { crlf, incomingEmail, sampleMessage } from "./support/email";
import { expectEmailThrow } from "./support/escapes";
import { fakePorts } from "./support/fakes";
import { capFor, injectPorts, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { valueOf } from "./support/results";

// tasks.md S2j: the REAL packages behind the ports. Each block runs once the
// package it needs says IMPLEMENTED (slices S1 and S3), and skips until then.
// No test here, or anywhere, sends real mail: SES is a fake, or a fetch that
// never leaves the isolate.

const CRYPTO = mailCrypto.IMPLEMENTED;
const OUTBOUND = outbound.IMPLEMENTED;
const mail = () => exports.MailService;

/** Real crypto and ids; fake SES, signal and clock. */
function realCryptoPorts(): MailboxPorts {
  const real = productionPorts(env);
  return { ...fakePorts(), sealer: real.sealer, ids: real.ids };
}

/** A provisioned mailbox, then enrolled exactly as the owner's browser would: S1's key pair and a recovery wrap. */
async function enrolledWithRealKey(ports: MailboxPorts) {
  const mb = await provisionMailbox({ status: "provisioned" });
  await injectPorts(mb.stub, ports);
  const { publicKey, privateKey } = await mailCrypto.generateMailboxKey();
  const recovery = mailCrypto.newRecoveryKey();
  const wrap = await mailCrypto.wrapPrivateKey(privateKey, {
    mailboxId: mb.id,
    wrapId: mailCrypto.newId("wrp"),
    kind: "recovery",
    secret: recovery.secret, // pragma: allowlist secret (S1's parameter name; a fresh test recovery key)
  });
  const enrolled = valueOf(
    await mail().enroll(await capFor(mb), {
      publicKey: base64urlFromBytes(publicKey.publicKey),
      wraps: [{ ...wrap, label: "Recovery key" }],
    }),
  );
  return { mb, publicKey, privateKey, recovery, enrolled };
}

async function deliver(mb: TestMailbox, raw: Uint8Array): Promise<void> {
  const email = incomingEmail(raw, { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  expect(email.rejects).toEqual([]);
}

async function sealedBody(mb: TestMailbox, messageId: string): Promise<Uint8Array> {
  return new Uint8Array(await new Response(valueOf(await mail().body(await capFor(mb), messageId))).arrayBuffer());
}

describe.skipIf(!CRYPTO)("with the real @platform-mail/crypto (S1)", () => {
  it("a message sealed by the Worker opens with the owner's private key to the exact raw bytes", async () => {
    const { mb, privateKey } = await enrolledWithRealKey(realCryptoPorts());
    const raw = sampleMessage({ to: mb.address, subject: "Kitchen remodel — Zürich", body: "Hola, ¿cuánto cuesta?" });
    await deliver(mb, raw);

    const [item] = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    const ids = { mailboxId: mb.id, messageId: item!.id };
    const opened = await mailCrypto.openBody(privateKey, ids, { keyEnvelope: item!.keyEnvelope, body: await sealedBody(mb, item!.id) });
    expect(opened).toEqual(raw);
    const header = await mailCrypto.openHeader(privateKey, ids, { keyEnvelope: item!.keyEnvelope, header: item!.header });
    expect(header).toMatchObject({ v: 1, direction: "in", subject: "Kitchen remodel — Zürich", from: { name: "Ana Ruiz", address: "ana@example.com" } });
    expect(header.snippet).toBe("Hola, ¿cuánto cuesta?");
  });

  it("recomputes the same keyId S1 computes, and the stored wrap unlocks to the advertised key (G7)", async () => {
    const { mb, publicKey, recovery, enrolled } = await enrolledWithRealKey(realCryptoPorts());
    expect(enrolled.keyId).toBe(publicKey.keyId);
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect(view.keys[0]!.publicKey).toBe(base64urlFromBytes(publicKey.publicKey));
    const wrap = view.wraps[0]!;
    const unlocked = await mailCrypto.unwrapPrivateKey(
      { id: wrap.id, keyId: wrap.keyId, kind: wrap.kind, wrapped: wrap.wrapped },
      { mailboxId: mb.id, secret: recovery.secret }, // pragma: allowlist secret (S1's parameter name)
    );
    expect(await mailCrypto.publicKeyMatches(unlocked, { keyId: view.keys[0]!.keyId, publicKey: bytesFromBase64url(view.keys[0]!.publicKey) })).toBe(true);
  });

  it("stores a message with a few thousand recipients, readable, with the minimal header", async () => {
    const { mb, privateKey } = await enrolledWithRealKey(realCryptoPorts());
    const many = Array.from({ length: 3000 }, (_, i) => `u${i}@example-${"d".repeat(20)}.com`).join(", ");
    const raw = crlf([`To: ${many}`, "Subject: party", "", "you are all invited"]);
    await deliver(mb, raw);
    const [item] = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    const ids = { mailboxId: mb.id, messageId: item!.id };
    expect(await mailCrypto.openHeader(privateKey, ids, item!)).toMatchObject({ subject: "party", to: [] });
    expect(await mailCrypto.openBody(privateKey, ids, { keyEnvelope: item!.keyEnvelope, body: await sealedBody(mb, item!.id) })).toEqual(raw);
  });
});

describe.skipIf(!CRYPTO || !OUTBOUND)("with the real @platform-mail/outbound (S3) and crypto (S1)", () => {
  it("sends real MIME (to a fake SES) and the Sent copy opens to exactly the bytes SES was handed", async () => {
    const ports = { ...realCryptoPorts(), mime: productionPorts(env).mime };
    const { mb, privateKey } = await enrolledWithRealKey(ports);
    valueOf(await mail().setPolicy(await capFor(mb), { displayName: "Operator" }));
    const sent = await mail().send(await capFor(mb), {
      idempotencyKey: "e2e-send",
      to: [{ name: "Ana Ruiz", address: "ana@example.com" }],
      bcc: [{ address: "archive@example.net" }],
      subject: "Your quote — Zürich",
      text: "Hi Ana,\n\nthe quote is attached.",
      attachments: [{ filename: "quote.pdf", mimeType: "application/pdf", content: new TextEncoder().encode("%PDF-1.4 test") }],
    });
    const result = valueOf(sent);
    const handed = (ports as unknown as { mailer: { sent: outbound.RawSendRequest[] } }).mailer.sent[0]!;
    expect(handed.fromAddress).toBe(mb.address);
    expect(handed.recipients.sort()).toEqual(["ana@example.com", "archive@example.net"]);

    const parsed = await PostalMime.parse(handed.raw);
    expect(parsed.from).toMatchObject({ name: "Operator", address: mb.address });
    expect(parsed.subject).toBe("Your quote — Zürich");
    expect(new TextDecoder().decode(handed.raw)).not.toMatch(/^bcc:/im);

    const ids = { mailboxId: mb.id, messageId: result.messageId! };
    const [item] = valueOf(await mail().list(await capFor(mb), { folder: "sent" })).items;
    expect(await mailCrypto.openBody(privateKey, ids, { keyEnvelope: item!.keyEnvelope, body: await sealedBody(mb, item!.id) })).toEqual(handed.raw);
    const header = await mailCrypto.openHeader(privateKey, ids, item!);
    expect(header).toMatchObject({ direction: "out", messageId: `${result.providerMessageId}@email.amazonses.com`, bcc: [{ name: "", address: "archive@example.net" }] });
  });

  it("the production RawMailer is sesRawMailer: SES v2 raw send for the mailbox's configuration set and tenant (fetch never leaves the isolate)", async () => {
    const mb = await provisionMailbox();
    const requests: { url: string; body: Record<string, unknown> }[] = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const request = new Request(input, init);
      requests.push({ url: request.url, body: (await request.json()) as Record<string, unknown> });
      return Response.json({ MessageId: "0100018e-test" });
    }) as typeof fetch;
    try {
      const testEnv = {
        ...env,
        SES_ACCESS_KEY_ID: "AKIATESTNOTAREALKEY0", // pragma: allowlist secret (fake, never leaves the isolate)
        SES_SECRET_ACCESS_KEY: "test-secret-never-sent-anywhere", // pragma: allowlist secret
      };
      await injectPorts(mb.stub, { ...fakePorts(), mime: productionPorts(env).mime, mailer: productionPorts(testEnv).mailer });
      const result = valueOf(
        await mail().send(await capFor(mb), { idempotencyKey: "wiring", to: [{ address: "success@simulator.amazonses.com" }], subject: "s", text: "t" }),
      );
      expect(result.providerMessageId).toBe("0100018e-test");
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(requests).toHaveLength(1);
    expect(requests[0]!.url).toBe("https://email.us-east-1.amazonaws.com/v2/email/outbound-emails");
    expect(requests[0]!.body).toMatchObject({ FromEmailAddress: mb.address, ConfigurationSetName: "send-test-mail", TenantName: "client-test" });
  });
});

describe.skipIf(CRYPTO)("until S1 lands", () => {
  it("the production wiring is live: an arrival fails loudly with NotImplemented, never silently", async ({ task }) => {
    const mb = await provisionMailbox();
    await runInDurableObject(mb.stub, (instance: Mailbox) => {
      instance.ports = productionPorts(env);
    });
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    const err = await expectEmailThrow(
      task,
      {
        reason: "store mode, storing fails (S1's stub cannot make a message id): email() throws so the message is not counted as delivered",
        error: "NotImplemented: @platform-mail/crypto",
        lines: 1,
      },
      worker.email!(email.message, env, createExecutionContext()),
    );
    expect(err.name).toBe("NotImplemented");
    expect(email.rejects).toEqual([]);
  });
});

describe.skipIf(OUTBOUND)("until S3 lands", () => {
  it("the production wiring is live: a send is answered as InternalError, and nothing is marked sent", async () => {
    const mb = await provisionMailbox();
    await injectPorts(mb.stub, { ...fakePorts(), mime: productionPorts(env).mime });
    // buildMime is S3's stub: it throws NotImplemented before anything goes out.
    const answer = await mail().send(await capFor(mb), { idempotencyKey: "stub", to: [{ address: "a@example.com" }], subject: "s", text: "t" });
    expect(answer).toEqual({ ok: false, error: { name: "InternalError", message: "internal error" } });
    const sends = await runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec("SELECT * FROM sends").toArray());
    expect(sends).toEqual([]);
  });
});
