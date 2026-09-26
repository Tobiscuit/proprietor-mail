import { createExecutionContext, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Directory } from "../src/directory/directory";
import worker from "../src/index";
import type { Mailbox } from "../src/mailbox/mailbox";
import { type CapturedConsole, captureConsole } from "./support/console";
import { crlf, incomingEmail, sampleMessage } from "./support/email";
import { provisionMailbox, rejectionOf, type TestMailbox } from "./support/mailbox";

// plan.md §5, "Arrival, step by step, and what each failure does": one test per row.

async function deliver(message: ForwardableEmailMessage): Promise<void> {
  const ctx = createExecutionContext();
  await worker.email!(message, env, ctx);
  await waitOnExecutionContext(ctx);
}

async function stored(mb: TestMailbox) {
  const rows = await runInDurableObject(mb.stub, (_i, state) =>
    state.storage.sql.exec("SELECT id, folder_id, direction, size, key_id, seen, body_key FROM messages").toArray(),
  );
  const objects = (await env.MAIL.list({ prefix: `mbx/${mb.id}/` })).objects.map((o) => o.key);
  return { rows, objects };
}

async function setDelivery(mb: TestMailbox, delivery: "store" | "store-and-forward", forwardTo?: string) {
  const entry = (await new Directory(env.DIRECTORY).byId(mb.id))!;
  await mb.stub.setDelivery(entry, "operator:test", forwardTo === undefined ? { delivery } : { delivery, forwardTo });
}

/** Makes the live Mailbox's R2 binding fail on put, the way an R2 outage would. */
async function breakR2(mb: TestMailbox) {
  await runInDurableObject(mb.stub, (instance: Mailbox) => {
    // `env` is protected on DurableObject; the test reaches in on purpose.
    const live = instance as unknown as { env: typeof env };
    const failing = Object.create(live.env.MAIL) as R2Bucket;
    failing.put = async () => {
      throw new Error("R2 is unavailable");
    };
    live.env = { ...live.env, MAIL: failing };
  });
}

let captured: CapturedConsole;
let errors: string[] = [];
beforeEach(() => {
  captured = captureConsole();
  errors = captured.lines;
});
afterEach(() => captured.restore());

describe("arrival: the plan.md §5 table", () => {
  it("row 1: no Directory row for the envelope recipient → setReject('No such mailbox')", async () => {
    const email = incomingEmail(sampleMessage({ to: "nobody@mail.test" }), { to: "nobody@mail.test" });
    await deliver(email.message);
    expect(email.rejects).toEqual(["No such mailbox"]);
  });

  it.each(["provisioned", "suspended", "closed"] as const)(
    "row 2 (M2): a %s mailbox → setReject('This mailbox is not accepting mail') and stores nothing",
    async (status) => {
      const mb = await provisionMailbox({ status });
      const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address }, mb.ports.trace);
      await deliver(email.message);
      expect(email.rejects).toEqual(["This mailbox is not accepting mail"]);
      expect(await stored(mb)).toEqual({ rows: [], objects: [] });
      // Rejected before the message was even read.
      expect(mb.ports.trace).toEqual(["reject"]);
    },
  );

  it("row 3: rawSize above 25 MiB → setReject('Message too large'), before reading a byte", async () => {
    const mb = await provisionMailbox();
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address, rawSize: 25 * 1024 * 1024 + 1 }, mb.ports.trace);
    await deliver(email.message);
    expect(email.rejects).toEqual(["Message too large"]);
    expect(mb.ports.trace).toEqual(["reject"]);
    expect(await stored(mb)).toEqual({ rows: [], objects: [] });
  });

  it("row 4: headers that do not parse → stored anyway, subject and snippet empty, raw bytes exact", async () => {
    const mb = await provisionMailbox();
    const raw = crlf([`X-Filler: ${"a".repeat(300 * 1024)}`, `To: ${mb.address}`, "Subject: lost to the parser", "", "body"]);
    const email = incomingEmail(raw, { to: mb.address, from: "sender@x.test" });
    await deliver(email.message);
    expect(email.rejects).toEqual([]);
    const sealed = mb.ports.sealer.sealed[0]!;
    expect(sealed.header).toMatchObject({ direction: "in", envelopeFrom: "sender@x.test", subject: "", snippet: "", from: null });
    expect(sealed.raw).toEqual(raw);
    expect((await stored(mb)).rows).toHaveLength(1);
  });

  it("row 5: store mode, R2 fails → throws, and nothing is stored", async () => {
    const mb = await provisionMailbox();
    await breakR2(mb);
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    const err = await rejectionOf(deliver(email.message));
    expect(err.message).toMatch(/R2 is unavailable/);
    expect(await stored(mb)).toEqual({ rows: [], objects: [] });
  });

  it("row 5: store mode, the SQLite insert fails → throws, and the R2 object just written is deleted", async () => {
    const mb = await provisionMailbox();
    // A sealed message the table refuses (key_envelope NOT NULL).
    const realSeal = mb.ports.sealer.seal.bind(mb.ports.sealer);
    mb.ports.sealer.seal = async (...args) => ({ ...(await realSeal(...args)), keyEnvelope: null as unknown as string });
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    const err = await rejectionOf(deliver(email.message));
    expect(err.message).toMatch(/NOT NULL/);
    expect(await stored(mb)).toEqual({ rows: [], objects: [] });
  });

  it("row 6: store-and-forward, the forward fails → throws before storing anything", async () => {
    const mb = await provisionMailbox();
    await setDelivery(mb, "store-and-forward", "owner@gmail.test");
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address, forwardFails: true }, mb.ports.trace);
    await rejectionOf(deliver(email.message));
    expect(mb.ports.trace).toEqual(["forward"]);
    expect(await stored(mb)).toEqual({ rows: [], objects: [] });
  });

  it("row 7: store-and-forward, the forward succeeded and storing fails → no throw, audited, operator alerted", async () => {
    const mb = await provisionMailbox();
    await setDelivery(mb, "store-and-forward", "owner@gmail.test");
    await breakR2(mb);
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address }, mb.ports.trace);
    await deliver(email.message); // resolves: never throw after a successful forward
    expect(email.forwards).toEqual([{ rcptTo: "owner@gmail.test" }]);
    expect(email.rejects).toEqual([]);
    expect(await stored(mb)).toEqual({ rows: [], objects: [] });
    const audit = await runInDurableObject(mb.stub, (_i, state) =>
      state.storage.sql.exec("SELECT actor, action FROM audit WHERE action = 'store-failed-after-forward'").toArray(),
    );
    expect(audit).toEqual([{ actor: "system:email", action: "store-failed-after-forward" }]);
    expect(errors.some((line) => line.includes('"operator-alert"') && line.includes("store-failed-after-forward"))).toBe(true);
  });

  it("store-and-forward, all well: forwards FIRST, then reads, seals and stores", async () => {
    const mb = await provisionMailbox();
    await setDelivery(mb, "store-and-forward", "Owner@Gmail.test");
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address }, mb.ports.trace);
    await deliver(email.message);
    expect(mb.ports.trace).toEqual(["forward", "read", "seal"]);
    expect(email.forwards).toEqual([{ rcptTo: "owner@gmail.test" }]);
    expect((await stored(mb)).rows).toHaveLength(1);
  });
});

describe("arrival: what a stored message is", () => {
  it("is sealed to the mailbox key, written to R2 at mbx/<mailbox>/msg/<message>, and indexed in Inbox", async () => {
    const mb = await provisionMailbox();
    const raw = sampleMessage({ to: mb.address, subject: "Quote please" });
    const email = incomingEmail(raw, { to: mb.address, from: "bounce@example.com" });
    await deliver(email.message);
    expect(email.rejects).toEqual([]);

    const sealed = mb.ports.sealer.sealed[0]!;
    expect(sealed.pub).toEqual({ keyId: mb.key!.keyId, publicKey: mb.key!.publicKey });
    expect(sealed.raw).toEqual(raw);
    expect(sealed.header).toMatchObject({ direction: "in", envelopeFrom: "bounce@example.com", subject: "Quote please" });

    const { rows, objects } = await stored(mb);
    expect(rows).toEqual([
      {
        id: sealed.ids.messageId,
        folder_id: "inbox",
        direction: "in",
        size: raw.byteLength,
        key_id: mb.key!.keyId,
        seen: 0,
        body_key: `mbx/${mb.id}/msg/${sealed.ids.messageId}`,
      },
    ]);
    expect(objects).toEqual([`mbx/${mb.id}/msg/${sealed.ids.messageId}`]);
    expect(sealed.ids).toEqual({ mailboxId: mb.id, messageId: sealed.ids.messageId });
  });

  it("tells the business's dashboard the new unread count, and only the count", async () => {
    const mb = await provisionMailbox();
    for (let i = 0; i < 2; i++) {
      await deliver(incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address }).message);
    }
    expect(mb.ports.signal.events).toEqual([
      { tenantId: mb.tenantId, mailboxId: mb.id, unread: 1 },
      { tenantId: mb.tenantId, mailboxId: mb.id, unread: 2 },
    ]);
  });

  it("does not fail an arrival because the new-mail signal failed", async () => {
    const mb = await provisionMailbox();
    mb.ports.signal.failWith = new Error("dashboard unreachable");
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    await deliver(email.message);
    expect((await stored(mb)).rows).toHaveLength(1);
  });

  it("finds the mailbox whatever the case of the envelope recipient", async () => {
    const mb = await provisionMailbox();
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address.toUpperCase() });
    await deliver(email.message);
    expect(email.rejects).toEqual([]);
    expect((await stored(mb)).rows).toHaveLength(1);
  });

  it("never loses a message to the header ceiling: a few thousand To: recipients are stored", async () => {
    const mb = await provisionMailbox();
    const many = Array.from({ length: 3000 }, (_, i) => `u${i}@example-${"d".repeat(20)}.com`).join(", ");
    const raw = crlf([`To: ${many}`, "Subject: party", "", "you are all invited"]);
    const email = incomingEmail(raw, { to: mb.address });
    await deliver(email.message);
    expect(email.rejects).toEqual([]);
    const sealed = mb.ports.sealer.sealed[0]!;
    expect(sealed.header).toMatchObject({ to: [], subject: "party", snippet: "" });
    expect(sealed.raw).toEqual(raw);
    expect((await stored(mb)).rows).toHaveLength(1);
  });

  it("retries once with the minimal header when sealMessage throws RangeError (S1: header still over 64 KiB)", async () => {
    const mb = await provisionMailbox();
    const realSeal = mb.ports.sealer.seal.bind(mb.ports.sealer);
    const seen: unknown[] = [];
    mb.ports.sealer.seal = async (pub, ids, header, raw) => {
      seen.push(header);
      if (seen.length === 1) throw new RangeError("the header is larger than 64 KiB");
      return realSeal(pub, ids, header, raw);
    };
    const email = incomingEmail(sampleMessage({ to: mb.address, subject: "Quote" }), { to: mb.address });
    await deliver(email.message);
    expect(seen).toHaveLength(2);
    expect(seen[1]).toMatchObject({ subject: "Quote", to: [], snippet: "", attachments: [] });
    expect((await stored(mb)).rows).toHaveLength(1);
  });

  it("M2: an active mailbox without a key refuses mail too (no key, no mail)", async () => {
    const mb = await provisionMailbox({ status: "active", enroll: false });
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    await deliver(email.message);
    expect(email.rejects).toEqual(["This mailbox is not accepting mail"]);
    expect(await stored(mb)).toEqual({ rows: [], objects: [] });
  });
});
