import { createExecutionContext, createScheduledController, runInDurableObject, waitOnExecutionContext } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FEED_BATCH, FEED_ROUNDS_MAX, pollDeliverabilityFeed } from "../src/deliverability/feed";
import worker from "../src/index";
import { type CapturedConsole, captureConsole } from "./support/console";
import { capFor, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";
import { byteString, directoryHaystacks, mailboxHaystacks, r2Haystacks, search } from "./support/scan";
import { bounceEvent, complaintEvent, deliveryDelayEvent, deliveryEvent, rejectEvent, renderingFailureEvent, snsEnvelope } from "./support/ses-events";
import { type FakeSqs, TEST_QUEUE_URL, fakeSqs } from "./support/sqs";

const mail = () => exports.MailService;
const utf8 = (s: string) => new TextEncoder().encode(s);

/** The Worker's environment with the feed configured; the credential never leaves the isolate (the fake SQS is the fetch). */
const feedEnv = () => ({
  ...env,
  MAIL_EVENTS_QUEUE_URL: TEST_QUEUE_URL,
  SES_ACCESS_KEY_ID: "AKIDEXAMPLE", // pragma: allowlist secret (AWS's example key id)
  SES_SECRET_ACCESS_KEY: "test-secret-never-sent-anywhere", // pragma: allowlist secret
});

function request(over: Record<string, unknown> = {}) {
  return {
    idempotencyKey: `send-${crypto.randomUUID()}`,
    to: [{ name: "Ana Ruiz", address: "ana@example.com" }],
    subject: "Your quote",
    text: "Hi Ana,\n\nthe quote is attached.",
    ...over,
  };
}

const sql = <T = Record<string, unknown>>(mb: TestMailbox, query: string) =>
  runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query).toArray() as T[]);
const suppressionRows = (mb: TestMailbox) => sql(mb, "SELECT recipient_hash, reason, first_at, last_at FROM suppression ORDER BY recipient_hash");
const sendsRows = (mb: TestMailbox) => sql(mb, "SELECT * FROM sends");
const auditRows = (mb: TestMailbox) => sql<{ action: string; detail: string }>(mb, "SELECT action, detail FROM audit ORDER BY id");

async function feed(sqs: FakeSqs) {
  return pollDeliverabilityFeed(feedEnv(), { fetch: sqs.fetch });
}

let captured: CapturedConsole;
beforeEach(() => {
  captured = captureConsole();
});
afterEach(() => {
  captured.restore();
});

const alerts = (kind: string) =>
  captured.lines.filter((l) => l.includes('"event":"operator-alert"') && l.includes(`"kind":"${kind}"`)).map((l) => JSON.parse(l) as Record<string, unknown>);
const feedLines = () => captured.lines.filter((l) => l.includes('"event":"deliverability-feed"')).map((l) => JSON.parse(l) as Record<string, unknown>);

describe("M11: a recipient who bounced permanently or complained is not written to again", () => {
  it("a permanent bounce suppresses: send answers RecipientSuppressed by position, before anything is reserved or sent", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["gone@example.com"], at: "2026-09-29T10:01:00.000Z" }));
    await feed(sqs);
    expect(await suppressionRows(mb)).toEqual([expect.objectContaining({ reason: "bounce", first_at: "2026-09-29T10:01:00.000Z", last_at: "2026-09-29T10:01:00.000Z" })]);

    const req = request({
      idempotencyKey: "k-suppressed",
      to: [{ address: "ana@example.com" }, { address: "Gone@Example.com" }],
      cc: [{ address: "gone@example.com" }],
    });
    expect(await mail().send(await capFor(mb), req)).toEqual({
      ok: false,
      error: {
        name: "RecipientSuppressed",
        message: "a recipient is suppressed after a bounce or complaint",
        suppressed: [
          { field: "to", index: 1, reason: "bounce", since: "2026-09-29T10:01:00.000Z" },
          { field: "cc", index: 0, reason: "bounce", since: "2026-09-29T10:01:00.000Z" },
        ],
      },
    });
    expect(mb.ports.mailer.sent).toEqual([]);
    expect(mb.ports.trace).toEqual([]);
    expect(await sendsRows(mb)).toEqual([]);
    // Nothing was reserved: the same key then sends to a clean recipient, and the rate limit never counted the refusal.
    valueOf(await mail().send(await capFor(mb), request({ idempotencyKey: "k-suppressed" })));
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("a complaint suppresses with reason complaint, in bcc as well", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(complaintEvent({ mailboxId: mb.id, recipients: ["upset@example.org"], at: "2026-09-29T11:00:00.000Z" }));
    await feed(sqs);
    const refusal = refusalOf(await mail().send(await capFor(mb), request({ bcc: [{ address: "upset@example.org" }] })));
    expect(refusal).toMatchObject({ name: "RecipientSuppressed", suppressed: [{ field: "bcc", index: 0, reason: "complaint", since: "2026-09-29T11:00:00.000Z" }] });
  });

  it("a transient or undetermined bounce changes nothing stored, and the recipient can still be written to", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["full@example.com"], bounceType: "Transient" }));
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["odd@example.com"], bounceType: "Undetermined" }));
    const summary = await feed(sqs);
    expect(summary).toMatchObject({ received: 2, bouncesTransient: 2, recorded: 0, deleted: 2 });
    expect(await suppressionRows(mb)).toEqual([]);
    expect(await sql(mb, "SELECT * FROM suppression_key")).toEqual([]);
    valueOf(await mail().send(await capFor(mb), request({ to: [{ address: "full@example.com" }, { address: "odd@example.com" }] })));
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("a second delivery of the same event changes nothing (M12): the rows and the audit are identical", async () => {
    const mb = await provisionMailbox();
    const event = bounceEvent({ mailboxId: mb.id, recipients: ["gone@example.com", "also-gone@example.com"] });
    const sqs = fakeSqs();
    sqs.enqueue(event);
    await feed(sqs);
    const rows = await suppressionRows(mb);
    const audit = await auditRows(mb);
    expect(rows).toHaveLength(2);
    expect(audit.filter((a) => a.action === "recipient-suppressed")).toEqual([{ action: "recipient-suppressed", detail: JSON.stringify({ reason: "bounce", recipients: 2 }) }]);

    sqs.enqueue(event);
    sqs.enqueue(event);
    expect(await feed(sqs)).toMatchObject({ received: 2, recorded: 2 });
    expect(await suppressionRows(mb)).toEqual(rows);
    expect(await auditRows(mb)).toEqual(audit);
  });

  it("a later event moves last_at and keeps first_at; a complaint outranks a bounce; since is the first date", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["gone@example.com"], at: "2026-09-29T10:01:00.000Z" }));
    sqs.enqueue(complaintEvent({ mailboxId: mb.id, recipients: ["gone@example.com"], at: "2026-10-01T09:00:00.000Z" }));
    await feed(sqs);
    expect(await suppressionRows(mb)).toEqual([
      expect.objectContaining({ reason: "complaint", first_at: "2026-09-29T10:01:00.000Z", last_at: "2026-10-01T09:00:00.000Z" }),
    ]);
    expect(refusalOf(await mail().send(await capFor(mb), request({ to: [{ address: "gone@example.com" }] })))).toMatchObject({
      suppressed: [{ field: "to", index: 0, reason: "complaint", since: "2026-09-29T10:01:00.000Z" }],
    });
  });

  it("an entry lapses one year after its last event (the daily housekeeping), and the recipient can be written to again", async () => {
    const mb = await provisionMailbox();
    const at = mb.ports.clock.now().toISOString();
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["gone@example.com"], at }));
    await feed(sqs);
    mb.ports.clock.advance(365 * 24 * 60 * 60 * 1000);
    // Exactly a year old: kept, like every other row at its limit.
    expect(await mb.stub.dailyHousekeeping()).toMatchObject({ suppression: 0 });
    expect(refusalOf(await mail().send(await capFor(mb), request({ to: [{ address: "gone@example.com" }] })))).toMatchObject({ name: "RecipientSuppressed" });
    mb.ports.clock.advance(1);
    expect(await mb.stub.dailyHousekeeping()).toMatchObject({ suppression: 1 });
    expect(await suppressionRows(mb)).toEqual([]);
    valueOf(await mail().send(await capFor(mb), request({ to: [{ address: "gone@example.com" }] })));
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("stores no address in the clear, and logs none (D15, the M1 scan extended to recipients)", async () => {
    const tag = crypto.randomUUID().slice(0, 8);
    const m = {
      bounced: `bounced-${tag}@example.com`,
      complained: `complained-${tag}@example.org`,
      subject: `Zürich-subject-${tag}`,
      sender: `sender-${tag}@example.com`,
    };
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: [m.bounced], subject: m.subject, from: m.sender }));
    sqs.enqueue(complaintEvent({ mailboxId: mb.id, recipients: [m.complained], subject: m.subject, from: m.sender }));
    sqs.enqueue(bounceEvent({ mailboxId: null, recipients: [m.bounced], subject: m.subject, from: m.sender }));
    sqs.enqueue(bounceEvent({ mailboxId: "mbx_00000000000000000000000000", recipients: [m.bounced], subject: m.subject, from: m.sender }));
    sqs.enqueue(`{"eventType":"Bounce","mail":{"commonHeaders":{"subject":"${m.subject}"}},"bounce":{"bounceType":"Permanent"}} trailing ${m.bounced}`);
    await feed(sqs);
    expect(await suppressionRows(mb)).toHaveLength(2);
    expect(refusalOf(await mail().send(await capFor(mb), request({ to: [{ address: m.bounced }], cc: [{ address: m.complained }] })))).toMatchObject({
      name: "RecipientSuppressed",
    });
    valueOf(await mail().audit(await capFor(mb), {}));

    const haystacks = [
      ...(await mailboxHaystacks(mb.stub)),
      ...(await directoryHaystacks()),
      ...(await r2Haystacks()),
      ...captured.lines.map((text, i) => ({ where: `console line ${i}`, text: byteString(utf8(text)) })),
    ];
    expect(haystacks.some((h) => h.where.startsWith("mailbox sqlite suppression"))).toBe(true);
    expect(haystacks.some((h) => h.where.startsWith("console"))).toBe(true);
    expect(search(haystacks, m)).toEqual([]);
  });

  it("every send carries the mailbox tag SES echoes back in its events (G22)", async () => {
    const mb = await provisionMailbox();
    valueOf(await mail().send(await capFor(mb), request()));
    expect(mb.ports.mailer.sent[0]!.tags).toEqual([{ name: "mailbox", value: mb.id }]);
  });
});

describe("the feed: SQS → parse → route by the mailbox tag → Mailbox → delete", () => {
  it("routes by Mail's own tag alone, never by the addresses in the event", async () => {
    const a = await provisionMailbox();
    const b = await provisionMailbox();
    const sqs = fakeSqs();
    // The tag names A; the mail object's addresses are B's. A gets the suppression.
    sqs.enqueue(bounceEvent({ mailboxId: a.id, recipients: ["gone@example.com"], from: b.address }));
    sqs.enqueue(complaintEvent({ mailboxId: b.id, recipients: ["upset@example.com"], from: a.address }));
    expect(await feed(sqs)).toMatchObject({ received: 2, bouncesPermanent: 1, complaints: 1, recorded: 2, deleted: 2, notDeleted: 0 });
    expect(await suppressionRows(a)).toEqual([expect.objectContaining({ reason: "bounce" })]);
    expect(await suppressionRows(b)).toEqual([expect.objectContaining({ reason: "complaint" })]);
    expect(sqs.messages).toEqual([]);
  });

  it("an event without the tag, or naming a mailbox that does not exist or is closed, is deleted and raised as an operator alert", async () => {
    const closed = await provisionMailbox({ status: "closed" });
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: null }));
    sqs.enqueue(bounceEvent({ mailboxId: "mbx_00000000000000000000000000" }));
    sqs.enqueue(bounceEvent({ mailboxId: "not-a-mailbox-id" }));
    sqs.enqueue(complaintEvent({ mailboxId: closed.id }));
    expect(await feed(sqs)).toMatchObject({ received: 4, unroutable: 4, recorded: 0, deleted: 4 });
    expect(sqs.messages).toEqual([]);
    expect(alerts("delivery-event-unroutable").map((a) => a.reason)).toEqual(["no-mailbox-tag", "unknown-mailbox", "no-mailbox-tag", "unknown-mailbox"]);
    expect(await suppressionRows(closed)).toEqual([]);
  });

  it("a record that is not an SES event is deleted and raised, and nothing from it is logged", async () => {
    const sqs = fakeSqs();
    sqs.enqueue("not json at all");
    sqs.enqueue({ hello: "world" });
    sqs.enqueue({ eventType: "Bounce", mail: { tags: { mailbox: ["mbx_00000000000000000000000000"] } }, bounce: { bounceType: "Permanent", bouncedRecipients: [] } });
    expect(await feed(sqs)).toMatchObject({ received: 3, unreadable: 3, deleted: 3 });
    expect(alerts("delivery-event-unreadable").map((a) => a.reason)).toEqual(["not-json", "not-an-event", "no-recipients"]);
    expect(captured.lines.join("\n")).not.toContain("world");
  });

  it("a transient bounce, a delay, a reject, a rendering failure and an unsubscribed kind are counted and deleted; nothing is stored", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, bounceType: "Transient" }));
    sqs.enqueue(deliveryDelayEvent({ mailboxId: mb.id }));
    sqs.enqueue(rejectEvent({ mailboxId: mb.id }));
    sqs.enqueue(renderingFailureEvent({ mailboxId: mb.id }));
    sqs.enqueue(deliveryEvent({ mailboxId: mb.id }));
    const summary = await feed(sqs);
    expect(summary).toMatchObject({ received: 5, bouncesTransient: 1, delays: 1, rejects: 1, renderingFailures: 1, other: 1, recorded: 0, deleted: 5 });
    expect(await suppressionRows(mb)).toEqual([]);
    expect(feedLines().at(-1)).toMatchObject({ received: 5, bouncesTransient: 1, delays: 1, rejects: 1, renderingFailures: 1, other: 1, deleted: 5 });
    expect(sqs.messages).toEqual([]);
  });

  it("unwraps the SNS envelope a subscription without raw delivery would add", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(snsEnvelope(bounceEvent({ mailboxId: mb.id, recipients: ["gone@example.com"] })));
    expect(await feed(sqs)).toMatchObject({ recorded: 1 });
    expect(await suppressionRows(mb)).toHaveLength(1);
  });

  it("a batch with a failed delete is retried once, and one that still fails is left for SQS to deliver again, not lost", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    const retried = sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["one@example.com"] }));
    const stuck = sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["two@example.com"] }));
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["three@example.com"] }));
    sqs.failDeleteOnce.add(retried.messageId);
    sqs.failDeleteAlways.add(stuck.messageId);

    expect(await feed(sqs)).toMatchObject({ received: 3, recorded: 3, deleted: 2, notDeleted: 1 });
    const deletes = sqs.deleted();
    expect(deletes).toHaveLength(2);
    expect((deletes[0]!.body.Entries as unknown[]).length).toBe(3);
    expect((deletes[1]!.body.Entries as { Id: string }[]).map((e) => e.Id).sort()).toEqual([retried.messageId, stuck.messageId].sort());
    expect(sqs.messages.map((m) => m.messageId)).toEqual([stuck.messageId]);
    expect(alerts("delivery-events-not-deleted")).toEqual([expect.objectContaining({ count: 1 })]);

    // Delivered again once its visibility timeout passes: recording is idempotent, so nothing changes.
    const rows = await suppressionRows(mb);
    sqs.failDeleteAlways.clear();
    sqs.releaseInFlight();
    expect(await feed(sqs)).toMatchObject({ received: 1, recorded: 1, deleted: 1 });
    expect(await suppressionRows(mb)).toEqual(rows);
    expect(sqs.messages).toEqual([]);
  });

  it("an event the Mailbox could not record is not deleted: SQS delivers it again", async () => {
    const mb = await provisionMailbox();
    mb.ports.clock.now = () => {
      throw new Error("clock broke");
    };
    const sqs = fakeSqs();
    sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: ["gone@example.com"] }));
    expect(await feed(sqs)).toMatchObject({ received: 1, notRecorded: 1, deleted: 0 });
    expect(sqs.deleted()).toEqual([]);
    expect(sqs.messages).toEqual([expect.objectContaining({ inFlight: true })]);
    expect(alerts("delivery-event-not-recorded")).toEqual([expect.objectContaining({ mailbox: mb.id, result: "InternalError" })]);
  });

  it("drains the queue ten at a time until a receive comes back empty, and stops after the round limit", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    for (let i = 0; i < 25; i++) sqs.enqueue(bounceEvent({ mailboxId: mb.id, recipients: [`gone-${i}@example.com`] }));
    expect(await feed(sqs)).toMatchObject({ rounds: 4, received: 25, recorded: 25, deleted: 25 });
    expect(sqs.received().map((r) => r.body.MaxNumberOfMessages)).toEqual([FEED_BATCH, FEED_BATCH, FEED_BATCH, FEED_BATCH]);
    expect(await suppressionRows(mb)).toHaveLength(25);

    for (let i = 0; i < FEED_ROUNDS_MAX * FEED_BATCH + 3; i++) sqs.enqueue(deliveryDelayEvent({ mailboxId: mb.id }));
    expect(await feed(sqs)).toMatchObject({ rounds: FEED_ROUNDS_MAX, received: FEED_ROUNDS_MAX * FEED_BATCH });
    expect(sqs.messages).toHaveLength(3);
  });

  it("a failed receive is raised and thrown, with the status and code only", async () => {
    const sqs = fakeSqs();
    sqs.answerWith = () =>
      new Response(JSON.stringify({ __type: "com.amazonaws.sqs#QueueDoesNotExist", message: "The specified queue does not exist for this wsdl version." }), {
        status: 400,
        headers: { "content-type": "application/x-amz-json-1.0", "x-amzn-query-error": "AWS.SimpleQueueService.NonExistentQueue;Sender" },
      });
    await expect(feed(sqs)).rejects.toThrow("the deliverability feed could not receive events");
    expect(alerts("events-feed-receive-failed")).toEqual([expect.objectContaining({ status: 400, code: "QueueDoesNotExist", retryable: false })]);
    expect(captured.lines.join("\n")).not.toContain("wsdl");
  });
});

describe("scheduled(): the cron every five minutes runs the feed", () => {
  it("without the queue secret it raises an operator alert and touches nothing", async () => {
    const realFetch = globalThis.fetch;
    let fetched = 0;
    globalThis.fetch = (async () => {
      fetched += 1;
      return new Response("", { status: 500 });
    }) as typeof fetch;
    try {
      const ctx = createExecutionContext();
      await worker.scheduled!(createScheduledController({ cron: "*/5 * * * *" }), env, ctx);
      await waitOnExecutionContext(ctx);
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(fetched).toBe(0);
    expect(alerts("events-feed-not-configured")).toHaveLength(1);
  });

  it("with the queue configured it polls, records and deletes (fetch never leaves the isolate)", async () => {
    const mb = await provisionMailbox();
    const sqs = fakeSqs();
    sqs.enqueue(complaintEvent({ mailboxId: mb.id, recipients: ["upset@example.com"] }));
    const realFetch = globalThis.fetch;
    globalThis.fetch = sqs.fetch;
    try {
      const ctx = createExecutionContext();
      await worker.scheduled!(createScheduledController({ cron: "*/5 * * * *" }), feedEnv(), ctx);
      await waitOnExecutionContext(ctx);
    } finally {
      globalThis.fetch = realFetch;
    }
    expect(sqs.received().length).toBeGreaterThanOrEqual(1);
    expect(sqs.messages).toEqual([]);
    expect(await suppressionRows(mb)).toHaveLength(1);
    expect(feedLines().at(-1)).toMatchObject({ cron: "*/5 * * * *", recorded: 1, deleted: 1 });
  });
});
