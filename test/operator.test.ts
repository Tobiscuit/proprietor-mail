import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { incomingEmail, sampleMessage } from "./support/email";
import { capFor, directoryRow, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

const admin = () => exports.MailAdmin;
const mail = () => exports.MailService;
const DAY = 24 * 60 * 60 * 1000;

async function arrive(mb: TestMailbox): Promise<string> {
  const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  return mb.ports.sealer.sealed.at(-1)!.ids.messageId;
}

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

function sendRequest(idempotencyKey: string) {
  return { idempotencyKey, to: [{ address: "ana@example.com" }], subject: "s", text: "t" };
}

describe("M9: Trash empties itself after 30 days (the daily housekeeping)", () => {
  it("deletes the row and the R2 object of a message trashed 30 days ago, and nothing younger", async () => {
    const mb = await provisionMailbox();
    const old = await arrive(mb);
    const young = await arrive(mb);
    const kept = await arrive(mb);
    valueOf(await mail().update(await capFor(mb), old, { folder: "trash" }));
    mb.ports.clock.advance(DAY);
    valueOf(await mail().update(await capFor(mb), young, { folder: "trash" }));

    mb.ports.clock.advance(29 * DAY); // old: 30 days in Trash; young: 29
    expect(await mb.stub.dailyHousekeeping()).toMatchObject({ trash: 1 });

    const ids = await runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec("SELECT id FROM messages").toArray().map((r) => r.id));
    expect(ids.sort()).toEqual([young, kept].sort());
    expect(await env.MAIL.head(`mbx/${mb.id}/msg/${old}`)).toBeNull();
    expect(await env.MAIL.head(`mbx/${mb.id}/msg/${young}`)).not.toBeNull();
    expect(valueOf(await mail().audit(await capFor(mb), {}))[0]).toMatchObject({ actor: "system:housekeeping", action: "trash-emptied", detail: { count: 1 } });

    mb.ports.clock.advance(DAY);
    expect(await mb.stub.dailyHousekeeping()).toMatchObject({ trash: 1 });
  });

  it("counts Trash time from the last move into Trash: a message taken out and put back starts again", async () => {
    const mb = await provisionMailbox();
    const id = await arrive(mb);
    valueOf(await mail().update(await capFor(mb), id, { folder: "trash" }));
    mb.ports.clock.advance(20 * DAY);
    valueOf(await mail().update(await capFor(mb), id, { folder: "inbox" }));
    valueOf(await mail().update(await capFor(mb), id, { folder: "trash" }));
    mb.ports.clock.advance(20 * DAY);
    expect(await mb.stub.dailyHousekeeping()).toMatchObject({ trash: 0 });
  });
});

describe("S2k: the same daily housekeeping prunes sends after 30 days and the audit after a year", () => {
  it("deletes sends rows older than 30 days and keeps one exactly 30 days old", async () => {
    const mb = await provisionMailbox();
    valueOf(await mail().send(await capFor(mb), sendRequest("older")));
    mb.ports.clock.advance(1);
    valueOf(await mail().send(await capFor(mb), sendRequest("at-the-limit")));

    mb.ports.clock.advance(30 * DAY); // "older" is 30 days and 1 ms old; "at-the-limit" exactly 30 days
    expect(await mb.stub.dailyHousekeeping()).toEqual({ trash: 0, sends: 1, audit: 0 });
    expect(await sql(mb, "SELECT idempotency_key FROM sends")).toEqual([{ idempotency_key: "at-the-limit" }]);

    mb.ports.clock.advance(1);
    expect(await mb.stub.dailyHousekeeping()).toEqual({ trash: 0, sends: 1, audit: 0 });
    expect(await sql(mb, "SELECT idempotency_key FROM sends")).toEqual([]);
  });

  it("keeps idempotency and the rate limit whole inside the window: a key repeated at 30 days still sends once", async () => {
    const mb = await provisionMailbox();
    const first = valueOf(await mail().send(await capFor(mb), sendRequest("repeated")));
    mb.ports.clock.advance(30 * DAY);
    await mb.stub.dailyHousekeeping();
    expect(valueOf(await mail().send(await capFor(mb), sendRequest("repeated")))).toEqual(first);
    expect(mb.ports.mailer.sent).toHaveLength(1);
  });

  it("deletes audit rows older than 365 days and keeps one exactly 365 days old", async () => {
    const mb = await provisionMailbox(); // mailbox-initialized, key-enrolled: now
    mb.ports.clock.advance(1);
    valueOf(await mail().setPolicy(await capFor(mb), { displayName: "At the limit" }));
    const before = await sql<{ action: string }>(mb, "SELECT action FROM audit ORDER BY id");
    expect(before.map((r) => r.action)).toEqual(["mailbox-initialized", "key-enrolled", "policy-changed"]);

    mb.ports.clock.advance(365 * DAY); // the first two are 365 days and 1 ms old; policy-changed exactly 365 days
    expect(await mb.stub.dailyHousekeeping()).toEqual({ trash: 0, sends: 0, audit: 2 });
    expect((await sql<{ action: string }>(mb, "SELECT action FROM audit ORDER BY id")).map((r) => r.action)).toEqual(["policy-changed"]);

    mb.ports.clock.advance(1);
    expect(await mb.stub.dailyHousekeeping()).toEqual({ trash: 0, sends: 0, audit: 1 });
    expect(await sql(mb, "SELECT action FROM audit")).toEqual([]);
  });

  it("never prunes the audit row of the Trash purge it just wrote", async () => {
    const mb = await provisionMailbox();
    const id = await arrive(mb);
    valueOf(await mail().update(await capFor(mb), id, { folder: "trash" }));
    mb.ports.clock.advance(400 * DAY);
    expect(await mb.stub.dailyHousekeeping()).toMatchObject({ trash: 1 });
    expect((await sql<{ action: string }>(mb, "SELECT action FROM audit")).map((r) => r.action)).toEqual(["trash-emptied"]);
  });
});

describe("M10: forwarding is visible and audited (MailAdmin, bound to nothing)", () => {
  it("sets store-and-forward with a target; mailbox() shows it; the audit names who and when", async () => {
    const mb = await provisionMailbox();
    const policy = valueOf(await admin().setDelivery({ mailboxId: mb.id, operator: "maintainer", delivery: "store-and-forward", forwardTo: "Owner@Gmail.test" }));
    expect(policy).toMatchObject({ delivery: "store-and-forward", forwardTo: "owner@gmail.test", updatedBy: "operator:maintainer" });
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect(view.policy).toMatchObject({ delivery: "store-and-forward", forwardTo: "owner@gmail.test" });
    const [entry] = valueOf(await mail().audit(await capFor(mb), {}));
    expect(entry).toMatchObject({
      actor: "operator:maintainer",
      action: "delivery-changed",
      at: mb.ports.clock.now().toISOString(),
      detail: { delivery: "store-and-forward", forwardTo: "owner@gmail.test" },
    });
  });

  it("goes back to store, clearing the target, and audits that too", async () => {
    const mb = await provisionMailbox();
    valueOf(await admin().setDelivery({ mailboxId: mb.id, operator: "maintainer", delivery: "store-and-forward", forwardTo: "owner@gmail.test" }));
    valueOf(await admin().setDelivery({ mailboxId: mb.id, operator: "maintainer", delivery: "store" }));
    expect(valueOf(await mail().mailbox(await capFor(mb))).policy).toMatchObject({ delivery: "store", forwardTo: null });
    expect(valueOf(await mail().audit(await capFor(mb), {})).map((a) => a.action).slice(0, 2)).toEqual(["delivery-changed", "delivery-changed"]);
  });

  it("refuses store-and-forward without a target, a target for store, and an anonymous operator", async () => {
    const mb = await provisionMailbox();
    for (const input of [
      { mailboxId: mb.id, operator: "maintainer", delivery: "store-and-forward" },
      { mailboxId: mb.id, operator: "maintainer", delivery: "store", forwardTo: "x@y.test" },
      { mailboxId: mb.id, operator: "", delivery: "store" },
      { mailboxId: mb.id, operator: "maintainer", delivery: "forward-only" },
    ]) {
      expect(refusalOf(await admin().setDelivery(input))).toMatchObject({ name: "InvalidRequest" });
    }
  });

  it("suspends (arrivals are then refused, M2) and resumes, each audited", async () => {
    const mb = await provisionMailbox();
    expect(await admin().suspend({ mailboxId: mb.id, operator: "maintainer" })).toEqual({ ok: true, value: { status: "suspended" } });
    expect((await directoryRow(mb.id))?.status).toBe("suspended");
    const refused = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    await worker.email!(refused.message, env, createExecutionContext());
    expect(refused.rejects).toEqual(["This mailbox is not accepting mail"]);

    expect(await admin().suspend({ mailboxId: mb.id, operator: "maintainer" })).toEqual({
      ok: false,
      error: { name: "InvalidRequest", message: "invalid request: only an active mailbox can be suspended" },
    });
    expect(await admin().resume({ mailboxId: mb.id, operator: "maintainer" })).toEqual({ ok: true, value: { status: "active" } });
    expect((await directoryRow(mb.id))?.status).toBe("active");
    const actions = valueOf(await mail().audit(await capFor(mb), {})).map((a) => [a.actor, a.action]);
    expect(actions.slice(0, 2)).toEqual([
      ["operator:maintainer", "mailbox-resumed"],
      ["operator:maintainer", "mailbox-suspended"],
    ]);
  });

  it("answers NotFound for an unknown or closed mailbox", async () => {
    const closed = await provisionMailbox({ status: "closed" });
    const notFound = { ok: false, error: { name: "NotFound", message: "not found" } };
    expect(await admin().suspend({ mailboxId: closed.id, operator: "maintainer" })).toEqual(notFound);
    expect(await admin().resume({ mailboxId: "mbx_missing", operator: "maintainer" })).toEqual(notFound);
  });
});
