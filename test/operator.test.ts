import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { incomingEmail, sampleMessage } from "./support/email";
import { capFor, directoryRow, provisionMailbox, rejectionOf, type TestMailbox } from "./support/mailbox";

const admin = () => exports.MailAdmin;
const mail = () => exports.MailService;
const DAY = 24 * 60 * 60 * 1000;

async function arrive(mb: TestMailbox): Promise<string> {
  const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  return mb.ports.sealer.sealed.at(-1)!.ids.messageId;
}

describe("M9: Trash empties itself after 30 days", () => {
  it("deletes the row and the R2 object of a message trashed 30 days ago, and nothing younger", async () => {
    const mb = await provisionMailbox();
    const old = await arrive(mb);
    const young = await arrive(mb);
    const kept = await arrive(mb);
    await mail().update(await capFor(mb), old, { folder: "trash" });
    mb.ports.clock.advance(DAY);
    await mail().update(await capFor(mb), young, { folder: "trash" });

    mb.ports.clock.advance(29 * DAY); // old: 30 days in Trash; young: 29
    expect(await mb.stub.purgeExpiredTrash()).toBe(1);

    const ids = await runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec("SELECT id FROM messages").toArray().map((r) => r.id));
    expect(ids.sort()).toEqual([young, kept].sort());
    expect(await env.MAIL.head(`mbx/${mb.id}/msg/${old}`)).toBeNull();
    expect(await env.MAIL.head(`mbx/${mb.id}/msg/${young}`)).not.toBeNull();
    expect((await mail().audit(await capFor(mb), {}))[0]).toMatchObject({ actor: "system:housekeeping", action: "trash-emptied", detail: { count: 1 } });

    mb.ports.clock.advance(DAY);
    expect(await mb.stub.purgeExpiredTrash()).toBe(1);
  });

  it("counts Trash time from the last move into Trash: a message taken out and put back starts again", async () => {
    const mb = await provisionMailbox();
    const id = await arrive(mb);
    await mail().update(await capFor(mb), id, { folder: "trash" });
    mb.ports.clock.advance(20 * DAY);
    await mail().update(await capFor(mb), id, { folder: "inbox" });
    await mail().update(await capFor(mb), id, { folder: "trash" });
    mb.ports.clock.advance(20 * DAY);
    expect(await mb.stub.purgeExpiredTrash()).toBe(0);
  });
});

describe("M10: forwarding is visible and audited (MailAdmin, bound to nothing)", () => {
  it("sets store-and-forward with a target; mailbox() shows it; the audit names who and when", async () => {
    const mb = await provisionMailbox();
    const policy = await admin().setDelivery({ mailboxId: mb.id, operator: "maintainer", delivery: "store-and-forward", forwardTo: "Owner@Gmail.test" });
    expect(policy).toMatchObject({ delivery: "store-and-forward", forwardTo: "owner@gmail.test", updatedBy: "operator:maintainer" });
    const view = await mail().mailbox(await capFor(mb));
    expect(view.policy).toMatchObject({ delivery: "store-and-forward", forwardTo: "owner@gmail.test" });
    const [entry] = await mail().audit(await capFor(mb), {});
    expect(entry).toMatchObject({
      actor: "operator:maintainer",
      action: "delivery-changed",
      at: mb.ports.clock.now().toISOString(),
      detail: { delivery: "store-and-forward", forwardTo: "owner@gmail.test" },
    });
  });

  it("goes back to store, clearing the target, and audits that too", async () => {
    const mb = await provisionMailbox();
    await admin().setDelivery({ mailboxId: mb.id, operator: "maintainer", delivery: "store-and-forward", forwardTo: "owner@gmail.test" });
    await admin().setDelivery({ mailboxId: mb.id, operator: "maintainer", delivery: "store" });
    expect((await mail().mailbox(await capFor(mb))).policy).toMatchObject({ delivery: "store", forwardTo: null });
    expect((await mail().audit(await capFor(mb), {})).map((a) => a.action).slice(0, 2)).toEqual(["delivery-changed", "delivery-changed"]);
  });

  it("refuses store-and-forward without a target, a target for store, and an anonymous operator", async () => {
    const mb = await provisionMailbox();
    for (const input of [
      { mailboxId: mb.id, operator: "maintainer", delivery: "store-and-forward" },
      { mailboxId: mb.id, operator: "maintainer", delivery: "store", forwardTo: "x@y.test" },
      { mailboxId: mb.id, operator: "", delivery: "store" },
      { mailboxId: mb.id, operator: "maintainer", delivery: "forward-only" },
    ]) {
      expect(await rejectionOf(admin().setDelivery(input))).toMatchObject({ name: "InvalidRequest" });
    }
  });

  it("suspends (arrivals are then refused, M2) and resumes, each audited", async () => {
    const mb = await provisionMailbox();
    expect(await admin().suspend({ mailboxId: mb.id, operator: "maintainer" })).toEqual({ status: "suspended" });
    expect((await directoryRow(mb.id))?.status).toBe("suspended");
    const refused = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    await worker.email!(refused.message, env, createExecutionContext());
    expect(refused.rejects).toEqual(["This mailbox is not accepting mail"]);

    expect(await rejectionOf(admin().suspend({ mailboxId: mb.id, operator: "maintainer" }))).toMatchObject({ name: "InvalidRequest" });
    expect(await admin().resume({ mailboxId: mb.id, operator: "maintainer" })).toEqual({ status: "active" });
    expect((await directoryRow(mb.id))?.status).toBe("active");
    const actions = (await mail().audit(await capFor(mb), {})).map((a) => [a.actor, a.action]);
    expect(actions.slice(0, 2)).toEqual([
      ["operator:maintainer", "mailbox-resumed"],
      ["operator:maintainer", "mailbox-suspended"],
    ]);
  });

  it("answers NotFound for an unknown or closed mailbox", async () => {
    const closed = await provisionMailbox({ status: "closed" });
    expect(await rejectionOf(admin().suspend({ mailboxId: closed.id, operator: "maintainer" }))).toMatchObject({ name: "NotFound" });
    expect(await rejectionOf(admin().resume({ mailboxId: "mbx_missing", operator: "maintainer" }))).toMatchObject({ name: "NotFound" });
  });
});
