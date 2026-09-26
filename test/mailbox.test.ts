import { runInDurableObject } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import type { Mailbox } from "../src/mailbox/mailbox";
import { callContext, provisionMailbox } from "./support/mailbox";
import { valueOf } from "./support/results";

const NOT_FOUND = { ok: false, error: { name: "NotFound", message: "not found" } };

async function sql<T = Record<string, unknown>>(mb: { stub: DurableObjectStub<Mailbox> }, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

describe("the Mailbox Agent: schema, identity, folders, policy, audit (tasks.md S2d)", () => {
  it("has the plan's tables", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const tables = (await sql<{ name: string }>(mb, "SELECT name FROM sqlite_master WHERE type = 'table'")).map((t) => t.name);
    for (const t of ["identity", "keys", "key_wraps", "folders", "messages", "drafts", "sends", "policy", "audit"]) {
      expect(tables).toContain(t);
    }
  });

  it("seeds the six system folders (M8)", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    expect(await sql(mb, "SELECT id, name, system FROM folders ORDER BY rowid")).toEqual([
      { id: "inbox", name: "Inbox", system: 1 },
      { id: "sent", name: "Sent", system: 1 },
      { id: "drafts", name: "Drafts", system: 1 },
      { id: "archive", name: "Archive", system: 1 },
      { id: "trash", name: "Trash", system: 1 },
      { id: "spam", name: "Spam", system: 1 },
    ]);
  });

  it("M8: a system folder cannot be renamed or deleted, even by SQL", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    await expect(sql(mb, "UPDATE folders SET name = 'Junk' WHERE id = 'spam'")).rejects.toThrow(/system folders are fixed/);
    await expect(sql(mb, "DELETE FROM folders WHERE id = 'trash'")).rejects.toThrow(/system folders are fixed/);
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM folders")).toEqual([{ n: 6 }]);
  });

  it("copies its identity from the Directory on first contact", async () => {
    const mb = await provisionMailbox({ status: "provisioned", enroll: false });
    expect(await sql(mb, "SELECT * FROM identity")).toEqual([]);
    valueOf(await mb.stub.describe(callContext(mb, { status: "provisioned" })));
    expect(await sql(mb, "SELECT mailbox_id, tenant_id, address, display_name FROM identity")).toEqual([
      { mailbox_id: mb.id, tenant_id: mb.tenantId, address: mb.address, display_name: "" },
    ]);
  });

  it("refuses to be re-initialized with a different tenant or address, answering NotFound as a value", async () => {
    const mb = await provisionMailbox({ status: "active" });
    const moved = callContext(mb);
    moved.mailbox.tenantId = "tnt_somebody_else";
    expect(await mb.stub.describe(moved)).toEqual(NOT_FOUND);
    const renamed = callContext(mb);
    renamed.mailbox.address = "other@mail.test";
    expect(await mb.stub.describe(renamed)).toEqual(NOT_FOUND);
    expect(await sql(mb, "SELECT tenant_id, address FROM identity")).toEqual([{ tenant_id: mb.tenantId, address: mb.address }]);
  });

  it("refuses a call meant for another mailbox", async () => {
    const a = await provisionMailbox({ status: "active" });
    const b = await provisionMailbox({ status: "active" });
    expect(await a.stub.describe(callContext(b))).toEqual(NOT_FOUND);
  });

  it("starts with the safe policy: owners only, assistant off, store only", async () => {
    const mb = await provisionMailbox({ status: "provisioned", enroll: false });
    const view = valueOf(await mb.stub.describe(callContext(mb, { status: "provisioned" })));
    expect(view.policy).toMatchObject({
      openRoles: ["owner"],
      sendRoles: ["owner"],
      assistant: "off",
      delivery: "store",
      forwardTo: null,
    });
  });

  it("audits its initialization with who and when", async () => {
    const mb = await provisionMailbox({ status: "provisioned", enroll: false });
    valueOf(await mb.stub.describe(callContext(mb, { status: "provisioned", accountId: "acc_first" })));
    const rows = await sql<{ at: string; actor: string; action: string }>(mb, "SELECT at, actor, action FROM audit ORDER BY id");
    expect(rows[0]).toMatchObject({ actor: "acc_first", action: "mailbox-initialized" });
    expect(rows[0]?.at).toBe(mb.ports.clock.now().toISOString());
  });

  it("schedules the daily housekeeping (the Trash purge, M9, and pruning, S2k) on first contact", async () => {
    const mb = await provisionMailbox({ status: "provisioned", enroll: false });
    valueOf(await mb.stub.describe(callContext(mb, { status: "provisioned" })));
    const schedules = await runInDurableObject(mb.stub, (instance: Mailbox) => instance.getSchedules());
    expect(schedules.filter((s) => s.callback === "dailyHousekeeping").map((s) => [s.type, (s as { cron?: string }).cron])).toEqual([["cron", "17 3 * * *"]]);
  });
});
