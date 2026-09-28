import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { Directory } from "../src/directory/directory";
import { provisionMailboxSql } from "../src/directory/provision";
import { freshMailboxId, freshTenantId } from "./support/ids";

const AT = new Date("2026-09-26T12:00:00.000Z");

async function insertRow(row: { id: string; tenantId: string; address: string; status: string }) {
  await env.DIRECTORY.prepare(
    "INSERT INTO mailboxes (id, tenant_id, address, status, created_at) VALUES (?, ?, ?, ?, ?)",
  )
    .bind(row.id, row.tenantId, row.address, row.status, AT.toISOString())
    .run();
}

function freshRow(status = "provisioned") {
  const id = freshMailboxId();
  return { id, tenantId: freshTenantId(), address: `${id.slice(4, 14)}@mail.test`, status };
}

describe("migration 0001: the Directory's own constraints", () => {
  it("allows one mailbox per address", async () => {
    const a = freshRow();
    await insertRow(a);
    await expect(insertRow({ ...freshRow(), address: a.address })).rejects.toThrow(/UNIQUE/);
  });

  it("allows one mailbox per tenant in v1", async () => {
    const a = freshRow();
    await insertRow(a);
    await expect(insertRow({ ...freshRow(), tenantId: a.tenantId })).rejects.toThrow(/UNIQUE/);
  });

  it("refuses a status outside the lifecycle", async () => {
    await expect(insertRow(freshRow("open"))).rejects.toThrow(/CHECK/);
  });
});

describe("Directory repository", () => {
  const directory = () => new Directory(env.DIRECTORY);

  it("finds a mailbox by id and by address, case-insensitively on the address", async () => {
    const row = freshRow("active");
    await insertRow(row);
    const byId = await directory().byId(row.id);
    expect(byId).toEqual({
      id: row.id,
      tenantId: row.tenantId,
      address: row.address,
      status: "active",
      sesTenant: null,
      sesConfigurationSet: null,
      createdAt: AT.toISOString(),
      activatedAt: null,
      closedAt: null,
    });
    expect(await directory().byAddress(row.address.toUpperCase())).toEqual(byId);
  });

  it("answers null for an unknown id or address", async () => {
    expect(await directory().byId(freshMailboxId())).toBeNull();
    expect(await directory().byAddress("nobody@mail.test")).toBeNull();
  });

  it("lists a tenant's mailboxes, leaving out closed ones", async () => {
    const open = freshRow("provisioned");
    await insertRow(open);
    const closed = freshRow("closed");
    await insertRow(closed);
    expect((await directory().forTenant(open.tenantId)).map((m) => m.id)).toEqual([open.id]);
    expect(await directory().forTenant(closed.tenantId)).toEqual([]);
  });

  it("activates only a provisioned mailbox, and stamps the time", async () => {
    const row = freshRow("provisioned");
    await insertRow(row);
    expect(await directory().activate(row.id, AT)).toBe(true);
    const after = await directory().byId(row.id);
    expect(after?.status).toBe("active");
    expect(after?.activatedAt).toBe(AT.toISOString());
    // Already active: nothing changes.
    expect(await directory().activate(row.id, new Date(AT.getTime() + 1000))).toBe(false);
    expect((await directory().byId(row.id))?.activatedAt).toBe(AT.toISOString());
  });

  it("moves between states only along the lifecycle's edges", async () => {
    const row = freshRow("active");
    await insertRow(row);
    expect(await directory().transition(row.id, "active", "suspended")).toBe(true);
    expect(await directory().transition(row.id, "active", "suspended")).toBe(false);
    expect(await directory().transition(row.id, "suspended", "active")).toBe(true);
    expect((await directory().byId(row.id))?.status).toBe("active");
  });
});

describe("provisioning SQL (printed for the operator, never executed by the script)", () => {
  it("creates a provisioned mailbox when the operator runs it", async () => {
    const id = freshMailboxId();
    const tenantId = freshTenantId();
    const sql = provisionMailboxSql({
      id,
      tenantId,
      address: `Hello.${id.slice(4, 10)}@Example.TEST`,
      sesTenant: "client-example",
      sesConfigurationSet: "send-example-mail",
      now: AT,
    });
    await env.DIRECTORY.exec(sql.replace(/\n/g, " "));
    const row = await new Directory(env.DIRECTORY).byId(id);
    expect(row).toMatchObject({
      tenantId,
      address: `hello.${id.slice(4, 10)}@example.test`,
      status: "provisioned",
      sesTenant: "client-example",
      sesConfigurationSet: "send-example-mail",
      createdAt: AT.toISOString(),
    });
  });

  it("is exactly one INSERT and nothing else", () => {
    const sql = provisionMailboxSql({ id: freshMailboxId(), tenantId: "t1", address: "a@b.test", now: AT });
    expect(sql.trim().startsWith("INSERT INTO mailboxes")).toBe(true);
    expect(sql.split(";").filter((s) => s.trim() !== "")).toHaveLength(1);
    expect(sql).toMatch(/'provisioned'/);
  });

  it.each([
    ["an id that is not a mailbox id", { id: "mbx_short" }],
    ["a tenant id carrying SQL", { tenantId: "t1'); DROP TABLE mailboxes; --" }],
    ["an address without a domain", { address: "hello@" }],
    ["an address with a quote", { address: "o'hara@example.test" }],
    ["an address with a line break", { address: "a@b.test\r\nX: y" }],
    ["an SES tenant carrying SQL", { sesTenant: "x' OR '1'='1" }],
  ])("refuses %s", (_what, override) => {
    expect(() =>
      provisionMailboxSql({ id: freshMailboxId(), tenantId: "t1", address: "a@b.test", now: AT, ...override }),
    ).toThrow(/invalid/i);
  });
});
