import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { Directory } from "../src/directory/directory";
import { addAddressesSql, provisionMailboxSql } from "../src/directory/provision";
import { freshMailboxId, freshBusinessId } from "./support/ids";

const AT = new Date("2026-09-26T12:00:00.000Z");

/** A mailbox row and, as the printers write it, its primary's `addresses` row (D-2). */
async function insertRow(row: { id: string; businessId: string; address: string; status: string }) {
  await env.DIRECTORY.batch([
    env.DIRECTORY.prepare("INSERT INTO mailboxes (id, business_id, address, status, created_at) VALUES (?, ?, ?, ?, ?)").bind(
      row.id,
      row.businessId,
      row.address,
      row.status,
      AT.toISOString(),
    ),
    env.DIRECTORY.prepare("INSERT INTO addresses (address, mailbox_id, created_at) VALUES (?, ?, ?)").bind(row.address, row.id, AT.toISOString()),
  ]);
}

async function insertAddress(address: string, mailboxId: string, at = AT) {
  await env.DIRECTORY.prepare("INSERT INTO addresses (address, mailbox_id, created_at) VALUES (?, ?, ?)").bind(address, mailboxId, at.toISOString()).run();
}

/** The printed SQL as the operator runs it: one statement per line, through the database's own multi-statement path. */
async function runPrinted(sql: string) {
  await env.DIRECTORY.exec(sql);
}

function freshRow(status = "provisioned") {
  const id = freshMailboxId();
  return { id, businessId: freshBusinessId(), address: `${id.slice(4, 14)}@mail.test`, status };
}

describe("migration 0001: the Directory's own constraints", () => {
  it("allows one mailbox per address", async () => {
    const a = freshRow();
    await insertRow(a);
    await expect(insertRow({ ...freshRow(), address: a.address })).rejects.toThrow(/UNIQUE/);
  });

  it("allows one mailbox per business in v1", async () => {
    const a = freshRow();
    await insertRow(a);
    await expect(insertRow({ ...freshRow(), businessId: a.businessId })).rejects.toThrow(/UNIQUE/);
  });

  it("refuses a status outside the lifecycle", async () => {
    await expect(insertRow(freshRow("open"))).rejects.toThrow(/CHECK/);
  });
});

describe("migration 0002: addresses (plan.md §12)", () => {
  it("D-1: an address belongs to at most one mailbox; a second mailbox cannot take it", async () => {
    const a = freshRow();
    const b = freshRow();
    await insertRow(a);
    await insertRow(b);
    await insertAddress(`team.${a.id.slice(4, 12)}@mail.test`, a.id);
    await expect(insertAddress(`team.${a.id.slice(4, 12)}@mail.test`, b.id)).rejects.toThrow(/UNIQUE|PRIMARY KEY/);
    // Nor another mailbox's primary.
    await expect(insertAddress(a.address, b.id)).rejects.toThrow(/UNIQUE|PRIMARY KEY/);
  });

  it("refuses an address for a mailbox that does not exist", async () => {
    await expect(insertAddress("orphan@mail.test", freshMailboxId())).rejects.toThrow(/FOREIGN KEY/);
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
      businessId: row.businessId,
      address: row.address,
      addresses: [row.address],
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

  it("resolves every address of a mailbox to it, and lists them primary first, then oldest first (G12)", async () => {
    const row = freshRow("active");
    await insertRow(row);
    const tag = row.id.slice(4, 12);
    const later = new Date(AT.getTime() + 60_000);
    await insertAddress(`zed.${tag}@mail.test`, row.id, AT);
    await insertAddress(`ann.${tag}@mail.test`, row.id, later);
    const expected = [row.address, `zed.${tag}@mail.test`, `ann.${tag}@mail.test`];
    for (const address of expected) {
      const entry = await directory().byAddress(address.toUpperCase());
      expect(entry?.id).toBe(row.id);
      expect(entry?.addresses).toEqual(expected);
    }
    expect((await directory().byId(row.id))?.addresses).toEqual(expected);
    expect((await directory().forBusiness(row.businessId)).map((m) => m.addresses)).toEqual([expected]);
  });

  it("does not route by the primary column alone: the addresses table is the authority for delivery", async () => {
    // A mailbox row whose primary has no addresses row (a hand-made row the printers never produce).
    const row = freshRow("active");
    await env.DIRECTORY.prepare("INSERT INTO mailboxes (id, business_id, address, status, created_at) VALUES (?, ?, ?, ?, ?)")
      .bind(row.id, row.businessId, row.address, row.status, AT.toISOString())
      .run();
    expect(await directory().byAddress(row.address)).toBeNull();
    expect((await directory().byId(row.id))?.addresses).toEqual([]);
  });

  it("lists a business's mailboxes, leaving out closed ones", async () => {
    const open = freshRow("provisioned");
    await insertRow(open);
    const closed = freshRow("closed");
    await insertRow(closed);
    expect((await directory().forBusiness(open.businessId)).map((m) => m.id)).toEqual([open.id]);
    expect(await directory().forBusiness(closed.businessId)).toEqual([]);
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
  it("creates a provisioned mailbox with its primary as its one address when the operator runs it", async () => {
    const id = freshMailboxId();
    const businessId = freshBusinessId();
    const sql = provisionMailboxSql({
      id,
      businessId,
      address: `Hello.${id.slice(4, 10)}@Example.TEST`,
      sesTenant: "client-example",
      sesConfigurationSet: "send-example-mail",
      now: AT,
    });
    await runPrinted(sql);
    const row = await new Directory(env.DIRECTORY).byId(id);
    expect(row).toMatchObject({
      businessId,
      address: `hello.${id.slice(4, 10)}@example.test`,
      addresses: [`hello.${id.slice(4, 10)}@example.test`],
      status: "provisioned",
      sesTenant: "client-example",
      sesConfigurationSet: "send-example-mail",
      createdAt: AT.toISOString(),
    });
  });

  it("D-2: with further addresses, every one delivers to the mailbox and the primary is always first", async () => {
    const id = freshMailboxId();
    const tag = id.slice(4, 10);
    const sql = provisionMailboxSql({
      id,
      businessId: freshBusinessId(),
      address: `hello.${tag}@example.test`,
      addresses: [`Team.${tag}@Example.test`, `juan.${tag}@example.test`],
      now: AT,
    });
    await runPrinted(sql);
    const directory = new Directory(env.DIRECTORY);
    // Primary first; the rest share one created_at, so they follow in address order.
    const expected = [`hello.${tag}@example.test`, `juan.${tag}@example.test`, `team.${tag}@example.test`];
    expect((await directory.byId(id))?.addresses).toEqual(expected);
    for (const address of expected) expect((await directory.byAddress(address))?.id).toBe(id);
  });

  it("is one INSERT into mailboxes, then one INSERT into addresses per address, primary first, one statement per line", () => {
    const id = freshMailboxId();
    const sql = provisionMailboxSql({ id, businessId: "t1", address: "a@b.test", addresses: ["c@b.test"], now: AT });
    const lines = sql.split("\n").filter((l) => l !== "");
    expect(lines.map((l) => l.split(" (")[0])).toEqual(["INSERT INTO mailboxes", "INSERT INTO addresses", "INSERT INTO addresses"]);
    expect(lines.every((l) => l.endsWith(";"))).toBe(true);
    expect(lines[0]).toMatch(/'provisioned'/);
    expect(lines[1]).toMatch(new RegExp(`^INSERT INTO addresses \\(address, mailbox_id, created_at\\) VALUES \\('a@b.test', '${id}', '2026-09-26T12:00:00.000Z'\\);$`));
    expect(lines[2]).toMatch(new RegExp(`^INSERT INTO addresses .* VALUES \\('c@b.test', '${id}', '2026-09-26T12:00:00.000Z'\\);$`));
  });

  it("adds addresses to an existing mailbox (the second printer), and the primary stays first", async () => {
    const id = freshMailboxId();
    const tag = id.slice(4, 10);
    await runPrinted(provisionMailboxSql({ id, businessId: freshBusinessId(), address: `hello.${tag}@example.test`, now: AT }));
    const sql = addAddressesSql({ mailboxId: id, addresses: [`Sales.${tag}@example.test`], now: new Date(AT.getTime() + 1000) });
    const lines = sql.split("\n").filter((l) => l !== "");
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(new RegExp(`^INSERT INTO addresses .* VALUES \\('sales\\.${tag}@example\\.test', '${id}', '2026-09-26T12:00:01\\.000Z'\\);$`));
    await runPrinted(sql);
    expect((await new Directory(env.DIRECTORY).byId(id))?.addresses).toEqual([`hello.${tag}@example.test`, `sales.${tag}@example.test`]);
  });

  it.each([
    ["an empty list of addresses to add", { mailboxId: freshMailboxId(), addresses: [], now: AT }],
    ["an address listed twice", { mailboxId: freshMailboxId(), addresses: ["a@b.test", "A@B.test"], now: AT }],
    ["an address that is not one", { mailboxId: freshMailboxId(), addresses: ["not-an-address"], now: AT }],
    ["a mailbox id that is not one", { mailboxId: "mbx_short", addresses: ["a@b.test"], now: AT }],
  ])("the second printer refuses %s", (_what, input) => {
    expect(() => addAddressesSql(input)).toThrow(/invalid/i);
  });

  it("refuses a further address equal to the primary, or listed twice", () => {
    const base = { id: freshMailboxId(), businessId: "t1", address: "a@b.test", now: AT };
    expect(() => provisionMailboxSql({ ...base, addresses: ["A@b.test"] })).toThrow(/invalid/i);
    expect(() => provisionMailboxSql({ ...base, addresses: ["c@b.test", "c@b.test"] })).toThrow(/invalid/i);
  });

  it.each([
    ["an id that is not a mailbox id", { id: "mbx_short" }],
    ["a business id carrying SQL", { businessId: "t1'); DROP TABLE mailboxes; --" }],
    ["an address without a domain", { address: "hello@" }],
    ["an address with a quote", { address: "o'hara@example.test" }],
    ["an address with a line break", { address: "a@b.test\r\nX: y" }],
    ["an SES tenant carrying SQL", { sesTenant: "x' OR '1'='1" }],
  ])("refuses %s", (_what, override) => {
    expect(() =>
      provisionMailboxSql({ id: freshMailboxId(), businessId: "t1", address: "a@b.test", now: AT, ...override }),
    ).toThrow(/invalid/i);
  });
});
