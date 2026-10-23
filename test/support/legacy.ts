import { runInDurableObject } from "cloudflare:test";
import type { Mailbox } from "../../src/mailbox/mailbox";
import { applyMigrations, mailboxMigrations } from "../../src/mailbox/schema";

/**
 * A mailbox as it was before migration 0003 (spec 002): its storage rebuilt
 * with 0001 and 0002 only, holding exactly the rows it held, in the columns
 * those two migrations made. Then the constructor's own call,
 * `applyMigrations(storage, mailboxMigrations)`, runs 0003 on it, the way the
 * first wake after the deploy does.
 *
 * Why a rebuild: the Mailbox applies every migration in its constructor, so a
 * Durable Object made in a test has 0003 from its first moment. Dropping the
 * mailbox's own tables (never the Agents SDK's) and recreating them with the
 * older migrations is the one way to hold the state an existing mailbox has
 * today.
 */

/** Every table the mailbox migrations make, children before the tables they reference (foreign keys are enforced). */
const MAILBOX_TABLES = [
  "key_seals",
  "devices",
  "challenges",
  "mail_sessions",
  "removed_factors",
  "rotation_due",
  "key_wraps",
  "messages",
  "drafts",
  "sends",
  "audit",
  "suppression",
  "suppression_key",
  "policy",
  "identity",
  "keys",
  "folders",
  "mailbox_migrations",
];

/** The tables 0001 and 0002 made whose rows a mailbox holds (folders are seeded by 0001 itself). */
const LEGACY_DATA_TABLES = ["identity", "policy", "keys", "key_wraps", "messages", "drafts", "sends", "audit", "suppression_key", "suppression"];

export interface MigrationReport {
  /** Rows of each legacy table before the rebuild, in the legacy columns only. */
  before: Record<string, Record<string, unknown>[]>;
  /** The same tables after 0003 ran, in the legacy columns only. */
  after: Record<string, Record<string, unknown>[]>;
  /** The migrations recorded as applied, in order. */
  applied: string[];
}

export async function migrateFromBeforeDevices(stub: DurableObjectStub<Mailbox>): Promise<MigrationReport> {
  return runInDurableObject(stub, (_instance, state) => {
    const sql = state.storage.sql;
    const rows = (q: string) => sql.exec(q).toArray() as Record<string, unknown>[];
    const saved = Object.fromEntries(LEGACY_DATA_TABLES.map((t) => [t, rows(`SELECT * FROM "${t}"`)]));

    state.storage.transactionSync(() => {
      for (const t of MAILBOX_TABLES) sql.exec(`DROP TABLE IF EXISTS "${t}"`);
    });
    applyMigrations(state.storage, mailboxMigrations.slice(0, 2));
    if (rows("SELECT name FROM mailbox_migrations").map((r) => r.name).join(",") !== "0001_mailbox,0002_suppression") {
      throw new Error("the rebuild did not stop before 0003");
    }

    const legacyColumns: Record<string, string[]> = Object.fromEntries(
      LEGACY_DATA_TABLES.map((t) => [t, rows(`PRAGMA table_info("${t}")`).map((c) => String(c.name))]),
    );
    const project = (table: string, row: Record<string, unknown>) =>
      Object.fromEntries(legacyColumns[table]!.map((c) => [c, row[c] ?? null]));
    const before = Object.fromEntries(LEGACY_DATA_TABLES.map((t) => [t, saved[t]!.map((r) => project(t, r))]));

    state.storage.transactionSync(() => {
      for (const t of LEGACY_DATA_TABLES) {
        for (const row of before[t]!) {
          const columns = Object.keys(row);
          sql.exec(
            `INSERT INTO "${t}" (${columns.map((c) => `"${c}"`).join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`,
            ...columns.map((c) => row[c]),
          );
        }
      }
    });

    // What the Mailbox's constructor does on its first wake after the deploy.
    applyMigrations(state.storage, mailboxMigrations);

    const after = Object.fromEntries(
      LEGACY_DATA_TABLES.map((t) => [t, rows(`SELECT ${legacyColumns[t]!.map((c) => `"${c}"`).join(", ")} FROM "${t}"`)]),
    );
    const applied = rows("SELECT name FROM mailbox_migrations ORDER BY rowid").map((r) => String(r.name));
    return { before, after, applied };
  });
}
