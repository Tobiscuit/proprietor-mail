import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

// Fitness functions over the deployable configuration (tasks.md S2a): read off
// disk, so they run in Node.
const root = path.resolve(import.meta.dirname, "../..");

/** wrangler.jsonc without its comments (none of its strings contain "//" or "/*"). */
function wranglerConfig(): Record<string, unknown> {
  const text = readFileSync(path.join(root, "wrangler.jsonc"), "utf8")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:"])\/\/.*$/gm, "$1");
  return JSON.parse(text) as Record<string, unknown>;
}

describe("wrangler.jsonc", () => {
  const config = wranglerConfig();

  it("has no public surface: no routes, no workers.dev, no preview URLs", () => {
    expect(config.workers_dev).toBe(false);
    expect(config.preview_urls).toBe(false);
    expect(config.routes).toBeUndefined();
    expect(config.route).toBeUndefined();
  });

  it("binds nothing to MailAdmin, or to any other service yet", () => {
    expect(config.services).toBeUndefined();
  });

  it("has the plan's bindings and a SQLite-backed Mailbox class", () => {
    expect(config.d1_databases).toEqual([expect.objectContaining({ binding: "DIRECTORY", database_name: "proprietor-mail" })]);
    expect(config.r2_buckets).toEqual([{ binding: "MAIL", bucket_name: "proprietor-mail" }]);
    expect(config.durable_objects).toEqual({ bindings: [{ name: "Mailbox", class_name: "Mailbox" }] });
    expect(config.migrations).toEqual([{ tag: "v1", new_sqlite_classes: ["Mailbox"] }]);
  });

  it("names the database by name only: no database id, so no resource identifier is published (G24)", () => {
    const [d1] = config.d1_databases as Record<string, unknown>[];
    expect(d1).toEqual({ binding: "DIRECTORY", database_name: "proprietor-mail", migrations_dir: "migrations" });
    expect(JSON.stringify(config)).not.toMatch(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
  });

  it("carries no secret: only the SES region as a plain var", () => {
    expect(config.vars).toEqual({ SES_REGION: "us-east-1" });
  });

  it("runs the deliverability feed every five minutes (plan.md §13)", () => {
    expect(config.triggers).toEqual({ crons: ["*/5 * * * *"] });
  });

  it("keeps Workers Logs off entirely: every entry of an email invocation names its sender and recipient (G25, D20)", () => {
    expect(config.observability).toEqual({ enabled: false });
  });
});
