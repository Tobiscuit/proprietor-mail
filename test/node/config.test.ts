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
    expect(config.d1_databases).toEqual([expect.objectContaining({ binding: "DIRECTORY", database_name: "platform-mail" })]);
    expect(config.r2_buckets).toEqual([{ binding: "MAIL", bucket_name: "platform-mail" }]);
    expect(config.durable_objects).toEqual({ bindings: [{ name: "Mailbox", class_name: "Mailbox" }] });
    expect(config.migrations).toEqual([{ tag: "v1", new_sqlite_classes: ["Mailbox"] }]);
  });

  it("points at no real database: the id is a placeholder until plan.md §6 is applied", () => {
    const [d1] = config.d1_databases as { database_id: string }[];
    expect(d1!.database_id).toBe("00000000-0000-0000-0000-000000000000");
  });

  it("carries no secret: only the SES region as a plain var", () => {
    expect(config.vars).toEqual({ SES_REGION: "us-east-1" });
  });
});
