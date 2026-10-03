import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { IMPLEMENTED } from "@proprietor/mail-crypto";
import { describe, expect, it } from "vitest";

// The provisioning script PRINTS SQL for the operator; it never runs it
// (tasks.md S2b). Node, because that is where the operator runs it.
const root = path.resolve(import.meta.dirname, "../..");
const script = path.join(root, "scripts/provision-mailbox.ts");
const ID = "mbx_0123456789abcdefghjkmnpqrs";

function run(args: string[]) {
  return spawnSync(process.execPath, [script, ...args], { cwd: root, encoding: "utf8" });
}

describe("scripts/provision-mailbox.ts", () => {
  it("prints the mailbox INSERT and one addresses INSERT per --address, the first as the primary, lower-cased", () => {
    const out = execFileSync(
      process.execPath,
      [
        script,
        "--business", "biz_example",
        "--address", "Hello@Example.com",
        "--address", "Team@example.com",
        "--id", ID,
        "--ses-tenant", "client-example",
        "--configuration-set", "send-example-mail",
      ],
      { cwd: root, encoding: "utf8" },
    );
    const statements = out.split("\n").filter((l) => l.trim() !== "" && !l.startsWith("--"));
    expect(statements).toHaveLength(3);
    expect(statements[0]).toMatch(
      /^INSERT INTO mailboxes .* VALUES \('mbx_0123456789abcdefghjkmnpqrs', 'biz_example', 'hello@example\.com', 'provisioned', 'client-example', 'send-example-mail', '\d{4}-\d\d-\d\dT[\d:.]+Z'\);$/,
    );
    expect(statements[1]).toMatch(/^INSERT INTO addresses .* VALUES \('hello@example\.com', 'mbx_0123456789abcdefghjkmnpqrs', '[^']+'\);$/);
    expect(statements[2]).toMatch(/^INSERT INTO addresses .* VALUES \('team@example\.com', 'mbx_0123456789abcdefghjkmnpqrs', '[^']+'\);$/);
    // It tells the operator how to run it, and that it has not been run.
    expect(out).toMatch(/^-- .*wrangler d1 execute proprietor-mail/m);
  });

  it("with --add-to, prints only the addresses INSERTs for an existing mailbox", () => {
    const out = execFileSync(process.execPath, [script, "--add-to", ID, "--address", "Sales@Example.com", "--address", "juan@example.com"], {
      cwd: root,
      encoding: "utf8",
    });
    const statements = out.split("\n").filter((l) => l.trim() !== "" && !l.startsWith("--"));
    expect(statements).toHaveLength(2);
    expect(statements[0]).toMatch(/^INSERT INTO addresses .* VALUES \('sales@example\.com', 'mbx_0123456789abcdefghjkmnpqrs', '[^']+'\);$/);
    expect(statements[1]).toMatch(/^INSERT INTO addresses .* VALUES \('juan@example\.com', 'mbx_0123456789abcdefghjkmnpqrs', '[^']+'\);$/);
    expect(out).not.toMatch(/INSERT INTO mailboxes/);
    expect(out).toMatch(/^-- .*wrangler d1 execute proprietor-mail/m);
  });

  it("refuses --add-to together with the options that make a new mailbox", () => {
    for (const extra of [["--business", "t1"], ["--id", ID], ["--ses-tenant", "x"], ["--configuration-set", "x"]]) {
      const res = run(["--add-to", ID, "--address", "a@b.test", ...extra]);
      expect(res.status).not.toBe(0);
      expect(res.stdout).not.toMatch(/INSERT/);
      expect(res.stderr).toMatch(/--add-to/);
    }
  });

  it("refuses bad input with a non-zero exit and prints no SQL", () => {
    const res = run(["--business", "t1", "--address", "not-an-address", "--id", ID]);
    expect(res.status).not.toBe(0);
    expect(res.stdout).not.toMatch(/INSERT/);
    expect(res.stderr).toMatch(/invalid address/);
  });

  it("requires --business and --address", () => {
    const res = run(["--address", "a@b.test", "--id", ID]);
    expect(res.status).not.toBe(0);
    expect(res.stderr).toMatch(/--business/);
  });

  it.skipIf(IMPLEMENTED)("asks for --id while @proprietor/mail-crypto cannot make one (slice S1)", () => {
    const res = run(["--business", "t1", "--address", "a@b.test"]);
    expect(res.status).not.toBe(0);
    expect(res.stdout).not.toMatch(/INSERT/);
    expect(res.stderr).toMatch(/--id/);
  });

  it.skipIf(!IMPLEMENTED)("makes the mailbox id itself once S1 has landed", () => {
    const res = run(["--business", "t1", "--address", "a@b.test"]);
    expect(res.status).toBe(0);
    expect(res.stdout).toMatch(/'mbx_[0-9a-hjkmnp-tv-z]{26}'/);
  });

  it("cannot execute anything: no process, network or database APIs in its source", () => {
    const source = readFileSync(script, "utf8");
    expect(source).not.toMatch(/child_process|node:net|node:http|fetch\(|wrangler d1 execute[^\n]*--(?:yes|y)\b/);
  });
});
