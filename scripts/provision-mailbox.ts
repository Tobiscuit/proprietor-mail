#!/usr/bin/env node
/**
 * Prints the SQL that provisions one mailbox (plan.md §3). It PRINTS; it
 * never runs anything. The operator reviews the output and runs it with
 * `wrangler d1 execute`, the way every Directory change is made in v1.
 *
 *   node scripts/provision-mailbox.ts --tenant <tenant id> --address <address> \
 *     [--id mbx_…] [--ses-tenant <name>] [--configuration-set <name>] > provision.sql
 *
 * Node 22.18+ runs this TypeScript file directly (type stripping).
 *
 * The mailbox id comes from `newId("mbx")` in @proprietor/mail-crypto, the one
 * implementation of the id format. Until slice S1 lands that is a stub, and
 * `--id` must be given.
 */
import { registerHooks } from "node:module";
import { parseArgs } from "node:util";
import { provisionMailboxSql } from "../src/directory/provision.ts";

// The workspace packages are TypeScript written for a bundler: their relative
// imports carry no extension, which Node's ESM loader refuses. Retry such an
// import with ".ts", and touch nothing else. (registerHooks: Node >= 22.15.)
registerHooks({
  resolve(specifier, context, nextResolve) {
    try {
      return nextResolve(specifier, context);
    } catch (err) {
      const relative = specifier.startsWith("./") || specifier.startsWith("../");
      if ((err as { code?: string }).code === "ERR_MODULE_NOT_FOUND" && relative && !/\.[cm]?[jt]s$/.test(specifier)) {
        return nextResolve(`${specifier}.ts`, context);
      }
      throw err;
    }
  },
});
// Loaded after the hook, so that the package's own imports resolve.
const { newId } = await import("@proprietor/mail-crypto");

function fail(message: string, code = 1): never {
  process.stderr.write(`provision-mailbox: ${message}\n`);
  process.exit(code);
}

const { values } = parseArgs({
  options: {
    tenant: { type: "string" },
    address: { type: "string" },
    id: { type: "string" },
    "ses-tenant": { type: "string" },
    "configuration-set": { type: "string" },
  },
  strict: true,
});

if (values.tenant === undefined) fail("--tenant is required");
if (values.address === undefined) fail("--address is required");

let id = values.id;
if (id === undefined) {
  try {
    id = newId("mbx");
  } catch (err) {
    if (err instanceof Error && err.name === "NotImplemented") {
      fail("@proprietor/mail-crypto cannot make ids yet (slice S1); pass --id mbx_<26 characters>", 2);
    }
    throw err;
  }
}

let sql: string;
try {
  sql = provisionMailboxSql({
    id,
    tenantId: values.tenant,
    address: values.address,
    sesTenant: values["ses-tenant"] ?? null,
    sesConfigurationSet: values["configuration-set"] ?? null,
    now: new Date(),
  });
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}

process.stdout.write(
  `-- Provisions mailbox ${id} (status: provisioned). NOT executed: review it, then run\n` +
    `--   npx wrangler d1 execute proprietor-mail --remote --file <this file>\n` +
    `-- The mailbox accepts no mail until its owner enrolls a key on their own device.\n` +
    sql,
);
