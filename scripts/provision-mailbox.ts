#!/usr/bin/env node
/**
 * Prints the SQL that provisions one mailbox (plan.md §3 and §12), or adds
 * addresses to one that exists. It PRINTS; it never runs anything. The
 * operator reviews the output and runs it with `wrangler d1 execute --file`,
 * the way every Directory change is made in v1.
 *
 *   node scripts/provision-mailbox.ts --business <business id> \
 *     --address <primary> [--address <further address>]... \
 *     [--id mbx_…] [--ses-tenant <name>] [--configuration-set <name>] > provision.sql
 *
 *   node scripts/provision-mailbox.ts --add-to <mbx_…> --address <address>... > addresses.sql
 *
 * The first --address is the primary: the mailbox's identity and its default
 * From. Every address delivers to the same mailbox. Nothing removes one.
 *
 * Node 22.18+ runs this TypeScript file directly (type stripping).
 *
 * The mailbox id comes from `newId("mbx")` in @proprietor/mail-crypto, the one
 * implementation of the id format. Until slice S1 lands that is a stub, and
 * `--id` must be given.
 */
import { registerHooks } from "node:module";
import { parseArgs } from "node:util";
import { addAddressesSql, provisionMailboxSql } from "../src/directory/provision.ts";

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
    business: { type: "string" },
    address: { type: "string", multiple: true },
    id: { type: "string" },
    "ses-tenant": { type: "string" },
    "configuration-set": { type: "string" },
    "add-to": { type: "string" },
  },
  strict: true,
});

const addresses = values.address ?? [];
if (addresses.length === 0) fail("--address is required");

const RUN_IT = "--   npx wrangler d1 execute proprietor-mail --remote --file <this file>\n";

if (values["add-to"] !== undefined) {
  for (const option of ["business", "id", "ses-tenant", "configuration-set"] as const) {
    if (values[option] !== undefined) fail(`--add-to takes only --address; --${option} is for a new mailbox`);
  }
  let sql: string;
  try {
    sql = addAddressesSql({ mailboxId: values["add-to"], addresses, now: new Date() });
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err));
  }
  process.stdout.write(
    `-- Adds ${addresses.length} address(es) to mailbox ${values["add-to"]}. NOT executed: review it, then run\n` +
      RUN_IT +
      "-- The Directory refuses an address that already belongs to another mailbox.\n" +
      sql,
  );
  process.exit(0);
}

if (values.business === undefined) fail("--business is required");

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
    businessId: values.business,
    address: addresses[0]!,
    addresses: addresses.slice(1),
    sesTenant: values["ses-tenant"] ?? null,
    sesConfigurationSet: values["configuration-set"] ?? null,
    now: new Date(),
  });
} catch (err) {
  fail(err instanceof Error ? err.message : String(err));
}

process.stdout.write(
  `-- Provisions mailbox ${id} (status: provisioned) with ${addresses.length} address(es), the first as the primary.\n` +
    "-- NOT executed: review it, then run\n" +
    RUN_IT +
    "-- The mailbox accepts no mail until its owner enrolls a key on their own device.\n" +
    sql,
);
