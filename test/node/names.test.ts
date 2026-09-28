import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// The names, fixed before anything depended on them (R0, 2026-09-28). The
// platform is called Proprietor: this Worker is `proprietor-mail`, its packages
// are `@proprietor/mail-crypto` and `@proprietor/mail-outbound`, capabilities
// are issued by `proprietor-dashboard`, and what a mailbox belongs to is a
// *business*, the dashboard's word for it. Protocol constants (the envelope's
// labels, the capability's iss, aud and claims) could be renamed for free only
// until the first mailbox enrolled or the repository went public, so this
// fitness function keeps the old names from coming back.
//
// It reads every file git tracks except:
// - specs/, which the spec's owner renames in a commit of its own;
// - this file, the one place that has to spell the old names to forbid them.
// Nothing else is excluded, the lockfile included: npm writes its integrity
// values in standard base64, which has no "-" (so "platform-mail" cannot occur
// in one), and six letters spelling "tenant" in any case turn up by chance
// about once in 34,000 lockfiles of this size (380 SHA-512 digests).
const root = path.resolve(import.meta.dirname, "../..");
const self = path.relative(root, fileURLToPath(import.meta.url)).split(path.sep).join("/");

/** The old names, in any case: the Worker and package scope, the old issuer, the old word. */
const OLD_NAMES = /platform-mail|platform-dashboard|tenant/gi;

/**
 * Amazon SES's product term keeps AWS's spelling. An SES tenant (spec D7) is
 * SES's own unit of isolation, named on each send by `TenantName`; it is not
 * the platform's business, and renaming it would misname what AWS documents.
 */
const SES_TENANT_TERMS: RegExp[] = [
  // First, because an ARN template holds other terms (${TenantName}/${TenantId}).
  /\barn:[^\s`"]*:ses:[^\s`"]*:tenant\/[^\s`"]*/g, // an SES tenant's ARN, as AWS writes it
  /\bses[_-]tenant\b/g, // the Directory column ses_tenant; the provisioning flag --ses-tenant
  /\bsesTenant\b/g, // DirectoryEntry.sesTenant, ProvisionInput.sesTenant
  /[tT]enantName\b/g, // SendEmail's TenantName, the IAM condition key ses:TenantName, RawSendRequest.tenantName
  /\bSES tenants?\b/g, // prose
  /\bSES_TEST_TENANT\b/g, // the live SES test's variable that holds an SES tenant name
];

/** Every old name in one line, once AWS's own term is set aside. */
function oldNamesIn(line: string): string[] {
  let rest = line;
  for (const term of SES_TENANT_TERMS) rest = rest.replace(term, " ");
  return rest.match(OLD_NAMES) ?? [];
}

describe("the old-name check", () => {
  it.each([
    "ses_tenant      TEXT,",
    "[--ses-tenant <name>]",
    "tenantName: ctx.mailbox.sesTenant",
    '"ses:TenantName": "client-example",',
    "const { tenantName: _omit, ...withoutTenantName } = request();",
    "omitted until the SES tenant exists; one SES tenant per business, SES tenants",
    "SES_TEST_TENANT",
    "`arn:${Partition}:ses:${Region}:${Account}:tenant/${TenantName}/${TenantId}`",
    "`arn:aws:ses:…:tenant/*` in `Resource`",
  ])("lets AWS's term through: %s", (line) => {
    expect(oldNamesIn(line)).toEqual([]);
  });

  it.each([
    ["tenant_id TEXT NOT NULL", ["tenant"]],
    ["directory.forTenant(capability.business)", ["Tenant"]],
    ["SES_TEST_TENANT_ID", ["TENANT"]],
    ["the SES tenant, and the tenant", ["tenant"]],
    ["sesTenantId", ["Tenant"]],
    ["arn:aws:iam::123456789012:tenant/x", ["tenant"]],
    ['import { newId } from "@platform-mail/crypto";', ["platform-mail"]],
    ['const ISSUER = "platform-dashboard";', ["platform-dashboard"]],
    ["# Platform-Mail", ["Platform-Mail"]],
  ])("finds %s", (line, found) => {
    expect(oldNamesIn(line)).toEqual(found);
  });
});

describe("names outside specs/", () => {
  const files = execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8" })
    .split("\0")
    .filter((file) => file !== "" && !file.startsWith("specs/") && file !== self);

  it("reads the whole repository, so an empty listing cannot pass", () => {
    expect(files).toEqual(expect.arrayContaining(["package.json", "package-lock.json", "wrangler.jsonc", "src/capability.ts"]));
  });

  it("no tracked file uses an old name, in its path or its text", () => {
    const found: string[] = [];
    for (const file of files) {
      if (oldNamesIn(file).length > 0) found.push(`${file}: the path`);
      const full = path.join(root, file);
      if (!existsSync(full)) continue; // deleted in the working tree, not yet in the index
      readFileSync(full, "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (oldNamesIn(line).length > 0) found.push(`${file}:${i + 1}: ${line.trim().slice(0, 160)}`);
        });
    }
    expect(found).toEqual([]);
  });
});
