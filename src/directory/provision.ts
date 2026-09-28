/**
 * The SQL that provisions one mailbox (plan.md §3): one Directory row with
 * status `provisioned`. It is PRINTED for the operator by
 * scripts/provision-mailbox.ts and run by them, reviewed, with
 * `wrangler d1 execute`; nothing in this repository executes it against a
 * remote database.
 *
 * Self-contained on purpose (no runtime imports), so that the Node script can
 * load this file directly.
 *
 * The values are interpolated into SQL text, so each is validated against a
 * narrow pattern first and quoted second; a value that needs escaping is
 * refused rather than escaped.
 */

export interface ProvisionInput {
  /** `mbx_` + 26 lowercase Crockford base32 characters (contracts/envelope-v1.md). */
  id: string;
  /** The platform's tenant id. */
  tenantId: string;
  address: string;
  sesTenant?: string | null;
  sesConfigurationSet?: string | null;
  now: Date;
}

const MAILBOX_ID = /^mbx_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;
const NAME = /^[A-Za-z0-9_-]{1,64}$/;
// Deliberately narrower than RFC 5321: a mailbox address the platform hands
// out, not every address the internet can carry.
const ADDRESS = /^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function invalid(what: string): never {
  throw new Error(`invalid ${what}`);
}

function quote(value: string | null): string {
  if (value === null) return "NULL";
  // Unreachable after validation; kept so that a future field cannot forget it.
  if (value.includes("'")) invalid("value (contains a quote)");
  return `'${value}'`;
}

export function provisionMailboxSql(input: ProvisionInput): string {
  if (!MAILBOX_ID.test(input.id)) invalid("mailbox id");
  if (!NAME.test(input.tenantId)) invalid("tenant id");
  const address = input.address.trim().toLowerCase();
  if (address.length > 254 || !ADDRESS.test(address)) invalid("address");
  const sesTenant = input.sesTenant ?? null;
  if (sesTenant !== null && !NAME.test(sesTenant)) invalid("SES tenant");
  const configurationSet = input.sesConfigurationSet ?? null;
  if (configurationSet !== null && !NAME.test(configurationSet)) invalid("SES configuration set");
  if (Number.isNaN(input.now.getTime())) invalid("time");

  return (
    "INSERT INTO mailboxes (id, tenant_id, address, status, ses_tenant, ses_configuration_set, created_at)\n" +
    `VALUES (${quote(input.id)}, ${quote(input.tenantId)}, ${quote(address)}, 'provisioned', ` +
    `${quote(sesTenant)}, ${quote(configurationSet)}, ${quote(input.now.toISOString())});\n`
  );
}
