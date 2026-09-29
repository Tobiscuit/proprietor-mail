/**
 * The SQL that provisions one mailbox (plan.md §3 and §12): one Directory row
 * with status `provisioned`, then one `addresses` row per address, the
 * primary first. A second printer adds addresses to an existing mailbox.
 * Nothing removes an address (domain-model D-1).
 *
 * The SQL is PRINTED for the operator by scripts/provision-mailbox.ts and run
 * by them, reviewed, with `wrangler d1 execute --file`, which runs a file as
 * one batch: every row or none. Nothing in this repository executes it
 * against a remote database. One statement per line, so that the same text
 * also runs through D1's own multi-statement `exec`.
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
  /** The platform's business id. */
  businessId: string;
  /** The primary address: the mailbox's identity and its default From. */
  address: string;
  /** Further addresses that deliver to the same mailbox. */
  addresses?: string[];
  sesTenant?: string | null;
  sesConfigurationSet?: string | null;
  now: Date;
}

export interface AddAddressesInput {
  /** An existing mailbox's id. */
  mailboxId: string;
  addresses: string[];
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

/** The Directory's form (trimmed, lower-case), or a refusal. */
function validAddress(value: string): string {
  const address = value.trim().toLowerCase();
  if (address.length > 254 || !ADDRESS.test(address)) invalid("address");
  return address;
}

/** Every address once: a repeat would only fail the primary key later, after the operator had reviewed it. */
function distinct(addresses: string[]): string[] {
  if (new Set(addresses).size !== addresses.length) invalid("addresses (one is listed twice)");
  return addresses;
}

function timestamp(now: Date): string {
  if (Number.isNaN(now.getTime())) invalid("time");
  return now.toISOString();
}

function addressRows(mailboxId: string, addresses: string[], at: string): string {
  return addresses
    .map((address) => `INSERT INTO addresses (address, mailbox_id, created_at) VALUES (${quote(address)}, ${quote(mailboxId)}, ${quote(at)});\n`)
    .join("");
}

export function provisionMailboxSql(input: ProvisionInput): string {
  if (!MAILBOX_ID.test(input.id)) invalid("mailbox id");
  if (!NAME.test(input.businessId)) invalid("business id");
  const addresses = distinct([input.address, ...(input.addresses ?? [])].map(validAddress));
  const address = addresses[0]!;
  const sesTenant = input.sesTenant ?? null;
  if (sesTenant !== null && !NAME.test(sesTenant)) invalid("SES tenant");
  const configurationSet = input.sesConfigurationSet ?? null;
  if (configurationSet !== null && !NAME.test(configurationSet)) invalid("SES configuration set");
  const at = timestamp(input.now);

  return (
    "INSERT INTO mailboxes (id, business_id, address, status, ses_tenant, ses_configuration_set, created_at) " +
    `VALUES (${quote(input.id)}, ${quote(input.businessId)}, ${quote(address)}, 'provisioned', ` +
    `${quote(sesTenant)}, ${quote(configurationSet)}, ${quote(at)});\n` +
    // D-2: the primary is always one of the mailbox's addresses, and the first.
    addressRows(input.id, addresses, at)
  );
}

/** The second printer: further addresses for a mailbox that exists. The Directory refuses one that belongs to another mailbox (D-1). */
export function addAddressesSql(input: AddAddressesInput): string {
  if (!MAILBOX_ID.test(input.mailboxId)) invalid("mailbox id");
  if (input.addresses.length === 0) invalid("addresses (none given)");
  const addresses = distinct(input.addresses.map(validAddress));
  return addressRows(input.mailboxId, addresses, timestamp(input.now));
}
