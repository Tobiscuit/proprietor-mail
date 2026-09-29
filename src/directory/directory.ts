/**
 * The Mail Directory (plan.md §3 and §12), Mail's own D1: which mailbox an
 * address belongs to, which business a mailbox belongs to, and where it is in
 * its lifecycle. The authority for existence, business and status; each
 * Mailbox object is the authority for its keys, messages and policy.
 *
 * A mailbox has one primary address (`mailboxes.address`: its identity and its
 * default From) and any number of further addresses. Every address that
 * delivers to it, the primary included, is a row of `addresses`, and delivery
 * is resolved through that table alone (domain-model D-1, D-2).
 *
 * Lifecycle: provisioned → active → suspended ⇄ active → closed (terminal).
 */

export type MailboxStatus = "provisioned" | "active" | "suspended" | "closed";

export interface DirectoryEntry {
  id: string;
  businessId: string;
  /** The primary address. Lower-case. */
  address: string;
  /** Every address that delivers to the mailbox, the primary first, then oldest first. Lower-case. */
  addresses: string[];
  status: MailboxStatus;
  sesTenant: string | null;
  sesConfigurationSet: string | null;
  createdAt: string;
  activatedAt: string | null;
  closedAt: string | null;
}

/** One mailbox row joined to one of its `addresses` rows (null when it has none). */
interface Row {
  id: string;
  business_id: string;
  address: string;
  status: MailboxStatus;
  ses_tenant: string | null;
  ses_configuration_set: string | null;
  created_at: string;
  activated_at: string | null;
  closed_at: string | null;
  delivers_to: string | null;
}

const COLUMNS =
  "m.id, m.business_id, m.address, m.status, m.ses_tenant, m.ses_configuration_set, m.created_at, m.activated_at, m.closed_at, " +
  "a.address AS delivers_to";

/**
 * Mailboxes in creation order, each joined to its addresses in the order the
 * entry lists them: the primary first, then oldest first (SQLite sorts a
 * false or NULL comparison after a true one under DESC).
 */
const ORDER = "ORDER BY m.created_at, m.id, (a.address = m.address) DESC, a.created_at, a.address";

/** Consecutive rows of one mailbox become one entry; the query's ORDER BY keeps them together. */
function group(rows: Row[]): DirectoryEntry[] {
  const entries: DirectoryEntry[] = [];
  for (const row of rows) {
    const last = entries.at(-1);
    if (last !== undefined && last.id === row.id) {
      if (row.delivers_to !== null) last.addresses.push(row.delivers_to);
      continue;
    }
    entries.push({
      id: row.id,
      businessId: row.business_id,
      address: row.address,
      addresses: row.delivers_to === null ? [] : [row.delivers_to],
      status: row.status,
      sesTenant: row.ses_tenant,
      sesConfigurationSet: row.ses_configuration_set,
      createdAt: row.created_at,
      activatedAt: row.activated_at,
      closedAt: row.closed_at,
    });
  }
  return entries;
}

/** The Directory's form of an address: trimmed, lower-case. The one normalisation, used wherever an address is compared. */
export function normalizeAddress(address: string): string {
  return address.trim().toLowerCase();
}

export class Directory {
  constructor(private readonly db: D1Database) {}

  async byId(id: string): Promise<DirectoryEntry | null> {
    return (await this.load("m.id = ?", id))[0] ?? null;
  }

  /**
   * The mailbox an address delivers to, through the `addresses` table only: a
   * primary that has no row there (which the printers never produce) does not
   * route. Addresses are stored lower-case; the lookup lower-cases its input.
   */
  async byAddress(address: string): Promise<DirectoryEntry | null> {
    return (await this.load("m.id = (SELECT mailbox_id FROM addresses WHERE address = ?)", normalizeAddress(address)))[0] ?? null;
  }

  /** A business's mailboxes, for `mailboxes()`. A closed mailbox is gone as far as the business is concerned. */
  async forBusiness(businessId: string): Promise<DirectoryEntry[]> {
    return this.load("m.business_id = ? AND m.status != 'closed'", businessId);
  }

  /** One statement per lookup: the matching mailboxes, each with all of its addresses. */
  private async load(where: string, ...binds: string[]): Promise<DirectoryEntry[]> {
    const { results } = await this.db
      .prepare(`SELECT ${COLUMNS} FROM mailboxes m LEFT JOIN addresses a ON a.mailbox_id = m.id WHERE ${where} ${ORDER}`)
      .bind(...binds)
      .all<Row>();
    return group(results);
  }

  /** provisioned → active, once, when the owner has enrolled a key (domain-model M5). */
  async activate(id: string, at: Date): Promise<boolean> {
    const result = await this.db
      .prepare("UPDATE mailboxes SET status = 'active', activated_at = ? WHERE id = ? AND status = 'provisioned'")
      .bind(at.toISOString(), id)
      .run();
    return result.meta.changes === 1;
  }

  /**
   * One edge of the lifecycle, conditional on the current state so that two
   * operators racing cannot skip a state. Suspend and resume only: activation
   * has its own method, and closure tooling is specified, not built (spec §7).
   */
  async transition(
    id: string,
    from: "active" | "suspended",
    to: "active" | "suspended",
  ): Promise<boolean> {
    const result = await this.db
      .prepare("UPDATE mailboxes SET status = ? WHERE id = ? AND status = ?")
      .bind(to, id, from)
      .run();
    return result.meta.changes === 1;
  }
}
