/**
 * The Mail Directory (plan.md §3), Mail's own D1: which mailbox an address
 * belongs to, which business a mailbox belongs to, and where it is in its
 * lifecycle. The authority for existence, business and status; each Mailbox
 * object is the authority for its keys, messages and policy.
 *
 * Lifecycle: provisioned → active → suspended ⇄ active → closed (terminal).
 */

export type MailboxStatus = "provisioned" | "active" | "suspended" | "closed";

export interface DirectoryEntry {
  id: string;
  businessId: string;
  /** Lower-case. */
  address: string;
  status: MailboxStatus;
  sesTenant: string | null;
  sesConfigurationSet: string | null;
  createdAt: string;
  activatedAt: string | null;
  closedAt: string | null;
}

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
}

const COLUMNS =
  "id, business_id, address, status, ses_tenant, ses_configuration_set, created_at, activated_at, closed_at";

function toEntry(row: Row): DirectoryEntry {
  return {
    id: row.id,
    businessId: row.business_id,
    address: row.address,
    status: row.status,
    sesTenant: row.ses_tenant,
    sesConfigurationSet: row.ses_configuration_set,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    closedAt: row.closed_at,
  };
}

export class Directory {
  constructor(private readonly db: D1Database) {}

  async byId(id: string): Promise<DirectoryEntry | null> {
    const row = await this.db.prepare(`SELECT ${COLUMNS} FROM mailboxes WHERE id = ?`).bind(id).first<Row>();
    return row === null ? null : toEntry(row);
  }

  /** Addresses are stored lower-case; the lookup lower-cases its input. */
  async byAddress(address: string): Promise<DirectoryEntry | null> {
    const row = await this.db
      .prepare(`SELECT ${COLUMNS} FROM mailboxes WHERE address = ?`)
      .bind(address.trim().toLowerCase())
      .first<Row>();
    return row === null ? null : toEntry(row);
  }

  /** A business's mailboxes, for `mailboxes()`. A closed mailbox is gone as far as the business is concerned. */
  async forBusiness(businessId: string): Promise<DirectoryEntry[]> {
    const { results } = await this.db
      .prepare(`SELECT ${COLUMNS} FROM mailboxes WHERE business_id = ? AND status != 'closed' ORDER BY created_at, id`)
      .bind(businessId)
      .all<Row>();
    return results.map(toEntry);
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
