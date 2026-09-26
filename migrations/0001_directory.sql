-- The Mail Directory (plan.md §3): which mailbox an address belongs to, which
-- tenant a mailbox belongs to, and its lifecycle status. Mail's own D1, never
-- the engine's. The Directory is the authority for existence, tenant and
-- lifecycle; each Mailbox Durable Object is the authority for its keys,
-- messages and policy.
CREATE TABLE mailboxes (
  id              TEXT PRIMARY KEY,                 -- mbx_…
  tenant_id       TEXT NOT NULL UNIQUE,             -- the engine's tenant id; one mailbox per tenant in v1
  address         TEXT NOT NULL UNIQUE,             -- lower-case, e.g. hello@operator.example
  status          TEXT NOT NULL CHECK (status IN ('provisioned','active','suspended','closed')),
  ses_tenant      TEXT,                             -- SES tenant name (D7); NULL until it exists
  ses_configuration_set TEXT,                       -- e.g. send-operator-mail (D7)
  created_at      TEXT NOT NULL,
  activated_at    TEXT,
  closed_at       TEXT
);
