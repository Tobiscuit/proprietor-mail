-- The Mail Directory (plan.md §3): which mailbox an address belongs to, which
-- business a mailbox belongs to, and its lifecycle status. Mail's own D1, never
-- another application's. The Directory is the authority for existence, business and
-- lifecycle; each Mailbox Durable Object is the authority for its keys,
-- messages and policy.
CREATE TABLE mailboxes (
  id              TEXT PRIMARY KEY,                 -- mbx_…
  business_id     TEXT NOT NULL UNIQUE,             -- the platform's business id; one mailbox per business in v1
  address         TEXT NOT NULL UNIQUE,             -- lower-case, e.g. hello@example.com
  status          TEXT NOT NULL CHECK (status IN ('provisioned','active','suspended','closed')),
  ses_tenant      TEXT,                             -- SES tenant name (D7); NULL until it exists
  ses_configuration_set TEXT,                       -- e.g. send-example-mail (D7)
  created_at      TEXT NOT NULL,
  activated_at    TEXT,
  closed_at       TEXT
);
