-- Several addresses, one mailbox (plan.md §12; domain-model G12, D-1, D-2).
-- Every address that delivers to a mailbox has a row here, the primary
-- included; `mailboxes.address` says which one is the primary (the mailbox's
-- identity and its default From). The resolver routes by this table alone.
--
-- D-1: an address belongs to at most one mailbox, ever. The primary key
-- refuses a second mailbox, and nothing in v1 deletes or moves a row: an
-- address that once delivered to a mailbox stays with it, closed or not.
CREATE TABLE addresses (
  address     TEXT PRIMARY KEY,                       -- lower-case
  mailbox_id  TEXT NOT NULL REFERENCES mailboxes(id),
  created_at  TEXT NOT NULL
);
CREATE INDEX addresses_by_mailbox ON addresses(mailbox_id);
