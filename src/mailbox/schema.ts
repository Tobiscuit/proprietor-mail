// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
//
// Modified by Juan Ramirez (Proprietor Systems), 2026-09: the migration runner is adapted from
// agentic-inbox's workers/durableObject/migrations.ts (tracking table renamed
// to mailbox_migrations; every migration runs inside transactionSync; the
// BEGIN/COMMIT stripping was dropped because nothing here writes them). The
// schema itself is proprietor-mail's own (plan.md §3): sealed headers and key
// envelopes only, no message content in any column.

import { SYSTEM_FOLDERS } from "./folders";

export interface Migration {
  name: string;
  sql: string;
}

const seedFolders = SYSTEM_FOLDERS.map((f) => `('${f.id}', '${f.name}', 1)`).join(", ");

export const mailboxMigrations: Migration[] = [
  {
    name: "0001_mailbox",
    sql: `
      CREATE TABLE identity (only INTEGER PRIMARY KEY CHECK (only = 1), mailbox_id TEXT NOT NULL,
        business_id TEXT NOT NULL, address TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '');
      CREATE TABLE keys (key_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at TEXT NOT NULL,
        created_by TEXT NOT NULL, retired_at TEXT);
      CREATE TABLE key_wraps (id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(key_id),
        kind TEXT NOT NULL CHECK (kind IN ('passkey-prf','recovery')), credential_id TEXT, label TEXT NOT NULL,
        wrapped TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL);
      CREATE TABLE folders (id TEXT PRIMARY KEY, name TEXT NOT NULL, system INTEGER NOT NULL);
      INSERT INTO folders (id, name, system) VALUES ${seedFolders};
      -- M8: system folders are fixed. Enforced by the database, not by the absence of an API.
      CREATE TRIGGER folders_system_fixed_update BEFORE UPDATE ON folders WHEN OLD.system = 1
        BEGIN SELECT RAISE(ABORT, 'system folders are fixed'); END;
      CREATE TRIGGER folders_system_fixed_delete BEFORE DELETE ON folders WHEN OLD.system = 1
        BEGIN SELECT RAISE(ABORT, 'system folders are fixed'); END;
      CREATE TABLE messages (id TEXT PRIMARY KEY, folder_id TEXT NOT NULL REFERENCES folders(id),
        direction TEXT NOT NULL CHECK (direction IN ('in','out')), received_at TEXT NOT NULL,
        size INTEGER NOT NULL, key_id TEXT NOT NULL, key_envelope TEXT NOT NULL, header TEXT NOT NULL,
        body_key TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0, flagged INTEGER NOT NULL DEFAULT 0,
        trashed_at TEXT);
      CREATE INDEX messages_by_folder ON messages(folder_id, received_at DESC);
      CREATE INDEX messages_in_trash ON messages(trashed_at) WHERE trashed_at IS NOT NULL;
      CREATE TABLE drafts (id TEXT PRIMARY KEY, key_id TEXT NOT NULL, key_envelope TEXT NOT NULL,
        sealed TEXT NOT NULL, updated_at TEXT NOT NULL);
      CREATE TABLE sends (idempotency_key TEXT PRIMARY KEY, message_id TEXT, provider_message_id TEXT,
        created_at TEXT NOT NULL);
      CREATE INDEX sends_by_time ON sends(created_at);
      CREATE TABLE policy (only INTEGER PRIMARY KEY CHECK (only = 1),
        open_roles TEXT NOT NULL DEFAULT '["owner"]', send_roles TEXT NOT NULL DEFAULT '["owner"]',
        assistant TEXT NOT NULL DEFAULT 'off' CHECK (assistant IN ('off','on')),
        delivery TEXT NOT NULL DEFAULT 'store' CHECK (delivery IN ('store','store-and-forward')),
        forward_to TEXT, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
      CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
        action TEXT NOT NULL, detail TEXT NOT NULL);
    `,
  },
  {
    // Suppression (domain-model M11, spec D15): a recipient who bounced
    // permanently or complained, as HMAC-SHA-256 of the lower-cased address
    // under this mailbox's own random key, never the address. The key is
    // made the first time an event is recorded. Rows lapse a year after
    // last_at (the daily housekeeping).
    name: "0002_suppression",
    sql: `
      CREATE TABLE suppression_key (only INTEGER PRIMARY KEY CHECK (only = 1), key BLOB NOT NULL, created_at TEXT NOT NULL);
      CREATE TABLE suppression (recipient_hash TEXT PRIMARY KEY,
        reason TEXT NOT NULL CHECK (reason IN ('bounce','complaint')), first_at TEXT NOT NULL, last_at TEXT NOT NULL);
      CREATE INDEX suppression_by_last ON suppression(last_at);
    `,
  },
  {
    // Kept devices, factor keys and mail sessions (spec 002, plan.md §2 and,
    // round 3, §10.1, edited in place before 0003 ran anywhere outside the
    // tests; contracts/device-v1.md Part B). Existing rows are untouched:
    // every added column is nullable, or NOT NULL with a default, so
    // `sessions` starts 'optional' and the mailbox behaves exactly as before
    // (R10). SQLite tests an added column's CHECK against every existing row
    // (since 3.37.0), and the default passes it. Tokens and challenge answers
    // are stored only as SHA-256.
    //
    // Round 3: factors carry their Ed25519 signing key and their admission
    // (A2b, A11), and a removed factor's record moves to removed_factors
    // (M24); a retired key's successor carries its transition (A11); a device
    // carries its admission and its unlock key's signature; challenges carry
    // the `key` and `email` purposes and their action descriptor (A10); and
    // rotation_due holds the rotation an email-code revocation left due
    // (M22, M23). (Nothing, not even a comment, may follow the last
    // statement: sql.exec refuses an empty one.)
    name: "0003_devices",
    sql: `
      ALTER TABLE policy    ADD COLUMN sessions TEXT NOT NULL DEFAULT 'optional' CHECK (sessions IN ('optional','required'));
      ALTER TABLE keys      ADD COLUMN successor_key_id    TEXT;     -- set when the key is retired
      ALTER TABLE keys      ADD COLUMN successor_seal      TEXT;     -- this key sealed to its successor (109 bytes)
      ALTER TABLE keys      ADD COLUMN successor_signed_by TEXT;     -- the factor whose proof the rotation spent (A11)
      ALTER TABLE keys      ADD COLUMN successor_sig       TEXT;     -- its transition signature, Ed25519, 64 bytes
      ALTER TABLE key_wraps ADD COLUMN factor_key         BLOB;      -- X25519 public key, 32 bytes (contract A2)
      ALTER TABLE key_wraps ADD COLUMN signing_key        BLOB;      -- Ed25519 public key, 32 bytes (A2b)
      ALTER TABLE key_wraps ADD COLUMN admission_by       TEXT;      -- A11: the factor that admitted it
      ALTER TABLE key_wraps ADD COLUMN admission_sig      TEXT;      --   its signature, 64 bytes
      ALTER TABLE key_wraps ADD COLUMN admission_self_sig TEXT;      --   and the factor's own
      ALTER TABLE key_wraps ADD COLUMN tag                TEXT;      -- binding tag (A5)
      ALTER TABLE key_wraps ADD COLUMN tag_key_id         TEXT;      -- the key the tag is made under
      CREATE TABLE removed_factors (
        id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('passkey-prf','recovery')), credential_id TEXT,
        label TEXT NOT NULL, factor_key BLOB NOT NULL, signing_key BLOB NOT NULL,
        admission_by TEXT NOT NULL, admission_sig TEXT NOT NULL, admission_self_sig TEXT NOT NULL,
        created_at TEXT NOT NULL, created_by TEXT NOT NULL, removed_at TEXT NOT NULL, removed_by TEXT NOT NULL);
      CREATE TABLE devices (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL, label TEXT NOT NULL,
        signing_key BLOB NOT NULL,            -- P-256, 65 bytes
        unlock_key  BLOB,                     -- P-256, 65 bytes; NULL while locked or for "right away"
        unlock_sig  TEXT,                     -- A11, by signing_key; NULL exactly when unlock_key is
        admission_by TEXT NOT NULL, admission_sig TEXT NOT NULL,   -- A11, by the factor whose proof kept it
        tag TEXT NOT NULL, tag_key_id TEXT NOT NULL,
        created_at TEXT NOT NULL, created_by TEXT NOT NULL, last_seen_at TEXT,
        CHECK ((unlock_key IS NULL) = (unlock_sig IS NULL)));
      CREATE TABLE key_seals (
        key_id TEXT NOT NULL REFERENCES keys(key_id),
        to_kind TEXT NOT NULL CHECK (to_kind IN ('device','factor')), to_id TEXT NOT NULL,
        sealed TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
        PRIMARY KEY (key_id, to_kind, to_id));
      -- answer_hash: SHA-256 of the answer, never for 'email' (the dashboard's attestation stands for it);
      -- it is NULL for a moment after the row reserves its place under the cap, until the answer is sealed.
      -- kind, descriptor (base64url of its bytes) and action_digest: for every purpose but 'session' (A10).
      CREATE TABLE challenges (
        id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK (purpose IN ('session','factor','key','email')),
        target_id TEXT NOT NULL, answer_hash TEXT, nonce TEXT NOT NULL, account_id TEXT NOT NULL,
        kind TEXT, descriptor TEXT, action_digest TEXT,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
        refused_at TEXT,                      -- set when a refusal of it as used or expired is first audited
        CHECK (purpose <> 'email' OR answer_hash IS NULL),
        CHECK ((purpose = 'session') = (kind IS NULL) AND (kind IS NULL) = (descriptor IS NULL)));
      CREATE INDEX challenges_by_expiry ON challenges(expires_at);
      CREATE INDEX challenges_by_digest ON challenges(action_digest);
      CREATE TABLE mail_sessions (
        token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL, device_id TEXT,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
      CREATE INDEX mail_sessions_by_device ON mail_sessions(device_id);
      CREATE INDEX mail_sessions_by_expiry ON mail_sessions(expires_at);
      CREATE TABLE rotation_due (one INTEGER PRIMARY KEY CHECK (one = 1),
        since TEXT NOT NULL, by_account TEXT NOT NULL,
        devices TEXT NOT NULL                 -- a JSON array of the revoked devices' ids
      );
    `,
  },
];

/**
 * Minimal migration runner. Each migration runs inside the Durable Object's
 * transactionSync (the DO runtime forbids SQL-level BEGIN/COMMIT), so a
 * multi-statement migration is all or nothing.
 */
export function applyMigrations(storage: DurableObjectStorage, migrations: Migration[]): void {
  const sql = storage.sql;
  sql.exec(`CREATE TABLE IF NOT EXISTS mailbox_migrations (
    name TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  )`);
  for (const migration of migrations) {
    if (sql.exec("SELECT 1 FROM mailbox_migrations WHERE name = ?", migration.name).toArray().length > 0) continue;
    storage.transactionSync(() => {
      sql.exec(migration.sql);
      sql.exec("INSERT INTO mailbox_migrations (name) VALUES (?)", migration.name);
    });
  }
}
