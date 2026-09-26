# Plan — the Inbox module

**Spec:** `spec.md` · **Domain model:** `domain-model.md` · **Tasks:** `tasks.md`

## 1. The seams, as the SEO-engine session answered them (2026-09-26)

They checked each answer against their code and spec 007. They are settled.

| Seam | Answer | What this plan does with it |
|---|---|---|
| (a) Where the mailbox agent lives | In Mail's OWN Durable Object class, in the Mail Worker, behind an RPC entrypoint — not in spec 007's per-business Agent. Mirror the gallery pattern: the dashboard authorizes the person, Mail owns the data. The per-business Agent may receive a "new mail" count, never content. | `Mailbox` is an Agents SDK `Agent` in `platform-mail`; `MailService` is the entrypoint; a `NewMailSignal` port sends counts only. |
| (b) Identity | The shell verifies the Access JWT itself (no `ctx.access` under static assets), runs each request in an AsyncLocalStorage session; modules call `currentSession()`; the tenant comes from the chooser, checked against memberships. Dashboard → Mail passes a signed capability `{accountId, tenantId, mailbox, exp ≤ 60 s}`, HMAC'd with a key only the two Workers hold. | `contracts/capability-v1.md` (an HS256 JWT). Mail never reads headers or sessions. |
| (c) UI home | A route group in the dashboard app, `apps/dashboard/app/(modules)/inbox/…`, owned by this lane; they review where it meets the shell (session, layout, nav, gating, bindings). Not a package. A module contract (nav entry, `enabled(manifest)` checking `has.email`, bindings). The UI reaches Mail only through server actions → RPC. Spec 007 step 0 (scaffold, session, module contract) is starting now. | Slice S6, held until step 0 exists. Ciphertext passes through server actions to the browser, which decrypts. |
| (d) SES | Reuse the adapter CODE, not the credential or the configuration set. Client mail gets its own IAM principal scoped by identity and `ses:FromAddress`, and its own configuration set with its own event destination. Specify, don't apply. | `packages/mail-outbound` ports the pattern of `seo-engine/src/adapters/ses-mailer.ts` (aws4fetch, injectable fetch) to raw MIME. Infrastructure in §6. |
| (e) Tenant | They create the operator tenant and site key after two engine gaps close: the kit's HTTPS transport server (`/v1/*`, planned on a infra.operator.example host, needs the maintainer's Terraform approval) and gating blog runs on `has.blog`. | Track B builds against the kit's `http()` contract with a stubbed transport. Mail does not need the site key at all; it needs the tenant id for the Directory row. |
| (f) Do not touch | `src/control/*`, `src/sites/manifest.ts` (`email` stays `built: false` until the inbox mounts), the Sites contract, engine migrations (Mail never uses the engine's D1), `packages/seo-kit` (main holds unreleased 0.4.0). | Nothing in this plan edits `~/seo-engine`. Flipping `email` to built is a PR to them when S6 lands. |

Also relayed: the dashboard is being renamed (so no host is hard-coded here;
D5 is about exactly that), and every client's dashboard will be themed from
the client's own site — the inbox UI uses only the shell's theme tokens
(shadcn/ui CSS variables such as `--background`, `--foreground`, `--primary`,
`--muted`, `--accent`, `--border`, `--ring`, `--radius`) and never a
hard-coded colour or font. The final token contract is still coming from the
design agent.

### Seams this plan opens (for the SEO-engine session)

1. **Minting.** The shell's module contract needs a way for a module to get a
   Mail capability for the current session and tenant, e.g.
   `mailCapability({ mailboxId })` inside the shell, signing with
   `MAIL_CAPABILITY_KEYS`. It must pass `contracts/capability-v1.vectors.json`.
2. **How the route group gets `mail-crypto`.** It is code the browser runs to
   handle keys, so it must be byte-for-byte the tested package. Proposal: a
   vendored copy under the route group with a test that compares its hash
   with a tagged release of this repo; alternatively a private package on
   GitHub Packages. Their call, since it is their build.
3. **Streaming ciphertext to the browser.** Bodies can be up to 25 MiB. A
   server action returning that much is awkward; proposal: one route handler
   in the route group that streams `MailService.body()` after checking the
   session, same trust rules as the actions.
4. **Web Push.** When spec 007 step 3 builds the per-business Agent, Mail
   needs its `script_name` binding (or an entrypoint) to send
   `{ tenantId, mailboxId, unread }`.

## 2. Repository layout and who owns what

```
platform-mail/
  specs/001-inbox-module/        architect
  contracts/                     architect (the .vectors.json files: S1 and S2)
  NOTICE, LICENSES/              architect; every slice appends its adapted files to NOTICE
  packages/mail-crypto/          S1
  packages/mail-outbound/        S3
  src/  test/  migrations/       S2
  wrangler.jsonc  vitest.config.ts  package.json (root)   S2
```

The two packages start as typed stubs with the final signatures, so all three
slices compile against the same API from the first commit. A stub throws
`NotImplemented` and exports `IMPLEMENTED = false`; S2's end-to-end tests that
need the real thing skip on that flag and start running when S1 and S3 merge.

## 3. The Mail Worker

Worker name `platform-mail`. No public HTTP routes (`workers_dev: false`,
`preview_urls: false`): it is reached by Email Routing and by service binding,
nothing else. `fetch` answers 404 to everything.

Bindings (sketch; S2 writes the real `wrangler.jsonc`):

```jsonc
{
  "name": "platform-mail",
  "main": "src/index.ts",
  "compatibility_flags": ["nodejs_compat"],
  "workers_dev": false,
  "preview_urls": false,
  "d1_databases": [{ "binding": "DIRECTORY", "database_name": "platform-mail", "database_id": "<created at deploy>" }],
  "r2_buckets": [{ "binding": "MAIL", "bucket_name": "platform-mail" }],
  "durable_objects": { "bindings": [{ "name": "Mailbox", "class_name": "Mailbox" }] },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["Mailbox"] }]
  // secrets: MAIL_CAPABILITY_KEYS, SES_ACCESS_KEY_ID, SES_SECRET_ACCESS_KEY
  // vars:    SES_REGION = "us-east-1"
}
```

### Directory (Mail's own D1)

```sql
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
```

The operator provisions a mailbox by inserting one row with status
`provisioned` (a script prints the SQL; `wrangler d1 execute` runs it; seo-admin
can grow a key for it later). The Directory is the authority for existence,
tenant and lifecycle; the Mailbox object is the authority for keys, messages
and policy. The Mailbox copies id, tenant and address from the Directory the
first time it is touched and refuses to be re-initialized with different
values.

### Mailbox (Durable Object SQLite, one per mailbox)

```sql
CREATE TABLE identity (only INTEGER PRIMARY KEY CHECK (only = 1), mailbox_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL, address TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '');
CREATE TABLE keys (key_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, created_at TEXT NOT NULL,
  created_by TEXT NOT NULL, retired_at TEXT);
CREATE TABLE key_wraps (id TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(key_id),
  kind TEXT NOT NULL CHECK (kind IN ('passkey-prf','recovery')), credential_id TEXT, label TEXT NOT NULL,
  wrapped TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL);
CREATE TABLE folders (id TEXT PRIMARY KEY, name TEXT NOT NULL, system INTEGER NOT NULL);
  -- seeded: inbox, sent, drafts, archive, trash, spam (agentic-inbox shared/folders.ts)
CREATE TABLE messages (id TEXT PRIMARY KEY, folder_id TEXT NOT NULL REFERENCES folders(id),
  direction TEXT NOT NULL CHECK (direction IN ('in','out')), received_at TEXT NOT NULL,
  size INTEGER NOT NULL, key_id TEXT NOT NULL, key_envelope TEXT NOT NULL, header TEXT NOT NULL,
  body_key TEXT NOT NULL, seen INTEGER NOT NULL DEFAULT 0, flagged INTEGER NOT NULL DEFAULT 0,
  trashed_at TEXT);
CREATE INDEX messages_by_folder ON messages(folder_id, received_at DESC);
CREATE TABLE drafts (id TEXT PRIMARY KEY, key_id TEXT NOT NULL, key_envelope TEXT NOT NULL,
  sealed TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE sends (idempotency_key TEXT PRIMARY KEY, message_id TEXT, provider_message_id TEXT,
  created_at TEXT NOT NULL);
CREATE TABLE policy (only INTEGER PRIMARY KEY CHECK (only = 1),
  open_roles TEXT NOT NULL DEFAULT '["owner"]', send_roles TEXT NOT NULL DEFAULT '["owner"]',
  assistant TEXT NOT NULL DEFAULT 'off' CHECK (assistant IN ('off','on')),
  delivery TEXT NOT NULL DEFAULT 'store' CHECK (delivery IN ('store','store-and-forward')),
  forward_to TEXT, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
CREATE TABLE audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, detail TEXT NOT NULL);   -- never message content
```

R2 bucket `platform-mail`, one object per message: `mbx/<mailboxId>/msg/<messageId>`
holding the sealed raw message. Nothing else is written to R2.

## 4. `MailService` — the RPC surface

Every method takes the capability string first. Errors cross RPC as `Error`s
whose `name` is one of: `CapabilityRejected` (reason `invalid` | `expired`),
`NotFound`, `Forbidden`, `InvalidRequest`, `MailboxNotActive`, `RateLimited`
(`retryAfterSeconds`), `SendFailed` (`retryable`), `AssistantUnavailable`.

| Method | Needs `mbx` | Role | Returns / does |
|---|---|---|---|
| `mailboxes(cap)` | no | any | `[{ id, address, status }]` for the capability's tenant, so the module can show "not set up", "set up your inbox" or the inbox |
| `mailbox(cap)` | yes | open | `{ id, address, status, displayName, keys[], wraps[], policy }` — wraps are ciphertext; `policy` includes `delivery` and `forwardTo` (M10) |
| `enroll(cap, { publicKey, wraps[] })` | yes | owner | only when `provisioned`; recomputes the keyId; requires one `recovery` wrap (M5); sets Directory `active` |
| `addWrap(cap, wrap)` / `removeWrap(cap, wrapId)` | yes | owner | the last recovery wrap cannot be removed |
| `list(cap, { folder, before?, limit? })` | yes | open | `{ items: [{ id, folder, direction, receivedAt, size, seen, flagged, keyId, keyEnvelope, header }], next }`, newest first, `limit` ≤ 100 |
| `body(cap, messageId)` | yes | open | `ReadableStream` of the sealed body |
| `update(cap, messageId, { seen?, flagged?, folder? })` | yes | open | moving to `trash` sets `trashedAt` |
| `purge(cap, messageId)` | yes | owner | row and R2 object deleted |
| `drafts(cap)` / `saveDraft(cap, { id, keyId, keyEnvelope, sealed })` / `deleteDraft(cap, id)` | yes | open | sealed in the browser |
| `send(cap, { idempotencyKey, to, cc?, bcc?, subject, text, html?, inReplyTo?, references?, attachments?, draftId? })` | yes | send | builds MIME, sends through SES, seals and stores the Sent copy, deletes `draftId`; plaintext lives only for the call |
| `unread(cap)` | yes | open | `{ inbox: number }` |
| `setPolicy(cap, { displayName?, assistant? })` | yes | owner | `assistant: "on"` answers `AssistantUnavailable` in v1 |
| `audit(cap, { before? })` | yes | owner | `[{ at, actor, action, detail }]` |

Operator actions (provision, suspend, change delivery mode, close) are not on
this surface. v1 does them with reviewed SQL against the Directory and one
narrowly scoped admin entrypoint that S2 specifies but binds to nothing.

## 5. Arrival, step by step, and what each failure does

| Situation | What the Worker does |
|---|---|
| No Directory row for the envelope recipient | `setReject("No such mailbox")` |
| Mailbox `provisioned`, `suspended` or `closed` | `setReject("This mailbox is not accepting mail")` (M2) |
| `rawSize` above 25 MiB | `setReject("Message too large")` |
| Headers do not parse | store it anyway, with `subject: ""`, `snippet: ""` and whatever parsed; never lose mail to a parser |
| `store` mode: R2 or SQLite fails | throw — Email Routing's behaviour on a throw is unverified (spec §8); S8 settles it before any address is routed here |
| `store-and-forward`: forward fails | throw before storing anything, so the sender's server retries and no half-delivery exists |
| `store-and-forward`: forward succeeded, storing fails | do not throw; audit row + an operator alert; Gmail has the message |

Order inside `onEmail`: status check → size check → (forward, in
`store-and-forward`) → read raw → parse → seal → R2 put → SQLite insert (a
failed insert deletes the R2 object it just wrote) → new-mail count. Nothing
from the message is logged: logs carry the mailbox id, the message id, the
size and the outcome.

## 6. Infrastructure to create later (specified here, applied by nobody yet)

**Cloudflare** (Terraform in `cloudflare-infra`, per its apply protocol):

- D1 `platform-mail`, R2 bucket `platform-mail` (private, no public access), the
  Worker itself (deployed with Workers Builds, like the engine).
- **operator.example receiving** (D4): `cloudflare_email_routing_dns` on the
  operator.example zone (writes the MX and the apex SPF; the SES MAIL FROM
  subdomain `mail.operator.example` is separate and untouched), and one
  `cloudflare_email_routing_rule`: `hello@operator.example` → worker
  `platform-mail`. DMARC for operator.example in monitor mode if it is still
  absent. The Terraform token already has the Email Routing grants (added
  2026-09-24).
- Nothing for Access: Mail has no web surface.

**AWS SES** (D7; through `cloudflare-infra/tf-aws` or Terraform):

- One SES tenant per business with mail (`client-operator`, later
  `client-exampleclient`), associated with its identity and its configuration
  set, `SuppressionScope: TENANT`.
- A client-mail configuration set per sending domain, in the repository's own
  convention (`SENDING.md`: "per domain, never shared"): `send-operator-mail`,
  later `send-exampleclient-mail`. The SEO-engine session suggested one shared
  `send-clients`; with tenant-scoped suppression either works. The per-domain
  name is recommended because it keeps `SENDING.md` literally true.
- Their event destination goes to **Mail's own** SNS topic and SQS queue
  (`platform-mail-events`), never to the engine's `ses-events-operator` feed:
  client recipients and subjects must not land in the engine's `mail_events`.
- A new IAM principal for client mail, policy to be checked in the IAM
  policy simulator before it is attached:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "SendOnlyAsClientMailboxes",
      "Effect": "Allow",
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": [
        "arn:aws:ses:us-east-1:123456789012:identity/operator.example",
        "arn:aws:ses:us-east-1:123456789012:configuration-set/send-operator-mail",
        "arn:aws:ses:us-east-1:123456789012:tenant/*"
      ],
      "Condition": { "StringEquals": { "ses:FromAddress": ["hello@operator.example"] } }
    }]
  }
  ```

  (the tenant ARN form is to be confirmed against the SES authorization
  reference at apply time). And the notification principal `ses-send-app`
  gains `ses:FromAddress = notify@operator.example`.

**Vault** (secrets reach Workers through the process environment only):

- `secret/platform-mail/capability` — `keys` (the JSON map) and `current_kid`;
  into both the dashboard and Mail Workers.
- `secret/aws/ses-send-mail` — the client-mail principal's access key; into
  the Mail Worker only.

## 7. How it is tested — no real mail to or from anyone

- **Worker tests** run in workerd (`@cloudflare/vitest-pool-workers`, the
  engine's harness): a real D1 with the real migration, a real Durable Object,
  a real R2 simulation. Inbound is exercised by calling the Worker's `email()`
  handler with a constructed message, and once end to end through `wrangler
  dev` and the local email endpoint (`POST /cdn-cgi/local/email`).
- **Invariant tests**: M1 is checked by sending a message whose subject,
  sender name, body and attachment name carry unique markers, then scanning
  every SQLite table, every R2 object and the captured console output for the
  markers in plain, base64 and quoted-printable form. M3 is checked by
  scanning storage for the test's private key bytes after enrolment.
- **Packages** run in Node (Web Crypto is standard there), and `mail-crypto`
  is also imported by the Worker tests, which proves it runs in workerd.
- **Vectors**: `contracts/*.vectors.json`, checked by both sides.
- **Outbound live check**: only against the SES mailbox simulator
  (`success@simulator.amazonses.com` and the bounce, complaint, out-of-office
  and suppression-list addresses), only with a credential read from Vault
  into the environment, and only in a test file that skips when the variables
  are absent.

## 8. Alex: a reversible move to dual delivery (planned, not executed)

Today `info@client.example` is forwarded by an Email Routing rule to his Gmail
(`sending-exampleclient.tf`, live since 2026-09-25). His mail is real business
mail; nothing below happens without the maintainer's go, and each step has its way
back.

1. **Prerequisites.** operator's mailbox has run for at least two weeks with no
   lost or duplicated mail. D1, D2 (publication), D5 and D7 are decided. The
   Worker's throw behaviour (spec §8) is verified.
2. **Provision** his mailbox (`provisioned`), SES tenant `client-exampleclient`,
   configuration set `send-exampleclient-mail`.
3. **He sets it up himself**, on his own phone, at his dashboard: passkey,
   recovery key printed or saved by him. the maintainer does not sit in for this step
   (D9); if he needs help it is over the phone, never by taking his device.
4. **Dual delivery.** Set the mailbox's delivery to `store-and-forward` with
   `forwardTo = owner@client.example` (already a verified destination on the
   account), then change the rule's action from `forward` to `worker
   platform-mail` in `sending-exampleclient.tf`. The Worker forwards first and
   stores second (§5), so Gmail keeps receiving everything even if storage
   fails. His dashboard shows "Also forwarded to owner@client.example".
5. **Watch for two to four weeks**: forwards attempted vs succeeded (must be
   equal), messages stored vs forwarded, no duplicates reported by him.
6. **He decides** whether to stop the Gmail copy. Only on his word (delivery →
   `store`).

**Rollback at any point:** restore the rule's `forward` action (one Terraform
change, apply protocol as always). Mail stored during the trial stays in his
mailbox; Gmail never missed anything, because during step 4 it got every
message first.

## 9. The assistant (held until D1)

- A separate Durable Object class, `MailAssistant` (`AIChatAgent`), one per
  mailbox, created only for a mailbox whose owner opted in. Its tools are
  agentic-inbox's nine, adapted to decrypted views; it never sends; the
  prompt-injection check and the draft cleaner stay. No MCP server.
- **Ask about one message**: the browser sends that message's 32-byte message
  key with the question; the assistant decrypts only that message, answers,
  and drops the key; the audit log records "message key disclosed to the
  assistant" with the message id.
- **Standing opt-in (Option C)**: the browser seals the mailbox private key to
  the assistant's own X25519 key (a Worker secret) and stores that escrow
  record; every decryption by the assistant writes an owner-visible audit row;
  turning it off deletes the escrow record. Auto-drafting new mail is possible
  only in this mode.
- The model and provider are chosen when this is built (Workers AI, or Gemini
  through the platform's own usage ledger with a purpose such as
  `mail-assistant`), priced from the ledger, not guessed.

## 10. The inbox screens (held until spec 007 step 0)

Route group `apps/dashboard/app/(modules)/inbox/` in the SEO-engine repo, a PR
to them. Screens:

- **Not set up** (no mailbox for the tenant): "Your inbox isn't set up yet."
- **Set up** (owner, mailbox `provisioned`): generate the key pair in the
  browser → create a passkey with PRF and wrap → show the recovery key once,
  have the owner confirm four characters of it → `enroll`. If the device's
  passkey provider offers no PRF, recovery-key-only enrolment with a clear
  warning; a passphrase wrap comes later.
- **Unlock**: one passkey prompt; the private key is kept in memory as a
  non-extractable key; lock after inactivity; the public-key check (G7).
- **Inbox, folders, threads, search**: decrypted in the browser; threading by
  Message-ID/References with agentic-inbox's subject-normalization fallback.
- **Read**: body decrypted on open and rendered in the script-less sandboxed
  frame (D3), remote images off until the owner clicks "show images".
- **Compose / reply / forward**: plain text with the quoted-reply block
  (adapted from agentic-inbox); drafts sealed in the browser on every save.
- **Settings**: display name, devices (passkey wraps), recovery key, "How your
  mail is protected" (the promise text for the mailbox's option and the §4
  metadata list), and the assistant switch showing "Off" with an explanation.

Everything is styled with the shell's theme tokens only.

## 11. Deploying (later, not in this work)

Workers Builds on `main`, like the engine. First deploy only after D1, D4, D5
and D7 are decided and the Cloudflare/AWS resources in §6 exist. The first
routed address is `hello@operator.example`; the first owner is the maintainer, enrolling
on his own devices.
