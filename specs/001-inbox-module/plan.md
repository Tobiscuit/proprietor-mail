# Plan — the Inbox module

**Spec:** `spec.md` · **Domain model:** `domain-model.md` · **Tasks:** `tasks.md`

## 1. The seams with the dashboard, as its maintainers answered them (2026-09-26)

The dashboard is a separate application (not in this repository). Its
maintainers checked each answer against the dashboard's code and design. They
are settled.

| Seam | Answer | What this plan does with it |
|---|---|---|
| (a) Where the mailbox agent lives | In Mail's OWN Durable Object class, in the Mail Worker, behind an RPC entrypoint — not in the dashboard's per-business Agent. The pattern the dashboard's other modules follow: the dashboard authorizes the person, the module owns the data. The per-business Agent may receive a "new mail" count, never content. | `Mailbox` is an Agents SDK `Agent` in `proprietor-mail`; `MailService` is the entrypoint; a `NewMailSignal` port sends counts only. |
| (b) Identity | The shell verifies the Access JWT itself (no `ctx.access` under static assets), runs each request in an AsyncLocalStorage session; modules call `currentSession()`; the business comes from the chooser, checked against memberships. Dashboard → Mail passes a signed capability `{accountId, businessId, mailbox, exp ≤ 60 s}`, HMAC'd with a key only the two Workers hold. | `contracts/capability-v1.md` (an HS256 JWT). Mail never reads headers or sessions. |
| (c) UI home | A route group in the dashboard app (the inbox's own directory), owned by this project; the dashboard's maintainers review where it meets the shell (session, layout, nav, gating, bindings). Not a package. A module contract (nav entry, `enabled(manifest)` checking `has.email`, bindings). The UI reaches Mail only through server actions → RPC. The dashboard's first step (scaffold, session, module contract) is starting now. | Slice S6, held until that first step exists. Ciphertext passes through server actions to the browser, which decrypts. |
| (d) SES | Reuse the adapter CODE, not the credential or the configuration set. Client mail gets its own IAM principal scoped by identity and `ses:FromAddress`, and its own configuration set with its own event destination. Specify, don't apply. | `packages/mail-outbound` ports the pattern of the platform's existing SES adapter (aws4fetch, an injectable fetch) to raw MIME. Infrastructure in §6. |
| (e) Business | The operator's own business is created on the platform side, after two unrelated gaps there are closed. | Mail needs nothing from that work except the business id for the Directory row. |
| (f) Boundaries | The dashboard's control plane, its site manifest (`email` stays unbuilt until the inbox mounts), its contracts and its database migrations are not Mail's to change; Mail never uses the dashboard's D1. | Nothing in this plan edits the dashboard's code. Marking the email module as built is a change on the dashboard side when S6 lands. |

Also relayed: the dashboard is moving to a new hostname (so no host is hard-coded here;
D5 is about exactly that), and every client's dashboard will be themed from
the client's own site — the inbox UI uses only the shell's theme tokens
(shadcn/ui CSS variables such as `--background`, `--foreground`, `--primary`,
`--muted`, `--accent`, `--border`, `--ring`, `--radius`) and never a
hard-coded colour or font. The final token contract is still being defined.

### Seams this plan opened, and the answers (settled 2026-09-26)

1. **Minting.** A server-only `mailCapability({ mailboxId? })` in the shell:
   `sub` from `currentSession()`, business and role from the already-checked
   acting membership, HS256 with the `kid` header, `exp = iat + 60`, a random
   `jti` that both Workers log. Internals are a pure
   `mint({ key, kid, now, jti }, claims)` tested against
   `contracts/capability-v1.vectors.json`. The contract now makes `jti`
   required and fixes the serialization order (conformance is "verifies and
   decodes to these claims", not byte identity).
2. **How the route group gets `mail-crypto`.** A vendored copy inside the
   inbox's route group (`_vendor/mail-crypto/`) with `VERSION` and
   `SHA256SUMS`, a test that recomputes the sums, and a script that pulls a
   tagged proprietor-mail release through `gh` and refuses to copy when the sums
   differ. **Our side:** each release tag `mail-crypto-vX.Y.Z` gets a GitHub
   release whose `SHA256SUMS` asset is produced by a workflow from the tagged
   tree (slice S1r), so their script checks against something other than the
   copy itself; the same workflow publishes the package to npm with
   provenance and attests both artifacts, and the tag is also signed if the
   maintainer has a signing key set up.
3. **Streaming ciphertext.** Agreed and added to their module contract: route
   handlers are allowed inside a module's group, GET only, behind the same
   entry gate; the handler resolves the acting business through the shell,
   mints its own capability, pipes `MailService.body()`'s stream through
   without buffering, and always sends `cache-control: private, no-store`,
   `content-type: application/octet-stream` and
   `x-content-type-options: nosniff`.
4. **Web Push.** Not a `script_name` Durable Object binding (that would expose
   the whole per-business Agent). At a later step the dashboard Worker
   exports a narrow `MailSignals` entrypoint with one method,
   `unread({ businessId, mailboxId, unread })`; Mail binds it by service and
   entrypoint. Until then Mail's `NewMailSignal` port has a no-op adapter.

**Also agreed:** D7 (one SES tenant per client; Mail's own SNS/SQS feed, so
client recipients and subjects never reach another application's database),
D3 (one `srcdoc` frame with `sandbox` and neither `allow-scripts` nor
`allow-same-origin`), and D5 (the RP ID is the dashboard's exact host, so the
hostname is on the critical path before any key is enrolled). D3 and D7 were
decided as recommended; D5 was reopened (`spec.md` §3).

**Found in the S2 audit:** refusals crossing RPC as thrown errors were logged
as uncaught exceptions and cancelled invocations, and lost their name and
fields between two processes. `MailService` therefore answers every call with a
plain result value (`contracts/mail-service-v1.md`), so the dashboard depends
on no error-serialization flag or compatibility date.

**The dashboard shell's commitments from its first step**, each with a test, because every
dashboard deploy is inside the key's trust boundary (D2): a strict nonce CSP
(`script-src 'nonce-…' 'strict-dynamic'; object-src 'none'; base-uri 'none';
frame-ancestors 'none'; connect-src 'self'`), Trusted Types enforced, zero
third-party scripts or analytics, and the inbox's client code (mail-crypto
included) split so it loads on inbox routes only. Consequences here:
`mail-crypto` and every runtime dependency use no `eval`, no `new Function`,
no WebAssembly and no DOM sink (S1 tests this); the inbox UI (S6) sets the
frame's `srcdoc` only through a named Trusted Types policy that returns
DOMPurify's `TrustedHTML`, loads nothing cross-origin, and uses no Web Worker
unless the shell adds a `worker-src` for it.

### Round 2 answers from the dashboard's maintainers (2026-09-28)

- **Capability v1**: claim `business` (not `tenant`), issuer
  `proprietor-dashboard`, audience `proprietor-mail`; the dashboard tests its
  minting against the regenerated vectors (G16).
- **The module boundary** (§14), agreed as proposed: this repository ships
  `mail-crypto`, a new framework-free `mail-client` and the `MailService`
  RPC; the dashboard hosts the inbox's route group, its module definition
  (`enabled` = `has.email`), the `MAIL` service binding, capability minting
  and the policy allowances. The route group's screens come from this
  project as a pull request into the dashboard, which its maintainers review
  where it meets the shell.
- **Policy**: nonce-stamped email styles on two conditions (the CSS is
  sanitised first; the nonce is read at run time from the page's own script
  element); no remote images; the Trusted Types allowlist gets
  `proprietor-mail#srcdoc` when enforcement starts.
- **Binary server-action arguments** are not verified in the dashboard's
  framework; use `FormData` with `File` parts. Its default body limit of
  1 MB is D22.
- **The operator's own business** does not exist on the platform yet (G20,
  D18). **`MailSignals`** is not started; the no-op adapter stays.
- **The new dashboard's cutover** to its final host has no date; S8 plans
  against it (G19, D12).

## 2. Repository layout and who owns what

```
proprietor-mail/
  specs/001-inbox-module/        architect
  contracts/                     architect (the .vectors.json files: S1 and S2)
  NOTICE, LICENSE                architect; every slice appends its adapted files to NOTICE
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

Worker name `proprietor-mail`. No public HTTP routes (`workers_dev: false`,
`preview_urls: false`): it is reached by Email Routing and by service binding,
nothing else. `fetch` answers 404 to everything.

Bindings (sketch; S2 writes the real `wrangler.jsonc`):

```jsonc
{
  "name": "proprietor-mail",
  "main": "src/index.ts",
  "compatibility_flags": ["nodejs_compat"],
  "workers_dev": false,
  "preview_urls": false,
  // No database_id: wrangler resolves the database by name (G24).
  "d1_databases": [{ "binding": "DIRECTORY", "database_name": "proprietor-mail", "migrations_dir": "migrations" }],
  "r2_buckets": [{ "binding": "MAIL", "bucket_name": "proprietor-mail" }],
  "durable_objects": { "bindings": [{ "name": "Mailbox", "class_name": "Mailbox" }] },
  "migrations": [{ "tag": "v1", "new_sqlite_classes": ["Mailbox"] }],
  "triggers": { "crons": ["*/5 * * * *"] },   // the deliverability feed (§13)
  "observability": { "enabled": true, "logs": { "invocation_logs": false } }   // G25, D20
  // secrets: MAIL_CAPABILITY_KEYS, SES_ACCESS_KEY_ID, SES_SECRET_ACCESS_KEY,
  //          MAIL_EVENTS_QUEUE_URL (it names the AWS account, so it is not a var)
  // vars:    SES_REGION = "us-east-1"
}
```

### Directory (Mail's own D1)

```sql
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
```

The operator provisions a mailbox by inserting one row with status
`provisioned` (a script prints the SQL; `wrangler d1 execute` runs it; the
operator's tooling can take this over later). The Directory is the authority for existence,
business and lifecycle; the Mailbox object is the authority for keys, messages
and policy. The Mailbox copies id, business and address from the Directory the
first time it is touched and refuses to be re-initialized with different
values.

### Mailbox (Durable Object SQLite, one per mailbox)

```sql
CREATE TABLE identity (only INTEGER PRIMARY KEY CHECK (only = 1), mailbox_id TEXT NOT NULL,
  business_id TEXT NOT NULL, address TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '');
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

R2 bucket `proprietor-mail`, one object per message: `mbx/<mailboxId>/msg/<messageId>`
holding the sealed raw message. Nothing else is written to R2.

## 4. `MailService` — the RPC surface

Every method takes the capability string first and resolves to a
`MailResult` (`contracts/mail-service-v1.md`): `{ ok: true, value }`, or
`{ ok: false, error }` whose `error.name` is one of `CapabilityRejected` (reason
`invalid` | `expired`), `NotFound`, `Forbidden`, `InvalidRequest`,
`MailboxNotActive`, `RateLimited` (`retryAfterSeconds`), `SendFailed`
(`retryable`), `AssistantUnavailable` or `InternalError`. Refusals are values,
never thrown exceptions (changed after the S2 audit; the contract file says
why). The "Returns" column below is the `value` of an `ok` result.

| Method | Needs `mbx` | Role | Returns / does |
|---|---|---|---|
| `mailboxes(cap)` | no | any | `[{ id, address, addresses, status }]` for the capability's business, so the module can show "not set up", "set up your inbox" or the inbox; `address` is the primary, `addresses` lists all, primary first (§12) |
| `mailbox(cap)` | yes | open | `{ id, address, addresses, status, displayName, keys[], wraps[], policy }` — wraps are ciphertext; `policy` includes `delivery` and `forwardTo` (M10) |
| `enroll(cap, { publicKey, wraps[] })` | yes | owner | only when `provisioned`; recomputes the keyId; requires one `recovery` wrap (M5); sets Directory `active` |
| `addWrap(cap, wrap)` / `removeWrap(cap, wrapId)` | yes | owner | the last recovery wrap cannot be removed |
| `list(cap, { folder, before?, limit? })` | yes | open | `{ items: [{ id, folder, direction, receivedAt, size, seen, flagged, keyId, keyEnvelope, header }], next }`, newest first, `limit` ≤ 100 |
| `body(cap, messageId)` | yes | open | `ReadableStream` of the sealed body |
| `update(cap, messageId, { seen?, flagged?, folder? })` | yes | open | moving to `trash` sets `trashedAt` |
| `purge(cap, messageId)` | yes | owner | row and R2 object deleted |
| `drafts(cap)` / `saveDraft(cap, { id, keyId, keyEnvelope, sealed })` / `deleteDraft(cap, id)` | yes | open | sealed in the browser |
| `send(cap, { idempotencyKey, from?, to, cc?, bcc?, subject, text, html?, inReplyTo?, references?, attachments?, draftId? })` | yes | send | `from` is one of the mailbox's addresses (default: the primary; M6). Refuses suppressed recipients with `RecipientSuppressed` (M11) before anything is reserved or sent. Builds MIME, sends through SES with the mailbox's SES tenant, its configuration set and the tag `mailbox=<id>` (§13), seals and stores the Sent copy, deletes `draftId`; plaintext lives only for the call |
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
| `store-and-forward`: forward succeeded, storing fails | do not throw; audit row + an operator alert; the forward target has the message |

Order inside `onEmail`: status check → size check → (forward, in
`store-and-forward`) → read raw → parse → seal → R2 put → SQLite insert (a
failed insert deletes the R2 object it just wrote) → new-mail count. Nothing
from the message is logged: logs carry the mailbox id, the message id, the
size and the outcome.

## 6. Infrastructure to create later (specified here, applied by nobody yet)

The shapes are here; the operator's real values (account and zone ids, domain
names, secret-store paths, infrastructure-code locations) are kept in the
operator's private deployment notes. `example.com`, `client-example`,
`send-example-mail` and AWS's documented placeholder account `123456789012`
stand in for them.

**Cloudflare** (Terraform, in the operator's infrastructure code, applied the
way the operator applies every change there):

- D1 `proprietor-mail`, R2 bucket `proprietor-mail` (private, no public access), the
  Worker itself (deployed with Workers Builds).
- **Receiving for the first mailbox's domain** (D4): `cloudflare_email_routing_dns`
  on that zone (writes the MX and the apex SPF; the SES MAIL FROM subdomain is
  separate and untouched), and one `cloudflare_email_routing_rule`:
  `hello@example.com` → worker `proprietor-mail`. DMARC for the domain in monitor
  mode if it is still absent. The Terraform credential needs the Email Routing
  permissions.
- Nothing for Access: Mail has no web surface.

**AWS SES** (D7; Terraform, or the AWS CLI where the provider lacks a resource):

- One SES tenant per business with mail (`client-example`), associated with its
  identity and its configuration set, `SuppressionScope: TENANT`.
- A client-mail configuration set per sending domain (`send-example-mail`),
  following the platform's convention of one configuration set per domain,
  never shared. One shared set for all clients would also work with
  tenant-scoped suppression; the per-domain set keeps that convention literally
  true.
- Their event destination goes to **Mail's own** SNS topic and SQS queue
  (`proprietor-mail-events`), never to another application's event feed: client
  recipients and subjects must not land in any other database.
- A new IAM principal for client mail, policy to be checked in the IAM
  policy simulator before it is attached:

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Sid": "SendOnlyAsClientMailboxes",
      "Effect": "Allow",
      "Action": ["ses:SendEmail"],
      "Resource": [
        "arn:aws:ses:us-east-1:123456789012:identity/example.com",
        "arn:aws:ses:us-east-1:123456789012:configuration-set/send-example-mail"
      ],
      "Condition": { "StringEquals": { "ses:FromAddress": ["hello@example.com"] } }
    }]
  }
  ```

  Corrected after S3 read the SES v2 service authorization reference and the
  SendEmail model: a v2 raw send is authorized as `ses:SendEmail` alone
  (`ses:SendRawEmail` is the v1/SMTP permission), and a tenant is not a
  resource type of `SendEmail`, so a `tenant/*` ARN in `Resource` would do
  nothing. Pin the tenant with a condition on the tenant name instead, once
  sends carry `TenantName` (confirm the condition key's exact name in the
  reference). Check the whole policy in the IAM policy simulator before it is
  attached. The platform's existing notification sender is restricted to its
  own `ses:FromAddress` at the same time, so neither key can send as the other.

**Secrets** (from the operator's secret store; they reach Workers through the
process environment only):

- The capability keys, `keys` (the JSON map) and `current_kid`; into both the
  dashboard and Mail Workers (`contracts/capability-v1.md`).
- The client-mail principal's access key; into the Mail Worker only.

## 7. How it is tested — no real mail to or from anyone

- **Worker tests** run in workerd (`@cloudflare/vitest-pool-workers`): a
  real D1 with the real migration, a real Durable Object,
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
  and suppression-list addresses), only with a credential put into the
  environment from the operator's secret store, and only in a test file that
  skips when the variables are absent.

## 8. Moving a forwarded address to the inbox: dual delivery (planned, not executed)

A business may already receive mail at its own domain through an Email Routing
rule that forwards it to a personal mailbox, for example `info@example.com`
forwarded to the owner's existing webmail. That is real business mail, so
nothing below happens without the operator's go, and each step has its way
back. The runbook for a particular client (names, addresses, infrastructure
files) is kept in the operator's private deployment notes.

1. **Prerequisites.** The operator's own mailbox has run for at least two
   weeks with no lost or duplicated mail. D1, D2 (publication), D5 and D7 are
   decided. The Worker's throw behaviour (spec §8) is verified.
2. **Provision** the business's mailbox (`provisioned`), its SES tenant and its
   configuration set.
3. **The owner sets it up themselves**, on their own device, at their
   dashboard: passkey, recovery key printed or saved by them. The operator does
   not sit in for this step (D9); if the owner needs help it is over the phone,
   never by taking their device.
4. **Dual delivery.** Set the mailbox's delivery to `store-and-forward` with
   `forwardTo` = the address the rule forwards to today (already a verified
   destination on the account), then change the rule's action from `forward`
   to `worker proprietor-mail`. The Worker forwards first and stores second
   (§5), so the existing mailbox keeps receiving everything even if storage
   fails. The owner's dashboard shows "Also forwarded to <that address>".
5. **Watch for two to four weeks**: forwards attempted vs succeeded (must be
   equal), messages stored vs forwarded, no duplicates reported by the owner.
6. **The owner decides** whether to stop the forwarded copy. Only on their word
   (delivery → `store`).

**Rollback at any point:** restore the rule's `forward` action (one
infrastructure change). Mail stored during the trial stays in the mailbox; the
existing mailbox never missed anything, because during step 4 it got every
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

## 10. The inbox screens (held until the dashboard's first step)

The inbox's route group in the dashboard (a separate application; a change on
that side). Screens:

- **Not set up** (no mailbox for the business): "Your inbox isn't set up yet."
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

Workers Builds on `main`. First deploy only after D1, D4, D5 and D7 are
decided and the Cloudflare/AWS resources in §6 exist. The first routed address
is the operator's own mailbox; the first owner is the operator, enrolling on
their own devices.

## 12. Several addresses, one mailbox (round 2, G12)

Migration `0002_addresses.sql` (the Directory is not deployed anywhere yet,
but the migration is added rather than folded into 0001, so that each slice
owns its own file):

```sql
CREATE TABLE addresses (
  address     TEXT PRIMARY KEY,                       -- lower-case
  mailbox_id  TEXT NOT NULL REFERENCES mailboxes(id),
  created_at  TEXT NOT NULL
);
CREATE INDEX addresses_by_mailbox ON addresses(mailbox_id);
```

- The resolver looks an envelope recipient up in `addresses`, joined to its
  mailbox. `mailboxes.address` stays the **primary address**: the Mailbox's
  identity (unchanged, so the identity check still compares it) and the
  default `From`.
- Provisioning prints one transaction: the mailbox row, then one `addresses`
  row per address, primary first. A second printer adds an address to an
  existing mailbox. Nothing removes an address (D-1): an address that ever
  delivered to a mailbox stays with it, closed or not.
- The Directory refuses an address that belongs to another mailbox (primary
  key), and a test proves D-2 (the primary is always one of the mailbox's
  addresses) for every row the printers can produce.
- **Sealed, not stored**: the Worker adds `envelopeTo` (the envelope
  recipient, one of the mailbox's addresses) to the sealed MessageHeader of
  every arrival, `null` on sent copies (envelope v1, amended before the first
  enrollment). The browser uses it to merge the copies of a message sent to
  two of the addresses (G13) and to reply from the address a message arrived
  at.
- **Sending as an address**: `send` takes an optional `from`, checked against
  the Directory's addresses on every call; the display name is the mailbox's.
  The sending principal's policy lists exactly these addresses (D14).

## 13. The deliverability feed (round 2, S5)

```
  Mail's send ──(ConfigurationSetName = the mailbox's, TenantName = its SES tenant,
                 EmailTags [{ Name: "mailbox", Value: <mailbox id> }])──▶ SES
  SES configuration set (one per sending domain, Mail's own)
     └─ event destination: BOUNCE, COMPLAINT, REJECT, DELIVERY_DELAY, RENDERING_FAILURE
          ──▶ SNS topic (Mail's own) ──▶ SQS queue (Mail's own; raw delivery; SSE;
                                          retention 4 days; dead-letter queue after 5 reads)
                                                  ▲
  Mail Worker, cron every 5 minutes: ReceiveMessage (AWS JSON protocol, SigV4 with
  aws4fetch and the sending principal's credential) → parse → route by the
  `mailbox` tag → Mailbox.recordDeliveryEvent → DeleteMessageBatch
```

- **No DELIVERY, SEND, OPEN or CLICK events**: every SES event carries the
  recipients and usually the subject (`commonHeaders`), so Mail subscribes
  only to what it acts on (D8).
- **Routing** is by Mail's own tag alone (G22). SES tags allow ASCII letters,
  digits, `_` and `-`, so a mailbox id fits as is. An event without the tag,
  or naming a mailbox that does not exist, is deleted and raised as an
  operator alert; nothing is ever logged from its content.
- **What a mailbox keeps** (M11, D15): for a `Permanent` bounce and for every
  complaint, the HMAC-SHA-256 of each named recipient's lower-cased address
  under the mailbox's own random 32-byte key, the reason, and first and last
  dates. `Transient` bounces, delays, rejects and rendering failures change
  nothing stored; they are counted in the Worker's log line (counts only).
  Entries lapse one year after their last event (the daily housekeeping).
- **At least once** (M12): SQS may deliver an event twice; recording is an
  upsert, so a second delivery changes nothing.
- **Refusing before sending**: `send` hashes every recipient and answers
  `RecipientSuppressed` with `{ field, index, reason, since }` for each hit,
  before reserving the idempotency key and before the rate limit counts it.
  SES's own tenant-level list (D23) stays the backstop.
- **Owner-visible bounces**: SES feedback forwarding (on by default) sends
  the bounce notification to the sending address, where it arrives as an
  ordinary message, sealed. Whether SES v2 falls back to the `From` address
  when no feedback address is given is not verified; the S8 simulator send
  settles it.

## 14. The browser half and the inbox screens (round 2, S6)

The boundary agreed with the dashboard's maintainers (§1, round 2):

```
  this repository (published)                  the dashboard (not published)
  ───────────────────────────────              ──────────────────────────────────────
  @proprietor/mail-crypto   envelope v1   ──▶  app/(modules)/inbox/_vendor/…  (VERSION,
  @proprietor/mail-client   keys, unlock,        SHA256SUMS, a test that recomputes them)
                            open, threads,     app/(modules)/inbox/**  screens, server
                            search, render,      actions, the one GET body route
                            compose helpers    modules/inbox.ts  (enabled = has.email)
  MailService (RPC)         ciphertext out ──▶ MAIL service binding, mailCapability()
```

- `contracts/mail-client-v1.md` is the API and its rules; the stub in
  `packages/mail-client` is its signature. The screens never hold a key,
  parse MIME or write message HTML: they call `mail-client`.
- The screens: not set up, set up (the key ceremony), unlock, the folders
  and threads, search, reading in the one frame, compose / reply / forward
  with drafts sealed on every save, and settings (display name, devices,
  recovery key, "How your mail is protected", the assistant shown "Off").
  Styled with the shell's theme tokens only.
- Transport: server actions return `MailResult` values unchanged; the body
  route streams ciphertext; sending posts `FormData` built by
  `encodeSendForm` and read by `decodeSendForm` (D22 decides the size limit).

## 15. Activating the operator's own mailbox (round 2, S8)

The operator's private runbook carries the real names and commands; this is
its shape. Every step is the operator's go; each has its way back.

1. **Gates**: the dashboard with the inbox serves its final host (G19, D12);
   the operator's business exists on the platform (D18).
2. **Infrastructure** (Terraform, parked until go): Mail's R2 bucket; Mail's
   configuration set for the domain, its SNS topic, SQS queue and dead-letter
   queue; the SES tenant and its associations (identity, configuration set);
   the sending principal's policy (its user is created by hand, inside the
   operator's sending boundary). Tenant suppression scope by CLI, since the
   provider has no resource for it; a new tenant gets the `standard`
   reputation policy by itself. The D1 Directory is created with wrangler
   BEFORE the first deploy (the operator's infrastructure credential has no
   D1 permission, on purpose): `wrangler.jsonc` names it by name only, and
   a failed lookup at deploy would create one of its own.
3. **Secrets** into the secret store, then into the Workers through standard
   input: the capability keys (both Workers), the sending principal's key and
   the queue's URL (Mail only).
4. **Probe** on a throwaway address with a throwaway Worker: what Email
   Routing does when `email()` throws, and what Workers Logs records for an
   email invocation (G25). Then remove both.
5. **Deploy** Mail: `wrangler d1 migrations apply --remote`, `wrangler
   deploy`, with the account from the environment.
6. **Provision** the mailbox and its addresses (the printed, reviewed SQL).
7. **Enroll**: the operator, on their own devices, in the dashboard.
8. **Dual delivery** (D13): `store-and-forward` to today's forward target,
   then switch the routing rules from `forward` to the Worker.
9. **Send tests**: the SES mailbox simulator first (success, bounce,
   complaint), then a real round trip.
10. **After two weeks** with no lost or duplicated mail: `store`, on the
    operator's word.

**Rollback at any step after 8**: restore the rules' `forward` action.

