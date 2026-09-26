# Domain model — the Inbox module

**Spec:** `spec.md` · **Plan:** `plan.md` · **Written:** 2026-09-26

The DDD pass, done before any code so that the gaps show up as questions and
not as migrations. It found eleven; they come first.

## 0. Gaps this pass found

| # | Gap | What happens if it is missed | Resolution |
|---|---|---|---|
| G1 | **Zero-access and a server-side AI assistant conflict.** Whatever can decrypt on the server can be made to decrypt for the operator. | A promise ("the maintainer can't read it") that the architecture does not keep. | Decision D1; the assistant is off and cannot be turned on in v1. |
| G2 | **Tenant membership is not mail access.** the maintainer is an accepted editor member of client tenants, so "any member may open the tenant's mailbox" would hand him ciphertext and metadata, and a setup flow he could run would hand him keys. | Zero-access broken by a convenience. | Read access is key possession, and keys are enrolled only on the owner's device. `openRoles` defaults to owners (D9). |
| G3 | **Passkeys are bound to a domain, and the dashboard is being renamed.** | Every enrolled passkey stops working at the rename; owners are locked out until they find their recovery key. | D5: fix the host before the first enrollment; the recovery key always works. |
| G4 | **With no iframes, the key lives in the whole dashboard's page.** | The promise would imply that only the inbox code handles keys. | D2: disclosed in the promise; publication of bundle hashes before the first client mailbox. |
| G5 | **Email HTML is hostile input in the same page as the key.** | One sanitizer bypass is a key theft. | D3: a script-less sandboxed frame for bodies; no remote content by default. |
| G6 | **Search and threading cannot run on the server** once headers are encrypted. | A server-side search API that could only work by keeping plaintext. | Both move to the browser over decrypted headers; bodies are searched later from a local index. |
| G7 | **A malicious server can substitute the mailbox public key** and receive future mail encrypted to a key it controls. | Silent interception after a key swap. | The browser checks the advertised public key against the unwrapped private key at every unlock and shows a blocking warning on a mismatch; key changes are audited. |
| G8 | **A mailbox with no key yet has nowhere safe to put mail.** | "Store it readable until they set up" — a plaintext backlog. | A mailbox is `provisioned` until keys are enrolled and never stores mail in that state; routing is pointed at the Worker only after activation. |
| G9 | **operator.example receives no mail today**, by a recorded decision (`cloudflare-infra/mail.tf`, 2026-09-06). | The "first mailbox" has no address to receive at. | D4. |
| G10 | **The operator controls routing.** Whoever controls Email Routing can add a forward of future mail to themselves, outside this module entirely. | A promise that ignores the routing layer. | Covered by the promise's first limit (mail in transit). The mailbox's own forwarding setting is always shown to the owner and every change is audited. |
| G11 | **Dual delivery can duplicate or drop.** During Alex's migration a Worker error after forwarding could make Email Routing retry and forward twice; an error before forwarding could lose the copy in his Gmail. | Duplicate or missing mail for a real business. | Forward first; never throw after a successful forward; failures to store are counted and alerted. `plan.md` §8. |

## 1. Bounded contexts

| Context | Owns | Lives in | Language |
|---|---|---|---|
| **Mail Storage** | Mailbox, StoredMessage, Folder, Draft, KeyRing, Mailbox policy, Audit | `platform-mail` Worker: the `Mailbox` Durable Object | "message", "sealed", "folder" |
| **Mail Directory** | Which mailbox an address belongs to, which tenant a mailbox belongs to, its lifecycle status | `platform-mail` Worker: Mail's own D1 | "mailbox", "address", "provisioned/active" |
| **Inbound Delivery** | Accepting or refusing an arriving message; forwarding during migration | `platform-mail` Worker: `email()` handler + `Mailbox.onEmail` | "arrival", "reject", "forward" |
| **Outbound Sending** | Turning a composed message into MIME and handing it to SES; rate limits; idempotency | `packages/mail-outbound` (the MIME builder and the SES adapter) + `Mailbox.send` | "send", "tenant", "configuration set" |
| **Key Custody** | Generating mailbox keys, wrapping and unwrapping them, sealing and opening messages and drafts | `packages/mail-crypto`, running in the owner's browser (and, for sealing only, in the Worker) | "wrap", "unlock", "recovery key", "seal/open" |
| **Identity & Access** | Accounts, memberships, the session, the tenant chooser; minting Mail capabilities | the dashboard shell (spec 007, SEO-engine repo) | "session", "membership", "capability" |
| **Business Catalogue** | The site manifest and `has.email` | the SEO engine | "module", "manifest" |
| **Presence** | Live state and Web Push for a business | the per-business Agent (spec 007) | "new mail count" |
| **Deliverability** | Bounces, complaints and suppression for client mail | `platform-mail` (a later slice), fed by the `send-clients` event destination | "bounce", "suppressed" |
| **Assistant** (held) | AI help over one mailbox's mail, only when the owner opted in | a separate Durable Object class in `platform-mail`, never instantiated in v1 | "ask", "draft", "opt-in" |

## 2. Context map

```
   Identity & Access (dashboard shell) ── Published Language: capability v1 ──▶ Mail Storage
        (supplier of who the person is)          contracts/capability-v1.md       (customer)

   Mail Storage ── Open Host Service: MailService RPC ──▶ dashboard inbox route group
                                                             (conformist to the RPC shapes)

   Key Custody ◀── Shared Kernel: envelope v1 (contracts/envelope-v1.md) ──▶ Mail Storage
      (browser)       one implementation, packages/mail-crypto, used by both

   Cloudflare Email Routing ──▶ Inbound Delivery        conformist (ForwardableEmailMessage)
   Outbound Sending ──▶ Amazon SES                      anti-corruption layer (a port + one adapter)
   Mail Storage ──▶ Presence                            one event: { tenantId, mailboxId, unread }
   Business Catalogue ··▶ dashboard                     has.email decides whether the module shows;
                                                        Mail never reads manifests
```

Mail is deliberately **independent of the auth provider**: it verifies a
capability, not an Access token and not a Better Auth session, so spec 008's
swap from Access to Better Auth does not touch it. And a Worker that merely
has a binding to Mail cannot open a mailbox, because it cannot mint a
capability without the key.

## 3. Aggregates and their invariants

### Mailbox (root) — one Durable Object per mailbox

Holds: identity (id, tenant, address — copied from the Directory at first
contact and never changed), the key ring, folders, stored messages, drafts,
sends, policy and audit.

Invariants, each a test:

- **M1 — No plaintext at rest.** Nothing the Mailbox writes to its SQLite, to
  R2 or to a log contains message content in the clear: not a subject, not a
  sender name, not a body, not an attachment name. Only sealed blobs and the
  metadata listed in `spec.md` §4.
- **M2 — No key, no mail.** A mailbox that is not `active` stores nothing; an
  arriving message is rejected with `setReject`.
- **M3 — The server holds no private key while the assistant is off.** No
  table, blob or variable in the Worker holds a mailbox private key or a
  message key in the clear, for any mailbox whose policy says `off` (in v1:
  every mailbox).
- **M4 — A mailbox belongs to one tenant for life.** Every call is checked:
  the capability's tenant and mailbox must equal the mailbox's own; a mismatch
  answers "not found", never "forbidden", so existence does not leak across
  tenants.
- **M5 — Activation requires a recovery wrap.** The mailbox becomes `active`
  only when its key ring has a public key and at least one recovery-key wrap.
  The last recovery wrap cannot be removed.
- **M6 — Only the owner sends, as the mailbox.** `From` is always the mailbox
  address; the request cannot choose it. Roles allowed to send default to
  `owner`.
- **M7 — Sending is bounded and idempotent.** At most 20 messages an hour and
  100 a day per mailbox (agentic-inbox's limits), at most 50 recipients a
  message; a repeated idempotency key returns the first result and sends
  nothing.
- **M8 — System folders are fixed.** Inbox, Sent, Drafts, Archive, Trash and
  Spam always exist and cannot be renamed or deleted.
- **M9 — Trash empties itself.** A message in Trash for 30 days is deleted
  (row and R2 object).
- **M10 — Forwarding is visible and audited.** Delivery mode and forwarding
  target are returned on every `mailbox()` read, and every change writes an
  audit row naming who and when.

### StoredMessage (entity inside Mailbox)

`id`, `direction` (in/out), `receivedAt` (server clock), `size`, `folder`,
`seen`, `flagged`, `keyId`, `keyEnvelope` (the message key sealed to the
mailbox key), `header` (sealed header block), `bodyKey` (the R2 object of the
sealed raw message), `trashedAt`.

Duplicates from a redelivery are accepted; the browser drops duplicates by
decrypted Message-ID. The server cannot deduplicate without keeping a
fingerprint of the content, which would itself leak.

### Draft (entity inside Mailbox)

Sealed in the browser with the same envelope as a message. The server sees an
id, a time and a blob.

### KeyRing (value-rich entity inside Mailbox)

One active key (`keyId`, raw X25519 public key); retired keys stay readable
for old mail. Wraps: `{ id, keyId, kind: passkey-prf | recovery, credentialId
(passkey only), label, wrapped, createdAt, createdBy }`. Passphrase wraps are a
later addition for devices without PRF.

### Directory entry (aggregate in Mail's D1)

`{ id, tenantId, address, status, sesTenant, createdAt, activatedAt,
closedAt }`. Status moves `provisioned → active → suspended ⇄ active →
closed`. Invariants: an address belongs to one mailbox (UNIQUE); a tenant has
at most one mailbox in v1 (UNIQUE, relaxed when aliases arrive); `closed` is
terminal.

### Capability (value object, Published Language)

`{ sub: accountId, tenant, mbx?, role, iat, exp, aud: "platform-mail", iss:
"platform-dashboard" }`, an HS256 JWT signed with a key only the dashboard and
Mail hold, valid for at most 60 seconds. `contracts/capability-v1.md`.

### Envelope (value object, Shared Kernel)

`contracts/envelope-v1.md`: HPKE-sealed message key, AES-256-GCM header and
body, each bound to its mailbox and message by associated data.

## 4. Ubiquitous language

| Term | Means | Does not mean |
|---|---|---|
| **Mailbox** | One business's store of mail, with one address and one key ring | A tenant; a person |
| **Owner** | A member with role `owner` of the mailbox's tenant | Anyone in the Access policy |
| **Provisioned** | The operator created the mailbox; no key yet; refuses mail | Working |
| **Active** | Keys enrolled; accepts mail | Unlocked |
| **Unlocked** | A browser holds the private key in memory right now | Active |
| **Seal / open** | Encrypt to the mailbox public key / decrypt with its private key | Sign |
| **Wrap / unwrap** | Encrypt / decrypt the private key under a passkey- or recovery-derived key | Seal |
| **Recovery key** | A 256-bit secret shown once at setup, never stored by the platform | A password reset |
| **Capability** | A ≤ 60 s signed statement from the dashboard: this account, this tenant, this mailbox, this role | A session |
| **Assistant** | The AI helper, off unless the owner opts in | The mailbox's Durable Object (which is an Agents SDK `Agent` class for `onEmail`, and runs no model) |

## 5. What agentic-inbox's model becomes

| agentic-inbox | Here | Why |
|---|---|---|
| Mailbox list in R2 JSON, any Access user sees all | Directory in D1, capability per call, owners only | per-tenant isolation (M4, D9) |
| `emails.body` plaintext in DO SQLite | sealed header in SQLite, sealed raw message in R2 | M1 |
| attachments as separate plaintext R2 objects | inside the sealed raw message, parsed in the browser | M1; one object per message |
| server-side SQL search and subject threading | browser-side, over decrypted headers | G6 |
| `send_email` binding (Cloudflare Email Service) | SES v2 raw send through a port | the platform's outbound decision |
| auto-draft on every arrival | off; held behind D1 | M3 |
| MCP server | removed | no per-mailbox authorization |
| folders, rate limits, threading headers, reply quoting, sandboxed HTML frame | kept, adapted, with attribution | they are right |
