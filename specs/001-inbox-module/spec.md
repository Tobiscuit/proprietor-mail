# 001 — The Inbox module

Status: written 2026-09-26. Spec only; nothing is deployed and no live
infrastructure was changed. The six seams with the SEO-engine session were
answered the same day and are recorded in `plan.md` §1.

Companion documents: `domain-model.md` (the DDD pass and the gaps it found),
`plan.md` (architecture, contracts, infrastructure, the Alex migration),
`tasks.md` (the builder slices), `../../contracts/` (the two contracts other
repositories implement).

## 1. What the maintainer asked for

- **One mailbox per business**, isolated per tenant, read inside the ONE
  dashboard (a route group in the dashboard app, in the dashboard's design
  system, themed from each client's own website). No full-page mail app, no
  iframes for composition, no module federation.
- **Client mail is zero-access.** the maintainer must not be able to read a client's
  mail. His words: "I run the wall of not being trusted."
- **Nothing client-facing depends on the operator's node** at runtime. The node is
  the operator's workbench (Vault, seo-admin) and nothing more.
- **Inbound** through Cloudflare Email Routing to a Worker, handed to a
  per-mailbox agent (Agents SDK `onEmail` / `routeAgentEmail`).
  **Outbound** through Amazon SES, not through Cloudflare's own sending.
- **Identity** is the platform login plus per-tenant membership. The module
  turns on when a site's manifest declares `has.email`.
- **The AI agent** from cloudflare/agentic-inbox keeps its tools, reconciled
  with zero-access. The safe default is built: the assistant is OFF for every
  mailbox, on only by an explicit opt-in.
- **The first mailbox is the maintainer's own operator mailbox.** Alex's comes
  later, through a safe, reversible migration that this spec plans and nobody
  executes yet.

## 2. The promise — and why its wording is the top decision

"the maintainer can't read your mail" can mean two different things, and a client is
owed the one that is true.

**A structural guarantee.** The servers never hold the key that opens stored
mail. Whoever has the database, the backups or the operator's account still
holds only ciphertext. This is what end-to-end encryption with keys kept on
the client's own devices gives.

**A policy guarantee.** The servers hold a key (so that a server-side feature,
such as an AI assistant, can read the mail), and a rule says nobody uses it
except for that feature. This can be audited and logged, but the operator who
owns the Cloudflare account and deploys the code is always *able* to read the
mail. The SEO-engine session put it exactly: it can be kept from him by policy
and audit, but not made impossible.

A server-side AI assistant needs the plaintext on the server. So the two goals
"the operator can't read it" and "an AI on the operator's infrastructure reads
it" conflict, and one of them has to give way per mailbox. That is Decision 1.

Even the structural option has two limits that apply to every web-based
encrypted mail service, and the promise has to name them rather than hide
them:

1. **Mail in transit.** Internet email arrives as plaintext at the receiving
   server and leaves as plaintext through the sending server. The platform's
   Worker encrypts each arriving message immediately and never stores it
   readable, and it holds an outgoing message only for the moment it hands it
   to SES. But during those moments the operator's code has the plaintext, and
   a changed version of that code could copy it.
2. **The code in the browser comes from the operator.** Decryption happens in
   the client's browser, in JavaScript the dashboard serves. A changed version
   of that JavaScript could read the key after the client unlocks. In 2026 no
   mainstream browser verifies web-app code against a published record:
   Cloudflare's WAICT proposal (October 2025) has a prototype in Firefox
   Nightly only, and other browsers have not taken a position (waict.dev,
   checked 2026-09-26). Because modules may not be isolated in iframes (a
   platform rule), the key lives in the same page as the whole dashboard, so
   this limit covers the dashboard's entire front-end, not just the inbox
   screens (Decision 2).

What the structural option does make impossible is reading **stored** mail
without first changing the code: not from the database, not from R2, not from
a backup, not from a Cloudflare dashboard, not by answering a request for a
client's data.

### The promise, worded for each option

These are the texts the owner is shown. Whichever option the maintainer picks, the
wording ships with it; the dashboard never shows a stronger claim than the
option supports.

**Option A — encrypted with your key (structural).**
> Mail in your inbox is stored encrypted with a key that only your own devices
> hold. Operator's servers never have that key, so the stored mail is
> unreadable without it — to Operator, to anyone who obtains a copy of the
> database, and to anyone who asks Operator for it.
> Two honest limits: like every email service, the platform's software handles
> each message in readable form for the moment it arrives and the moment you
> send one, and does not keep it that way. And the inbox runs in your browser
> from code Operator serves, so a changed version of that code could read what
> you read.

When Decision 2's publication step exists, one sentence is added: "Every
version of that code is published, so a change like that would be on the
public record." Until then it is not said.

**Option B — encrypted, with the key on our servers (policy).**
> Your mail is stored encrypted, and the platform holds the key so that
> features like the assistant can work. Operator's policy is never to open
> your mail, and every time the platform's software decrypts it, the access is
> recorded in a log you can see. Operator is technically able to read your
> mail: this is a promise about how we behave, not a technical barrier.

The word "can't" never appears in Option B's wording, anywhere.

**Option C — A by default, B only for a mailbox that turns the assistant on.**
The mailbox shows Option A's wording. Turning the assistant on is a separate,
explicit step by the owner, on a screen that shows Option B's wording and
asks for a second confirmation. While it is on, the mailbox shows Option B's
wording and a visible "Assistant is on" marker. Turning it off deletes the
server's copy of the key and returns to Option A's wording, plus one sentence:
"The assistant's copy of your key was deleted on <date>. We can't prove to you
that no other copy exists, so treat mail from the time it was on as having
been readable by the platform."

A narrower form of C needs no standing key at all: **ask about one message.**
The owner presses "Ask the assistant" on a single email; the browser sends
that one message's key to the assistant for that one request, and the
confirmation says so: "To answer, this message will be decrypted on Operator's
servers for the assistant. While it is there, Operator could technically read
it."

## 3. Decisions for the maintainer

**Decided 2026-09-26: the maintainer approved all ten as recommended — then REOPENED
D5 the same day.** He is weighing a separate domain for the whole platform
(dashboard, inbox, anything clients log into or receive mail from), with
operator.example staying his business website. Until he picks, nothing may enroll a
passkey or bake a platform host in anywhere; `app.operator.example` is on hold, not
decided. D2's publication step (making this repository public under D10's
Apache-2.0) still gets his explicit go at the moment it happens, because making
a repository public cannot be taken back.

| # | Decision | Recommendation |
|---|---|---|
| **D1** | **Which zero-access option — A, B or C — and therefore what the assistant can be.** | **C, with A as every mailbox's default.** Build A now (it is the design already on record for client mail: encrypt on arrival with the client's public key, private key only on the client's devices, recovery key shown once, decrypt in the browser). Offer "ask about one message" as the first AI feature, because it discloses one message rather than the whole mailbox. Build the standing opt-in (key escrow) only after the maintainer approves Option B's wording as the text an owner sees when turning it on. Never offer Option B as a platform-wide default. |
| **D2** | **The browser trust boundary.** With the no-iframes rule, the key lives in the same page as the whole dashboard, so every dashboard deploy is inside the mail trust boundary. | **For v1, accept it and disclose it** (Option A's second limit says so), and shrink what can go wrong inside it: the SEO-engine session has committed the shell, from spec 007 step 0, to a strict nonce CSP, enforced Trusted Types, zero third-party scripts, and loading the inbox code on inbox routes only, each with a test. Before Alex's mailbox exists: open-source `platform-mail` (the Mail Worker and `mail-crypto`) under Apache-2.0 and publish a SHA-256 manifest of the dashboard's client bundle for every deploy, so the claim "published" becomes true; serve a WAICT integrity manifest as well, knowing that only Firefox Nightly checks it today. If a client ever needs more, the stronger design is a separate-origin key vault page, which needs an explicit exception to the no-iframes rule — not recommended for v1. |
| **D3** | **A sandboxed frame for message bodies.** Email HTML is hostile input. Rendering it in the dashboard page means one sanitizer bypass runs script in the page that holds the key. agentic-inbox renders it in a `srcdoc` iframe with a sandbox and a strict CSP. | **Allow it as a security control, not as composition.** One `srcdoc` frame with `sandbox` and neither `allow-scripts` nor `allow-same-origin` (so it can neither run script nor share the page's origin), set through a Trusted Types policy, remote images blocked until the owner clicks "show images", fixed to the reading pane with its own scrolling (it cannot report its height without script). This is the only frame the module uses. The SEO-engine session agreed to exactly this on 2026-09-26. |
| **D4** | **The first mailbox's address.** Today operator.example has no MX record and receives no mail; `cloudflare-infra/mail.tf` records a 2026-09-06 partition that says so ("operator.example keeps its SES sending identity only") and assigns the maintainer's own mail to @personal.example, which currently forwards through Namecheap's registrar forwarding. | **`hello@operator.example`**, with Email Routing enabled on operator.example (MX + SPF at the apex; the SES MAIL FROM subdomain is unaffected). This changes the 2026-09-06 note for operator.example only. It dogfoods exactly what clients will get, on the brand the platform is sold under. |
| **D5** | **The dashboard's final hostname, before anyone enrolls a mail key.** Passkeys are bound to a domain (the WebAuthn RP ID); the dashboard is being renamed from review.operator.example. | **REOPENED 2026-09-26 (see above).** **Choose the final host first and use exactly that host as the RP ID.** Do not use the parent `operator.example`: any operator.example subdomain, including the Vercel-hosted www site, could then ask the same passkey for the same secret. If the host ever changes again, owners re-enroll with their recovery key. The SEO-engine session agrees and is telling the maintainer the rename is now on the critical path. |
| **D6** | **Lost keys mean lost mail.** The recovery key is shown once and never stored by the platform. If an owner loses every device passkey and the recovery key, nobody — the maintainer included — can open the stored mail. | **Accept it, and say it at setup.** Enrollment requires saving the recovery key (a printable sheet) before the mailbox activates. Support's answer to "I lost everything" is: your old mail cannot be recovered; new mail will arrive once you set up a new key. |
| **D7** | **SES isolation for client mail** (the SEO-engine session's answer (d) plus a newer SES feature). | **One SES tenant per client business** (SES "tenants": `TenantName` on `SendEmail`, a reputation policy and a pause switch per tenant, tenant-level suppression — AWS docs, checked 2026-09-26), a shared `send-clients` configuration set with its own event destination, and a client-mail IAM principal whose policy names only client identities, that configuration set and `ses:FromAddress` values that are mailbox addresses. Client-mail events go to Mail's own SNS/SQS feed, never the engine's, so client recipients and subjects never reach the engine's `mail_events`. Also tighten the notification principal `ses-send-app` to `ses:FromAddress = notify@operator.example`, so neither key can send as the other. The SEO-engine session agreed on 2026-09-26. Infrastructure only; specified in `plan.md` §6, not applied. |
| **D8** | **Metadata the platform can see**, even under Option A (§4). | **Accept and publish the list** in the owner-facing "How your mail is protected" page. Minimize: the Mail Worker never logs addresses or subjects, and the bounce/complaint consumer keeps only the recipient address and the result. |
| **D9** | **Who may open a mailbox.** the maintainer is an accepted editor member of client tenants in the engine (so he can open their dashboards). Tenant membership must not mean mail access. | **Only owners open a mailbox by default** (`openRoles: ["owner"]`), and the key ceremony runs on the owner's own device. the maintainer never enrolls a key for a client, never sees a client's recovery key, and never sets a client's mailbox up "to save them time". |
| **D10** | **The repository's license, when opened.** | **Apache-2.0**, matching the upstream the adapted code comes from, and allowing anyone to verify builds. |

Track B (operator.example intake) has its own decisions in
`~/portfolio/specs/001-platform-intake/spec.md`.

## 4. What the platform can see, even under Option A

This is the list D8 asks the maintainer to accept and publish. "Can see" means the
operator could read it from systems he controls.

| What | Where it is visible | Why it exists |
|---|---|---|
| That a message arrived, when, how large, for which mailbox | Mailbox storage (plaintext columns) | Sorting, quotas, the unread count |
| Folder, read and starred flags | Mailbox storage | Set by the owner's own actions |
| Envelope sender and recipient of arriving mail | Cloudflare's Email Routing, in transit (whether its activity log shows them is unverified) | That is how SMTP delivery works |
| The full message, in transit, for the moment of arrival | Mail Worker memory | Encryption happens there, immediately |
| Recipients and subject of mail the owner sends, and the full message for the moment of sending | Mail Worker memory; SES delivery events include `commonHeaders` with the subject (AWS event-publishing examples, checked 2026-09-26) | SES needs the message to send it; SES reports what it delivered |
| That a new message arrived (a count, never content) | The per-business dashboard Agent, for Web Push | So the phone can buzz |
| Which devices and recovery keys exist (labels and times, not the secrets) | Mailbox key ring | So the owner can manage devices |

Everything else — subject, sender name, body, attachments, drafts, search,
threads — is encrypted before it is stored and decrypted only in the owner's
browser.

## 5. How it works

```
                    Cloudflare Email Routing                Amazon SES
                    (MX for the business domain)            (client tenant)
                          │ rule: hello@ → Worker                ▲
                          ▼                                      │ raw MIME
  ┌──────────────────── platform-mail Worker ──────────────────────────────┐
  │ email()  → routeAgentEmail(resolver = Directory lookup, D1)             │
  │             │                                                          │
  │             ▼                                                          │
  │   Mailbox (Agents SDK Agent = Durable Object, one per mailbox)         │
  │     onEmail: check status → parse → encrypt to the mailbox public key  │
  │              → R2 (body) + SQLite (sealed header) → count to the Agent │
  │     send:    build MIME → SES → encrypt the Sent copy → store         │
  │                                                                        │
  │ MailService (WorkerEntrypoint, RPC only)                               │
  │   every call carries a capability the dashboard minted (≤ 60 s, HMAC)  │
  └────────────────────────────▲───────────────────────────────────────────┘
                               │ service binding (RPC); ciphertext out,
                               │ plaintext in only for send
  ┌──────────── dashboard Worker (spec 007, SEO-engine repo) ──────────────┐
  │ shell: Access JWT → session → memberships → tenant chooser             │
  │ app/(modules)/inbox/…  server actions → MailService                    │
  └────────────────────────────▲───────────────────────────────────────────┘
                               │ HTML + ciphertext
  ┌──────────── owner's browser ───────────────────────────────────────────┐
  │ mail-crypto: unlock with passkey (PRF) or recovery key → private key   │
  │ in memory → decrypt headers, bodies, drafts; encrypt drafts            │
  └────────────────────────────────────────────────────────────────────────┘
```

**A message arrives.** Email Routing hands it to the Worker's `email()`
handler. `routeAgentEmail` asks our resolver which mailbox owns the envelope
recipient; the resolver reads the Mail Directory (Mail's own D1, never the
engine's). An unknown address is rejected. The mailbox's Durable Object checks
that it is active (a mailbox without a key never stores mail — it rejects
instead), reads the raw message, extracts the headers, a snippet and the
attachment list, draws a fresh 256-bit message key, encrypts the header block
and the raw message with it (AES-256-GCM), seals the message key to the
mailbox's public key (HPKE, RFC 9180), writes the sealed body to R2 and the
sealed header to its SQLite, and forgets the plaintext. It then tells the
business's dashboard Agent the new unread count.

**The owner reads.** The dashboard's inbox screens call server actions, which
call `MailService` with a capability. Mail returns ciphertext. The browser
opens the message key with the mailbox private key, then the header block;
threads and search are built in the browser from the decrypted headers. A body
is fetched and decrypted only when opened, then rendered in the sandboxed
frame (D3).

**The owner unlocks.** The private key is stored on the platform only in
wrapped form: once per enrolled passkey (the key that wraps it is derived from
the passkey's WebAuthn PRF output) and once under the recovery key. Unlocking
means one passkey prompt; the browser unwraps the private key into memory as a
non-extractable key and checks that it matches the mailbox's advertised public
key, warning loudly if it does not (that would mean the server substituted a
key it controls).

**The owner sends.** The browser sends the composed message through a server
action to `MailService.send`. The Mail Worker builds the MIME message (From is
always the mailbox address, never taken from the request), sends it through
SES with the client's SES tenant and the `send-clients` configuration set,
then encrypts the Sent copy exactly like an arriving message and stores it.
Drafts are encrypted in the browser before they are saved; the server never
sees a draft in the clear.

**First setup.** The operator creates the mailbox (a Directory row: tenant,
address, status `provisioned`). The owner opens Inbox on the dashboard and is
walked through setup on their own device: the browser generates the mailbox
key pair, enrolls a passkey, shows the recovery key once and asks the owner to
confirm it, then uploads the public key and the wrapped copies. Only then does
the mailbox become `active` and accept mail.

## 6. The assistant

agentic-inbox's agent is an `AIChatAgent` with nine tools (list, get, thread,
search, draft email, draft reply, mark read, move, discard draft), an
auto-draft step on every arriving email, a prompt-injection check, a draft
cleaner, and an MCP server that lets any Access user operate any mailbox —
including two tools that send.

Kept: the nine tools, the "draft only, never send" rule, the prompt-injection
check and the draft cleaner. Dropped for good: the MCP server (it has no
per-mailbox authorization, by its README's own statement) and every tool that
sends.

Under Option A the assistant cannot run on the server at all, because nothing
on the server can decrypt. So v1 builds only the safe default: the mailbox
policy says `assistant: "off"`, the policy API refuses `"on"` until D1 is
decided, and the Worker holds no private-key material for any mailbox (a test
proves it). The two opt-in forms from §2 are specified in `plan.md` §9 and
held. An on-device model in the browser would keep Option A's promise; the
available options (browser built-in models, WebGPU models) were not verified
for this spec and are listed as future work, not as a plan.

## 7. Out of scope for v1

- Aliases (several addresses on one mailbox) and several mailboxes per
  business. The Directory allows one of each per business for now.
- Full-text search of bodies (v1 searches decrypted headers and snippets in
  the browser).
- Spam filtering beyond what Email Routing does before delivery; a `spam`
  folder exists and rules come later.
- Rich-text compose. v1 composes plain text with a quoted reply block.
- Mailbox closure tooling (crypto-shred + delete). Specified, not built.
- IMAP/JMAP access from other mail apps: incompatible with browser-held keys
  unless a client-side bridge exists.

## 8. Facts this rests on

| Fact | Source, checked 2026-09-26 |
|---|---|
| Email handler: `ForwardableEmailMessage` has `from`, `to` (envelope), `headers`, `raw`, `rawSize`, `setReject()`, `forward()` (verified destinations only), `reply()`; inbound messages are limited to 25 MiB | Cloudflare Email Service docs (context7) |
| Local test of an email Worker: `POST /cdn-cgi/local/email?from=…&to=…` with a raw RFC 5322 body that has a Message-ID | Cloudflare Email Service local-development docs (context7); the builder confirms the path against the installed wrangler, because older docs name `/cdn-cgi/handler/email` |
| `routeAgentEmail(message, env, { resolver, onNoRoute })`, `AgentEmail` with `getRaw()`, `forward()`, `setReject()`; custom resolvers return the agent to route to | Agents SDK docs (context7) |
| Workers Web Crypto supports X25519 and Ed25519 (since 2023-04-28), HKDF, AES-GCM | Workers docs (context7) |
| SES v2 `SendEmail` accepts `Content.Raw`; IAM conditions `ses:FromAddress`, `ses:FromDisplayName`, `ses:Recipients`, `ses:FeedbackAddress`; resources are identity and configuration-set ARNs | AWS SES docs (context7) |
| SES tenants: `create-tenant`, identity and configuration-set associations, reputation policy, pause, tenant-level suppression, `TenantName` on `SendEmail` | AWS SES docs (context7) |
| SES event records carry `commonHeaders` including `subject` | AWS SES event-publishing examples (context7) |
| WebAuthn PRF: Chrome/Edge, Firefox 148+, Safari 18+ with iCloud Keychain, Windows Hello since the February 2026 update, Google Password Manager on Android; iOS does not pass PRF to external security keys | Corbado's 2026 overview (secondary source) — the UI builder re-checks against chromestatus and MDN |
| WAICT: proposed October 2025, prototype in Firefox Nightly only | waict.dev, Cloudflare blog |
| agentic-inbox stores bodies in plaintext in the mailbox Durable Object's SQLite and attachments in R2, searches with SQL, drafts on every arrival, and exposes an MCP server with no per-mailbox authorization | its source at commit 48039bb (read, not assumed) |
| operator.example has no MX and no DMARC record; its DNS is on Cloudflare; the site is on Vercel | `dig @1.1.1.1`, `curl -I` |

**Not verified**, and where it gets checked:

- Whether an exception thrown from the `email()` handler makes Email Routing
  answer with a temporary failure (the sender retries) or a bounce. The design
  never relies on it silently: permanent problems use `setReject`, and the
  Alex migration forwards before it stores. Checked before any address is
  routed to the Worker (`tasks.md` S8).
- Which fields Email Routing's activity log shows the account owner.
- Whether Terraform's AWS provider has SES tenant resources yet (otherwise the
  AWS CLI through `cloudflare-infra/tf-aws`).
- Browser support for X25519 in Web Crypto. `mail-crypto` uses `@hpke/core`
  and carries its pure-JavaScript X25519 fallback until the builder confirms
  the browsers that matter support it natively.
