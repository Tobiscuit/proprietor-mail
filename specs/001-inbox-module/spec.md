# 001 — The Inbox module

Status: written 2026-09-26. Spec only; nothing is deployed and no live
infrastructure was changed. The six seams with the dashboard were answered by
its maintainers the same day and are recorded in `plan.md` §1.

Renamed 2026-09-28, before any mailbox was enrolled (D11): the module is
`proprietor-mail` (formerly `platform-mail`), its packages are
`@proprietor/mail-crypto` and `@proprietor/mail-outbound`, and what the
platform calls a business is called a business here too (formerly "tenant").
"SES tenant" keeps its name: it is Amazon's term for an SES feature.

Companion documents: `domain-model.md` (the DDD pass and the gaps it found),
`plan.md` (architecture, contracts, infrastructure, moving a forwarded address
to the inbox), `tasks.md` (the build slices), `../../contracts/` (the
contracts other repositories implement).

In this repository **the operator** is the person or business that runs the
platform: they own the Cloudflare and AWS accounts and deploy the code. **The
dashboard** is the platform's separate web application, where business owners
sign in; it is not published here.

## 1. Requirements

- **One mailbox per business**, isolated from every other business, read inside the ONE
  dashboard (a route group in the dashboard app, in the dashboard's design
  system, themed from each client's own website). No full-page mail app, no
  iframes for composition, no module federation.
- **Client mail is zero-access.** The operator must not be able to read a
  client's mail.
- **Nothing client-facing depends on the operator's own server** at runtime.
  That server is the operator's workbench and nothing more.
- **Inbound** through Cloudflare Email Routing to a Worker, handed to a
  per-mailbox agent (Agents SDK `onEmail` / `routeAgentEmail`).
  **Outbound** through Amazon SES, not through Cloudflare's own sending.
- **Identity** is the platform login plus per-business membership. The module
  turns on when a site's manifest declares `has.email`.
- **The AI agent** from cloudflare/agentic-inbox keeps its tools, reconciled
  with zero-access. The safe default is built: the assistant is OFF for every
  mailbox, on only by an explicit opt-in.
- **The first mailbox is the operator's own.** The first client's mailbox
  comes later, through a safe, reversible move from forwarding that this spec
  plans (`plan.md` §8) and nobody executes yet.

## 2. The promise — and why its wording is the top decision

"The operator can't read your mail" can mean two different things, and a
client is owed the one that is true.

**A structural guarantee.** The servers never hold the key that opens stored
mail. Whoever has the database, the backups or the operator's account still
holds only ciphertext. This is what end-to-end encryption with keys kept on
the client's own devices gives.

**A policy guarantee.** The servers hold a key (so that a server-side feature,
such as an AI assistant, can read the mail), and a rule says nobody uses it
except for that feature. This can be audited and logged, but the operator who
owns the Cloudflare account and deploys the code is always *able* to read the
mail. In short: it can be kept from the operator by policy and audit, but not
made impossible.

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

These are the texts the owner is shown. Whichever option is chosen, the
wording ships with it; the dashboard never shows a stronger claim than the
option supports. `{operator}` stands for the name of the business that runs
the platform; the dashboard fills it in.

**Option A — encrypted with your key (structural).**
> Mail in your inbox is stored encrypted with a key that only your own devices
> hold. {operator}'s servers never have that key, so the stored mail is
> unreadable without it — to {operator}, to anyone who obtains a copy of the
> database, and to anyone who asks {operator} for it.
> Two honest limits: like every email service, the platform's software handles
> each message in readable form for the moment it arrives and the moment you
> send one, and does not keep it that way. And the inbox runs in your browser
> from code {operator} serves, so a changed version of that code could read
> what you read.

When Decision 2's publication step exists, one sentence is added: "Every
version of that code is published, so a change like that would be on the
public record." Until then it is not said.

**Option B — encrypted, with the key on our servers (policy).**
> Your mail is stored encrypted, and the platform holds the key so that
> features like the assistant can work. {operator}'s policy is never to open
> your mail, and every time the platform's software decrypts it, the access is
> recorded in a log you can see. {operator} is technically able to read your
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
confirmation says so: "To answer, this message will be decrypted on
{operator}'s servers for the assistant. While it is there, {operator} could
technically read it."

## 3. Decisions

**Decided 2026-09-26: all ten as recommended, then D5 reopened the same day.**
The operator is weighing a separate domain for the whole platform (dashboard,
inbox, anything clients log into or receive mail from), apart from the
operator's business website. Until that is chosen, nothing may enroll a
passkey or build a platform hostname in anywhere.

**Publication: from the start (2026-09-26).** This repository (the Mail
Worker, mail-crypto and mail-outbound) is published as open source under
Apache-2.0 as soon as it has been reviewed for publication, rather than just
before the first client mailbox. The platform's other applications are not
published. Apache-2.0 does not require publishing anything; the reason is that
"we can't read your mail" is only checkable if the code that handles the key
is public. Making the repository public is the operator's deliberate step,
taken after that review, because it cannot be taken back.

**Everything in this repository is written for a public audience**: commit
messages, pull request titles and bodies, comments and specs.
- No client names, addresses or domains (use `example.com`, RFC 2606).
- No infrastructure identifiers: AWS account IDs, Cloudflare account or
  resource IDs, secret-store paths, internal hostnames. Operator-specific
  values live in the operator's private deployment notes.

| # | Decision | Recommendation |
|---|---|---|
| **D1** | **Which zero-access option — A, B or C — and therefore what the assistant can be.** | **C, with A as every mailbox's default.** Build A now (it is the design already on record for client mail: encrypt on arrival with the client's public key, private key only on the client's devices, recovery key shown once, decrypt in the browser). Offer "ask about one message" as the first AI feature, because it discloses one message rather than the whole mailbox. Build the standing opt-in (key escrow) only after the operator approves Option B's wording as the text an owner sees when turning it on. Never offer Option B as a platform-wide default. |
| **D2** | **The browser trust boundary.** With the no-iframes rule, the key lives in the same page as the whole dashboard, so every dashboard deploy is inside the mail trust boundary. | **For v1, accept it and disclose it** (Option A's second limit says so), and shrink what can go wrong inside it: the dashboard's maintainers have committed its shell, from its first step, to a strict nonce CSP, enforced Trusted Types, zero third-party scripts, and loading the inbox code on inbox routes only, each with a test. Before the first client mailbox exists: open-source `proprietor-mail` (the Mail Worker and `mail-crypto`) under Apache-2.0 and publish a SHA-256 manifest of the dashboard's client bundle for every deploy, so the claim "published" becomes true; serve a WAICT integrity manifest as well, knowing that only Firefox Nightly checks it today. If a client ever needs more, the stronger design is a separate-origin key vault page, which needs an explicit exception to the no-iframes rule — not recommended for v1. |
| **D3** | **A sandboxed frame for message bodies.** Email HTML is hostile input. Rendering it in the dashboard page means one sanitizer bypass runs script in the page that holds the key. agentic-inbox renders it in a `srcdoc` iframe with a sandbox and a strict CSP. | **Allow it as a security control, not as composition.** One `srcdoc` frame with `sandbox` and neither `allow-scripts` nor `allow-same-origin` (so it can neither run script nor share the page's origin), set through a Trusted Types policy, remote images blocked until the owner clicks "show images", fixed to the reading pane with its own scrolling (it cannot report its height without script). This is the only frame the module uses. The dashboard's maintainers agreed to exactly this on 2026-09-26. |
| **D4** | **The first mailbox's address.** Today the operator's business domain has no MX record and receives no mail: an earlier decision kept it for sending only, and the operator's own mail goes to another domain. | **`hello@` on the operator's business domain**, with Email Routing enabled on that domain (MX + SPF at the apex; the SES MAIL FROM subdomain is unaffected). This changes the earlier decision for that one domain. It dogfoods exactly what clients will get, on the brand the platform is sold under. |
| **D5** | **The dashboard's final hostname, before anyone enrolls a mail key.** Passkeys are bound to a domain (the WebAuthn RP ID), and the dashboard is moving to a new hostname. | **REOPENED 2026-09-26 (see above).** **Choose the final host first and use exactly that host as the RP ID.** Do not use a parent domain: every subdomain of it, including a marketing site hosted elsewhere, could then ask the same passkey for the same secret. If the host ever changes again, owners re-enroll with their recovery key. The dashboard's maintainers agree, which puts the hostname on the critical path. |
| **D6** | **Lost keys mean lost mail.** The recovery key is shown once and never stored by the platform. If an owner loses every device passkey and the recovery key, nobody — the operator included — can open the stored mail. | **Accept it, and say it at setup.** Enrollment requires saving the recovery key (a printable sheet) before the mailbox activates. Support's answer to "I lost everything" is: your old mail cannot be recovered; new mail will arrive once you set up a new key. |
| **D7** | **SES isolation for client mail** (the dashboard maintainers' answer (d) plus a newer SES feature). | **One SES tenant per client business** (SES "tenants": `TenantName` on `SendEmail`, a reputation policy and a pause switch per tenant, tenant-level suppression — AWS docs, checked 2026-09-26), a client-mail configuration set with its own event destination (one per sending domain, `plan.md` §6), and a client-mail IAM principal whose policy names only client identities, that configuration set and `ses:FromAddress` values that are mailbox addresses. Client-mail events go to Mail's own SNS/SQS feed, never to the feed of the platform's notification mail, so client recipients and subjects never reach another application's database. Also restrict the platform's existing notification sender to its own `ses:FromAddress`, so neither key can send as the other. Agreed with the dashboard's maintainers on 2026-09-26. Infrastructure only; specified in `plan.md` §6, not applied. |
| **D8** | **Metadata the platform can see**, even under Option A (§4). | **Accept and publish the list** in the owner-facing "How your mail is protected" page. Minimize: the Mail Worker never logs addresses or subjects, and the bounce/complaint consumer keeps only the recipient address and the result. |
| **D9** | **Who may open a mailbox.** The operator is an editor member of client businesses (so they can support clients in the dashboard). Business membership must not mean mail access. | **Only owners open a mailbox by default** (`openRoles: ["owner"]`), and the key ceremony runs on the owner's own device. The operator never enrolls a key for a client, never sees a client's recovery key, and never sets a client's mailbox up "to save them time". |
| **D10** | **The repository's license, when opened.** | **Apache-2.0**, matching the upstream the adapted code comes from, and allowing anyone to verify builds. |

### Round 2 (2026-09-28): what changed, and what is open

The operator said go on finishing the module so that the operator's own
mailbox can go live, and then preparing the first client's.

**Updated decisions:**

- **D3, amended.** The frame's `sandbox` also carries `allow-popups` and
  `allow-popups-to-escape-sandbox`, so that a link can open in a new tab;
  still no `allow-scripts`, `allow-same-origin`, `allow-forms` or top
  navigation. **No remote content at all in v1** (domain-model G17): the page's
  policy forbids remote images, and loosening it on the page that holds the
  key is not worth a feature, so there is no "show images" button. Inline
  images are shown as `data:` URLs. An email's own styles are kept by stamping
  the page's nonce on its sanitised `<style>` elements (G18). Agreed with the
  dashboard's maintainers on 2026-09-28.
- **D4, updated.** The first mailbox is the operator's own, with a primary
  address and two further addresses delivering into the SAME mailbox (G12).
  One of them is also the address the platform's notification mail is sent
  from, so owners' replies to that mail arrive in this mailbox (G14).
- **D5, decided.** The dashboard's final host is chosen, and that exact host
  is the WebAuthn RP ID. The dashboard that carries the inbox must be serving
  that host before anyone enrolls (G19).

**Decided 2026-09-28: the operator approved D11–D23 as recommended**, with two
notes. D16 is decided: the name is "Juan Ramirez (Proprietor Systems)" (2026-09-29).
D22 is settled with the dashboard's maintainers: **one gated `POST` route**,
not a raised action limit (a server-action limit is global in every
Next-shaped runtime, and a route can stream the multipart body to the
MailService binding instead of buffering it). The contract the mail-client
builder writes against: `POST /inbox/send` inside the inbox route group,
behind the same entry gate; `multipart/form-data`; the same same-origin check
as every mutation; the capability minted server-side from the session for
that request; a hard cap of 25 MB per message; JSON back, `{ok, messageId}`
or `{ok: false, message}`. The dashboard's maintainers write the route
handler; this module owns what it forwards to MailService. Recommendations
are kept below for the record.

| # | Decision | Recommendation |
|---|---|---|
| **D11** | **The rename** to `proprietor-mail`, `@proprietor/*`, and "business" for "tenant" (protocol labels, capability issuer, audience and claim, Worker, D1 and R2 names). Free only until the first mailbox enrolls or the repository is published. | **Merge it first.** Then rename the repository on GitHub, and create the npm organization before the first package release. |
| **D12** | **Enroll before the new dashboard reaches its final host?** WebAuthn lets a page on a host UNDER the RP ID use that RP ID. | **Wait for the cutover.** If it is more than two weeks away and the mailbox is wanted sooner, serve the new dashboard's preview on one host under the RP ID, behind the same access gate, and enroll there. Do this only if nothing except the dashboard is ever served on any host under the RP ID. The passkey keeps working after the cutover. |
| **D13** | **The operator's first weeks in dual delivery.** | **Yes.** Two weeks in `store-and-forward` to the address the routing forwards to today, then `store` on the operator's word: `plan.md` §8's procedure, run first on the operator's own mail. |
| **D14** | **Sending as any of the mailbox's addresses** (M6 as amended). | **Yes.** The sending principal's policy lists exactly those addresses and pins the SES tenant (`ses:TenantName`). |
| **D15** | **Suppression kept as keyed hashes** (M11), rather than plaintext addresses as D8 would allow. | **Yes.** The bounce itself still reaches the owner as a sealed message, through SES feedback forwarding. |
| **D16** | **The copyright holder's name** in `NOTICE` and in the modification notices. | The operator's choice. Nothing in the code depends on it; the rename leaves it untouched. |
| **D17** | **Restrict the platform's notification sender to its own `From` addresses** (D7's second half). Today that principal has no `ses:FromAddress` condition. | **Yes**, in that application's own (hand-managed) policy. Until then, D7 holds by configuration set only. |
| **D18** | **Create the operator's own business on the platform** (G20). | **Yes**, before the mailbox is provisioned. |
| **D19** | **No remote images in v1** (D3 as amended). | **Yes.** Both applications' maintainers agree. |
| **D20** | **Workers Logs for the Mail Worker.** | **Off** (G25). Decided first as "keep the Worker's own id-only lines, invocation logs off"; the S8 probe (2026-10-13) showed every entry of an email invocation still carries the envelope sender and recipient, so logs are off entirely and `wrangler tail` serves a deliberate debugging session. |
| **D21** | **PKCS #8 wraps opened with `unwrapKey`** (K1). The raw private key then never exists as bytes in JavaScript. This is a change to envelope v1's wrap bytes, free before the first enrollment. | **Yes.** The architect recommends it; it can be reverted until the first enrollment. |
| **D22** | **Attachments above the dashboard's server-action body limit** (1 MB by default in its framework). | Raise the limit for the inbox's send action only. If the framework cannot do that per action, allow the inbox module one `POST` route for sending, behind the same gate. For the dashboard's maintainers and the operator. |
| **D23** | **The SES tenant for each mailbox's business**, with suppression scoped to the tenant and the `standard` reputation policy. | **Yes**, the operator's own business included. |

## 4. What the platform can see, even under Option A

This is the list D8 accepts and publishes. "Can see" means the operator could
read it from systems they control.

| What | Where it is visible | Why it exists |
|---|---|---|
| That a message arrived, when, how large, for which mailbox | Mailbox storage (plaintext columns) | Sorting, quotas, the unread count |
| Folder, read and starred flags | Mailbox storage | Set by the owner's own actions |
| Envelope sender and recipient of arriving mail | Cloudflare's Email Routing, in transit (whether its activity log shows them is unverified) | That is how SMTP delivery works |
| The full message, in transit, for the moment of arrival | Mail Worker memory | Encryption happens there, immediately |
| Recipients and subject of mail the owner sends, and the full message for the moment of sending | Mail Worker memory, and the dashboard Worker's memory (its server action passes the composed message on); SES delivery events include `commonHeaders` with the subject (AWS event-publishing examples, checked 2026-09-26) | SES needs the message to send it; SES reports what it delivered |
| That a new message arrived (a count, never content) | The per-business dashboard Agent, for Web Push | So the phone can buzz |
| Which devices and recovery keys exist (labels and times, not the secrets) | Mailbox key ring | So the owner can manage devices |

Everything else — subject, sender name, body, attachments, drafts, search,
threads — is encrypted before it is stored and decrypted only in the owner's
browser.

## 5. How it works

```
                    Cloudflare Email Routing                Amazon SES
                    (MX for the business domain)            (SES tenant)
                          │ rule: hello@ → Worker                ▲
                          ▼                                      │ raw MIME
  ┌──────────────────── proprietor-mail Worker ────────────────────────────┐
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
  ┌──────────── dashboard Worker (separate application) ───────────────────┐
  │ shell: Access JWT → session → memberships → business chooser           │
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
SES with the client's SES tenant and client-mail configuration set,
then encrypts the Sent copy exactly like an arriving message and stores it.
Drafts are encrypted in the browser before they are saved; the server never
sees a draft in the clear.

**First setup.** The operator creates the mailbox (a Directory row: business,
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

- Several mailboxes per business. (Several addresses on one mailbox arrived
  in round 2: D4, domain-model G12.)
- Remote images, and any remote content in a message (D3 as amended).
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
| The operator's business domain has no MX and no DMARC record, and its DNS is on Cloudflare | `dig @1.1.1.1` |

**Round 2 (checked 2026-09-28):**

| Fact | Source |
|---|---|
| `message.to` is a single envelope recipient, so one message to two routed addresses reaches the Worker once per address; `setReject` is a permanent SMTP failure; `forward()` needs a verified destination | Cloudflare Email Workers docs, workers-types |
| Workers Logs' invocation log for an email names the recipient; `observability.logs.invocation_logs: false` turns those off | Cloudflare Workers Logs docs |
| wrangler 4.141 resolves a D1 binding by `database_name` when `database_id` is omitted (and creates one when the lookup fails, so the runbook checks first); `wrangler secret put` reads standard input | wrangler source and docs |
| SES tenants: `aws_sesv2_tenant` and `aws_sesv2_tenant_resource_association` exist (hashicorp/aws 6.28 and 6.29); tenant suppression scope and reputation policy are API/CLI only; a send with `TenantName` succeeds only when its identity and configuration set are associated with that tenant; under `TENANT` suppression scope the account-level list does not apply | AWS SES API reference and developer guide; the provider's changelog |
| `ses:TenantName` is a condition key of `ses:SendEmail`; tenant is not a resource type of `SendEmail` | AWS Service Authorization Reference |
| SES message tags: ASCII letters, digits, `_` and `-`, at most 256 characters; SES events carry no tenant field; bounce subtypes include `OnAccountSuppressionList` and `OnTenantSuppressionList` | SES API reference, event-publishing examples |
| A configuration set named on the send overrides the identity's default one; email feedback forwarding is on by default | SES developer guide |
| SQS speaks the AWS JSON protocol (`X-Amz-Target: AmazonSQS.<Op>`), SigV4-signed; with raw delivery the message body is the SES event itself | SQS API reference, SNS docs |
| WebAuthn PRF: the salt is SHA-256("WebAuthn PRF" ‖ 0x00 ‖ input); `evalByCredential` is not allowed at creation; results at creation depend on the authenticator (Chromium's virtual authenticator with `hasPrf` returns them at both) | WebAuthn Level 3; reproduced in Chromium 153 |
| X25519 in Web Crypto: Chrome 133, Firefox 130, Safari 17; importing a private scalar as `raw` silently yields a PUBLIC key; `unwrapKey("pkcs8", …, AES-GCM)` yields a non-extractable private key; `@hpke/core` 1.9.0 opens with a non-extractable `CryptoKey` and has no fallback without native X25519 | MDN; reproduced in Chromium 153 and Firefox 155; its source |
| An `about:srcdoc` document inherits the embedder's policy container, sandboxed or not: `<style>` needs the nonce, remote images are blocked, `frame-ancestors` does not block it, `frame-src` does not apply | HTML and CSP3 specifications; web-platform-tests results |
| `srcdoc` is a Trusted Types sink; React 19.3 passes the value through unchanged; Trusted Types ship in Chrome 83, Firefox 148, Safari 26 | Trusted Types specification; React source |
| DOMPurify 3.4.16 is the minimum version without a 2026 advisory; postal-mime 3.0.1 has the linear-time parsing fixes (4.0.0 is a rewrite without security fixes) | their advisories and changelogs |
| The dashboard's framework caps a server action's body at 1 MB by default | its source (vinext 1.0.0-beta.12) |

**Not verified**, and where it gets checked:

- Whether an exception thrown from the `email()` handler makes Email Routing
  answer with a temporary failure (the sender retries) or a bounce. The design
  never relies on it silently: permanent problems use `setReject`, and the
  move from forwarding (`plan.md` §8) forwards before it stores. Checked
  before any address is routed to the Worker (`tasks.md` S8).
- Which fields Email Routing's activity log shows the account owner.
- Whether a page's `blob:` URL loads inside the opaque-origin frame (the
  reason `mail-client` uses `data:`), and React under ENFORCED Trusted Types:
  S6a's browser tests.
- Whether SES v2 forwards a bounce notification to the `From` address when no
  feedback address is given: the S8 simulator send.
- The exact errors for a send through an unassociated or paused SES tenant:
  S5's tests treat both as a non-retryable refusal until seen.
- Browser support for X25519 in Web Crypto. `mail-crypto` uses `@hpke/core`
  and carries its pure-JavaScript X25519 fallback until the builder confirms
  the browsers that matter support it natively.
