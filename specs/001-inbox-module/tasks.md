# Tasks — the Inbox module

Derived from `spec.md`, `domain-model.md` and `plan.md`. Each slice names its
inputs, the contract it honours, its acceptance tests and the files it owns.
Slices that run in parallel never own the same file.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[H]` held (the reason is given)

Branching: `main` holds only GitHub's bootstrap README. PR #1 is branch
`spec/001-inbox-module` (spec + scaffold). Slice branches start from it and
open their PRs against it; GitHub retargets them to `main` when PR #1 merges.
Nobody merges; the maintainer does.

## Rules for every builder

- Failing tests first: write the test, watch it fail for the right reason,
  then make it pass.
- Every library and platform fact from context7 (or the official docs when
  context7 has nothing) — the Agents SDK, Email Routing / Email Service,
  Durable Objects, D1, R2, vitest-pool-workers, wrangler, HPKE, Web Crypto,
  WebAuthn, SES v2, aws4fetch. When the installed binary disagrees with the
  docs (it happens with wrangler), the installed binary's `--help` or source
  wins, and you say so.
- Pin exact versions you checked on npm today; no ranges for anything security
  relevant.
- Code adapted from cloudflare/agentic-inbox keeps Cloudflare's copyright
  header, adds `// Modified by Operator, 2026-09: <what changed>`, and is listed
  in `NOTICE`.
- No real mail to or from anyone. No deploys, no `wrangler d1 create`, no DNS,
  no Email Routing, no Access, no AWS resources.
- Secrets only from Vault (`VAULT_ADDR=https://vault.operator.example`), only
  through the process environment; never argv, never a kept file, never a
  message. The global pre-commit secret scanner stays on; never
  `--no-verify`.
- Commit at every green step; push your branch; open a PR against
  `spec/001-inbox-module`. Commit messages end with the two trailer lines
  given in your brief; PR descriptions end with the two lines given there.

---

## S0 — Spec and scaffold  *(architect)*

- [x] S0a spec, domain model, plan, tasks
- [x] S0b contracts: capability v1, envelope v1
- [x] S0c scaffold: workspaces, typed stubs for both packages, NOTICE,
  Apache-2.0 text

## S1 — `packages/mail-crypto`  *(builder, parallel)* — built, PR #3, audited 2026-09-26 (unmerged)

**Inputs:** `contracts/envelope-v1.md`, the stub `packages/mail-crypto/src/index.ts`.
**Contract:** the exported signatures in the stub; the byte formats in the
contract. **Owns:** `packages/mail-crypto/**`,
`contracts/envelope-v1.vectors.json`, its `NOTICE` lines (none expected).

- [x] S1a `newId`, `keyIdOf`, `fingerprint`
- [x] S1b `generateMailboxKey`, `sealMessage`, `openHeader`, `openBody` —
  HPKE via `@hpke/core` (plus `@hpke/dhkem-x25519` wherever Web Crypto lacks
  X25519: decide from evidence which browsers need it, and say which)
- [x] S1c `sealDraft`, `openDraft`
- [x] S1d `prfInput`, `wrapPrivateKey`, `unwrapPrivateKey`,
  `publicKeyMatches`
- [x] S1e `newRecoveryKey`, `parseRecoveryKey` (Crockford base32 + 2-byte
  checksum)
- [x] S1f `contracts/envelope-v1.vectors.json` and a test that opens every
  vector and refuses every negative case
- [x] S1g `IMPLEMENTED = true`
- [x] S1h runs under the dashboard's strict CSP and Trusted Types: no `eval`,
  no `new Function`, no WebAssembly, no DOM sink, no network, in the package
  or any runtime dependency — with a test that scans the shipped JS
  (`plan.md` §1); self-contained so the dashboard can vendor `src/` as is

**Acceptance tests:**
- round trips: seal → open returns the exact header and the exact raw bytes,
  including a non-ASCII subject and a 5 MiB body;
- binding: a header opened with another message id, a body opened with
  another mailbox id, and a key envelope from another message each throw
  `DecryptionFailed`; a flipped byte anywhere throws `DecryptionFailed`;
- wraps: a wrap opens only with its own secret, mailbox, wrap id, kind and
  key id; `publicKeyMatches` is false for a different key pair;
- recovery: display round-trips; every single-character substitution of a
  valid display is caught by `parseRecoveryKey` as `RecoveryKeyTypo` or
  decodes to a different secret whose wrap fails; lower case, spaces and
  I/L/O are accepted;
- `sealMessage` uses a fresh message key and fresh IVs every call (two seals
  of the same input differ);
- runs in Node and imports cleanly in workerd (S2's tests will import it).

## S2 — The Mail Worker  *(builder, parallel)* — built, PR #4, audited 2026-09-26 (unmerged)

**Inputs:** `plan.md` §3–§5 and §7, `domain-model.md` §3 (invariants M1–M10),
`contracts/capability-v1.md`, the two package stubs.
**Contract:** the `MailService` surface in `plan.md` §4; capability v1;
envelope v1 via `sealMessage` only.
**Owns:** `src/**`, `test/**`, `migrations/**`, `wrangler.jsonc`,
`vitest.config.ts`, root `package.json` (and the lockfile),
`contracts/capability-v1.vectors.json`, its `NOTICE` lines.

- [x] S2a harness: wrangler config (no routes, `workers_dev: false`,
  `preview_urls: false`), vitest with a workerd project (real D1 + DO + R2)
  and a Node project for the packages; `npm test` runs everything
- [x] S2b Directory: migration 0001, repository, provisioning script that
  prints SQL (never runs it against a remote)
- [x] S2c capability verification (jose, HS256 only) + the vectors file:
  `jti` required and logged with the method and outcome on every call; the
  canonical vector in the contract's serialization order; conformance worded
  as "verifies and decodes to these claims"
- [x] S2d `Mailbox` Agent: schema, identity copy from the Directory, folders
  seeded, policy defaults, audit
- [x] S2e inbound: `email()` → `routeAgentEmail` with a Directory resolver →
  `Mailbox.onEmail`, following `plan.md` §5 exactly, parsing with
  `postal-mime`, sealing through a `Sealer` port
- [x] S2f `MailService` entrypoint: every method in `plan.md` §4 except
  `send`, with capability checks (M4) and role checks
- [x] S2g `send` through ports (`MimeBuilder`, `RawMailer`): M6, M7
  (limits + idempotency), Sent copy sealed and stored
- [x] S2h trash purge after 30 days (M9); orphan R2 cleanup on failed insert
- [x] S2i′ `NewMailSignal` port shaped as the dashboard's future `MailSignals`
  entrypoint, `unread({ tenantId, mailboxId, unread })`, no-op adapter now
- [x] S2i `MailAdmin` entrypoint (suspend, resume, set delivery mode and
  forward target — M10), exported but bound to nothing
- [x] S2j wiring: the real `sealMessage`, `buildMime` and `sesRawMailer`
  behind the ports; end-to-end tests that skip while a package's
  `IMPLEMENTED` is false

**Acceptance tests:**
- M1: the marker scan over SQLite, R2 and console after an arrival and after
  a send (plain, base64, quoted-printable forms);
- M2: arrival for a `provisioned`, `suspended` or unknown address is
  rejected with `setReject` and stores nothing;
- M3: after `enroll`, no storage holds the test's private key bytes; no
  method accepts a private key;
- M4: a capability for tenant A cannot read tenant B's mailbox (NotFound,
  identical to a missing mailbox); every capability vector behaves as listed;
- M5: `enroll` without a recovery wrap is refused; removing the last
  recovery wrap is refused;
- M6/M7: `From` is the mailbox address whatever the request says; the 21st
  send in an hour answers `RateLimited`; a repeated idempotency key sends
  once;
- §5 table: every row has a test, including forward-first ordering in
  `store-and-forward` and "no throw after a successful forward";
- a local end-to-end run: `wrangler dev` + `POST /cdn-cgi/local/email` (or the
  path the installed wrangler uses) delivers a sample message into a test
  mailbox, documented in `test/README.md` with the exact command;
- with real S1 merged: a message sealed by the Worker opens with the test's
  private key to the exact raw bytes.

## S3 — `packages/mail-outbound`  *(builder, parallel)* — built, PR #2, audited 2026-09-26 (unmerged)

**Inputs:** `plan.md` §6, the stub `packages/mail-outbound/src/index.ts`, the
engine's `src/adapters/ses-mailer.ts` (read, do not edit: aws4fetch, an
injectable fetch) and the portfolio's `app/lib/ses/contact.ts` (header
injection handling, quoted display names).
**Contract:** the exported signatures in the stub.
**Owns:** `packages/mail-outbound/**`, its `NOTICE` lines.

- [x] S3a `buildMime`: RFC 5322 headers (From, To, Cc, Reply-To, Subject,
  Date, Message-ID, In-Reply-To, References, MIME-Version), RFC 2047
  encoded-words for non-ASCII names and subjects, text-only /
  multipart/alternative / multipart/mixed with attachments, base64 or
  quoted-printable bodies, CRLF, lines ≤ 998, no Bcc header; decide between a
  vetted library and a small builder from evidence, and say why
- [x] S3b header-injection refusal (`InvalidMessage` on CR/LF in any header
  value), recipient and size limits (`LIMITS`), confirming SES's own maximum
- [x] S3c `sesRawMailer`: SES v2 `SendEmail` with `Content.Raw`,
  `FromEmailAddress`, `Destination`, `ConfigurationSetName`, `TenantName`,
  signed with aws4fetch; `SendRejected` with `retryable` for throttling and
  5xx; a timeout
- [x] S3d `IMPLEMENTED = true`

**Acceptance tests:**
- golden files for each MIME shape; every produced message parses back with
  `postal-mime` to the same fields (round-trip property);
- Bcc recipients are in `recipients` and absent from `raw`;
- a signed request's URL, headers and JSON body are exactly as SES v2
  documents (checked against the API reference, cited in the test);
- a live test file, skipped unless `SES_TEST_ACCESS_KEY_ID`,
  `SES_TEST_SECRET_ACCESS_KEY` and `SES_TEST_FROM` are set, that sends each
  MIME shape only to `success@simulator.amazonses.com` (and one each to the
  bounce and complaint simulator addresses) and asserts a message id. Run it
  once if a Vault token is valid, with the credential read into the
  environment; otherwise say it was not run.

## S1r — mail-crypto releases  *(after S1 merges)*

- [ ] a workflow on tags `mail-crypto-vX.Y.Z` that computes `SHA256SUMS` over
  `packages/mail-crypto/src/**` from the tagged tree and attaches it to a
  GitHub release, so the dashboard's vendoring script checks against CI's
  record rather than the copy; sign the tag if the maintainer has a signing key

## S4 — Integration  *(architect, after S1–S3 are audited)*

- [ ] stack or rebase S1 and S3 under S2, regenerate the lockfile, run the
  whole suite with the end-to-end tests un-skipped, fix the seams, report

## S2k — Housekeeping found in the S2 audit  *(small, after S4)*

- [ ] prune `sends` (idempotency and rate-limit rows) after 30 days and the
  audit table after one year, in the same daily alarm as the Trash purge;
  today both grow without limit

## S5 — Deliverability feed  *[H: needs the §6 AWS resources]*

- [H] pull `platform-mail-events` from SQS on a schedule; per-mailbox
  suppression checked before `send`; events kept 90 days with only the
  recipient address, the event type and the time (D8)

## S6 — The inbox screens  *[H: spec 007 step 0 (shell, session, module contract) and the theme-token contract]*

- [H] `plan.md` §10, as a PR to the SEO-engine repo's route group
  (`apps/dashboard/app/(modules)/inbox/`), with the vendored mail-crypto at
  `_vendor/mail-crypto/` and the GET-only streaming route handler (`plan.md`
  §1). Works under the shell's CSP and Trusted Types: the frame's `srcdoc` is
  set only through a named Trusted Types policy returning DOMPurify's
  `TrustedHTML`; verify in a real browser (Playwright) that the `srcdoc`
  document, which inherits the page's CSP, renders under it, and that the
  inherited `frame-ancestors 'none'` does not block it

## S7 — The assistant  *[H: Decision D1]*

- [H] `plan.md` §9

## S8 — Activation for hello@operator.example  *[H: D4, D5, D7, the §6 resources]*

- [H] verify what Email Routing does when the `email()` handler throws, on a
  throwaway address the maintainer approves, before routing a real one
- [H] on that same throwaway deployment, read what Workers Logs and a Tail
  Worker record for an email invocation. If it is more than spec §4 lists,
  turn `observability` off for this Worker before any real address is routed.
  (The Agents SDK's own email diagnostics channel, which publishes each
  arriving message's from, to and subject, is already disabled in the
  Mailbox, and a test fails if that changes on an SDK upgrade.)
- [H] create the resources, deploy, route the address, the maintainer enrolls on his
  own devices, send from the simulator first

## S9 — Alex  *[H: `plan.md` §8 prerequisites]*

- [H] the reversible dual-delivery plan in `plan.md` §8
