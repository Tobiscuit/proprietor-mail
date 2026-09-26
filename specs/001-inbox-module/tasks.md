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

## S1 — `packages/mail-crypto`  *(builder, parallel)*

**Inputs:** `contracts/envelope-v1.md`, the stub `packages/mail-crypto/src/index.ts`.
**Contract:** the exported signatures in the stub; the byte formats in the
contract. **Owns:** `packages/mail-crypto/**`,
`contracts/envelope-v1.vectors.json`, its `NOTICE` lines (none expected).

- [ ] S1a `newId`, `keyIdOf`, `fingerprint`
- [ ] S1b `generateMailboxKey`, `sealMessage`, `openHeader`, `openBody` —
  HPKE via `@hpke/core` (plus `@hpke/dhkem-x25519` wherever Web Crypto lacks
  X25519: decide from evidence which browsers need it, and say which)
- [ ] S1c `sealDraft`, `openDraft`
- [ ] S1d `prfInput`, `wrapPrivateKey`, `unwrapPrivateKey`,
  `publicKeyMatches`
- [ ] S1e `newRecoveryKey`, `parseRecoveryKey` (Crockford base32 + 2-byte
  checksum)
- [ ] S1f `contracts/envelope-v1.vectors.json` and a test that opens every
  vector and refuses every negative case
- [ ] S1g `IMPLEMENTED = true`

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

## S2 — The Mail Worker  *(builder, parallel)*

**Inputs:** `plan.md` §3–§5 and §7, `domain-model.md` §3 (invariants M1–M10),
`contracts/capability-v1.md`, the two package stubs.
**Contract:** the `MailService` surface in `plan.md` §4; capability v1;
envelope v1 via `sealMessage` only.
**Owns:** `src/**`, `test/**`, `migrations/**`, `wrangler.jsonc`,
`vitest.config.ts`, root `package.json` (and the lockfile),
`contracts/capability-v1.vectors.json`, its `NOTICE` lines.

- [ ] S2a harness: wrangler config (no routes, `workers_dev: false`,
  `preview_urls: false`), vitest with a workerd project (real D1 + DO + R2)
  and a Node project for the packages; `npm test` runs everything
- [ ] S2b Directory: migration 0001, repository, provisioning script that
  prints SQL (never runs it against a remote)
- [ ] S2c capability verification (jose, HS256 only) + the vectors file
- [ ] S2d `Mailbox` Agent: schema, identity copy from the Directory, folders
  seeded, policy defaults, audit
- [ ] S2e inbound: `email()` → `routeAgentEmail` with a Directory resolver →
  `Mailbox.onEmail`, following `plan.md` §5 exactly, parsing with
  `postal-mime`, sealing through a `Sealer` port
- [ ] S2f `MailService` entrypoint: every method in `plan.md` §4 except
  `send`, with capability checks (M4) and role checks
- [ ] S2g `send` through ports (`MimeBuilder`, `RawMailer`): M6, M7
  (limits + idempotency), Sent copy sealed and stored
- [ ] S2h trash purge after 30 days (M9); orphan R2 cleanup on failed insert
- [ ] S2i `MailAdmin` entrypoint (suspend, resume, set delivery mode and
  forward target — M10), exported but bound to nothing
- [ ] S2j wiring: the real `sealMessage`, `buildMime` and `sesRawMailer`
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

## S3 — `packages/mail-outbound`  *(builder, parallel)*

**Inputs:** `plan.md` §6, the stub `packages/mail-outbound/src/index.ts`, the
engine's `src/adapters/ses-mailer.ts` (read, do not edit: aws4fetch, an
injectable fetch) and the portfolio's `app/lib/ses/contact.ts` (header
injection handling, quoted display names).
**Contract:** the exported signatures in the stub.
**Owns:** `packages/mail-outbound/**`, its `NOTICE` lines.

- [ ] S3a `buildMime`: RFC 5322 headers (From, To, Cc, Reply-To, Subject,
  Date, Message-ID, In-Reply-To, References, MIME-Version), RFC 2047
  encoded-words for non-ASCII names and subjects, text-only /
  multipart/alternative / multipart/mixed with attachments, base64 or
  quoted-printable bodies, CRLF, lines ≤ 998, no Bcc header; decide between a
  vetted library and a small builder from evidence, and say why
- [ ] S3b header-injection refusal (`InvalidMessage` on CR/LF in any header
  value), recipient and size limits (`LIMITS`), confirming SES's own maximum
- [ ] S3c `sesRawMailer`: SES v2 `SendEmail` with `Content.Raw`,
  `FromEmailAddress`, `Destination`, `ConfigurationSetName`, `TenantName`,
  signed with aws4fetch; `SendRejected` with `retryable` for throttling and
  5xx; a timeout
- [ ] S3d `IMPLEMENTED = true`

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

## S4 — Integration  *(architect, after S1–S3 are audited)*

- [ ] stack or rebase S1 and S3 under S2, regenerate the lockfile, run the
  whole suite with the end-to-end tests un-skipped, fix the seams, report

## S5 — Deliverability feed  *[H: needs the §6 AWS resources]*

- [H] pull `platform-mail-events` from SQS on a schedule; per-mailbox
  suppression checked before `send`; events kept 90 days with only the
  recipient address, the event type and the time (D8)

## S6 — The inbox screens  *[H: spec 007 step 0 (shell, session, module contract) and the theme-token contract]*

- [H] `plan.md` §10, as a PR to the SEO-engine repo's route group, after the
  seams in `plan.md` §1 "Seams this plan opens" are answered

## S7 — The assistant  *[H: Decision D1]*

- [H] `plan.md` §9

## S8 — Activation for hello@operator.example  *[H: D4, D5, D7, the §6 resources]*

- [H] verify what Email Routing does when the `email()` handler throws, on a
  throwaway address the maintainer approves, before routing a real one
- [H] create the resources, deploy, route the address, the maintainer enrolls on his
  own devices, send from the simulator first

## S9 — Alex  *[H: `plan.md` §8 prerequisites]*

- [H] the reversible dual-delivery plan in `plan.md` §8
