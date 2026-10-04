# Tasks — the Inbox module

Derived from `spec.md`, `domain-model.md` and `plan.md`. Each slice names its
inputs, the contract it honours, its acceptance tests and the files it owns.
Slices that run in parallel never own the same file.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[H]` held (the reason is given)

Branching, during the build: the spec branch `spec/001-inbox-module` held the
spec and the scaffold; each slice branch started from it and opened its pull
request against it, and an integration branch merged the slices. Only the
maintainer merges.

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
  header, adds `// Modified by Juan Ramirez (Proprietor Systems), 2026-09: <what changed>`, and is listed
  in `NOTICE`.
- No real mail to or from anyone. No deploys, no `wrangler d1 create`, no DNS,
  no Email Routing, no Access, no AWS resources.
- Secrets only from the operator's secret store, only through the process
  environment; never argv, never a kept file, never a message. A pre-commit
  secret scanner stays on; never `--no-verify`.
- Commit at every green step; push your branch; open a pull request. Commit
  messages, pull requests and comments are written for a public audience
  (`spec.md` §3): `example.com` for addresses, no client names, no
  infrastructure identifiers.

---

## S0 — Spec and scaffold  *(architect)*

- [x] S0a spec, domain model, plan, tasks
- [x] S0b contracts: capability v1, envelope v1
- [x] S0c scaffold: workspaces, typed stubs for both packages, NOTICE,
  Apache-2.0 text

## S1 — `packages/mail-crypto`  *(builder, parallel)* — built and audited 2026-09-26

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

## S2 — The Mail Worker  *(builder, parallel)* — built and audited 2026-09-26

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
  entrypoint, `unread({ businessId, mailboxId, unread })`, no-op adapter now
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
- M4: a capability for business A cannot read business B's mailbox (NotFound,
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

## S3 — `packages/mail-outbound`  *(builder, parallel)* — built and audited 2026-09-26

**Inputs:** `plan.md` §6, the stub `packages/mail-outbound/src/index.ts`, and
two senders in the platform's other, private codebases, read only: the
existing SES adapter (aws4fetch, an injectable fetch) and a contact-form
sender (header-injection handling, quoted display names).
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
  once if a client-mail credential is available, read into the environment;
  otherwise say it was not run.

## S1r — mail-crypto releases  *(written; first real release after publication)*

- [x] a workflow on tags `mail-crypto-vX.Y.Z` that computes `SHA256SUMS` over
  `packages/mail-crypto/src/**` from the tagged tree and attaches it to a
  GitHub release, so the dashboard's vendoring script checks against CI's
  record rather than the copy; sign the tag if the maintainer has a signing
  key
- [x] the same workflow packs `@proprietor/mail-crypto` once, attests the
  tarball and `SHA256SUMS` with GitHub artifact attestations, and stages the
  tarball on npm with trusted publishing (OIDC, no token; provenance). A
  maintainer approves the staged version with 2FA before it goes live. The
  GitHub release carries the same tarball, so npm, the release and
  `SHA256SUMS` describe one set of bytes
- [ ] the first run, after publication: the npm package and its trusted
  publisher exist (the package must exist before a trusted publisher can be
  added; `README.md` › Releases)

## S4 — Integration  *(architect, after S1–S3 are audited)* — 2026-09-26

- [x] S1, S2 and S3 merged on an integration branch, the lockfile regenerated
  (`npm ci` works), NOTICE lists the adapted files; 409 passed, 8 skipped (all
  intended), typecheck clean. The one seam found (mail-crypto did not
  typecheck under workers-types) went back to S1 and was fixed there.

## S2r — Refusals as values, and a suite that fails on escapes  *(builder, 2026-09-26)* — done, audited

- [x] `MailService` and the `Mailbox` answer with `MailResult` values
  (`contracts/mail-service-v1.md`); no expected refusal is thrown across either
  RPC hop
- [x] a harness guard: `npm test` fails when workerd logs an uncaught exception
  or a "hung" cancellation, except where a test declares the one deliberate
  throw (`email()` in `store` mode when storing fails)
- [x] a floating-promise audit of `src/` (type-aware lint if it runs under
  TypeScript 7, otherwise a reviewed list), with each finding fixed

## CI and S1r  *(builder, 2026-09-26)* — done, audited

- [x] `.github/workflows/ci.yml`: `npm ci`, `npm run typecheck`, `npm test` on
  every pull request and on push to `main`; read-only token, actions pinned to
  full commit SHAs
- [x] S1r (below) on the S1 branch

## S2k — Housekeeping found in the S2 audit — done, audited

- [x] prune `sends` (idempotency and rate-limit rows) after 30 days and the
  audit table after one year, in the same daily alarm as the Trash purge;
  today both grow without limit

## Round 2 (2026-09-28): to the operator's mailbox going live

Base: the rename (R0) on `main`, then the round-2 spec. Each slice branches
from the round-2 spec branch and opens its pull request against it. A slice
touches only the files it owns; `package-lock.json` is regenerated at
integration. Every rule for builders above still holds.

### R0 — The rename (D11) — builder

- [x] (#8, audited: 484 passed, four mutations caught) `platform-mail` → `proprietor-mail`, `@platform-mail/*` →
  `@proprietor/*`, capability issuer, audience and claim (`business`),
  "tenant" → "business" in Mail's own vocabulary; both vector files
  regenerated; a fitness test that fails on the old names outside `specs/`.

### S2b — Addresses (G12, G13, M6 amended) — [ ] not started

**Contract:** `plan.md` §12; `mail-service-v1` (`addresses`, `from`);
envelope v1 `envelopeTo`. **Owns:** `migrations/0002_addresses.sql`,
`src/directory/**`, `src/inbound/**`, `src/mail/header.ts`,
`scripts/provision-mailbox.ts`, in `src/mailbox/mailbox.ts` the hunks for
`describe`, `parseSendRequest` and the `From` in `sendReserved`, in
`src/service.ts` `mailboxes()`, in `packages/mail-crypto` the MessageHeader
type, its parse/serialise and the vectors.
**Acceptance:** an alias routes to its mailbox; an unknown address is
rejected; the primary is always one of the addresses (D-1, D-2); `from`
outside the mailbox's addresses is refused, inside is used; `envelopeTo` is
sealed (the M1 marker scan still passes) and opens in the browser; the vectors
regenerate and verify.

### S5 — Deliverability feed (M11, M12) — [ ] not started

**Contract:** `plan.md` §13; `mail-service-v1` (`RecipientSuppressed`).
**Owns:** `src/deliverability/**`, `scheduled()` in `src/index.ts`, `src/env.ts`,
in `wrangler.jsonc` the cron and observability lines and the removal of the
placeholder `database_id` (G24), with `test/node/config.test.ts`, the Mailbox's
`recordDeliveryEvent`, its suppression check in `send` and the schema
migration for it, the `EmailTags` option in `packages/mail-outbound`.
**Acceptance:** fixtures of each SES event type (AWS's documented shapes, with
example.com addresses); a permanent bounce and a complaint suppress; a
transient bounce does not; a second delivery of the same event changes
nothing; a suppressed recipient is refused before any reservation; no address
is stored or logged in the clear (the marker scan extended to recipients);
SQS requests signed and shaped as the SQS JSON protocol documents; a batch
with a failed delete is retried, not lost.

### S6a — `@proprietor/mail-client` (K1, G17, G18, G23) — [x] built 2026-10-04 (PR #13)

**Contract:** `contracts/mail-client-v1.md`; the stub in
`packages/mail-client`. **Owns:** `packages/mail-client/**`; in
`packages/mail-crypto` the PKCS #8 wrap (D21: `wrap.ts`, `keys.ts`, the
unwrap signature, vectors) and envelope v1's wrap section; the wrap length
check in `src/mailbox/mailbox.ts` (`parseWrap`); the browser job in
`.github/workflows/ci.yml`.
**Acceptance:** everything under "Tests this contract requires" in the
contract, in Chromium, Firefox and WebKit under the dashboard's exact policy
with Trusted Types enforced; PRF through Chromium's virtual authenticator
(`hasPrf`) and through an injected double elsewhere; the mutations named
there make the tests fail.

Builder's notes (2026-10-04):
- D21 landed first: wraps are 77 bytes (PKCS #8 inside), `unwrapPrivateKey`
  takes `{ wrappable }`, `generateMailboxKey` uses `generateKey`, the Mailbox
  expects 77, vectors regenerated.
- 86 Node tests; 12 browser tests per engine, opt-in
  (`MAIL_CLIENT_BROWSER_TESTS=1`, the CI job `browsers`). Chromium (PRF via
  the virtual authenticator) and Firefox passed on the builder's node; WebKit
  could not launch there (host libraries), so it is proven only by CI.
- Found in the browser tests, both agreed-upon policy consequences: under
  Trusted Types enforcement `DOMParser.parseFromString` is a sink, so
  DOMPurify must be handed the package's policy (`TRUSTED_TYPES_POLICY`),
  which accepts the message's HTML for the detached parse and the final
  document, during a render only; and `style-src-attr` refuses an email's
  inline `style` attributes inside the frame, so they are moved into the
  nonce-stamped sheet as class rules. The detached parse reports the email's
  styles and `<base>` as CSP violations on the page (harmless; S6b's report
  endpoint will see them).
- The frame renders under `frame-src 'self'` (the test policy): about:srcdoc
  needs no entry of its own. Playwright 1.63's own `context.credentials` has
  no PRF, so Chromium uses CDP `WebAuthn.addVirtualAuthenticator` with
  `hasPrf`.

### S6b — The inbox screens, a pull request into the dashboard — [ ] not started

**Contract:** `plan.md` §14; `mail-client-v1`; `mail-service-v1`. **Owns**,
in the dashboard's repository only: `app/(modules)/inbox/**`,
`modules/inbox.ts`, its one line in the module list, the `MAIL` binding, the
vendored copies with `SHA256SUMS`. Never its control plane, manifest,
migrations or site kit.
**Acceptance:** render tests against the built Worker with a fake
`MailService` (every `MailResult` branch, including `CapabilityRejected:
expired` → re-mint once); the key ceremony end to end in Chromium with a
virtual authenticator; the frame under the shell's policy.

### S8 — Activation kit (`plan.md` §15) — runbook and Terraform: architect; scripts: [ ] not started

- [x] the operator's private runbook with the real values and commands
  (architect)
- [x] parked Terraform in the operator's infrastructure checkout: Mail's D1
  and R2, configuration set, events feed, SES tenant and associations, the
  sending principal's policy, the probe's rule, and the routing switch as a
  full replacement of today's rules file (architect)
- [ ] scripts (builder): secrets from the secret store into `wrangler secret
  put` through standard input; the provisioning printer's address rows (with
  S2b); and **an operator CLI for `MailAdmin`** (`setDelivery`, `suspend`,
  `resume`). `MailAdmin` is bound to nothing on purpose, so without this CLI
  `plan.md` §15 step 8 has no caller. Proposed: a local `wrangler dev` with a
  remote service binding to the deployed Worker's `MailAdmin` entrypoint, so
  that nothing new is deployed. Whether remote bindings reach a named
  entrypoint is checked with context7 first. The probe is a throwaway in the
  operator's runbook, not code in this repository.

### S7 — The assistant, "ask about one message" only  *[H: after the above; D1]*

- [H] `plan.md` §9, the one-message form only

### S9 — The first client mailbox  *[H: `plan.md` §8 prerequisites]*

- [H] the reversible move to dual delivery in `plan.md` §8, from the
  operator's private runbook for that client

Audited 2026-09-29: PR #11, 528 passed; a mutation that drops the `from` guard fails `test/send.test.ts`.

Audited 2026-10-03: PR #12, 563 passed; a mutation that drops the suppression check in `send` fails six tests in `test/deliverability.test.ts`.

## P — Publication  *(2026-09-26)*

- [x] everything written for a public audience; example values in every
  fixture; operator-specific values moved out (`plan.md` §6)
- [x] `LICENSE` (Apache-2.0), `NOTICE` per §4(d), modification notices per
  §4(b) kept, `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`
- [x] CI for a public repository: least-privilege tokens, actions pinned by
  commit SHA, no `pull_request_target`, CodeQL, dependency review,
  Dependabot, OpenSSF Scorecard
- [ ] the repository settings that only exist once it is public (secret
  scanning and push protection, private vulnerability reporting, rulesets),
  applied by the maintainer
