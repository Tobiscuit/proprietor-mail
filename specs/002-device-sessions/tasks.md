# Tasks — unlock once per device, with revocation

Derived from `spec.md`, `domain-model.md`, `plan.md` and
`../../contracts/device-v1.md`. Each slice names its inputs, the contract it
honours, its acceptance tests and the files it owns. Slices that run at the
same time never own the same file.

Legend: `[ ]` todo · `[~]` in progress · `[x]` done · `[H]` held (the reason is given)

Branching: the spec branch `spec/002-device-sessions` holds this spec, the
contract and the id prefixes. D1 and D2 branch from it and open pull requests
against it. D3 is a pull request in the dashboard's repository, built on the
integration commit of D1 and D2. Only the maintainer merges.

## Rules for every builder

001's rules hold (`../001-inbox-module/tasks.md`, "Rules for every builder"):
failing tests first; every library and platform fact from context7 or the
official docs, with the installed binary or source winning when they disagree;
exact versions; no deploys, no DNS, no Email Routing, no Access, no AWS
resources, no real mail; secrets only through the process environment; the
pre-commit secret scanner on, never `--no-verify`; commit at every green step;
everything written for a public audience (`example.com`, no client names, no
infrastructure identifiers). Also:

- Run builds and test suites under `nice -n 10`, and afterwards stop your
  worktree's leftover processes with a pattern that cannot match the shell
  running it: `pkill -f '[/]home/…/your-worktree'` (the brackets).
- Install dependencies in your own worktree (`npm ci`). Never symlink another
  checkout's `node_modules`: workspace packages would then resolve to that
  checkout's sources.
- A contract that cannot be built as written goes back to the architect
  before code works around it.

---

## S0 — Spec  *(architect)*

- [x] spec, domain model, plan, tasks
- [x] `contracts/device-v1.md`, and a pointer to it in `mail-service-v1.md`
- [x] `newId` accepts `dev` and `chl`

## D1 — mail-crypto (formats, the browser's half) and mail-client  *(builder)*

**Inputs:** `contracts/device-v1.md` (Parts A and C), `plan.md` §3 and §5,
`contracts/mail-client-v1.md` (amended section, a first draft by the
architect), the existing `packages/mail-crypto` and `packages/mail-client`.
**Contract:** device-v1 Part A, byte for byte; Part C's rules; the mail-client
API, whose final signatures this slice writes into `mail-client-v1.md` (the
architect reviews them before D3 starts).
**Owns:** `packages/mail-crypto/**` except `src/proofs.ts` and
`test/proofs.test.ts`, and the one `index.ts` line that re-exports them;
`packages/mail-client/**`; `contracts/device-v1.vectors.json`; the API part of
`contracts/mail-client-v1.md`'s amendment; the browser job in
`.github/workflows/ci.yml` if it needs a change.

- [x] D1a mail-crypto: factor keys (A2), key seals for both KEMs and successor
  seals (A4), the binding key and tags (A5), opening challenges (A6), signing
  device proofs (A7), P-256 device key generation (A3)
- [x] D1b `contracts/device-v1.vectors.json` with every positive and negative
  case of A9, and a test that checks every one
- [x] D1c mail-client: the kept-device store (IndexedDB and memory), the
  storage check, `resumeDevice`, the lock engine
- [x] D1d mail-client: sessions hold every key the chain reaches; K2′ and K3
  at every unlock; FreshFactor; `sessionProof`
- [x] D1e mail-client: keep, rekey, lock now, forget, remove (with rotation),
  upgrade, `setFactorKey`, add a passkey and replace the recovery key with
  factor keys, enrollment with factor keys and a device, the send form's
  `session`
- [x] D1f PROTECTION gains spec §5's text and rows, compared with the spec
- [x] D1g browser tests in Chromium and Firefox (and WebKit in CI)

**Acceptance tests:**
- every A9 vector opens or verifies, and every negative case is refused;
- K4: an envelope v1 key envelope, a wrap and a key seal each fail to open as
  a challenge, and a challenge fails to open as a key seal;
- a key seal opened with another `toId`, `toKind` or recipient fails; an opened
  key whose keyId is not `sealedKeyId` is refused; `extractable` is false
  unless asked;
- a tag changes when any field changes (label, either key, id, keyId);
- K2′: a chain of three keys is accepted from a factor's anchor and from a
  device's `lastKeyId`; a seal of a key made by someone who never held the
  previous key is refused with `KeySubstitutionDetected`; so is an advertised
  key older than `lastKeyId`;
- K3: a key ring with one forged tag stops the unlock;
- a rotation request names exactly the remaining recipients, and is refused
  while any of their tags fails;
- `resumeDevice` for each lock setting (right away, 15 minutes, 1 hour, when I
  sign out with the same and with a changed sign-in id), a device missing from
  the view (wiped), a device whose seal is of an older key with a valid chain;
- K5: after keeping a device, the stored record holds exactly the listed
  fields; its keys are non-extractable P-256 `CryptoKey`s; no X25519 key and no
  token is in IndexedDB (browser test);
- a kept device survives a reload in a real browser and opens with no prompt;
  the storage check returns false where keys cannot be kept;
- an FF refuses after 2 minutes (injected clock);
- the runtime scan (no `eval`, no DOM sink, no network) passes for both
  packages, and the mail-client rule-3 test allows exactly the device store.

**Mutation checks (the audit runs them):** drop the chain walk; drop the tag
check; let `resumeDevice` skip the lock check; let the store keep the mailbox
key. Each must fail a test.

## D2 — The Mail Worker  *(builder, at the same time as D1)*

**Inputs:** `contracts/device-v1.md` (Parts A6–A8 and B), `plan.md` §2–§4,
`domain-model.md` §3 (M5′, M13–M21), `contracts/mail-service-v1.md`,
the existing `src/` and `test/`.
**Contract:** device-v1 Part B, exactly; `sealChallenge` and
`verifyDeviceProof` per A6 and A7.
**Owns:** `packages/mail-crypto/src/proofs.ts`, `packages/mail-crypto/test/proofs.test.ts`,
the one `index.ts` re-export line; `src/**`, `test/**`, `wrangler.jsonc`,
`vitest.config.ts`, the root `package.json` and lockfile.

Open pull request #8 (`fix/unread-sealed-and-docs`) changes `inboxUnread()` in
`src/mailbox/mailbox.ts`, and `test/service.test.ts`. Keep this slice additive
there: new tests in new files, nothing within a few lines of `inboxUnread()`.
Check with `git merge-tree` against that branch before the pull request, and
report the result.

- [x] D2a `proofs.ts`: `sealChallenge(target, ids) → { sealed, answer }` and
  `verifyDeviceProof(signingKey, ids, signature) → boolean`, with tests that
  open the challenge with `@hpke/core` directly, per A6
- [x] D2b migration `0003_devices`; the view's new fields
- [x] D2c `challenge`, `openSession`; sessions and their checks;
  `SESSION_NEEDS` with its fitness test; the three error names
- [x] D2d `upgrade`, `registerDevice`, `updateDevice`, `setFactorKey`;
  `addWrap` and `removeWrap` with factor proofs and factor keys; `enroll` with
  factor keys and a device
- [x] D2e `removeDevice` and the rotation, in one transaction (M18)
- [x] D2f housekeeping of challenges and sessions; audit rows
- [x] D2g `send` reads `request.session`

**Acceptance tests:**
- 0003 on a mailbox created before it: existing keys, wraps and messages are
  intact, `sessions` is `optional`, and **the whole existing suite passes
  unchanged**;
- a challenge is used once, expires after 2 minutes, is consumed by a wrong
  answer (`ProofRejected`), and the 21st live one is `RateLimited`;
- `openSession`: a device signature that verifies, one over another nonce
  (refused), an unknown device (`DeviceRevoked`), another account's device
  (`DeviceRevoked`), a session past 60 minutes (`SessionRequired`);
- after `upgrade`: every method in `SESSION_NEEDS` marked session refuses
  without one, with another account's, and with an expired one; `mailboxes`,
  `mailbox`, `unread` work without; `upgrade` a second time is refused; an
  upgrade without a recovery factor is refused (M20);
- the fitness test fails when a MailService method is missing from
  `SESSION_NEEDS`;
- each method needing a factor proof refuses without one, with a used one,
  and with one for an unknown factor; `setFactorKey` refuses a proof from the
  factor being keyed;
- `removeDevice`: a rotation missing one recipient, naming the removed device,
  naming an extra one, with a stale `from`, or with a wrong seal length
  changes nothing (`InvalidRequest`); a good one leaves M18's state exactly;
  M5′ refuses a rotation without a keyed recovery factor; every other session
  ends; the next arrival is sealed to the new key; old messages keep their
  keyIds;
- M19: no seal of a retired key remains after a rotation;
- `removeWrap` refuses the last recovery factor that reaches the active key;
- M1's marker scan: no session token or challenge answer appears in SQLite in
  the clear (only their SHA-256), nor in logs. A challenge's nonce is not a
  secret (Mail sends it with the challenge, for the device to sign) and is
  stored as it is;
- the escape guard: no uncaught exception, no "hung" cancellation.

**Mutation checks (the audit runs them):** remove `list` from the session
check; drop the factor proof on `removeDevice`; drop the exact-coverage check;
let a wrong answer leave the challenge usable. Each must fail a test.

## D3 — The dashboard's inbox  *(builder, after D1 and D2 are audited)*

**Inputs:** `plan.md` §3 and §6, the mail-client contract as D1 finalized it,
device-v1 Part B, the dashboard's inbox as merged on its `main` (inbox pull
requests #9 and #10).
**Contract:** the actions call Mail exactly as Part B says; the screens use
only mail-client for keys, storage and proofs.
**Owns (the dashboard repository):** `apps/dashboard/app/(modules)/inbox/**`,
`apps/dashboard/lib/strings/inbox.ts`, `apps/dashboard/test/{unit,render,screens}/inbox*`,
`apps/dashboard/test/render/fake-mail/**`, `apps/dashboard/test/render/mail-fixture.ts`,
`apps/dashboard/vendor/**` and the lockfile entries of the two vendored
packages. Never the shell (`components/shell`, `lib/modules.ts`,
`worker/index.ts`, `lib/mail.ts`, `lib/mail-capability.ts`, `lib/inbox-send.ts`,
the send route): what it needs from there goes into the report as an ask.

- [x] D3a vendor mail-client and mail-crypto from the integration commit
- [x] D3b actions and the body route carry `auth`; the new actions; local
  types and error names
- [x] D3c MailboxProvider: resume, sessions, renewal, `DeviceRevoked`, the
  lock engine
- [x] D3d the gate: the question, the upgrade offer, the removed notice, the
  storage notice
- [x] D3e Settings: This device, Your devices, Security keys and passkeys,
  Recovery key
- [x] D3f strings (US grade 8 at most), in the inbox's words file
- [x] D3g the fake Mail Worker's new methods

**Acceptance tests:** the dashboard's own suites (`npm run typecheck`,
`npm test`), and the browser flow
(`npx vitest run --project screens test/screens/inbox-flow.test.ts`) extended
with:
- F1, then a reload opens the inbox with no prompt;
- Lock now, then a reload asks for a factor;
- in a second browser context with no authenticator: the recovery key, "this
  device is mine", a reload with no prompt;
- from that second context: remove the first context's device (with the
  recovery key). The first context's next action wipes it and asks for a
  factor. A message that arrives afterwards opens in the second context only;
- a shared computer keeps nothing (IndexedDB holds no record), and a reload
  asks;
- F5 on a fake mailbox seeded as enrolled before this spec;
- no console error and no policy violation anywhere, as today.

**Mutation checks (the audit runs them):** keep the record on
`DeviceRevoked`; let a shared computer write the store. Each must fail a test.

## D4 — Integration and audit  *(architect)*

- [x] merge D1 and D2 on an integration branch; the full suite and both
  typechecks; the cross-tests (real crypto on both sides) for F1, F2, F5, F6,
  F10 (`test/device-e2e.test.ts`, pull request #16)
- [x] each slice's mutation checks
- [x] the vendoring commit for D3
- [x] the report: what to review before merging, what needs the operator, what
  needs the shell

## Audit (architect, 2026-10-17 to 19)

- **D1, pull request #15** (head 658f00f): 225 mail-crypto and 245 mail-client
  tests pass in Node, Chromium and Firefox here. CI also passes in WebKit on
  Linux and macOS. Each of these mutations fails tests: ignoring K2′'s anchors
  (2), skipping K3's device tags (3), letting a key off the chain through (1).
  The builder's own list is in its pull request. Found in CI and fixed: WebKit
  bug 307095 (spec §9).
- **D2, pull request #10** (head e83a610): 736 passed and 8 skipped; the
  escape guard is clean; it merges cleanly with #8. Each of these mutations
  fails tests: keeping the old key's seals at a rotation, dropping M21's
  account check, dropping M5′ from the rotation, ignoring a sent token while
  sessions are optional, and dropping openSession's checks after the
  signature await. Found and fixed in review: MailService's and MailAdmin's
  TypeScript-`private` helpers were served over RPC, so a caller holding the
  binding could reach a Mailbox with a forged call context. That issue was
  already on `main` and is fixed by this pull request; they are now
  `#private`, with a test that pins each entrypoint's surface.
- **D4, pull request #16** (head 0fed951): D1 and D2 merged, 959 passed and
  8 skipped, typecheck clean. Its end-to-end test runs mail-client against
  the real Worker for F12, F1, F2, F6, F10 and F5. It merges cleanly with #8
  and with `main`.
- **D3, the dashboard's pull request #13** (head db6e11e, with mail-crypto
  repacked from 0fed951): typecheck; unit 245, render 111 and the Chromium
  flow 13 all pass. Dropping the session from `list` fails 9 of the 13
  browser tests, and the rules test catches it statically. Dropping the body
  route's session header is caught by its unit test.

## Round 2: an independent review (2026-10-19)

A read-only review asked for these before the operator's upgrade. Each was
checked against the code first; none was wrong.

- [x] R2-1 (D1, D3) K3 flags a recipient whose tag fails instead of stopping
  everything: never sealed to, shown, removable (contract Part C K3)
- [x] R2-2 (D1) K8: a rotation opens its successor seal and the used factor's
  seal before it is sent; tested with a corrupted seal
- [x] R2-3 (D1) K9: the factor just used derives the factor key Mail lists;
  one that does not is flagged; tested
- [x] R2-4 (D1, D2, D3) the upgrade names every factor (B5, M20); `setFactorKey`,
  the partial upgrade and the stale-factor flows are removed
- [x] R2-5 (D3) the body route's header is `x-proprietor-mail-session-token`,
  a name Cloudflare's log redaction covers
- [x] R2-6 (architect) the rollback text and the upgrade's order (spec §7,
  plan §8)
- [x] R2-7 (D3) the dashboard vendors the packages from the merged commit
- [x] R2-8 (D1) the workaround for WebKit bug 307095 leaves #15 for the
  branch `feat/002-webkitgtk-workaround`; CI tests WebKit on macOS only

Round 2 audited (architect, 2026-10-19): D1 #15 at c908477, D2 #10 at
2eab8b3, D4 #16 at a05d74a (965 passed, 8 skipped; its new end-to-end test
plants a device in Mail's storage and the real client flags it, keeps
reading, refuses other removals, and removes it), D3 seo-engine #13 at
b10c16c (unit 253, render 111, Chromium 13). Mutations that fail tests: a
failing tag throwing again, a flagged device not reported, an upgrade that
misses a wrap, the header back to its unredacted name.

## Held

- [H] Mail enforcing timed locks (spec §8), until the operator wants it.
- [H] The external cryptographic review (D32), before the first client mailbox.

## Round 3: Better Auth, bound confirmations, factor signatures (2026-10-22)

The spec's D34–D43, `plan.md` §10, `contracts/device-v1.md` (every change
marked "round 3") and `contracts/action-descriptor-v1.md` with its vectors
are the inputs. One builder at a time, in this order; each slice is audited
before the next starts. Every rule of "Rules for every builder" holds, and
these:

- Use context7 at every step of the way. Memory isn't a source for any of
  it. (Load the tools with ToolSearch
  `select:mcp__context7__resolve-library-id,mcp__context7__query-docs`;
  resolve and query before writing or reviewing code against any API; take
  versions from `npm view` or the lockfile; where context7 has nothing, the
  official docs or the RFC text, and what could not be verified goes into the
  spec.)
- Run every build, test run and dev server inside its own memory box
  (`boxed`, with `timeout`), in the foreground, and leave nothing running.
- Read the `package.json` scripts for self-calls before the first build.

**Branches.** mail-crypto lives on the client branch (#15), so R3-1 changes
it there. The Worker needs round 3's mail-crypto, so R3-2 first merges the
client branch into the Worker branch (#10 then carries #15's commits; both
are pull requests into the spec branch, so nothing is duplicated when they
merge). R3-4 merges both into the integration branch (#16).

### R3-1a — mail-crypto  *(builder)*

**Owns:** `packages/mail-crypto/**` on `feat/002-device-client`,
`contracts/device-v1.vectors.json`.

- [ ] RFC 8785 for the values descriptors and requests hold, the action
  descriptor (build, strict read, digest) and the request digest (A10);
  tests run every vector of `action-descriptor-v1.vectors.json`
- [ ] A2b factor signing keys; A11 statements (sign and verify each); the
  factor graph helper (trusted component, admitted devices and factors,
  trusted transitions) as pure functions over a view
- [ ] A6: `factor` and `key` challenges open only with their action digest
- [ ] device-v1 vectors: A9's round 3 additions

**Acceptance:** every descriptor vector (valid parses to its object and
digest; every invalid one refused); a statement fails after any one field
changes; a challenge opened with another digest fails; the factor graph
connects a later factor through its admission and refuses an admission
whose self-signature or admitter key fails; a transition by a factor
outside the component is refused; the runtime scan passes.

### R3-1b — mail-client  *(the same builder, after R3-1a is audited)*

**Owns:** `packages/mail-client/**`, the API part of
`contracts/mail-client-v1.md`'s round 3 amendment.

- [ ] K10: the store keyed by mailbox and account (version 2), `accountId`
  everywhere a record is read or written; `Forbidden` wipes nothing
- [ ] K11: `lastKeyId` compare-and-swap in one transaction; resume again on a
  miss
- [ ] K2″ and K3′ wherever K2′ and K3 ran; `trustRoot` in the record
- [ ] K4/K12: `FreshFactor.answer` takes the request it confirms; the
  descriptor built and compared; signed transitions, admissions and unlock
  keys in every flow (keep, rekey, enrollment, upgrade, add a passkey,
  replace the recovery key)
- [ ] D38: a deviceless session proof carries a factor proof
- [ ] D40, K13: `removeDevices` (several; none while a rotation is due;
  every flagged device included); `revokeRequest`; `rotationDue`
- [ ] D34: lock checks unchanged in meaning ("signed-out" on a changed id and
  on null after non-null), with tests for both
- [ ] PROTECTION's text follows spec §5 as amended ("passkey")

**Acceptance:** another account's record is never read, opened or deleted
(resume, unlock, `DeviceRevoked`, `Forbidden`); two pages: the slower one's
`lastKeyId` write misses and it resumes again; a forked chain (a key from a
removed device, a successor and seal made with it) is refused at a factor
unlock and at resume; a planted device with a genuine tag but no admission is
flagged and never sealed to; a factor challenge for another request is not
answered; `removeDevices` with two flagged devices succeeds; with a rotation
due, a FreshFactor finishes it first; every earlier test still passes.

**Mutation checks (the audit runs them):** drop the account check in
`resumeDevice`; drop the transition-signature check; seal to a recipient
without an admission; answer a factor challenge without comparing the
descriptor; write `lastKeyId` unconditionally. Each must fail a test.

### R3-2 — the Mail Worker  *(builder, after R3-1 is audited)*

**Owns:** on `feat/002-mail-worker` after merging `feat/002-device-client`:
`src/**`, `test/**`, `packages/mail-crypto/src/proofs.ts` and its test, the
root `package.json` and lockfile.

- [ ] 0003 as §10.1; the view's new fields; `removed_factors`
- [ ] `challenge` with actions and the four purposes; descriptors issued and
  stored by digest; `sealChallenge` with the digest (A6)
- [ ] M15′: sessions need a device signature or a factor proof
- [ ] M17′: every factor and key proof checked against its call's own request
- [ ] M21′: another account's device is `Forbidden`, nothing written
- [ ] M22, B7a: `revokeDevices` with the capability's `confirmation`;
  `rotation_due`; audit with `codeId`
- [ ] M18′, M23: `removeDevices` (0 to 20, 0 only while due; transition
  signed by the proof's factor; clears the due rotation)
- [ ] M24, M25: removed factors kept; every signature checked before writing
- [ ] capability: the `confirmation` claim read strictly, only for
  `revokeDevices`

**Acceptance:** each attestation case of the descriptor vectors; two
concurrent `revokeDevices` with one attestation: exactly one is applied; an
email attestation never opens any other method; a factor proof answered for
one descriptor is refused on another call; a relay's rotation with the
owner's proof and session is refused; a session with a key proof alone is
refused while required; another account's device answers `Forbidden` and
its record and sessions are untouched; `removeDevices` of two devices; a
rotation whose transition is unsigned or signed by another factor is
refused; the whole earlier suite passes.

**Mutation checks:** accept an email attestation on `removeDevices`; drop the
request-digest comparison; let a key proof alone open a session; answer
another account's device with `DeviceRevoked`; accept a transition signed by
a factor other than the proof's. Each must fail a test.

### R3-3 — the dashboard's inbox  *(after R3-2; in the dashboard's repository)*

**Owns:** as D3, on `feat/inbox-kept-devices` stacked on the dashboard's
spec 008 branch; and `feat/mail-shell-types` (`lib/mail.ts`'s types). Never
the shell's sign-in code.

- [ ] D34: `InboxShell.signInId` from `currentSignInId()`, `accountId` from
  `currentSession().accountId`
- [ ] the new actions, `revokeWithCode` (the code checked and the capability
  minted in one server action), the screens of F13 and F14
- [ ] the vendored packages from the integration commit

**Acceptance:** the dashboard's suites (`npm run typecheck`, `npm test`,
`npx vitest run --project screens test/screens/inbox-flow.test.ts`), with:
a second account on the same browser profile sees no kept device and the
owner's still opens; "when I sign out" locks after a new sign-in; F13 with a
fake code service; F14.

### R3-4 — integration  *(architect)*

- [ ] merge R3-1 and R3-2 into `integration/002-device-sessions`; the
  end-to-end test grows F13, F14, the account check, a relayed proof, and a
  fork attempt, with the real crypto on both sides

### R3-5 — the formal model  *(architect)*

- [ ] `formal/002/ir.md` first (round 3's design, its expected verdicts),
  then `device.spthy`; the bounded sweep, boxed; README's results
