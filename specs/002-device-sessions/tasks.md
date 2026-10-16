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

- [ ] D1a mail-crypto: factor keys (A2), key seals for both KEMs and successor
  seals (A4), the binding key and tags (A5), opening challenges (A6), signing
  device proofs (A7), P-256 device key generation (A3)
- [ ] D1b `contracts/device-v1.vectors.json` with every positive and negative
  case of A9, and a test that checks every one
- [ ] D1c mail-client: the kept-device store (IndexedDB and memory), the
  storage check, `resumeDevice`, the lock engine
- [ ] D1d mail-client: sessions hold every key the chain reaches; K2′ and K3
  at every unlock; FreshFactor; `sessionProof`
- [ ] D1e mail-client: keep, rekey, lock now, forget, remove (with rotation),
  upgrade, `setFactorKey`, add a passkey and replace the recovery key with
  factor keys, enrollment with factor keys and a device, the send form's
  `session`
- [ ] D1f PROTECTION gains spec §5's text and rows, compared with the spec
- [ ] D1g browser tests in Chromium and Firefox (and WebKit in CI)

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

- [ ] D2a `proofs.ts`: `sealChallenge(target, ids) → { sealed, answer }` and
  `verifyDeviceProof(signingKey, ids, signature) → boolean`, with tests that
  open the challenge with `@hpke/core` directly, per A6
- [ ] D2b migration `0003_devices`; the view's new fields
- [ ] D2c `challenge`, `openSession`; sessions and their checks;
  `SESSION_NEEDS` with its fitness test; the three error names
- [ ] D2d `upgrade`, `registerDevice`, `updateDevice`, `setFactorKey`;
  `addWrap` and `removeWrap` with factor proofs and factor keys; `enroll` with
  factor keys and a device
- [ ] D2e `removeDevice` and the rotation, in one transaction (M18)
- [ ] D2f housekeeping of challenges and sessions; audit rows
- [ ] D2g `send` reads `request.session`

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
- M1's marker scan: no session token, challenge answer or nonce appears in
  SQLite in the clear (only hashes), nor in logs;
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

- [ ] D3a vendor mail-client and mail-crypto from the integration commit
- [ ] D3b actions and the body route carry `auth`; the new actions; local
  types and error names
- [ ] D3c MailboxProvider: resume, sessions, renewal, `DeviceRevoked`, the
  lock engine
- [ ] D3d the gate: the question, the upgrade offer, the removed notice, the
  storage notice
- [ ] D3e Settings: This device, Your devices, Security keys and passkeys,
  Recovery key
- [ ] D3f strings (US grade 8 at most), in the inbox's words file
- [ ] D3g the fake Mail Worker's new methods

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

- [ ] merge D1 and D2 on an integration branch; the full suite and both
  typechecks; the cross-tests (real crypto on both sides) for F1, F2, F5, F6,
  F10
- [ ] each slice's mutation checks
- [ ] the vendoring commit for D3
- [ ] the report: what to review before merging, what needs the operator, what
  needs the shell

## Held

- [H] Mail enforcing timed locks (spec §8), until the operator wants it.
- [H] The external cryptographic review (D32), before the first client mailbox.
