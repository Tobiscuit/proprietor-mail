# Testing the Mail Worker (slice S2)

No test here sends or receives real mail. Inbound mail is simulated (a
constructed `ForwardableEmailMessage`, or wrangler's local email endpoint);
SES is a fake, or a `fetch` that never leaves the isolate.

## `npm test`

```sh
cd /home/link/platform-mail-worktrees/s2-mail-worker && npm test
```

One `vitest run`, three kinds of project (`vitest.config.ts`):

| Project | Runs in | What |
|---|---|---|
| `worker` | workerd (`@cloudflare/vitest-pool-workers` 0.22.0) | everything under `test/` except `test/node/`: a real D1 with `migrations/` applied, real SQLite-backed Durable Objects, a real R2 simulation |
| `packages/*` | Node, with each package's **own** `vitest.config.ts` | S1's and S3's tests (none while they are stubs) |
| `node` | Node | `test/node/`: the provisioning script and the `wrangler.jsonc` fitness checks |

`npm run typecheck` runs TypeScript 7 over `src/` and `test/` (and each
package's own typecheck).

### How the Worker is tested

- **Fakes go into the live object.** The `Mailbox` Durable Object builds its
  ports from the real packages (`src/wiring.ts`). A test replaces them on the
  live instance through `runInDurableObject` (`test/support/mailbox.ts`,
  `injectPorts`); nothing in `src/` knows about tests. The fake sealer does
  real AES-GCM under a key it throws away, so storage only ever sees
  ciphertext, and it keeps the plaintext it was handed (in test memory) so
  tests can check what the Worker built.
- **MailService is called through real RPC** (`exports.MailService` from
  `cloudflare:workers`), so error names and fields are checked as the
  dashboard will receive them.
- **Storage is isolated per test file**, not per test: every test makes fresh
  mailbox ids.
- **End-to-end tests** (`test/e2e.test.ts`) put the real `@platform-mail/crypto`
  and `@platform-mail/outbound` behind the ports and skip on each package's
  `IMPLEMENTED` flag; they start running when S1 and S3 merge.

### Harness quirks (vitest-pool-workers 0.22.0, workerd 1.20260815.1)

- Assert RPC rejections with `rejectionOf(p)` (a plain `await`), never
  `expect(p).rejects`: vitest reads properties off workerd's RPC promise, and
  each property read on an RPC promise is a pipelined call that rejects too,
  unhandled.
- workerd prints `uncaught exception; source = Uncaught (in promise)` for every
  Durable Object RPC method that rejects, and the pool prints
  `…your Worker's code had hung…` once for every call through `exports` that
  rejects. Both are noise from the harness; the error still reaches the caller
  intact and the test result is right.
- Capture console output with `captureConsole()` (`test/support/console.ts`),
  not `vi.spyOn`: a vitest spy called from another request context makes
  workerd report that request as hung.

## Local end to end: `wrangler dev` and the local email endpoint

The path is the one the **installed** wrangler (4.141.0, miniflare
5.20260925.0-alpha) serves: `POST /cdn-cgi/local/email?from=…&to=…`, a raw
RFC 5322 body that has a `Message-ID`, at most 1 MiB locally; `&format=json`
returns `{ outcome, rejectReason, forwards, replies, events }`. (Older docs
name `/cdn-cgi/handler/email`; this wrangler has no such route.)

Two local sessions: the Mail Worker on :8787 (the local email endpoint
reaches the primary worker of a session), and `test/local/driver.ts` on
:8788, a stand-in for the dashboard that mints capabilities with the public
TEST key and calls `MailService` over a real service binding; the local dev
registry connects the two (`env.MAIL (platform-mail#MailService) … [connected]`).
Everything is `--local`; nothing touches an account.

```sh
cd /home/link/platform-mail-worktrees/s2-mail-worker && npx wrangler d1 migrations apply platform-mail --local
cd /home/link/platform-mail-worktrees/s2-mail-worker && node scripts/provision-mailbox.ts --tenant tnt_local --address hello@operator.test > /tmp/provision.sql   # add --id mbx_… until S1 lands
cd /home/link/platform-mail-worktrees/s2-mail-worker && npx wrangler d1 execute platform-mail --local --file /tmp/provision.sql

# The capability key is the public TEST key from contracts/capability-v1.vectors.json, not a secret.
cd /home/link/platform-mail-worktrees/s2-mail-worker && printf '%s\n' "MAIL_CAPABILITY_KEYS='{\"test-2026-09\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}'" > /tmp/mail-local.env  # pragma: allowlist secret (public test key)
cd /home/link/platform-mail-worktrees/s2-mail-worker && npx wrangler dev --local --port 8787 --inspector-port 9231 --env-file /tmp/mail-local.env
cd /home/link/platform-mail-worktrees/s2-mail-worker && npx wrangler dev --local -c test/local/driver.wrangler.jsonc --port 8788 --inspector-port 9232   # a second terminal

M=<the mbx_ id from /tmp/provision.sql>
cd /home/link/platform-mail-worktrees/s2-mail-worker && curl -s -X POST "http://localhost:8788/enroll?tenant=tnt_local&mbx=$M"
cd /home/link/platform-mail-worktrees/s2-mail-worker && curl -s -X POST "http://localhost:8787/cdn-cgi/local/email?from=ana@example.com&to=hello@operator.test&format=json" --data-binary @test/local/sample.eml
cd /home/link/platform-mail-worktrees/s2-mail-worker && curl -s "http://localhost:8788/list?tenant=tnt_local&mbx=$M"
cd /home/link/platform-mail-worktrees/s2-mail-worker && curl -s "http://localhost:8788/open?tenant=tnt_local&mbx=$M"
```

### Observed, 2026-09-26

**With S1 and S3 merged** (run in a throwaway copy of this branch with the
`feat/s1-mail-crypto` and `feat/s3-mail-outbound` heads overlaid):

```text
unknown address  → {"outcome":"ok","rejectReason":"No such mailbox",…}
provisioned      → {"outcome":"ok","rejectReason":"This mailbox is not accepting mail",…}
/enroll          → {"keyId":"f559d47420157465385d893fe121b9e7"}
deliver          → {"outcome":"ok","forwards":[],"replies":[],"events":[{"type":"received",…}]}
/list            → [{"id":"msg_33r954wgvv9wvdmxqtap387nvb","folder":"inbox","size":283,
                     "receivedAt":"2026-09-26T16:38:20.069Z","keyId":"f559d474…","sealedHeaderChars":583}]
/open            → {"id":"msg_33r954wgvv9wvdmxqtap387nvb","subject":"Kitchen remodel quote",
                     "from":{"name":"Ana Ruiz","address":"ana@example.com"},
                     "snippet":"Hi, we'd like a quote for a kitchen remodel.","rawBytes":283}
without &format=json → Worker successfully processed email
GET http://localhost:8787/ → 404
```

The Mail Worker's log lines for that run carry ids, sizes, outcomes and jti
values only, for example
`{"event":"arrival","mailbox":"mbx_6m3c…","size":283,"outcome":"stored","message":"msg_33r9…","forwarded":false}`.
A `grep` of the whole `.wrangler/state` directory (D1, Durable Object SQLite,
R2, wrangler's local observability capture) for the subject, the sender's
name and address and the body found nothing; the R2 object starts with `PMB1`.

**On this branch alone** (the packages are still stubs): the two rejections
are the same, `/enroll` answers `{"error":"Error","message":"internal error"}`
(the Mailbox recomputes the keyId with S1's `keyIdOf`, a stub), and the Worker
logs `Uncaught NotImplemented: @platform-mail/crypto: keyIdOf is not
implemented yet (slice S1)`. Nothing is stored without S1, by design.
