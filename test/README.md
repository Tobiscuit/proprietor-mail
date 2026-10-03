# Testing the Mail Worker (slice S2)

No test here sends or receives real mail. Inbound mail is simulated (a
constructed `ForwardableEmailMessage`, or wrangler's local email endpoint);
SES is a fake, or a `fetch` that never leaves the isolate.

## `npm test`

From the repository root:

```sh
npm test
```

One `vitest run`, three kinds of project (`vitest.config.ts`):

| Project | Runs in | What |
|---|---|---|
| `worker` | workerd (`@cloudflare/vitest-pool-workers` 0.22.0) | everything under `test/` except `test/node/`: a real D1 with `migrations/` applied, real SQLite-backed Durable Objects, a real R2 simulation |
| `packages/*` | Node, with each package's **own** `vitest.config.ts` | S1's and S3's tests (none while they are stubs) |
| `node` | Node | `test/node/`: the provisioning script, the `wrangler.jsonc` fitness checks, the escape guard's own judgement, and the names check (`names.test.ts`: no old name outside `specs/`) |

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
  `cloudflare:workers`), so answers are checked as the dashboard will receive
  them. Every answer is a value (`contracts/mail-service-v1.md`): read it with
  `valueOf(answer)` or `refusalOf(answer)` (`test/support/results.ts`), or
  compare the whole `{ ok, … }` object. A refused call resolves; if one
  rejects, that is a bug, and the escape guard says so.
- **Storage is isolated per test file**, not per test: every test makes fresh
  mailbox ids.
- **End-to-end tests** (`test/e2e.test.ts`) put the real `@proprietor/mail-crypto`
  and `@proprietor/mail-outbound` behind the ports and skip on each package's
  `IMPLEMENTED` flag, so they ran as soon as S1 and S3 were merged.

### The escape guard: exceptions that escape an RPC hop fail the run

When a Workers RPC method throws, workerd prints it and the caller's test
never sees that line: `uncaught exception; source = Uncaught (in promise); …`
on the side that threw, and, when it was an entrypoint, `uncaught exception;
exception = … your Worker's code had hung and would never generate a
response` as well. That is not harness noise. It is how workerd treats any
RPC method that throws: the S2 audit reproduced it in this pool, through a
real service binding, and under `wrangler dev` with two processes, so in
production, before refusals became values, every refused call would have
logged an uncaught exception and a cancelled invocation.

`escapeGuard()` (`test/harness/escape-guard.ts`, wired in `vitest.config.ts`)
reads those lines where the pool writes them, in the vitest process, and at
the end of the run fails `npm test` (exit code 1, with a report naming each
line) unless every one of them was declared by the test that caused it. It
adds its own reporter, so `--reporter` cannot switch it off. Why there:
nothing inside the isolate sees these lines (an `unhandledrejection` listener
in a test stays silent for them), vitest's unhandled-error policy therefore
never hears of them, and the pool (0.22.0) offers no hook for workerd's
output (miniflare no longer has `handleRuntimeStdio`, and the pool sets
`handleStructuredLogs` itself).

**The one declaration there is.** Only `email()` throws on purpose: when a
delivery fails, so that Email Routing does not count the message as delivered
(`plan.md` §5: storing fails in `store` mode, or the forward fails in
`store-and-forward`). The throw starts in the Mailbox, which the Agents SDK
reaches over Durable Object RPC, so workerd prints it. A test that makes
`email()` throw declares it with `expectEmailThrow` (`test/support/escapes.ts`),
which delivers, returns what was thrown, and records the declaration in the
test's `task.meta`:

```ts
it("row 5: store mode, R2 fails → throws, and nothing is stored", async ({ task }) => {
  // …
  const err = await expectEmailThrow(
    task,
    { reason: "store mode, the R2 put fails: email() throws so the message is not counted as delivered", error: "Error: R2 is unavailable", lines: 1 },
    deliver(email.message),
  );
```

`error` is text in the thrown error's first line and `lines` the number of
escape lines workerd prints for it (one for each hop the throw crosses: the
Mailbox's `_onEmail`, and the SDK's `EmailBridge.forward` too when a forward
fails). The guard matches each line to a declaration by that text and wants
the count exactly, so a declaration excuses nothing else, and a declared
escape that stops printing fails the run as well: that is what shows the
guard can still see workerd. A "hung" cancellation can never be declared.

### Harness quirks (vitest-pool-workers 0.22.0, workerd 1.20260815.1)

- Capture console output with `captureConsole()` (`test/support/console.ts`),
  not `vi.spyOn`: a vitest spy called from another request context makes
  workerd report that request as hung, which the escape guard fails.

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
registry connects the two (`env.MAIL (proprietor-mail#MailService) … [connected]`).
Everything is `--local`; nothing touches an account. From the repository root:

```sh
npx wrangler d1 migrations apply proprietor-mail --local
node scripts/provision-mailbox.ts --business biz_local --address hello@example.test > /tmp/provision.sql   # repeat --address for further addresses; the first is the primary
npx wrangler d1 execute proprietor-mail --local --file /tmp/provision.sql

# The capability key is the public TEST key from contracts/capability-v1.vectors.json, not a secret.
printf '%s\n' "MAIL_CAPABILITY_KEYS='{\"test-2026-09\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\"}'" > /tmp/mail-local.env  # pragma: allowlist secret (public test key)
npx wrangler dev --local --port 8787 --inspector-port 9231 --env-file /tmp/mail-local.env
npx wrangler dev --local -c test/local/driver.wrangler.jsonc --port 8788 --inspector-port 9232   # a second terminal

M=<the mbx_ id from /tmp/provision.sql>
curl -s -X POST "http://localhost:8788/enroll?business=biz_local&mbx=$M"
curl -s -X POST "http://localhost:8787/cdn-cgi/local/email?from=ana@example.com&to=hello@example.test&format=json" --data-binary @test/local/sample.eml
curl -s "http://localhost:8788/list?business=biz_local&mbx=$M"
curl -s "http://localhost:8788/open?business=biz_local&mbx=$M"
curl -s "http://localhost:8788/refuse?business=biz_local&mbx=$M"   # a refusal, across two processes, as a value
```

The driver prints Mail's answers as the dashboard will branch on them: an ok
answer's value, or `{"refused":{"name":…,"message":…}}` (status 409) for a
refusal. An exception in the driver itself (opening a message) or a failing
binding shows as `{"failed":<name>}` (status 500). The driver keeps the
owner's private key in memory only after Mail accepts the enrolment, and
loses it when it reloads.

### Observed, 2026-09-26 (after refusals became values)

**With S1 and S3 merged** (a throwaway checkout of the integration branch;
ports 8797/8798 because 8787 was already in use):

```text
unknown address  → {"outcome":"ok","rejectReason":"No such mailbox",…}
provisioned      → {"outcome":"ok","rejectReason":"This mailbox is not accepting mail",…}
/refuse          → {"ok":false,"error":{"name":"CapabilityRejected","message":"capability rejected: expired","reason":"expired"}}
/list, business_x  → {"refused":{"name":"NotFound","message":"not found"}}
/enroll          → {"keyId":"dcb51e21bad5f954d952328b3398f464"}
/enroll again    → {"refused":{"name":"InvalidRequest","message":"invalid request: the mailbox is not awaiting enrolment"}}
deliver          → {"outcome":"ok","forwards":[],"replies":[],"events":[{"type":"received",…}]}
/list            → [{"id":"msg_23senmk2xh6a2pds2bj9v3t45b","folder":"inbox","size":283,…,"sealedHeaderChars":583}]
/open            → {"id":"msg_23senmk2xh6a2pds2bj9v3t45b","subject":"Kitchen remodel quote",
                     "from":{"name":"Ana Ruiz","address":"ana@example.com"},
                     "snippet":"Hi, we'd like a quote for a kitchen remodel.","rawBytes":283}
without &format=json → Worker successfully processed email
GET http://localhost:8797/ → 404
```

Across the two processes a refusal arrives as a value with its `name` and
`reason` (the S2 audit saw a thrown one arrive as `Error`, the name folded
into its message and `reason` gone), and `body()`'s `ReadableStream` arrives inside
the ok answer and opens to the exact raw bytes. No refusal made either
process log an uncaught exception or a "hung" cancellation. The Mail Worker
logged two "hung" cancellations once, around its first request while the
driver was connecting through the dev registry; repeating every request of
the run did not bring them back.

The Mail Worker's log lines carry ids, sizes, outcomes and jti values only,
for example
`{"event":"mail-service","method":"enroll","jti":"a-fU8itiSMVEZO0Zs1s9eQ","outcome":"accepted","mailbox":"mbx_0a0p…","result":"InvalidRequest"}`;
it holds none of the subject, the sender's name or address, or the body.
(The earlier run, before this change, also grepped the whole `.wrangler/state`
directory for them and found nothing; the R2 object starts with `PMB1`.)

**Before S1 and S3 were merged** (the packages were still stubs; not re-run
after this change): the Mailbox recomputes the keyId with S1's `keyIdOf`, a stub
that throws, so `/enroll` answers
`{"refused":{"name":"InternalError","message":"internal error"}}`, the
Mailbox logs a `mailbox-error` naming `NotImplemented`, and MailService an
operator alert with the jti. That path is the InternalError test in
`test/service.test.ts`. Nothing is stored without S1, by design.
