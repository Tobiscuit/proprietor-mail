# Contract: `MailService` RPC, version 1

**Served by** `proprietor-mail`'s `MailService` entrypoint. **Called by** the
dashboard's inbox route group, only from server actions and its one streaming
route handler, over a service binding with `entrypoint: "MailService"`.
**Status:** agreed shape 2026-09-26. The method table is `specs/001-inbox-module/plan.md`
§4; this file fixes how answers and refusals cross the RPC boundary.

## Every answer is a value; expected refusals are never thrown

```ts
type MailResult<T> = { ok: true; value: T } | { ok: false; error: MailError };

interface MailError {
  name:
    | "CapabilityRejected" | "NotFound" | "Forbidden" | "InvalidRequest"
    | "MailboxNotActive" | "RateLimited" | "SendFailed" | "AssistantUnavailable"
    | "RecipientSuppressed" | "InternalError";
  /** Safe to log and to show: never mail content, never an address. */
  message: string;
  reason?: "invalid" | "expired";   // CapabilityRejected
  retryAfterSeconds?: number;       // RateLimited
  retryable?: boolean;              // SendFailed
  /** RecipientSuppressed: which recipients, by position; never an address. */
  suppressed?: { field: "to" | "cc" | "bcc"; index: number; reason: "bounce" | "complaint"; since: string }[];
}
```

Every `MailService` method resolves to a `MailResult`. None of the nine error
names above is ever delivered as a thrown exception. A failure Mail did not
expect is answered as `InternalError`, and it is logged inside Mail as an
operator alert carrying the capability's `jti`.

The caller (the dashboard) branches on `ok` and `error.name`. It never inspects
an `Error` object that came out of Mail. If a call to Mail does reject, that
means the binding or the runtime failed, not a refusal, and the caller treats
it as `InternalError`.

## Why (found in the S2 audit, 2026-09-26, reproduced with a three-line Worker)

- When a Workers RPC method throws, workerd logs the throw as "Uncaught" on the
  callee's side, and then cancels the callee's invocation with "your Worker's
  code had hung and would never generate a response". The caller gets the error
  at once, so nothing waits forever, but every refused call then appears in
  production logs as an uncaught exception and a cancelled invocation.
  - Seen with the test pool's workerd 1.20260815.1 through `exports`.
  - Seen through a real `serviceBindings` entry.
  - Seen under `wrangler dev` 4.141.0 (workerd 1.20260925.1) with two
    processes joined by a service binding.
- In that last, two-process setup, the error reached the caller named `Error`,
  with "CapabilityRejected: …" folded into its message and its `reason` field
  gone, although both Workers had compatibility date 2026-08-15. Only inside
  one isolate did the name and fields survive. A plain result value carries
  the same data on every path.

The same rule holds inside Mail, from the `Mailbox` Durable Object to the
entrypoint: expected refusals cross that hop as values too.

## Exceptions that remain deliberate

The `email()` handler (not an RPC method) still throws in two cases, both from
`plan.md` §5 and both real failures that should be loud:

- in `store` delivery mode, when storing fails, so that Email Routing does not
  treat the message as delivered;
- in `store-and-forward` mode, when the forward fails, before anything is
  stored, so that the sender's server retries and no half-delivery exists.

The test suite fails on any other uncaught exception or "hung" cancellation
that workerd prints. A test that exercises one of these two throws declares it
by name.

## Amended 2026-09-28 (round 2)

- `RecipientSuppressed` (domain-model M11): `send` refuses before anything is
  reserved or sent when a recipient bounced permanently or complained, and
  names each one by its position in `to`, `cc` or `bcc`. The dashboard shows
  which recipient it was from its own copy of the request. Implemented by
  slice S5.
- `mailboxes()` and `mailbox()` return `addresses` (the primary first), and
  `send` takes an optional `from`, one of those addresses (M6 as amended,
  `plan.md` §12). Implemented by slice S2b.
- Nine error names become ten. A caller that meets a name it does not know
  treats it as `InternalError`.

## Amended 2026-10-16: `unread` counts only what can be opened

`unread(cap)` answers `{ inbox }`: the Inbox messages not yet marked seen
whose `keyId` is one of the mailbox's keys, live or retired (the `keys` of
`mailbox()`). A message sealed to any other key can never be opened on the
owner's devices, so it could never be marked seen, and it would hold the
count at 1 for good. `list` still returns it, with its `keyId`, so the owner
sees that something arrived; `unread` does not count it. The count Mail
sends the dashboard on each arrival (the `NewMailSignal`, `plan.md` §1,
seam 4) follows the same rule.

