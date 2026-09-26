# Contract: `MailService` RPC, version 1

**Served by** `platform-mail`'s `MailService` entrypoint. **Called by** the
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
    | "InternalError";
  /** Safe to log and to show: never mail content, never an address. */
  message: string;
  reason?: "invalid" | "expired";   // CapabilityRejected
  retryAfterSeconds?: number;       // RateLimited
  retryable?: boolean;              // SendFailed
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

The `email()` handler still throws in one case. In `store` delivery mode, when
storing fails, it throws so that Email Routing does not treat the message as
delivered (`plan.md` §5). That is a real failure, and it should be loud.
