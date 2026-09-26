/**
 * The errors MailService answers with (plan.md §4). They cross Workers RPC as
 * errors whose `name` is one of these, with their own fields intact: the
 * Worker's compatibility date is after 2026-04-21, so enhanced error
 * serialization preserves `name`, `message` and serializable own properties.
 * RPC does NOT preserve the class, so a caller must check `name` (and `reason`,
 * `retryAfterSeconds`, `retryable`), never `instanceof`.
 *
 * Messages are fixed strings. None carries message content, an address, a
 * subject or a key.
 */

export type ErrorName =
  | "CapabilityRejected"
  | "NotFound"
  | "Forbidden"
  | "InvalidRequest"
  | "MailboxNotActive"
  | "RateLimited"
  | "SendFailed"
  | "AssistantUnavailable";

export const ERROR_NAMES: ReadonlySet<string> = new Set<ErrorName>([
  "CapabilityRejected",
  "NotFound",
  "Forbidden",
  "InvalidRequest",
  "MailboxNotActive",
  "RateLimited",
  "SendFailed",
  "AssistantUnavailable",
]);

export class CapabilityRejected extends Error {
  readonly reason: "invalid" | "expired";
  constructor(reason: "invalid" | "expired") {
    super(`capability rejected: ${reason}`);
    this.name = "CapabilityRejected";
    this.reason = reason;
  }
}

/** Also the answer for a mailbox of another tenant (domain-model M4): identical, so existence does not leak. */
export class NotFound extends Error {
  constructor() {
    super("not found");
    this.name = "NotFound";
  }
}

export class Forbidden extends Error {
  constructor() {
    super("forbidden");
    this.name = "Forbidden";
  }
}

export class InvalidRequest extends Error {
  /** A fixed description of what was wrong with the request's SHAPE; never an echo of its values. */
  constructor(problem: string) {
    super(`invalid request: ${problem}`);
    this.name = "InvalidRequest";
  }
}

export class MailboxNotActive extends Error {
  constructor() {
    super("this mailbox is not active");
    this.name = "MailboxNotActive";
  }
}

export class RateLimited extends Error {
  readonly retryAfterSeconds: number;
  constructor(retryAfterSeconds: number) {
    super("send rate limit reached");
    this.name = "RateLimited";
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class SendFailed extends Error {
  readonly retryable: boolean;
  constructor(retryable: boolean) {
    super(retryable ? "sending failed; it may be retried" : "sending failed");
    this.name = "SendFailed";
    this.retryable = retryable;
  }
}

export class AssistantUnavailable extends Error {
  constructor() {
    super("the assistant is not available (spec decision D1)");
    this.name = "AssistantUnavailable";
  }
}

/** True for an error MailService may hand to its caller as it is. */
export function isPublicError(err: unknown): err is Error {
  return err instanceof Error && ERROR_NAMES.has(err.name);
}

/**
 * A fresh copy of a public error, carrying only its documented fields. An
 * error that crossed a Durable Object RPC hop picks up runtime fields
 * (`remote`, `durableObjectId`); rebuilding keeps MailService's answers exactly
 * the documented shape, so a NotFound from a Mailbox cannot be told apart from
 * a NotFound decided here (M4).
 */
export function publicError(err: Error): Error {
  const fields = err as Error & { reason?: unknown; retryAfterSeconds?: unknown; retryable?: unknown };
  switch (err.name as ErrorName) {
    case "CapabilityRejected":
      return new CapabilityRejected(fields.reason === "expired" ? "expired" : "invalid");
    case "NotFound":
      return new NotFound();
    case "Forbidden":
      return new Forbidden();
    case "InvalidRequest": {
      const copy = new InvalidRequest("");
      copy.message = err.message;
      return copy;
    }
    case "MailboxNotActive":
      return new MailboxNotActive();
    case "RateLimited":
      return new RateLimited(typeof fields.retryAfterSeconds === "number" ? fields.retryAfterSeconds : 60);
    case "SendFailed":
      return new SendFailed(fields.retryable === true);
    case "AssistantUnavailable":
      return new AssistantUnavailable();
    default:
      return new Error("internal error");
  }
}
