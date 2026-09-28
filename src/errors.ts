/**
 * How MailService answers (contracts/mail-service-v1.md): every method
 * resolves to a MailResult, and a refusal is a VALUE, never a thrown
 * exception. When a Workers RPC method throws, workerd logs it as uncaught on
 * the callee's side and cancels the invocation as "hung" (the S2 audit), and
 * across processes the error arrived renamed to `Error` with its fields gone.
 * A plain object carries the same data on every path.
 *
 * Inside this Worker a refusal is still thrown, as a `Refusal`, because that
 * is the shortest way out of a deep check. It never crosses an RPC hop: the
 * Mailbox's methods (`Mailbox.answer`) and the entrypoints (`MailService.call`,
 * `MailAdmin.run`) catch it and answer with its `error`. Anything else they
 * catch is a failure nobody expected, and is answered as `InternalError`.
 *
 * Messages are fixed strings. None carries message content, an address, a
 * subject or a key.
 */

export type MailErrorName =
  | "CapabilityRejected"
  | "NotFound"
  | "Forbidden"
  | "InvalidRequest"
  | "MailboxNotActive"
  | "RateLimited"
  | "SendFailed"
  | "AssistantUnavailable"
  | "InternalError";

export interface MailError {
  name: MailErrorName;
  /** Safe to log and to show: never mail content, never an address. */
  message: string;
  /** CapabilityRejected only. */
  reason?: "invalid" | "expired";
  /** RateLimited only. */
  retryAfterSeconds?: number;
  /** SendFailed only. */
  retryable?: boolean;
}

export type MailResult<T> = { ok: true; value: T } | { ok: false; error: MailError };

export function ok<T>(value: T): { ok: true; value: T } {
  return { ok: true, value };
}

export function refused(error: MailError): { ok: false; error: MailError } {
  return { ok: false, error: publicCopy(error) };
}

/** The answer to a failure nobody expected. The details go to the operator's log, never to the caller. */
export function internalError(): MailError {
  return { name: "InternalError", message: "internal error" };
}

/**
 * Exactly the documented fields of an error, rebuilt. Whatever a MailError
 * picked up on its way (a field added by mistake, a runtime property), the
 * caller gets the contract's shape, so a NotFound decided in the Mailbox cannot
 * be told apart from one decided in MailService (domain-model M4).
 */
export function publicCopy(error: MailError): MailError {
  const copy: MailError = { name: error.name, message: error.message };
  if (error.name === "CapabilityRejected") copy.reason = error.reason === "expired" ? "expired" : "invalid";
  if (error.name === "RateLimited") copy.retryAfterSeconds = typeof error.retryAfterSeconds === "number" ? error.retryAfterSeconds : 60;
  if (error.name === "SendFailed") copy.retryable = error.retryable === true;
  return copy;
}

/** An expected refusal, thrown inside this Worker and answered as a value at the RPC boundary. */
export class Refusal extends Error {
  readonly error: MailError;
  constructor(error: MailError) {
    super(error.message);
    this.name = error.name;
    this.error = error;
  }
}

export class CapabilityRejected extends Refusal {
  readonly reason: "invalid" | "expired";
  constructor(reason: "invalid" | "expired") {
    super({ name: "CapabilityRejected", message: `capability rejected: ${reason}`, reason });
    this.reason = reason;
  }
}

/** Also the answer for a mailbox of another business (domain-model M4): identical, so existence does not leak. */
export class NotFound extends Refusal {
  constructor() {
    super({ name: "NotFound", message: "not found" });
  }
}

export class Forbidden extends Refusal {
  constructor() {
    super({ name: "Forbidden", message: "forbidden" });
  }
}

export class InvalidRequest extends Refusal {
  /** A fixed description of what was wrong with the request's SHAPE; never an echo of its values. */
  constructor(problem: string) {
    super({ name: "InvalidRequest", message: `invalid request: ${problem}` });
  }
}

export class MailboxNotActive extends Refusal {
  constructor() {
    super({ name: "MailboxNotActive", message: "this mailbox is not active" });
  }
}

export class RateLimited extends Refusal {
  constructor(retryAfterSeconds: number) {
    super({ name: "RateLimited", message: "send rate limit reached", retryAfterSeconds });
  }
}

export class SendFailed extends Refusal {
  constructor(retryable: boolean) {
    super({ name: "SendFailed", message: retryable ? "sending failed; it may be retried" : "sending failed", retryable });
  }
}

export class AssistantUnavailable extends Refusal {
  constructor() {
    super({ name: "AssistantUnavailable", message: "the assistant is not available (spec decision D1)" });
  }
}

/** The name of whatever was thrown, for a log line: never its message, which a library may fill with content. */
export function errorName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err;
}
