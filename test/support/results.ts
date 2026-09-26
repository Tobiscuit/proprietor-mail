import type { MailError } from "../../src/errors";

/**
 * MailService, MailAdmin and the Mailbox answer with values
 * (contracts/mail-service-v1.md): `{ ok: true, value }` or `{ ok: false, error }`.
 * A refused call RESOLVES; it never rejects. These two read an answer and fail
 * the test, naming what came instead, when it is not the expected kind.
 *
 * Typed structurally (`ok` and `value`/`error`) so that they accept the RPC
 * stub's mapped type of a MailResult as well as the result itself.
 */
type Answer = { ok: true; value: unknown } | { ok: false; error: MailError };

export function valueOf<R extends Answer>(answer: R): Extract<R, { ok: true }>["value"] {
  if (isAnswer(answer) && answer.ok) return answer.value as Extract<R, { ok: true }>["value"];
  throw new Error(`expected an ok answer, got ${describe(answer)}`);
}

export function refusalOf(answer: Answer): MailError {
  if (isAnswer(answer) && !answer.ok) return answer.error;
  throw new Error(`expected a refusal, got ${describe(answer)}`);
}

function isAnswer(value: unknown): value is Answer {
  return typeof value === "object" && value !== null && "ok" in value && typeof (value as { ok: unknown }).ok === "boolean";
}

function describe(value: unknown): string {
  if (!isAnswer(value)) return `something that is not a MailResult (${typeof value})`;
  return value.ok ? "an ok answer" : `a refusal ${JSON.stringify(value.error)}`;
}
