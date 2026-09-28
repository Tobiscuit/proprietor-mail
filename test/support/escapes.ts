import type { TestContext } from "vitest";
import { type DeclaredEscape, EMAIL_THROW } from "../harness/escape-guard";

declare module "vitest" {
  interface TaskMeta {
    /** Escapes this test expects; read by the escape guard (test/harness/escape-guard.ts). */
    escapes?: DeclaredEscape[];
  }
}

/**
 * The ONE throw this suite lets escape an RPC hop: `email()` failing a
 * delivery, on purpose, so that Email Routing does not count the message as
 * delivered (plan.md §5). The throw starts in the Mailbox's `onEmail`, which
 * the Agents SDK reaches over Durable Object RPC (`_onEmail`), so workerd
 * prints it as an uncaught exception there; a forward that fails prints once
 * more, on the SDK's EmailBridge.
 *
 * Declares the escape for the escape guard, then delivers and returns what
 * `email()` threw. `error` is text in the thrown error's message and `lines`
 * how many escape lines workerd prints for it; the guard fails the run if the
 * count differs either way. Everything reached over RPC answers with values
 * instead (test/support/results.ts), and nothing else may be declared.
 */
export async function expectEmailThrow(
  task: TestContext["task"],
  declared: { reason: string; error: string; lines: number },
  delivery: Promise<unknown>,
): Promise<Error> {
  (task.meta.escapes ??= []).push({ kind: EMAIL_THROW, ...declared });
  try {
    await delivery;
  } catch (err) {
    return err as Error;
  }
  throw new Error("expected email() to throw");
}
