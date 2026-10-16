import { WorkerEntrypoint } from "cloudflare:workers";
import { Directory, type DirectoryEntry } from "./directory/directory";
import type { Env } from "./env";
import { InvalidRequest, type MailResult, NotFound, Refusal, errorName, internalError, ok, refused } from "./errors";
import { logAlert, logEvent } from "./log";
import type { PolicyView } from "./mailbox/types";
import { mailboxRpc } from "./service";

/**
 * The operator's narrow entrypoint (plan.md §4, tasks.md S2i): suspend,
 * resume, and the delivery mode with its forward target (M10). Exported and
 * bound to nothing deployed: its only caller is the operator's own tool,
 * `scripts/mail-admin`, a local `wrangler dev` with a remote binding to this
 * entrypoint (tasks.md S8). It carries no capability because it acts for
 * the operator, never for a mailbox owner; every change it makes is written
 * to the mailbox's audit log, which the owner reads.
 *
 * It answers the way MailService does (contracts/mail-service-v1.md): a
 * MailResult, with refusals as values and never thrown across the hop.
 */
const OPERATOR = /^[A-Za-z0-9._@:-]{1,100}$/;

export class MailAdmin extends WorkerEntrypoint<Env> {
  async suspend(input: { mailboxId: string; operator: string }): Promise<MailResult<{ status: "suspended" }>> {
    return this.run("suspend", input, async (entry, operator) => {
      if (!(await new Directory(this.env.DIRECTORY).transition(entry.id, "active", "suspended"))) {
        throw new InvalidRequest("only an active mailbox can be suspended");
      }
      const recorded = await (await mailboxRpc(this.env, entry.id)).recordOperatorAction(entry, operator, "mailbox-suspended");
      return recorded.ok ? ok({ status: "suspended" as const }) : recorded;
    });
  }

  async resume(input: { mailboxId: string; operator: string }): Promise<MailResult<{ status: "active" }>> {
    return this.run("resume", input, async (entry, operator) => {
      if (!(await new Directory(this.env.DIRECTORY).transition(entry.id, "suspended", "active"))) {
        throw new InvalidRequest("only a suspended mailbox can be resumed");
      }
      const recorded = await (await mailboxRpc(this.env, entry.id)).recordOperatorAction(entry, operator, "mailbox-resumed");
      return recorded.ok ? ok({ status: "active" as const }) : recorded;
    });
  }

  /** `store`, or `store-and-forward` with a verified Email Routing destination (plan.md §8, step 4). */
  async setDelivery(input: { mailboxId: string; operator: string; delivery: string; forwardTo?: string | null }): Promise<MailResult<PolicyView>> {
    return this.run("setDelivery", input, async (entry, operator) => {
      const { delivery, forwardTo } = input;
      const stub = await mailboxRpc(this.env, entry.id);
      return stub.setDelivery(entry, operator, forwardTo === undefined ? { delivery } : { delivery, forwardTo });
    });
  }

  private async run<T>(
    method: string,
    input: { mailboxId: string; operator: string },
    fn: (entry: DirectoryEntry, operator: string) => Promise<MailResult<T>>,
  ): Promise<MailResult<T>> {
    let mailbox: string | null = null;
    let answer: MailResult<T>;
    let failure: string | null = null;
    try {
      if (typeof input?.operator !== "string" || !OPERATOR.test(input.operator)) throw new InvalidRequest("operator must name who acts");
      const entry = typeof input.mailboxId === "string" ? await new Directory(this.env.DIRECTORY).byId(input.mailboxId) : null;
      if (entry === null || entry.status === "closed") throw new NotFound();
      mailbox = entry.id;
      answer = await fn(entry, `operator:${input.operator.replace(/^operator:/, "")}`);
    } catch (err) {
      if (err instanceof Refusal) {
        answer = refused(err.error);
      } else {
        failure = errorName(err);
        answer = { ok: false, error: internalError() };
      }
    }
    if (!answer.ok && answer.error.name === "InternalError") logAlert("mail-admin-internal-error", { method, mailbox, error: failure });
    logEvent("mail-admin", { method, mailbox, result: answer.ok ? "ok" : answer.error.name });
    return answer.ok ? answer : refused(answer.error);
  }
}
