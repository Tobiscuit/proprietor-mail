import { WorkerEntrypoint } from "cloudflare:workers";
import { Directory, type DirectoryEntry } from "./directory/directory";
import type { Env } from "./env";
import { InvalidRequest, NotFound, isPublicError, publicError } from "./errors";
import { logEvent } from "./log";
import type { PolicyView } from "./mailbox/types";
import { mailboxRpc } from "./service";

/**
 * The operator's narrow entrypoint (plan.md §4, tasks.md S2i): suspend,
 * resume, and the delivery mode with its forward target (M10). Exported and
 * bound to NOTHING: no Worker can call it until the operator deliberately
 * binds it to his own tooling. It carries no capability because it acts for
 * the operator, never for a mailbox owner; every change it makes is written
 * to the mailbox's audit log, which the owner reads.
 */
const OPERATOR = /^[A-Za-z0-9._@:-]{1,100}$/;

export class MailAdmin extends WorkerEntrypoint<Env> {
  async suspend(input: { mailboxId: string; operator: string }): Promise<{ status: "suspended" }> {
    return this.run("suspend", input, async (entry, operator) => {
      if (!(await new Directory(this.env.DIRECTORY).transition(entry.id, "active", "suspended"))) {
        throw new InvalidRequest("only an active mailbox can be suspended");
      }
      await (await mailboxRpc(this.env, entry.id)).recordOperatorAction(entry, operator, "mailbox-suspended");
      return { status: "suspended" as const };
    });
  }

  async resume(input: { mailboxId: string; operator: string }): Promise<{ status: "active" }> {
    return this.run("resume", input, async (entry, operator) => {
      if (!(await new Directory(this.env.DIRECTORY).transition(entry.id, "suspended", "active"))) {
        throw new InvalidRequest("only a suspended mailbox can be resumed");
      }
      await (await mailboxRpc(this.env, entry.id)).recordOperatorAction(entry, operator, "mailbox-resumed");
      return { status: "active" as const };
    });
  }

  /** `store`, or `store-and-forward` with a verified Email Routing destination (plan.md §8, step 4). */
  async setDelivery(input: { mailboxId: string; operator: string; delivery: string; forwardTo?: string | null }): Promise<PolicyView> {
    return this.run("setDelivery", input, async (entry, operator) => {
      const { delivery, forwardTo } = input;
      const stub = await mailboxRpc(this.env, entry.id);
      return stub.setDelivery(entry, operator, forwardTo === undefined ? { delivery } : { delivery, forwardTo });
    });
  }

  private async run<T>(
    method: string,
    input: { mailboxId: string; operator: string },
    fn: (entry: DirectoryEntry, operator: string) => Promise<T>,
  ): Promise<T> {
    try {
      if (typeof input?.operator !== "string" || !OPERATOR.test(input.operator)) throw new InvalidRequest("operator must name who acts");
      const entry = typeof input.mailboxId === "string" ? await new Directory(this.env.DIRECTORY).byId(input.mailboxId) : null;
      if (entry === null || entry.status === "closed") throw new NotFound();
      const result = await fn(entry, `operator:${input.operator.replace(/^operator:/, "")}`);
      logEvent("mail-admin", { method, mailbox: entry.id, result: "ok" });
      return result;
    } catch (err) {
      logEvent("mail-admin", { method, result: isPublicError(err) ? err.name : "internal-error" });
      throw isPublicError(err) ? publicError(err) : new Error("internal error");
    }
  }
}
