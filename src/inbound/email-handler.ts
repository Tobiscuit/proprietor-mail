import { routeAgentEmail } from "agents";
import { Directory } from "../directory/directory";
import type { Env } from "../env";
import { logEvent } from "../log";

/**
 * Email Routing → here → the recipient's Mailbox (plan.md §5).
 *
 * `routeAgentEmail` asks the resolver which Agent owns the message. The
 * resolver reads the Mail Directory by the ENVELOPE recipient (never a header,
 * which the sender controls) and answers with the binding name and the mailbox
 * id: agents 0.24.0 matches `agentName` against the env's binding names (as
 * written, kebab-case or lower-case), not class names, then calls the Agent's
 * `_onEmail` over RPC, which runs `Mailbox.onEmail`. An unknown address has no
 * route, and `onNoRoute` rejects it.
 *
 * Status, size and everything after are the Mailbox's to check: it is the one
 * place that knows the policy, and it re-reads the Directory itself.
 */
export const MAILBOX_AGENT = "Mailbox";

export async function handleEmail(message: ForwardableEmailMessage, env: Env): Promise<void> {
  const directory = new Directory(env.DIRECTORY);
  await routeAgentEmail(message, env, {
    resolver: async (email) => {
      const entry = await directory.byAddress(email.to);
      return entry === null ? null : { agentName: MAILBOX_AGENT, agentId: entry.id };
    },
    onNoRoute: (email) => {
      email.setReject("No such mailbox");
      // No address in the log (spec D8): the size and the outcome only.
      logEvent("arrival", { mailbox: null, size: email.rawSize, outcome: "rejected", reason: "no-such-mailbox" });
    },
  });
}
