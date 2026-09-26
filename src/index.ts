import type { Env } from "./env";
import { handleEmail } from "./inbound/email-handler";

export { Mailbox } from "./mailbox/mailbox";

export default {
  // No public HTTP surface (plan.md §3): 404 to everything.
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },

  // Email Routing's hand-off. A throw from here is a storage failure in
  // `store` mode; what Email Routing then does (retry or bounce) is unverified
  // (spec §8) and is settled by tasks.md S8 before any address is routed here.
  async email(message: ForwardableEmailMessage, env: Env, _ctx: ExecutionContext): Promise<void> {
    await handleEmail(message, env);
  },
} satisfies ExportedHandler<Env>;
