import { runDeliverabilityFeed } from "./deliverability/feed";
import type { Env } from "./env";
import { handleEmail } from "./inbound/email-handler";

export { MailAdmin } from "./admin";
export { Mailbox } from "./mailbox/mailbox";
export { MailService } from "./service";

export default {
  // No public HTTP surface (plan.md §3): 404 to everything.
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },

  // Email Routing's hand-off. A throw from here is a storage failure in
  // `store` mode: the sending server sees a temporary failure and retries on
  // its own (the S8 probe, tasks.md), so the message is delayed, never lost
  // or bounced.
  async email(message: ForwardableEmailMessage, env: Env, _ctx: ExecutionContext): Promise<void> {
    await handleEmail(message, env);
  },

  // The cron (wrangler.jsonc `triggers`): the deliverability feed (plan.md §13).
  // A failure to reach the queue throws, so the run shows as failed; nothing
  // is lost, the queue keeps what was not deleted.
  async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    await runDeliverabilityFeed(env, controller.cron);
  },
} satisfies ExportedHandler<Env>;
