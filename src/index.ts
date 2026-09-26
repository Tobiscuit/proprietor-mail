import type { Env } from "./env";

export { Mailbox } from "./mailbox/mailbox";

export default {
  // No public HTTP surface (plan.md §3): 404 to everything.
  async fetch(): Promise<Response> {
    return new Response(null, { status: 404 });
  },
} satisfies ExportedHandler<Env>;
