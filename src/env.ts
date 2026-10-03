import type { Mailbox } from "./mailbox/mailbox";

/**
 * The Mail Worker's bindings (wrangler.jsonc). Written by hand rather than
 * generated, so that production code sees exactly these and nothing a test
 * configuration adds.
 */
export interface Env {
  /** The Mail Directory (Mail's own D1). */
  DIRECTORY: D1Database;
  /** Sealed raw messages, one object per message. */
  MAIL: R2Bucket;
  /** One Mailbox Agent per mailbox; the binding name is routeAgentEmail's `agentName`. */
  Mailbox: DurableObjectNamespace<Mailbox>;
  /** Secret: JSON object of key id → base64url 32-byte HS256 key (contracts/capability-v1.md). */
  MAIL_CAPABILITY_KEYS: string;
  /** Secrets: the client-mail SES principal (plan.md §6). It also reads the events queue. */
  SES_ACCESS_KEY_ID: string;
  SES_SECRET_ACCESS_KEY: string;
  SES_REGION: string;
  /**
   * Secret: the URL of Mail's own SES events queue (plan.md §13), set after the
   * first deploy (plan.md §15). A secret rather than a var because it names
   * the AWS account. Until it is set, the cron raises an operator alert and
   * does nothing else.
   */
  MAIL_EVENTS_QUEUE_URL: string;
}

declare global {
  namespace Cloudflare {
    // `import { env } from "cloudflare:workers"` is typed from this.
    interface Env extends MailEnv {}
  }
}

type MailEnv = Env;
