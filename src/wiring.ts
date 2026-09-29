import { keyIdOf, newId, sealMessage } from "@proprietor/mail-crypto";
import { buildMime, sesRawMailer } from "@proprietor/mail-outbound";
import type { Env } from "./env";
import type { MailboxPorts, NewMailSignal, RawMailer } from "./ports";

/**
 * The real implementations behind the Mailbox's ports: @proprietor/mail-crypto
 * (slice S1) and @proprietor/mail-outbound (slice S3). Until those slices land,
 * their functions throw `NotImplemented`; nothing here calls one before it is
 * needed, so constructing the ports never throws.
 */
export function productionPorts(env: Env): MailboxPorts {
  let ses: RawMailer | undefined;
  return {
    sealer: { seal: sealMessage, keyIdOf },
    ids: { messageId: () => newId("msg") },
    mime: { build: buildMime },
    mailer: {
      // Built on the first send, so a mailbox that never sends never reads the credential.
      send: (req) =>
        (ses ??= sesRawMailer({
          accessKeyId: env.SES_ACCESS_KEY_ID,
          secretAccessKey: env.SES_SECRET_ACCESS_KEY,
          region: env.SES_REGION,
        })).send(req),
    },
    signal: noNewMailSignal,
    clock: { now: () => new Date() },
  };
}

/**
 * The new-mail signal until the dashboard exports a `MailSignals` entrypoint
 * to bind (wrangler.jsonc has the sketch). Deliberately silent: it
 * receives a count and drops it.
 */
export const noNewMailSignal: NewMailSignal = {
  async unread() {},
};
