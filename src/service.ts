import { getAgentByName } from "agents";
import { WorkerEntrypoint } from "cloudflare:workers";
import { type Capability, type CapabilityKeys, loggableJti, parseCapabilityKeys, verifyCapability } from "./capability";
import { Directory } from "./directory/directory";
import type { Env } from "./env";
import { CapabilityRejected, InvalidRequest, type MailResult, NotFound, Refusal, errorName, internalError, ok, refused } from "./errors";
import { logAlert, logEvent } from "./log";
import type { Mailbox } from "./mailbox/mailbox";
import { NO_AUTH, parseAuth } from "./mailbox/sessions";
import type {
  AuditEntry,
  CallContext,
  ChallengeView,
  DeviceView,
  DraftRecord,
  ListPage,
  MailboxView,
  MessageItem,
  PolicyView,
  SendResult,
  SessionView,
} from "./mailbox/types";

/**
 * The dashboard's only way in (plan.md §4): RPC over a service binding, no
 * HTTP. Every method takes a capability first (contracts/capability-v1.md),
 * and answers with ciphertext; plaintext comes in only for `send`.
 *
 * Here: rules 1-6 of the capability, then rule 7 against the Directory (M4:
 * a missing, closed or other business's mailbox is one and the same NotFound).
 * In the Mailbox: rule 8 (its policy's roles) and every invariant of its own.
 *
 * Every method resolves to a MailResult (contracts/mail-service-v1.md): a
 * refusal is a value, never a thrown exception, on this hop and on the hop to
 * the Mailbox. A failure nobody expected is answered as InternalError and
 * raised to the operator with the capability's jti.
 *
 * Every call writes exactly one log line: the method, the capability's jti and
 * the outcome, so the dashboard's log of the same jti finds it. Never content.
 *
 * Spec 002 (contracts/device-v1.md Part B): every mailbox call but
 * `mailboxes`, `mailbox`, `unread`, `enroll`, `challenge` and `openSession`
 * takes a last argument `auth` (B1), the mail session and, where it is
 * needed, a factor proof; `send` carries its session inside the request (D29).
 * Each answer's need is SESSION_NEEDS's (src/mailbox/sessions.ts), applied in
 * the Mailbox. Every public method of this class is an RPC method; its
 * helpers are `#private`, so the runtime does not serve them.
 */

/** device-v1 B1: the last argument of every method that needs a session. */
export interface Auth {
  /** The token from openSession(). */
  session?: string;
  /** A fresh factor proof, for the methods that need one. */
  factorProof?: { challengeId: string; answer: string };
}

let keyCache: { json: string | undefined; keys: CapabilityKeys } | undefined;

function capabilityKeys(env: Env): CapabilityKeys {
  if (keyCache === undefined || keyCache.json !== env.MAIL_CAPABILITY_KEYS) {
    keyCache = { json: env.MAIL_CAPABILITY_KEYS, keys: parseCapabilityKeys(env.MAIL_CAPABILITY_KEYS) };
  }
  return keyCache.keys;
}

/**
 * The Mailbox as MailService calls it. Typed from the class's own methods:
 * the runtime's RPC stub types, mapped twice (entrypoint → Agent stub),
 * collapse to `never` under TypeScript 7.
 */
export type MailboxRpc = Pick<
  Mailbox,
  | "describe"
  | "createChallenge"
  | "openSession"
  | "upgrade"
  | "registerDevice"
  | "updateDevice"
  | "removeDevice"
  | "enroll"
  | "addWrap"
  | "removeWrap"
  | "listMessages"
  | "bodyKey"
  | "updateMessage"
  | "purgeMessage"
  | "listDrafts"
  | "saveDraft"
  | "deleteDraft"
  | "send"
  | "unreadCount"
  | "setPolicy"
  | "readAudit"
  | "setDelivery"
  | "recordOperatorAction"
>;

export async function mailboxRpc(env: Env, mailboxId: string): Promise<MailboxRpc> {
  // getAgentByName, not namespace.get: it starts the Agent's lifecycle first.
  return (await getAgentByName(env.Mailbox, mailboxId)) as unknown as MailboxRpc;
}

type Stub = MailboxRpc;

/** One row of `mailboxes()`: enough to show "not set up", "set up your inbox" or the inbox, and to offer a From. */
export interface MailboxSummary {
  id: string;
  /** The primary address. */
  address: string;
  /** Every address that delivers to the mailbox, the primary first (plan.md §12). */
  addresses: string[];
  status: string;
}

export class MailService extends WorkerEntrypoint<Env> {
  /** The capability's business's mailboxes, for "not set up" / "set up your inbox" / the inbox. Any member role. */
  async mailboxes(cap: string): Promise<MailResult<MailboxSummary[]>> {
    return this.#call("mailboxes", cap, async (capability) =>
      ok(
        (await new Directory(this.env.DIRECTORY).forBusiness(capability.business)).map((m) => ({
          id: m.id,
          address: m.address,
          addresses: m.addresses,
          status: m.status,
        })),
      ),
    );
  }

  async mailbox(cap: string): Promise<MailResult<MailboxView>> {
    return this.#withMailbox("mailbox", cap, undefined, (stub, ctx) => stub.describe(ctx));
  }

  /** Only while provisioned; M5: the Directory row turns active only after the key ring has a key and a recovery wrap. */
  async enroll(cap: string, input: unknown): Promise<MailResult<{ keyId: string }>> {
    return this.#withMailbox("enroll", cap, undefined, async (stub, ctx) => {
      const enrolled = await stub.enroll(ctx, input);
      // A failed activation is an InternalError; the retry is safe (the Mailbox takes the same key again).
      if (enrolled.ok) await new Directory(this.env.DIRECTORY).activate(ctx.mailbox.id, new Date());
      return enrolled;
    });
  }

  /** B6: a challenge sealed to the active key (`purpose: "session"`) or to a factor's key. No session needed. */
  async challenge(cap: string, request: unknown): Promise<MailResult<ChallengeView>> {
    return this.#withMailbox("challenge", cap, undefined, (stub, ctx) => stub.createChallenge(ctx, request));
  }

  /** B6: a 60-minute mail session from a key proof (and a kept device's signature). */
  async openSession(cap: string, request: unknown): Promise<MailResult<SessionView>> {
    return this.#withMailbox("openSession", cap, undefined, (stub, ctx) => stub.openSession(ctx, request));
  }

  /** B5: an existing mailbox learns its factors' keys, and sessions become required, once. */
  async upgrade(cap: string, request: unknown, auth?: Auth): Promise<MailResult<null>> {
    return this.#withMailbox("upgrade", cap, auth, (stub, ctx) => stub.upgrade(ctx, request));
  }

  /** B7, F1: keeps the calling browser as a device, with a factor proof; the caller's session becomes the device's. */
  async registerDevice(cap: string, request: unknown, auth?: Auth): Promise<MailResult<DeviceView>> {
    return this.#withMailbox("registerDevice", cap, auth, (stub, ctx) => stub.registerDevice(ctx, request));
  }

  /** B7: from a device's own session, its new unlock key, tag and seal, or none (it locked). */
  async updateDevice(cap: string, request: unknown, auth?: Auth): Promise<MailResult<DeviceView>> {
    return this.#withMailbox("updateDevice", cap, auth, (stub, ctx) => stub.updateDevice(ctx, request));
  }

  /**
   * B7, F6: removes a kept device and rotates the mailbox key in one step: the
   * new key sealed to every remaining recipient, the old one retired with its
   * successor seal, every other session ended. Answers the new key's id.
   */
  async removeDevice(cap: string, request: unknown, auth?: Auth): Promise<MailResult<{ keyId: string }>> {
    return this.#withMailbox("removeDevice", cap, auth, (stub, ctx) => stub.removeDevice(ctx, request));
  }

  async addWrap(cap: string, wrap: unknown, auth?: Auth): Promise<MailResult<null>> {
    return this.#withMailbox("addWrap", cap, auth, (stub, ctx) => stub.addWrap(ctx, wrap));
  }

  async removeWrap(cap: string, wrapId: string, auth?: Auth): Promise<MailResult<null>> {
    return this.#withMailbox("removeWrap", cap, auth, (stub, ctx) => stub.removeWrap(ctx, wrapId));
  }

  async list(cap: string, query: unknown, auth?: Auth): Promise<MailResult<ListPage>> {
    return this.#withMailbox("list", cap, auth, (stub, ctx) => stub.listMessages(ctx, query));
  }

  /**
   * The sealed body, streamed from R2 (up to 25 MiB; never buffered here): the
   * `value` of an ok answer is the object's byte stream, which Workers RPC
   * carries inside the result with flow control.
   */
  async body(cap: string, messageId: string, auth?: Auth): Promise<MailResult<ReadableStream>> {
    return this.#withMailbox("body", cap, auth, async (stub, ctx) => {
      const key = await stub.bodyKey(ctx, messageId);
      if (!key.ok) return key;
      const object = await this.env.MAIL.get(key.value);
      if (object === null) throw new NotFound();
      return ok(object.body);
    });
  }

  async update(cap: string, messageId: string, patch: unknown, auth?: Auth): Promise<MailResult<MessageItem>> {
    return this.#withMailbox("update", cap, auth, (stub, ctx) => stub.updateMessage(ctx, messageId, patch));
  }

  async purge(cap: string, messageId: string, auth?: Auth): Promise<MailResult<null>> {
    return this.#withMailbox("purge", cap, auth, (stub, ctx) => stub.purgeMessage(ctx, messageId));
  }

  async drafts(cap: string, auth?: Auth): Promise<MailResult<DraftRecord[]>> {
    return this.#withMailbox("drafts", cap, auth, (stub, ctx) => stub.listDrafts(ctx));
  }

  async saveDraft(cap: string, draft: unknown, auth?: Auth): Promise<MailResult<{ id: string; updatedAt: string }>> {
    return this.#withMailbox("saveDraft", cap, auth, (stub, ctx) => stub.saveDraft(ctx, draft));
  }

  async deleteDraft(cap: string, draftId: string, auth?: Auth): Promise<MailResult<null>> {
    return this.#withMailbox("deleteDraft", cap, auth, (stub, ctx) => stub.deleteDraft(ctx, draftId));
  }

  /**
   * Plaintext lives only for this call: MIME → SES → the Sent copy, sealed.
   * The session rides inside the request (`request.session`, device-v1 B1,
   * D29), because the dashboard's send route hands the browser's request on
   * unchanged; it goes no further than the session check.
   */
  async send(cap: string, request: unknown): Promise<MailResult<SendResult>> {
    return this.#withMailbox("send", cap, sessionInside(request), (stub, ctx) => stub.send(ctx, request));
  }

  async unread(cap: string): Promise<MailResult<{ inbox: number }>> {
    return this.#withMailbox("unread", cap, undefined, (stub, ctx) => stub.unreadCount(ctx));
  }

  async setPolicy(cap: string, patch: unknown, auth?: Auth): Promise<MailResult<PolicyView & { displayName: string }>> {
    return this.#withMailbox("setPolicy", cap, auth, (stub, ctx) => stub.setPolicy(ctx, patch));
  }

  async audit(cap: string, query: unknown, auth?: Auth): Promise<MailResult<AuditEntry[]>> {
    return this.#withMailbox("audit", cap, auth, (stub, ctx) => stub.readAudit(ctx, query));
  }

  // ---- the checks every method shares ----------------------------------------

  /** `auth` is the method's last argument as the caller sent it (B1); its shape is checked here, its worth in the Mailbox. */
  async #withMailbox<T>(
    method: string,
    cap: string,
    auth: unknown,
    fn: (stub: Stub, ctx: CallContext) => Promise<MailResult<T>>,
  ): Promise<MailResult<T>> {
    return this.#call(method, cap, async (capability) => {
      if (capability.mbx === undefined) throw new InvalidRequest("the capability names no mailbox");
      const entry = await new Directory(this.env.DIRECTORY).byId(capability.mbx);
      // Rule 7 and M4: one answer for missing, closed and another business's.
      if (entry === null || entry.status === "closed" || entry.businessId !== capability.business) throw new NotFound();
      const ctx: CallContext = {
        mailbox: entry,
        actor: { accountId: capability.sub, role: capability.role },
        auth: auth === undefined ? NO_AUTH : parseAuth(auth),
      };
      const stub = await mailboxRpc(this.env, entry.id);
      return fn(stub, ctx);
    });
  }

  /**
   * The RPC boundary: capability rules 1-6, one log line, and every way out as
   * a MailResult. A Refusal thrown here becomes its value; anything else thrown
   * (the Directory, the Mailbox binding, a bug), and an InternalError the
   * Mailbox answered, is raised to the operator with the jti.
   */
  async #call<T>(method: string, cap: unknown, fn: (capability: Capability) => Promise<MailResult<T>>): Promise<MailResult<T>> {
    const jti = typeof cap === "string" ? loggableJti(cap) : null;
    let capability: Capability;
    try {
      if (typeof cap !== "string") throw new CapabilityRejected("invalid");
      capability = await verifyCapability(cap, capabilityKeys(this.env), Math.floor(Date.now() / 1000));
    } catch (err) {
      const rejected = err instanceof CapabilityRejected ? err : new CapabilityRejected("invalid");
      logEvent("mail-service", { method, jti, outcome: "rejected", reason: rejected.reason });
      return refused(rejected.error);
    }
    const mailbox = capability.mbx ?? null;
    let answer: MailResult<T>;
    // The name of what failed here; null when the Mailbox answered InternalError (its own line names it).
    let failure: string | null = null;
    try {
      answer = await fn(capability);
    } catch (err) {
      if (err instanceof Refusal) {
        answer = refused(err.error);
      } else {
        failure = errorName(err);
        answer = { ok: false, error: internalError() };
      }
    }
    if (!answer.ok && answer.error.name === "InternalError") {
      logAlert("mail-service-internal-error", { method, jti, mailbox, error: failure });
    }
    logEvent("mail-service", { method, jti, outcome: "accepted", mailbox, result: answer.ok ? "ok" : answer.error.name });
    return answer.ok ? answer : refused(answer.error);
  }
}

/** `send`'s auth (D29): the `session` field of its request, when the request is an object; its shape is checked with any other auth. */
function sessionInside(request: unknown): unknown {
  if (typeof request !== "object" || request === null || Array.isArray(request)) return undefined;
  const session = (request as { session?: unknown }).session;
  return session === undefined ? undefined : { session };
}
