import { getAgentByName } from "agents";
import { WorkerEntrypoint } from "cloudflare:workers";
import { type Capability, type CapabilityKeys, loggableJti, parseCapabilityKeys, verifyCapability } from "./capability";
import { Directory } from "./directory/directory";
import type { Env } from "./env";
import { CapabilityRejected, InvalidRequest, NotFound, isPublicError, publicError } from "./errors";
import { logEvent } from "./log";
import type { Mailbox } from "./mailbox/mailbox";
import type {
  AuditEntry,
  CallContext,
  DraftRecord,
  ListPage,
  MailboxView,
  MessageItem,
  PolicyView,
  SendResult,
} from "./mailbox/types";

/**
 * The dashboard's only way in (plan.md §4): RPC over a service binding, no
 * HTTP. Every method takes a capability first (contracts/capability-v1.md),
 * and answers with ciphertext; plaintext comes in only for `send`.
 *
 * Here: rules 1-6 of the capability, then rule 7 against the Directory (M4:
 * a missing, closed or other tenant's mailbox is one and the same NotFound).
 * In the Mailbox: rule 8 (its policy's roles) and every invariant of its own.
 *
 * Every call writes exactly one log line: the method, the capability's jti and
 * the outcome, so the dashboard's log of the same jti finds it. Never content.
 */

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

export class MailService extends WorkerEntrypoint<Env> {
  /** The capability's tenant's mailboxes, for "not set up" / "set up your inbox" / the inbox. Any member role. */
  async mailboxes(cap: string): Promise<{ id: string; address: string; status: string }[]> {
    return this.call("mailboxes", cap, async (capability) =>
      (await new Directory(this.env.DIRECTORY).forTenant(capability.tenant)).map((m) => ({ id: m.id, address: m.address, status: m.status })),
    );
  }

  async mailbox(cap: string): Promise<MailboxView> {
    return this.withMailbox("mailbox", cap, (stub, ctx) => stub.describe(ctx));
  }

  /** Only while provisioned; M5: the Directory row turns active only after the key ring has a key and a recovery wrap. */
  async enroll(cap: string, input: unknown): Promise<{ keyId: string }> {
    return this.withMailbox("enroll", cap, async (stub, ctx) => {
      const result = await stub.enroll(ctx, input);
      await new Directory(this.env.DIRECTORY).activate(ctx.mailbox.id, new Date());
      return result;
    });
  }

  async addWrap(cap: string, wrap: unknown): Promise<void> {
    return this.withMailbox("addWrap", cap, (stub, ctx) => stub.addWrap(ctx, wrap));
  }

  async removeWrap(cap: string, wrapId: string): Promise<void> {
    return this.withMailbox("removeWrap", cap, (stub, ctx) => stub.removeWrap(ctx, wrapId));
  }

  async list(cap: string, query: unknown): Promise<ListPage> {
    return this.withMailbox("list", cap, (stub, ctx) => stub.listMessages(ctx, query));
  }

  /** The sealed body, streamed from R2 (up to 25 MiB; never buffered here). */
  async body(cap: string, messageId: string): Promise<ReadableStream> {
    return this.withMailbox("body", cap, async (stub, ctx) => {
      const object = await this.env.MAIL.get(await stub.bodyKey(ctx, messageId));
      if (object === null) throw new NotFound();
      return object.body;
    });
  }

  async update(cap: string, messageId: string, patch: unknown): Promise<MessageItem> {
    return this.withMailbox("update", cap, (stub, ctx) => stub.updateMessage(ctx, messageId, patch));
  }

  async purge(cap: string, messageId: string): Promise<void> {
    return this.withMailbox("purge", cap, (stub, ctx) => stub.purgeMessage(ctx, messageId));
  }

  async drafts(cap: string): Promise<DraftRecord[]> {
    return this.withMailbox("drafts", cap, (stub, ctx) => stub.listDrafts(ctx));
  }

  async saveDraft(cap: string, draft: unknown): Promise<{ id: string; updatedAt: string }> {
    return this.withMailbox("saveDraft", cap, (stub, ctx) => stub.saveDraft(ctx, draft));
  }

  async deleteDraft(cap: string, draftId: string): Promise<void> {
    return this.withMailbox("deleteDraft", cap, (stub, ctx) => stub.deleteDraft(ctx, draftId));
  }

  /** Plaintext lives only for this call: MIME → SES → the Sent copy, sealed. */
  async send(cap: string, request: unknown): Promise<SendResult> {
    return this.withMailbox("send", cap, (stub, ctx) => stub.send(ctx, request));
  }

  async unread(cap: string): Promise<{ inbox: number }> {
    return this.withMailbox("unread", cap, (stub, ctx) => stub.unreadCount(ctx));
  }

  async setPolicy(cap: string, patch: unknown): Promise<PolicyView & { displayName: string }> {
    return this.withMailbox("setPolicy", cap, (stub, ctx) => stub.setPolicy(ctx, patch));
  }

  async audit(cap: string, query: unknown): Promise<AuditEntry[]> {
    return this.withMailbox("audit", cap, (stub, ctx) => stub.readAudit(ctx, query));
  }

  // ---- the checks every method shares ----------------------------------------

  private async withMailbox<T>(method: string, cap: string, fn: (stub: Stub, ctx: CallContext) => Promise<T>): Promise<T> {
    return this.call(method, cap, async (capability) => {
      if (capability.mbx === undefined) throw new InvalidRequest("the capability names no mailbox");
      const entry = await new Directory(this.env.DIRECTORY).byId(capability.mbx);
      // Rule 7 and M4: one answer for missing, closed and another tenant's.
      if (entry === null || entry.status === "closed" || entry.tenantId !== capability.tenant) throw new NotFound();
      const stub = await mailboxRpc(this.env, entry.id);
      return fn(stub, { mailbox: entry, actor: { accountId: capability.sub, role: capability.role } });
    });
  }

  private async call<T>(method: string, cap: unknown, fn: (capability: Capability) => Promise<T>): Promise<T> {
    let capability: Capability;
    try {
      if (typeof cap !== "string") throw new CapabilityRejected("invalid");
      capability = await verifyCapability(cap, capabilityKeys(this.env), Math.floor(Date.now() / 1000));
    } catch (err) {
      const rejected = err instanceof CapabilityRejected ? err : new CapabilityRejected("invalid");
      logEvent("mail-service", {
        method,
        jti: typeof cap === "string" ? loggableJti(cap) : null,
        outcome: "rejected",
        reason: rejected.reason,
      });
      throw rejected;
    }
    const logged = { method, jti: loggableJti(cap as string), outcome: "accepted", mailbox: capability.mbx ?? null };
    try {
      const result = await fn(capability);
      logEvent("mail-service", { ...logged, result: "ok" });
      return result;
    } catch (err) {
      logEvent("mail-service", { ...logged, result: isPublicError(err) ? err.name : "internal-error" });
      throw isPublicError(err) ? publicError(err) : new Error("internal error");
    }
  }
}
