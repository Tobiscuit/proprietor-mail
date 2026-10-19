import { Agent } from "agents";
import type { AgentEmail } from "agents/email";
import { LIMITS } from "@proprietor/mail-outbound";
import type { Role } from "../capability";
import { Directory, type DirectoryEntry, normalizeAddress } from "../directory/directory";
import type { Env } from "../env";
import {
  AssistantUnavailable,
  Forbidden,
  InvalidRequest,
  type MailResult,
  MailboxNotActive,
  NotFound,
  RateLimited,
  RecipientSuppressed,
  Refusal,
  SendFailed,
  type SuppressedRecipient,
  errorName,
  internalError,
  ok,
  refused,
} from "../errors";
import { hashRecipient, newSuppressionKey } from "../deliverability/suppression";
import { type LogValue, logAlert, logEvent } from "../log";
import type { MessageHeader } from "@proprietor/mail-crypto";
import { inboundHeader, minimalHeader, outboundHeader, parseMessage } from "../mail/header";
import { sesMessageId } from "../mail/ses-message-id";
import type { MailboxPorts } from "../ports";
import { productionPorts } from "../wiring";
import { type FolderId, Folders } from "./folders";
import { applyMigrations, mailboxMigrations } from "./schema";
import {
  addKeyedWrap,
  enrolmentDevice,
  enrolmentFactors,
  registerDevice,
  removeDevice,
  removeKeyedWrap,
  splitFactorFields,
  updateDevice,
  upgradeMailbox,
  writeKeyedEnrolment,
} from "./devices";
import { keyRingView, sessionsMode } from "./keyring";
import { type Access, checkAccess, deleteExpired, issueChallenge, type MailServiceMethod, openMailSession } from "./sessions";
import type { MailboxStore } from "./store";
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
} from "./types";
import * as v from "./validate";

export type { CallContext } from "./types";

/** Email Routing's own ceiling for an inbound message (spec §8). */
export const MAX_INBOUND_BYTES = 25 * 1024 * 1024;
/** Once a day at 03:17 UTC: the Trash purge (M9) and the pruning of sends and audit (tasks.md S2k). */
export const HOUSEKEEPING_CRON = "17 3 * * *";
export const TRASH_DAYS = 30;
/**
 * `sends` rows (idempotency keys and the rate-limit count) are kept 30 days.
 * The rate limit looks back one day, and a dashboard repeats a key within
 * seconds; past 30 days a repeated key sends again, including one whose SES
 * outcome was never known.
 */
export const SENDS_KEPT_DAYS = 30;
/** Audit rows are kept one year. */
export const AUDIT_KEPT_DAYS = 365;
/** A suppressed recipient lapses one year after its last bounce or complaint (domain-model M11). */
export const SUPPRESSION_KEPT_DAYS = 365;
const DAY_MS = 24 * 60 * 60 * 1000;
/** agentic-inbox's limits, domain-model M7. */
export const SENDS_PER_HOUR = 20;
export const SENDS_PER_DAY = 100;

const NOT_ACCEPTING = "This mailbox is not accepting mail";
const TOO_LARGE = "Message too large";

interface IdentityRow {
  mailbox_id: string;
  business_id: string;
  address: string;
  display_name: string;
}

interface PolicyRow {
  open_roles: string;
  send_roles: string;
  assistant: "off" | "on";
  delivery: "store" | "store-and-forward";
  forward_to: string | null;
  updated_at: string;
  updated_by: string;
}

interface MessageRow {
  id: string;
  folder_id: FolderId;
  direction: "in" | "out";
  received_at: string;
  size: number;
  key_id: string;
  key_envelope: string;
  header: string;
  body_key: string;
  seen: number;
  flagged: number;
  trashed_at: string | null;
}

interface SendRow {
  idempotency_key: string;
  message_id: string | null;
  provider_message_id: string | null;
  created_at: string;
}

const bodyKeyOf = (mailboxId: string, messageId: string) => `mbx/${mailboxId}/msg/${messageId}`;

function toItem(row: MessageRow): MessageItem {
  return {
    id: row.id,
    folder: row.folder_id,
    direction: row.direction,
    receivedAt: row.received_at,
    size: row.size,
    seen: row.seen === 1,
    flagged: row.flagged === 1,
    keyId: row.key_id,
    keyEnvelope: row.key_envelope,
    header: row.header,
  };
}

/**
 * One mailbox (domain-model §3, the aggregate root): an Agents SDK Agent, so a
 * SQLite-backed Durable Object named by the mailbox id. It holds the sealed
 * messages' index, the key ring (public keys and wrapped private keys only),
 * drafts, sends, policy and the audit log. Sealed bodies live in R2.
 *
 * Every method but `onEmail` and the housekeeping is reached through
 * MailService (capability and Directory checked, M4) or MailAdmin; each takes
 * the Directory row and the actor, and applies the rest here: its identity,
 * its policy and its invariants. Each answers with a MailResult through
 * `answer`: a refusal crosses the RPC hop as a value, never as a throw
 * (contracts/mail-service-v1.md). `onEmail` is the one method that throws on
 * purpose (plan.md §5).
 */
export class Mailbox extends Agent<Env> {
  /**
   * The outside world, as ports. Production: the real packages. Tests replace
   * this on the live object. An own instance property, so it is not reachable
   * over RPC.
   */
  ports: MailboxPorts;

  /**
   * The Agents SDK's default observability publishes every arriving email's
   * `from`, `to` and SUBJECT to the `agents:email` diagnostics channel, which
   * Tail Workers receive (agents 0.24.0, Agent._onEmail). That is a log of
   * message content, so this mailbox publishes nothing (domain-model M1).
   */
  override observability = undefined;

  /** Idempotency keys whose SES call is running in this object right now. */
  private readonly sendsInFlight = new Set<string>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Synchronous and first, so no request can see a half-built schema.
    applyMigrations(ctx.storage, mailboxMigrations);
    this.ports = productionPorts(env);
  }

  /** The base class logs the whole error; this logs its name only. Errors never carry content here, but a library's might. */
  override onError(connectionOrError: unknown, error?: unknown): void {
    const err = error ?? connectionOrError;
    console.error(JSON.stringify({ event: "mailbox-error", mailbox: this.safeName(), error: errorName(err) }));
    throw err;
  }

  override async onStart(): Promise<void> {
    // Heals a lost schedule on every wake; cron schedules are idempotent.
    if (this.identityRow() !== null) await this.schedule(HOUSEKEEPING_CRON, "dailyHousekeeping");
  }

  // ---- inbound (plan.md §5) --------------------------------------------------

  /**
   * Order: status → size → (forward, in store-and-forward) → read raw → parse →
   * seal → R2 put → SQLite insert (a failed insert deletes the R2 object) →
   * new-mail count. Nothing from the message is logged.
   */
  async onEmail(email: AgentEmail): Promise<void> {
    const mailboxId = this.name;
    const entry = await new Directory(this.env.DIRECTORY).byId(mailboxId);
    const outcome = (result: string, fields: Record<string, LogValue> = {}) =>
      logEvent("arrival", { mailbox: mailboxId, size: email.rawSize, outcome: result, ...fields });

    // M2: no key, no mail. Checked before anything is stored, identity included.
    if (entry === null || entry.status !== "active") {
      await this.reject(email, NOT_ACCEPTING);
      outcome("rejected", { reason: "not-active" });
      return;
    }
    if (email.rawSize > MAX_INBOUND_BYTES) {
      await this.reject(email, TOO_LARGE);
      outcome("rejected", { reason: "too-large" });
      return;
    }
    try {
      await this.ensureIdentity(entry, "system:email");
    } catch (err) {
      // M4: the Directory row no longer matches the identity this mailbox was
      // created with (already raised as an operator alert). Refuse the mail:
      // never store it under an identity that changed.
      if (errorName(err) !== "NotFound") throw err;
      await this.reject(email, NOT_ACCEPTING);
      outcome("rejected", { reason: "identity-conflict" });
      return;
    }
    const key = this.activeKey();
    if (key === null) {
      await this.reject(email, NOT_ACCEPTING);
      logAlert("active-mailbox-without-key", { mailbox: mailboxId });
      outcome("rejected", { reason: "no-key" });
      return;
    }

    const policy = this.policyRow();
    let forwarded = false;
    if (policy.delivery === "store-and-forward" && policy.forward_to !== null) {
      // Forward FIRST (domain-model G11). A failure here throws before anything
      // is stored, so the sender's server retries and no half-delivery exists.
      await email.forward(policy.forward_to);
      forwarded = true;
    }

    try {
      const messageId = await this.storeArrival(email, entry, key);
      outcome("stored", { message: messageId, forwarded });
    } catch (err) {
      if (!forwarded) {
        outcome("failed", { error: errorName(err) });
        throw err;
      }
      // The forward succeeded: the copy is safe elsewhere. Never throw now, or
      // Email Routing could retry and forward it twice.
      this.audit("system:email", "store-failed-after-forward", { size: email.rawSize, error: errorName(err) });
      logAlert("store-failed-after-forward", { mailbox: mailboxId, size: email.rawSize, error: errorName(err) });
      outcome("forwarded-not-stored", { error: errorName(err) });
    }
  }

  /**
   * `AgentEmail.setReject` is typed `void`, but inside an Agent it is an RPC
   * call back through the SDK's EmailBridge to the `email()` invocation, and
   * returns a promise (agents 0.24.0, Agent._onEmail). Unawaited, the handler
   * can finish before the rejection reaches Email Routing, and a refused
   * message would count as delivered.
   */
  private async reject(email: AgentEmail, reason: string): Promise<void> {
    await (email.setReject(reason) as unknown as Promise<void> | undefined);
  }

  /**
   * Seals, and never loses a message to the header ceiling: when sealMessage
   * throws RangeError (a header still over 64 KiB after the contract's own
   * trimming), it retries once with the contract's minimal header. The full
   * headers are inside the sealed raw message either way.
   */
  private async seal(key: { keyId: string; publicKey: Uint8Array }, messageId: string, header: MessageHeader, raw: Uint8Array) {
    const ids = { mailboxId: this.name, messageId };
    try {
      return await this.ports.sealer.seal(key, ids, header, raw);
    } catch (err) {
      if (errorName(err) !== "RangeError") throw err;
      logEvent("seal", { mailbox: this.name, message: messageId, outcome: "minimal-header" });
      return await this.ports.sealer.seal(key, ids, minimalHeader(header), raw);
    }
  }

  private async storeArrival(email: AgentEmail, entry: DirectoryEntry, key: { keyId: string; publicKey: Uint8Array }): Promise<string> {
    const raw = await email.getRaw();
    // A message the parser cannot read is still stored, with an empty header.
    // The envelope recipient goes into the sealed header in the Directory's
    // form, so the browser can match it against the mailbox's addresses.
    const header = inboundHeader(await parseMessage(raw), { from: email.from, to: normalizeAddress(email.to) });
    const messageId = this.ports.ids.messageId();
    const sealed = await this.seal(key, messageId, header, raw);
    await this.storeSealed({
      messageId,
      folder: Folders.INBOX,
      direction: "in",
      size: raw.byteLength,
      sealed,
      seen: false,
    });
    await this.signalUnread(entry);
    return messageId;
  }

  /** R2 first, then SQLite; an insert that fails deletes the object it just wrote (tasks.md S2h). */
  private async storeSealed(m: {
    messageId: string;
    folder: FolderId;
    direction: "in" | "out";
    size: number;
    sealed: { keyId: string; keyEnvelope: string; header: string; body: Uint8Array };
    seen: boolean;
  }): Promise<void> {
    const mailboxId = this.name;
    const bodyKey = bodyKeyOf(mailboxId, m.messageId);
    await this.env.MAIL.put(bodyKey, m.sealed.body);
    try {
      this.ctx.storage.sql.exec(
        `INSERT INTO messages (id, folder_id, direction, received_at, size, key_id, key_envelope, header, body_key, seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        m.messageId,
        m.folder,
        m.direction,
        this.now(),
        m.size,
        m.sealed.keyId,
        m.sealed.keyEnvelope,
        m.sealed.header,
        bodyKey,
        m.seen ? 1 : 0,
      );
    } catch (err) {
      try {
        await this.env.MAIL.delete(bodyKey);
      } catch (cleanupErr) {
        logAlert("orphan-body-not-deleted", { mailbox: mailboxId, message: m.messageId, error: errorName(cleanupErr) });
      }
      throw err;
    }
  }

  private async signalUnread(entry: DirectoryEntry): Promise<void> {
    try {
      await this.ports.signal.unread({ businessId: entry.businessId, mailboxId: entry.id, unread: this.inboxUnread() });
    } catch (err) {
      // A count that did not reach the dashboard is not worth failing mail for.
      logEvent("new-mail-signal", { mailbox: entry.id, outcome: "failed", error: errorName(err) });
    }
  }

  // ---- reading (MailService) --------------------------------------------------

  async describe(ctx: CallContext): Promise<MailResult<MailboxView>> {
    return this.answer("describe", async () => {
      await this.enter(ctx, "mailbox", "open");
      const identity = this.identityRow()!;
      return {
        id: identity.mailbox_id,
        address: identity.address,
        // Read from the Directory on every call: addresses are its to grant (plan.md §12).
        addresses: ctx.mailbox.addresses,
        status: ctx.mailbox.status,
        displayName: identity.display_name,
        sessions: sessionsMode(this.ctx.storage.sql),
        // Keys with their successor seals, wraps with their factor keys, devices and seals (device-v1 B4).
        ...keyRingView(this.ctx.storage.sql),
        policy: this.policyView(),
      };
    });
  }

  async listMessages(ctx: CallContext, query: unknown): Promise<MailResult<ListPage>> {
    return this.answer("listMessages", async () => {
      await this.enter(ctx, "list", "open");
      const q = v.object(query, "list query", ["folder", "before", "limit"]);
      const folder = v.oneOf(q.folder, "folder", Object.values(Folders));
      const limit = v.optional(q.limit, (l) => v.integer(l, "limit", 1, 100)) ?? 50;
      const before = v.optional(q.before, (b) => parseCursor(b));
      const rows = before
        ? this.rows<MessageRow>(
            `SELECT * FROM messages WHERE folder_id = ? AND (received_at < ? OR (received_at = ? AND id < ?))
             ORDER BY received_at DESC, id DESC LIMIT ?`,
            folder,
            before.receivedAt,
            before.receivedAt,
            before.id,
            limit + 1,
          )
        : this.rows<MessageRow>("SELECT * FROM messages WHERE folder_id = ? ORDER BY received_at DESC, id DESC LIMIT ?", folder, limit + 1);
      const page = rows.slice(0, limit);
      const last = page.at(-1);
      return { items: page.map(toItem), next: rows.length > limit && last ? `${last.received_at}|${last.id}` : null };
    });
  }

  /** The R2 key of a message's sealed body; MailService streams it from R2 itself. */
  async bodyKey(ctx: CallContext, messageId: unknown): Promise<MailResult<string>> {
    return this.answer("bodyKey", async () => {
      await this.enter(ctx, "body", "open");
      return this.messageRow(v.id(messageId, "message id", "msg")).body_key;
    });
  }

  async updateMessage(ctx: CallContext, messageId: unknown, patch: unknown): Promise<MailResult<MessageItem>> {
    return this.answer("updateMessage", async () => {
      await this.enter(ctx, "update", "open");
      const id = v.id(messageId, "message id", "msg");
      const p = v.object(patch, "update", ["seen", "flagged", "folder"]);
      const seen = v.optional(p.seen, (s) => v.bool(s, "seen"));
      const flagged = v.optional(p.flagged, (f) => v.bool(f, "flagged"));
      // Drafts are their own table; no message moves into that folder.
      const folder = v.optional(p.folder, (f) =>
        v.oneOf(f, "folder", Object.values(Folders).filter((x) => x !== Folders.DRAFTS)),
      );
      if (seen === undefined && flagged === undefined && folder === undefined) throw new InvalidRequest("nothing to update");
      const row = this.messageRow(id);
      const trashedAt =
        folder === undefined ? row.trashed_at : folder === Folders.TRASH ? (row.trashed_at ?? this.now()) : null;
      this.ctx.storage.sql.exec(
        "UPDATE messages SET seen = ?, flagged = ?, folder_id = ?, trashed_at = ? WHERE id = ?",
        seen === undefined ? row.seen : seen ? 1 : 0,
        flagged === undefined ? row.flagged : flagged ? 1 : 0,
        folder ?? row.folder_id,
        trashedAt,
        id,
      );
      return toItem(this.messageRow(id));
    });
  }

  async purgeMessage(ctx: CallContext, messageId: unknown): Promise<MailResult<null>> {
    return this.answer("purgeMessage", async () => {
      await this.enter(ctx, "purge", "owner");
      const row = this.messageRow(v.id(messageId, "message id", "msg"));
      await this.deleteMessage(row);
      this.audit(ctx.actor.accountId, "message-purged", { message: row.id });
      return null;
    });
  }

  async unreadCount(ctx: CallContext): Promise<MailResult<{ inbox: number }>> {
    return this.answer("unreadCount", async () => {
      await this.enter(ctx, "unread", "open");
      return { inbox: this.inboxUnread() };
    });
  }

  // ---- drafts: sealed in the browser; the server sees an id, a time and a blob --

  async listDrafts(ctx: CallContext): Promise<MailResult<DraftRecord[]>> {
    return this.answer("listDrafts", async () => {
      await this.enter(ctx, "drafts", "open");
      return this.rows<{ id: string; key_id: string; key_envelope: string; sealed: string; updated_at: string }>(
        "SELECT id, key_id, key_envelope, sealed, updated_at FROM drafts ORDER BY updated_at DESC, id DESC",
      ).map((d) => ({ id: d.id, keyId: d.key_id, keyEnvelope: d.key_envelope, sealed: d.sealed, updatedAt: d.updated_at }));
    });
  }

  async saveDraft(ctx: CallContext, draft: unknown): Promise<MailResult<{ id: string; updatedAt: string }>> {
    return this.answer("saveDraft", async () => {
      await this.enter(ctx, "saveDraft", "open");
      const d = v.object(draft, "draft", ["id", "keyId", "keyEnvelope", "sealed"]);
      const id = v.id(d.id, "draft id", "drf");
      const keyId = this.knownKeyId(d.keyId);
      const keyEnvelope = v.base64url(d.keyEnvelope, "key envelope", { bytes: 80 });
      const sealed = v.base64url(d.sealed, "sealed draft", { maxChars: 1_400_000 });
      const updatedAt = this.now();
      this.ctx.storage.sql.exec(
        `INSERT INTO drafts (id, key_id, key_envelope, sealed, updated_at) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET key_id = excluded.key_id, key_envelope = excluded.key_envelope,
           sealed = excluded.sealed, updated_at = excluded.updated_at`,
        id,
        keyId,
        keyEnvelope,
        sealed,
        updatedAt,
      );
      return { id, updatedAt };
    });
  }

  async deleteDraft(ctx: CallContext, draftId: unknown): Promise<MailResult<null>> {
    return this.answer("deleteDraft", async () => {
      await this.enter(ctx, "deleteDraft", "open");
      const id = v.id(draftId, "draft id", "drf");
      if (this.ctx.storage.sql.exec("DELETE FROM drafts WHERE id = ?", id).rowsWritten === 0) throw new NotFound();
      return null;
    });
  }

  // ---- keys (M3, M5) -----------------------------------------------------------

  /** Stores the public key and its wraps. MailService then activates the Directory row. */
  async enroll(ctx: CallContext, input: unknown): Promise<MailResult<{ keyId: string }>> {
    return this.answer("enroll", async () => {
      await this.enter(ctx, "enroll", "owner");
      if (ctx.mailbox.status !== "provisioned") throw new InvalidRequest("the mailbox is not awaiting enrolment");
      const req = v.object(input, "enrolment", ["publicKey", "wraps", "device"]);
      const publicKey = v.decodeBase64url(v.base64url(req.publicKey, "public key", { bytes: 32 }));
      // Recomputed here: a keyId the browser claims is never trusted.
      const keyId = await this.ports.sealer.keyIdOf(publicKey);
      const split = v.array(req.wraps, "wraps", 10).map(splitFactorFields);
      const wraps = split.map((w, i) => parseWrap(w.plain, `wrap ${i + 1}`));
      if (wraps.length === 0 || !wraps.some((w) => w.kind === "recovery")) throw new InvalidRequest("a recovery wrap is required");
      if (wraps.some((w) => w.keyId !== keyId)) throw new InvalidRequest("a wrap names another key");
      if (new Set(wraps.map((w) => w.id)).size !== wraps.length) throw new InvalidRequest("wrap ids repeat");
      // device-v1 B5: wraps that all carry factor keys start the mailbox with sessions required, and may bring the enrolling device.
      const factors = await enrolmentFactors(wraps, split.map((w) => w.fields), keyId);
      const device = req.device === undefined ? null : await enrolmentDevice(req.device, keyId);
      if (device !== null && factors === null) throw new InvalidRequest("a device needs factor keys");

      const at = this.now();
      const by = ctx.actor.accountId;
      const store = this.store();
      this.ctx.storage.transactionSync(() => {
        const existing = this.rows<{ key_id: string }>("SELECT key_id FROM keys WHERE retired_at IS NULL");
        if (existing.length > 0) {
          // A retry after the Directory update failed: same key, nothing to do.
          if (existing[0]?.key_id === keyId) return;
          throw new InvalidRequest("a key is already enrolled");
        }
        this.ctx.storage.sql.exec(
          "INSERT INTO keys (key_id, public_key, created_at, created_by) VALUES (?, ?, ?, ?)",
          keyId,
          publicKey,
          at,
          by,
        );
        if (factors === null) for (const w of wraps) this.insertWrap(w, at, by);
        this.audit(by, "key-enrolled", { keyId, wraps: wraps.map((w) => `${w.id}:${w.kind}`).join(",") });
        if (factors !== null) writeKeyedEnrolment(store, ctx, keyId, wraps, factors, device, at);
      });
      return { keyId };
    });
  }

  async addWrap(ctx: CallContext, wrap: unknown): Promise<MailResult<null>> {
    return this.answer("addWrap", async () => {
      const access = await this.enter(ctx, "addWrap", "owner");
      if (access.sessions === "required") {
        // device-v1 B7: once sessions are required a wrap also brings its factor key and a tag (devices.ts).
        const { plain, fields } = splitFactorFields(wrap);
        return addKeyedWrap(this.store(), ctx, parseWrap(plain, "wrap"), fields);
      }
      const w = parseWrap(wrap, "wrap");
      const key = this.activeKey();
      if (key === null || w.keyId !== key.keyId) throw new InvalidRequest("a wrap must name the mailbox's key");
      if (this.rows("SELECT 1 FROM key_wraps WHERE id = ?", w.id).length > 0) throw new InvalidRequest("that wrap id exists");
      this.ctx.storage.transactionSync(() => {
        this.insertWrap(w, this.now(), ctx.actor.accountId);
        this.audit(ctx.actor.accountId, "wrap-added", { wrap: w.id, kind: w.kind });
      });
      return null;
    });
  }

  async removeWrap(ctx: CallContext, wrapId: unknown): Promise<MailResult<null>> {
    return this.answer("removeWrap", async () => {
      const access = await this.enter(ctx, "removeWrap", "owner");
      const id = v.id(wrapId, "wrap id", "wrp");
      // device-v1 B7: once sessions are required its seals go with it, and M5′ guards the active key.
      if (access.sessions === "required") return removeKeyedWrap(this.store(), ctx, id);
      const wrap = this.rows<{ id: string; key_id: string; kind: string }>("SELECT id, key_id, kind FROM key_wraps WHERE id = ?", id)[0];
      if (wrap === undefined) throw new NotFound();
      if (wrap.kind === "recovery") {
        const recoveries = this.rows("SELECT 1 FROM key_wraps WHERE key_id = ? AND kind = 'recovery'", wrap.key_id).length;
        // M5: the last recovery wrap stays; without it a lost device is lost mail.
        if (recoveries <= 1) throw new InvalidRequest("the last recovery wrap cannot be removed");
      }
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("DELETE FROM key_wraps WHERE id = ?", id);
        this.audit(ctx.actor.accountId, "wrap-removed", { wrap: id, kind: wrap.kind });
      });
      return null;
    });
  }

  // ---- sessions and devices (spec 002, contracts/device-v1.md Part B) --------------
  // Thin: the logic is in sessions.ts and devices.ts; each method enters
  // through `enter`, which applies SESSION_NEEDS.

  /** B6: a challenge sealed to the active key or to a factor's key. MailService's `challenge`. */
  async createChallenge(ctx: CallContext, request: unknown): Promise<MailResult<ChallengeView>> {
    return this.answer("createChallenge", async () => {
      await this.enter(ctx, "challenge", "open");
      return issueChallenge(this.store(), ctx, request);
    });
  }

  /** B6, M15: a 60-minute session from a key proof, and a kept device's signature when it names one. */
  async openSession(ctx: CallContext, request: unknown): Promise<MailResult<SessionView>> {
    return this.answer("openSession", async () => {
      await this.enter(ctx, "openSession", "open");
      return openMailSession(this.store(), ctx, request);
    });
  }

  /** B5, M20: the factors' keys and `sessions = required`, once. */
  async upgrade(ctx: CallContext, request: unknown): Promise<MailResult<null>> {
    return this.answer("upgrade", async () => {
      const access = await this.enter(ctx, "upgrade", "owner");
      return upgradeMailbox(this.store(), ctx, access, request);
    });
  }

  /** B7, F1: keeps the calling browser, with a factor proof. */
  async registerDevice(ctx: CallContext, request: unknown): Promise<MailResult<DeviceView>> {
    return this.answer("registerDevice", async () => {
      const access = await this.enter(ctx, "registerDevice", "owner");
      return registerDevice(this.store(), ctx, access, request);
    });
  }

  /** B7, F3, F4: a device's own session sets or clears its unlock key, tag and seal. */
  async updateDevice(ctx: CallContext, request: unknown): Promise<MailResult<DeviceView>> {
    return this.answer("updateDevice", async () => {
      const access = await this.enter(ctx, "updateDevice", "owner");
      return updateDevice(this.store(), ctx, access, request);
    });
  }

  /** B7, F6, M18: the device goes and the key rotates, in one transaction. */
  async removeDevice(ctx: CallContext, request: unknown): Promise<MailResult<{ keyId: string }>> {
    return this.answer("removeDevice", async () => {
      const access = await this.enter(ctx, "removeDevice", "owner");
      return removeDevice(this.store(), ctx, access, request);
    });
  }

  // ---- policy and audit ----------------------------------------------------------

  async setPolicy(ctx: CallContext, patch: unknown): Promise<MailResult<PolicyView & { displayName: string }>> {
    return this.answer("setPolicy", async () => {
      await this.enter(ctx, "setPolicy", "owner");
      const p = v.object(patch, "policy", ["displayName", "assistant"]);
      const assistant = v.optional(p.assistant, (a) => v.oneOf(a, "assistant", ["off", "on"] as const));
      // Spec §6 and decision D1: v1 builds only the safe default.
      if (assistant === "on") throw new AssistantUnavailable();
      const displayName = v.optional(p.displayName, (d) => v.text(d, "display name", { max: 100, singleLine: true }));
      const fields = [...(displayName === undefined ? [] : ["displayName"]), ...(assistant === undefined ? [] : ["assistant"])];
      if (fields.length === 0) throw new InvalidRequest("nothing to update");
      this.ctx.storage.transactionSync(() => {
        if (displayName !== undefined) this.ctx.storage.sql.exec("UPDATE identity SET display_name = ?", displayName);
        this.ctx.storage.sql.exec("UPDATE policy SET updated_at = ?, updated_by = ?", this.now(), ctx.actor.accountId);
        this.audit(ctx.actor.accountId, "policy-changed", { fields: fields.join(",") });
      });
      return { ...this.policyView(), displayName: this.identityRow()!.display_name };
    });
  }

  async readAudit(ctx: CallContext, query: unknown): Promise<MailResult<AuditEntry[]>> {
    return this.answer("readAudit", async () => {
      await this.enter(ctx, "audit", "owner");
      const q = v.object(query ?? {}, "audit query", ["before"]);
      const before = v.optional(q.before, (b) => v.integer(b, "before", 1, Number.MAX_SAFE_INTEGER));
      const rows = this.rows<{ id: number; at: string; actor: string; action: string; detail: string }>(
        `SELECT id, at, actor, action, detail FROM audit ${before === undefined ? "" : "WHERE id < ?"} ORDER BY id DESC LIMIT 100`,
        ...(before === undefined ? [] : [before]),
      );
      return rows.map((r) => ({ id: r.id, at: r.at, actor: r.actor, action: r.action, detail: JSON.parse(r.detail) as AuditEntry["detail"] }));
    });
  }

  // ---- sending (M6, M7) -----------------------------------------------------------

  async send(ctx: CallContext, request: unknown): Promise<MailResult<SendResult>> {
    return this.answer("send", async () => {
      await this.enter(ctx, "send", "send");
      if (ctx.mailbox.status !== "active") throw new MailboxNotActive();
      const req = parseSendRequest(request);
      const key = this.activeKey();
      if (key === null) throw new MailboxNotActive();
      const identity = this.identityRow()!;
      const now = this.ports.clock.now();

      // M7, idempotency: a repeated key returns the first result and sends nothing.
      const previous = this.rows<SendRow>("SELECT * FROM sends WHERE idempotency_key = ?", req.idempotencyKey)[0];
      if (previous?.provider_message_id) {
        return { messageId: previous.message_id, providerMessageId: previous.provider_message_id };
      }
      if (previous !== undefined) {
        // Running right now (ask again shortly), or its outcome is unknown: SES
        // may have accepted it, so it is NEVER sent again under this key.
        throw new SendFailed(this.sendsInFlight.has(req.idempotencyKey));
      }
      // The key is marked in flight before the first await (the suppression
      // hashes), so a concurrent repeat is told to ask again shortly rather
      // than racing this call to the reservation.
      if (this.sendsInFlight.has(req.idempotencyKey)) throw new SendFailed(true);
      this.sendsInFlight.add(req.idempotencyKey);
      try {
        // M11: a recipient who bounced permanently or complained is refused
        // here, before the key is reserved and before the rate limit counts it.
        const suppressed = await this.suppressedRecipients(req);
        if (suppressed.length > 0) throw new RecipientSuppressed(suppressed);

        // M7, rate: counted over sends made or in flight.
        this.checkRate(now);
        const configurationSet = ctx.mailbox.sesConfigurationSet;
        if (configurationSet === null) {
          logAlert("mailbox-without-configuration-set", { mailbox: this.name });
          throw new SendFailed(false);
        }

        // Reserve the key: from here a repeat returns this call's result.
        this.ctx.storage.sql.exec("INSERT INTO sends (idempotency_key, created_at) VALUES (?, ?)", req.idempotencyKey, now.toISOString());
        const release = () => this.ctx.storage.sql.exec("DELETE FROM sends WHERE idempotency_key = ?", req.idempotencyKey);
        return await this.sendReserved(ctx, req, key, identity, now, configurationSet, release);
      } finally {
        this.sendsInFlight.delete(req.idempotencyKey);
      }
    });
  }

  private async sendReserved(
    ctx: CallContext,
    req: ParsedSendRequest,
    key: { keyId: string; publicKey: Uint8Array },
    identity: IdentityRow,
    now: Date,
    configurationSet: string,
    release: () => void,
  ): Promise<SendResult> {
    // M6 as amended (plan.md §12, D14): From is one of the mailbox's own
    // addresses, the primary unless the request names another of them, checked
    // against the Directory's addresses on every call. The display name is the
    // mailbox's. Refused before anything is built, and the key is freed.
    const fromAddress = req.from ?? identity.address;
    if (!ctx.mailbox.addresses.includes(fromAddress)) {
      release();
      throw new InvalidRequest("from is not one of the mailbox's addresses");
    }
    const from = identity.display_name === "" ? { address: fromAddress } : { name: identity.display_name, address: fromAddress };
    let built;
    try {
      built = this.ports.mime.build(
        {
          from,
          to: req.to,
          ...(req.cc.length > 0 ? { cc: req.cc } : {}),
          ...(req.bcc.length > 0 ? { bcc: req.bcc } : {}),
          subject: req.subject,
          text: req.text,
          ...(req.html === undefined ? {} : { html: req.html }),
          ...(req.inReplyTo === undefined ? {} : { inReplyTo: req.inReplyTo }),
          ...(req.references.length > 0 ? { references: req.references } : {}),
          ...(req.attachments.length > 0 ? { attachments: req.attachments } : {}),
        },
        { messageIdDomain: fromAddress.slice(fromAddress.lastIndexOf("@") + 1), now },
      );
    } catch (err) {
      release();
      if (errorName(err) === "InvalidMessage") throw new InvalidRequest("the message could not be built");
      throw err;
    }

    let providerMessageId: string;
    try {
      ({ providerMessageId } = await this.ports.mailer.send({
        raw: built.raw,
        fromAddress,
        recipients: built.recipients,
        configurationSet,
        ...(ctx.mailbox.sesTenant === null ? {} : { tenantName: ctx.mailbox.sesTenant }),
        // SES echoes this tag in every event for the message; the feed routes by it alone (plan.md §13, G22).
        tags: [{ name: "mailbox", value: this.name }],
      }));
    } catch (err) {
      const rejected = err as { status?: unknown; retryable?: unknown };
      if (errorName(err) === "SendRejected" && typeof rejected.status === "number" && rejected.status !== 0) {
        // SES answered, and did not take the message: the key is free again.
        release();
        const retryable = rejected.retryable === true;
        logEvent("send", { mailbox: this.name, outcome: "refused", status: rejected.status, retryable });
        throw new SendFailed(retryable);
      }
      // Status 0 (timeout, network, a 2xx without an id) or anything else: SES
      // may have accepted it. The reservation stays, so the key never sends again.
      this.audit(ctx.actor.accountId, "send-outcome-unknown", { idempotencyKey: req.idempotencyKey, error: errorName(err) });
      logAlert("send-outcome-unknown", { mailbox: this.name, error: errorName(err) });
      throw new SendFailed(false);
    }
    // From here the message is out. Nothing below may report failure.
    this.ctx.storage.sql.exec("UPDATE sends SET provider_message_id = ? WHERE idempotency_key = ?", providerMessageId, req.idempotencyKey);

    let messageId: string | null = null;
    try {
      const header = outboundHeader({
        from: { name: identity.display_name, address: fromAddress },
        to: req.to,
        cc: req.cc,
        bcc: req.bcc,
        subject: req.subject,
        text: req.text,
        date: now,
        // The id recipients see: SES replaces the one in the raw message (S3).
        messageId: sesMessageId(providerMessageId, this.env.SES_REGION),
        ...(req.inReplyTo === undefined ? {} : { inReplyTo: req.inReplyTo }),
        references: req.references,
        attachments: req.attachments,
      });
      const id = this.ports.ids.messageId();
      const sealed = await this.seal(key, id, header, built.raw);
      await this.storeSealed({ messageId: id, folder: Folders.SENT, direction: "out", size: built.raw.byteLength, sealed, seen: true });
      this.ctx.storage.sql.exec("UPDATE sends SET message_id = ? WHERE idempotency_key = ?", id, req.idempotencyKey);
      messageId = id;
    } catch (err) {
      this.audit(ctx.actor.accountId, "sent-copy-not-stored", { error: errorName(err) });
      logAlert("sent-copy-not-stored", { mailbox: this.name, error: errorName(err) });
    }
    if (req.draftId !== undefined) this.ctx.storage.sql.exec("DELETE FROM drafts WHERE id = ?", req.draftId);
    logEvent("send", { mailbox: this.name, message: messageId, size: built.raw.byteLength, recipients: built.recipients.length, outcome: "sent" });
    return { messageId, providerMessageId };
  }

  private checkRate(now: Date): void {
    const windows = [
      { ms: 60 * 60 * 1000, max: SENDS_PER_HOUR },
      { ms: 24 * 60 * 60 * 1000, max: SENDS_PER_DAY },
    ];
    for (const w of windows) {
      const since = new Date(now.getTime() - w.ms).toISOString();
      const inWindow = this.rows<{ created_at: string }>(
        "SELECT created_at FROM sends WHERE created_at > ? ORDER BY created_at ASC",
        since,
      );
      if (inWindow.length >= w.max) {
        const oldest = Date.parse(inWindow[0]!.created_at);
        throw new RateLimited(Math.max(1, Math.ceil((oldest + w.ms - now.getTime()) / 1000)));
      }
    }
  }

  // ---- operator (MailAdmin) -----------------------------------------------------------

  /** M10: the delivery mode and forward target change only here, and every change is audited. */
  async setDelivery(entry: DirectoryEntry, operator: string, input: unknown): Promise<MailResult<PolicyView>> {
    return this.answer("setDelivery", async () => {
      await this.ensureIdentity(entry, operator);
      const i = v.object(input, "delivery", ["delivery", "forwardTo"]);
      const delivery = v.oneOf(i.delivery, "delivery", ["store", "store-and-forward"] as const);
      const forwardTo =
        delivery === "store-and-forward" ? v.address(i.forwardTo, "forward target").toLowerCase() : i.forwardTo === undefined || i.forwardTo === null ? null : invalidForward();
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec(
          "UPDATE policy SET delivery = ?, forward_to = ?, updated_at = ?, updated_by = ?",
          delivery,
          forwardTo,
          this.now(),
          operator,
        );
        this.audit(operator, "delivery-changed", { delivery, forwardTo });
      });
      return this.policyView();
    });
  }

  async recordOperatorAction(entry: DirectoryEntry, operator: string, action: "mailbox-suspended" | "mailbox-resumed"): Promise<MailResult<null>> {
    return this.answer("recordOperatorAction", async () => {
      await this.ensureIdentity(entry, operator);
      this.audit(operator, action, {});
      return null;
    });
  }

  // ---- deliverability (M11, M12; the feed in src/deliverability) ------------------------

  /**
   * A permanent bounce or a complaint from the feed: each recipient becomes a
   * keyed hash (spec D15) with the reason and the first and last dates. An
   * upsert, so the same event twice changes nothing (M12); only a recipient
   * new to the table is audited, as a count. Not reached through MailService.
   */
  async recordDeliveryEvent(entry: DirectoryEntry, event: unknown): Promise<MailResult<{ recipients: number; added: number }>> {
    return this.answer("recordDeliveryEvent", async () => {
      await this.ensureIdentity(entry, "system:deliverability");
      const e = v.object(event, "delivery event", ["kind", "recipients", "at"]);
      const kind = v.oneOf(e.kind, "kind", ["bounce", "complaint"] as const);
      const recipients = [...new Set(v.array(e.recipients, "recipients", LIMITS.maxRecipients).map((r, i) => normalizeAddress(v.address(r, `recipient ${i + 1}`))))];
      if (recipients.length === 0) throw new InvalidRequest("at least one recipient");
      const at = typeof e.at === "string" && !Number.isNaN(Date.parse(e.at)) ? new Date(Date.parse(e.at)).toISOString() : invalid("event time");
      const key = this.suppressionKey(true)!;
      const hashes = await Promise.all(recipients.map((r) => hashRecipient(key, r)));
      let added = 0;
      this.ctx.storage.transactionSync(() => {
        for (const hash of hashes) {
          if (this.rows("SELECT 1 FROM suppression WHERE recipient_hash = ?", hash).length === 0) added += 1;
          this.ctx.storage.sql.exec(
            `INSERT INTO suppression (recipient_hash, reason, first_at, last_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(recipient_hash) DO UPDATE SET
               reason = CASE WHEN excluded.reason = 'complaint' THEN 'complaint' ELSE reason END,
               first_at = MIN(first_at, excluded.first_at),
               last_at = MAX(last_at, excluded.last_at)`,
            hash,
            kind,
            at,
            at,
          );
        }
        if (added > 0) this.audit("system:deliverability", "recipient-suppressed", { reason: kind, recipients: added });
      });
      return { recipients: recipients.length, added };
    });
  }

  /** M11: every recipient of the request, hashed under the mailbox's key and looked up; positions only, never addresses. */
  private async suppressedRecipients(req: ParsedSendRequest): Promise<SuppressedRecipient[]> {
    const key = this.suppressionKey(false);
    if (key === null) return [];
    const hits: SuppressedRecipient[] = [];
    for (const [field, list] of [
      ["to", req.to],
      ["cc", req.cc],
      ["bcc", req.bcc],
    ] as const) {
      for (const [index, recipient] of list.entries()) {
        const row = this.rows<{ reason: "bounce" | "complaint"; first_at: string }>(
          "SELECT reason, first_at FROM suppression WHERE recipient_hash = ?",
          await hashRecipient(key, recipient.address),
        )[0];
        if (row !== undefined) hits.push({ field, index, reason: row.reason, since: row.first_at });
      }
    }
    return hits;
  }

  /** The mailbox's own random HMAC key (spec D15), made the first time an event is recorded; null until then when `create` is false. */
  private suppressionKey(create: boolean): Uint8Array | null {
    const row = this.rows<{ key: ArrayBuffer }>("SELECT key FROM suppression_key")[0];
    if (row !== undefined) return new Uint8Array(row.key);
    if (!create) return null;
    const key = newSuppressionKey();
    this.ctx.storage.sql.exec("INSERT INTO suppression_key (only, key, created_at) VALUES (1, ?, ?)", key, this.now());
    return key;
  }

  // ---- housekeeping (M9, tasks.md S2k) --------------------------------------------------

  /**
   * The daily alarm (HOUSEKEEPING_CRON): empties Trash of messages 30 days in
   * it (M9), then deletes `sends` rows more than 30 days old, audit rows more
   * than a year old, and suppression entries whose last event is more than a
   * year old (M11). A row exactly at its limit stays. It also deletes the
   * challenges and mail sessions that have expired (device-v1 B9); their
   * counts are in the log line, and the answer keeps its shape. Not reached
   * over RPC by MailService; a failure throws into the Agents SDK's
   * scheduler (agents 0.24.0), which retries the job and runs the cron again
   * next day.
   */
  async dailyHousekeeping(): Promise<{ trash: number; sends: number; audit: number; suppression: number }> {
    const trash = await this.purgeExpiredTrash();
    const now = this.ports.clock.now().getTime();
    const sends = this.deleteOlderThan("sends", "created_at", new Date(now - SENDS_KEPT_DAYS * DAY_MS));
    const audit = this.deleteOlderThan("audit", "at", new Date(now - AUDIT_KEPT_DAYS * DAY_MS));
    const suppression = this.deleteOlderThan("suppression", "last_at", new Date(now - SUPPRESSION_KEPT_DAYS * DAY_MS));
    const { challenges, sessions } = deleteExpired(this.ctx.storage.sql, this.ports.clock.now());
    logEvent("housekeeping", { mailbox: this.safeName(), trash, sends, audit, suppression, challenges, sessions });
    return { trash, sends, audit, suppression };
  }

  /** Deletes every message that has been in Trash for 30 days: the R2 object, then the row. */
  private async purgeExpiredTrash(): Promise<number> {
    const cutoff = new Date(this.ports.clock.now().getTime() - TRASH_DAYS * DAY_MS).toISOString();
    const expired = this.rows<MessageRow>(
      "SELECT * FROM messages WHERE folder_id = ? AND trashed_at IS NOT NULL AND trashed_at <= ?",
      Folders.TRASH,
      cutoff,
    );
    for (const row of expired) await this.deleteMessage(row);
    if (expired.length > 0) this.audit("system:housekeeping", "trash-emptied", { count: expired.length });
    return expired.length;
  }

  /** Rows whose ISO timestamp is before `cutoff`; the table and column are this file's constants, never input. */
  private deleteOlderThan(table: "sends" | "audit" | "suppression", column: "created_at" | "at" | "last_at", cutoff: Date): number {
    return this.rows(`DELETE FROM ${table} WHERE ${column} < ? RETURNING 1`, cutoff.toISOString()).length;
  }

  // ---- internals ------------------------------------------------------------------------

  /**
   * The RPC boundary (contracts/mail-service-v1.md). A Refusal becomes a value;
   * anything else is a failure nobody expected: logged here by its name only
   * (a library's message may carry content) and answered as InternalError,
   * which MailService raises to the operator with the capability's jti.
   * Nothing is thrown across the hop, so workerd never logs an uncaught
   * exception for an answer.
   */
  private async answer<T>(method: string, run: () => Promise<T>): Promise<MailResult<T>> {
    try {
      return ok(await run());
    } catch (err) {
      if (err instanceof Refusal) return refused(err.error);
      console.error(JSON.stringify({ event: "mailbox-error", mailbox: this.safeName(), method, error: errorName(err) }));
      return { ok: false, error: internalError() };
    }
  }

  /**
   * Every MailService call comes in here: the mailbox's identity (M4), the
   * caller's role, then what the method needs by SESSION_NEEDS (a session, a
   * factor proof, a device's session: device-v1 B2, B3), in one place. The
   * caller passes the MailService method it serves; the table decides.
   */
  private async enter(ctx: CallContext, method: MailServiceMethod, role: "open" | "send" | "owner"): Promise<Access> {
    await this.ensureIdentity(ctx.mailbox, ctx.actor.accountId);
    this.requireRole(ctx, role);
    return checkAccess(this.store(), ctx, method);
  }

  /** The key ring's modules reach this object only through this (src/mailbox/store.ts). */
  private store(): MailboxStore {
    return {
      mailboxId: this.name,
      sql: this.ctx.storage.sql,
      transaction: (fn) => this.ctx.storage.transactionSync(fn),
      now: () => this.ports.clock.now(),
      newChallengeId: () => this.ports.ids.challengeId(),
      keyIdOf: (publicKey) => this.ports.sealer.keyIdOf(publicKey),
      activeKey: () => this.activeKey(),
      audit: (actor, action, detail) => this.audit(actor, action, detail),
      proofs: this.ports.proofs,
    };
  }

  /**
   * Identity is copied from the Directory the first time the mailbox is
   * touched and never changes: a call carrying another business or address is
   * refused as NotFound (M4) and raised to the operator.
   */
  private async ensureIdentity(entry: DirectoryEntry, actor: string): Promise<void> {
    if (entry.id !== this.name || entry.status === "closed") throw new NotFound();
    const existing = this.identityRow();
    if (existing !== null) {
      if (existing.business_id !== entry.businessId || existing.address !== entry.address) {
        logAlert("identity-conflict", { mailbox: this.name });
        throw new NotFound();
      }
      return;
    }
    const at = this.now();
    this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec(
        "INSERT INTO identity (only, mailbox_id, business_id, address) VALUES (1, ?, ?, ?)",
        entry.id,
        entry.businessId,
        entry.address,
      );
      this.ctx.storage.sql.exec("INSERT INTO policy (only, updated_at, updated_by) VALUES (1, ?, ?)", at, actor);
      this.audit(actor, "mailbox-initialized", {});
    });
    await this.schedule(HOUSEKEEPING_CRON, "dailyHousekeeping");
  }

  private requireRole(ctx: CallContext, need: "open" | "send" | "owner"): void {
    const role: Role = ctx.actor.role;
    if (need === "owner") {
      if (role !== "owner") throw new Forbidden();
      return;
    }
    const policy = this.policyRow();
    const allowed = JSON.parse(need === "open" ? policy.open_roles : policy.send_roles) as Role[];
    if (!allowed.includes(role)) throw new Forbidden();
  }

  private identityRow(): IdentityRow | null {
    return this.rows<IdentityRow>("SELECT mailbox_id, business_id, address, display_name FROM identity")[0] ?? null;
  }

  private policyRow(): PolicyRow {
    const row = this.rows<PolicyRow>("SELECT * FROM policy")[0];
    if (row === undefined) throw new Error("mailbox policy missing");
    return row;
  }

  private policyView(): PolicyView {
    const p = this.policyRow();
    return {
      openRoles: JSON.parse(p.open_roles) as Role[],
      sendRoles: JSON.parse(p.send_roles) as Role[],
      assistant: p.assistant,
      delivery: p.delivery,
      forwardTo: p.forward_to,
      updatedAt: p.updated_at,
      updatedBy: p.updated_by,
    };
  }

  private activeKey(): { keyId: string; publicKey: Uint8Array } | null {
    const row = this.rows<{ key_id: string; public_key: ArrayBuffer }>(
      "SELECT key_id, public_key FROM keys WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )[0];
    return row === undefined ? null : { keyId: row.key_id, publicKey: new Uint8Array(row.public_key) };
  }

  private knownKeyId(value: unknown): string {
    if (typeof value !== "string" || !v.KEY_ID.test(value) || this.rows("SELECT 1 FROM keys WHERE key_id = ?", value).length === 0) {
      throw new InvalidRequest("key id names no key of this mailbox");
    }
    return value;
  }

  private insertWrap(w: ParsedWrap, at: string, by: string): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO key_wraps (id, key_id, kind, credential_id, label, wrapped, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      w.id,
      w.keyId,
      w.kind,
      w.credentialId,
      w.label,
      w.wrapped,
      at,
      by,
    );
  }

  private messageRow(id: string): MessageRow {
    const row = this.rows<MessageRow>("SELECT * FROM messages WHERE id = ?", id)[0];
    if (row === undefined) throw new NotFound();
    return row;
  }

  private async deleteMessage(row: MessageRow): Promise<void> {
    await this.env.MAIL.delete(row.body_key);
    this.ctx.storage.sql.exec("DELETE FROM messages WHERE id = ?", row.id);
  }

  private inboxUnread(): number {
    return this.rows<{ n: number }>("SELECT COUNT(*) AS n FROM messages WHERE folder_id = ? AND seen = 0", Folders.INBOX)[0]?.n ?? 0;
  }

  /** Never message content: ids, kinds, counts and outcomes only. */
  private audit(actor: string, action: string, detail: Record<string, LogValue>): void {
    this.ctx.storage.sql.exec(
      "INSERT INTO audit (at, actor, action, detail) VALUES (?, ?, ?, ?)",
      this.now(),
      actor,
      action,
      JSON.stringify(detail),
    );
  }

  private rows<T>(query: string, ...args: unknown[]): T[] {
    return this.ctx.storage.sql.exec(query, ...args).toArray() as T[];
  }

  private now(): string {
    return this.ports.clock.now().toISOString();
  }

  private safeName(): string | null {
    try {
      return this.name;
    } catch {
      return null;
    }
  }
}

function invalidForward(): never {
  throw new InvalidRequest("a forward target is only for store-and-forward");
}

interface ParsedWrap {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  wrapped: string;
}

function parseWrap(value: unknown, what: string): ParsedWrap {
  const w = v.object(value, what, ["id", "keyId", "kind", "credentialId", "label", "wrapped"]);
  const kind = v.oneOf(w.kind, `${what} kind`, ["passkey-prf", "recovery"] as const);
  const keyId = typeof w.keyId === "string" && v.KEY_ID.test(w.keyId) ? w.keyId : invalid(`${what} key id`);
  const credentialId =
    kind === "passkey-prf"
      ? v.base64url(w.credentialId, `${what} credential id`, { maxChars: 1400 })
      : w.credentialId === undefined || w.credentialId === null
        ? null
        : invalid(`${what} credential id (recovery wraps have none)`);
  return {
    id: v.id(w.id, `${what} id`, "wrp"),
    keyId,
    kind,
    credentialId,
    label: v.text(w.label, `${what} label`, { min: 1, max: 100, singleLine: true }),
    // 0x01 || iv (12) || AES-256-GCM of the key's 48-byte PKCS #8 PrivateKeyInfo (+16 tag) = 77 bytes (envelope v1, D21).
    wrapped: v.base64url(w.wrapped, `${what} wrapped key`, { bytes: 77 }),
  };
}

function invalid(what: string): never {
  throw new InvalidRequest(`invalid ${what}`);
}

const BARE_ID = /^[^\s<>\u0000-\u001f\u007f]{1,998}$/;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{1,200}$/;

export interface ParsedSendRequest {
  idempotencyKey: string;
  /** One of the mailbox's addresses, in the Directory's form; the primary when absent. Checked in `sendReserved`. */
  from?: string;
  to: v.Recipient[];
  cc: v.Recipient[];
  bcc: v.Recipient[];
  subject: string;
  text: string;
  html?: string;
  inReplyTo?: string;
  references: string[];
  attachments: { filename: string; mimeType: string; content: Uint8Array; inline?: boolean; contentId?: string }[];
  draftId?: string;
}

function parseSendRequest(value: unknown): ParsedSendRequest {
  // `session` (device-v1 B1, D29) was read by MailService into the call's auth; it is never stored or passed to SES.
  const r = v.object(value, "send request", [
    "session",
    "idempotencyKey",
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "text",
    "html",
    "inReplyTo",
    "references",
    "attachments",
    "draftId",
  ]);
  const idempotencyKey = typeof r.idempotencyKey === "string" && IDEMPOTENCY_KEY.test(r.idempotencyKey) ? r.idempotencyKey : invalid("idempotency key");
  const list = (x: unknown, what: string) => (x === undefined ? [] : v.array(x, what, LIMITS.maxRecipients).map((a, i) => v.recipient(a, `${what} ${i + 1}`)));
  const to = list(r.to, "to");
  const cc = list(r.cc, "cc");
  const bcc = list(r.bcc, "bcc");
  if (to.length === 0) throw new InvalidRequest("at least one recipient in to is required");
  // M7: at most 50 recipients a message, across to, cc and bcc.
  if (to.length + cc.length + bcc.length > LIMITS.maxRecipients) throw new InvalidRequest(`at most ${LIMITS.maxRecipients} recipients`);
  // A bare address, never a name: the display name is the mailbox's (M6).
  const from = v.optional(r.from, (f) => normalizeAddress(v.address(f, "from")));
  const html = v.optional(r.html, (h) => v.text(h, "html", { max: 5_000_000 }));
  const inReplyTo = v.optional(r.inReplyTo, (x) => (typeof x === "string" && BARE_ID.test(x) ? x : invalid("in-reply-to")));
  const draftId = v.optional(r.draftId, (d) => v.id(d, "draft id", "drf"));
  const attachments = (r.attachments === undefined ? [] : v.array(r.attachments, "attachments", 50)).map((a, i) => {
    const what = `attachment ${i + 1}`;
    const x = v.object(a, what, ["filename", "mimeType", "content", "inline", "contentId"]);
    if (!(x.content instanceof Uint8Array)) throw new InvalidRequest(`${what} content must be bytes`);
    const inline = v.optional(x.inline, (b) => v.bool(b, `${what} inline`));
    const contentId = v.optional(x.contentId, (c) => v.text(c, `${what} content id`, { min: 1, max: 200, singleLine: true }));
    return {
      filename: v.text(x.filename, `${what} filename`, { min: 1, max: 255, singleLine: true }),
      mimeType: v.text(x.mimeType, `${what} type`, { min: 3, max: 255, singleLine: true }),
      content: x.content,
      ...(inline === undefined ? {} : { inline }),
      ...(contentId === undefined ? {} : { contentId }),
    };
  });
  if (attachments.reduce((n, a) => n + a.content.byteLength, 0) > LIMITS.maxRawBytes) throw new InvalidRequest("the attachments are too large");
  return {
    idempotencyKey,
    ...(from === undefined ? {} : { from }),
    to,
    cc,
    bcc,
    subject: v.text(r.subject, "subject", { max: 998, singleLine: true }),
    text: v.text(r.text, "text", { max: 5_000_000 }),
    ...(html === undefined ? {} : { html }),
    ...(inReplyTo === undefined ? {} : { inReplyTo }),
    references: (r.references === undefined ? [] : v.array(r.references, "references", 100)).map((x) =>
      typeof x === "string" && BARE_ID.test(x) ? x : invalid("reference"),
    ),
    attachments,
    ...(draftId === undefined ? {} : { draftId }),
  };
}

const CURSOR = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\|(msg_[0-9abcdefghjkmnpqrstvwxyz]{26})$/;

function parseCursor(value: unknown): { receivedAt: string; id: string } {
  const m = typeof value === "string" ? CURSOR.exec(value) : null;
  if (m === null) throw new InvalidRequest("before must be a cursor from a previous page");
  return { receivedAt: m[1]!, id: m[2]! };
}
