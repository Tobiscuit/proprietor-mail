import { InvalidRequest, MailboxNotActive, SessionRequired } from "../errors";
import { sessionsMode, wrapRow } from "./keyring";
import { x25519Key } from "./public-keys";
import type { Access } from "./sessions";
import { type MailboxStore, rows } from "./store";
import type { CallContext } from "./types";
import * as v from "./validate";

/**
 * Changes to the key ring that spec 002 adds (contracts/device-v1.md B5,
 * B7): the upgrade, kept devices, factor keys and the rotation. Each one
 * checks its request's shapes first (the awaits: key imports and hashes),
 * then, with nothing more to await, checks the current state and writes in
 * one transaction: a check that fails changes nothing (M18).
 */

/** A binding tag (A5): HMAC-SHA-256, 32 bytes. Mail stores it and cannot check it (only key holders can). */
const tag = (value: unknown, what: string) => v.base64url(value, what, { bytes: 32 });

const keyIdOf = (value: unknown, what: string): string => {
  if (typeof value !== "string" || !v.KEY_ID.test(value)) throw new InvalidRequest(`${what} must be a key id`);
  return value;
};

interface FactorKeyInput {
  id: string;
  factorKey: Uint8Array;
  tag: string;
  tagKeyId: string;
}

async function parseFactorKey(value: unknown, what: string): Promise<FactorKeyInput> {
  const f = v.object(value, what, ["id", "factorKey", "tag", "tagKeyId"]);
  return {
    id: v.id(f.id, `${what} id`, "wrp"),
    factorKey: await x25519Key(f.factorKey, `${what} factor key`),
    tag: tag(f.tag, `${what} tag`),
    tagKeyId: keyIdOf(f.tagKeyId, `${what} tag key id`),
  };
}

/**
 * B5, M20: the one moment an existing mailbox learns factor keys without a
 * factor proof (D26, G30). Only while sessions are optional and no factor has
 * a key, in a live session (opened with a key proof), naming wraps of the
 * active key with tags under it, a recovery wrap among them. The factor keys,
 * the tags and `sessions = required` are written together, for good (M13).
 */
export async function upgradeMailbox(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<null> {
  if (access.session === null) throw new SessionRequired();
  if (access.sessions === "required") throw new InvalidRequest("the mailbox is already upgraded");
  const r = v.object(request, "upgrade", ["factors"]);
  const listed = v.array(r.factors, "factors", 20);
  const factors: FactorKeyInput[] = [];
  for (const [i, f] of listed.entries()) factors.push(await parseFactorKey(f, `factor ${i + 1}`));
  if (new Set(factors.map((f) => f.id)).size !== factors.length) throw new InvalidRequest("a factor is named twice");

  store.transaction(() => {
    if (sessionsMode(store.sql) === "required") throw new InvalidRequest("the mailbox is already upgraded");
    const key = store.activeKey();
    if (key === null) throw new MailboxNotActive();
    if (rows(store.sql, "SELECT 1 FROM key_wraps WHERE factor_key IS NOT NULL LIMIT 1").length > 0) throw new InvalidRequest("a factor already has a factor key");
    const kinds = factors.map((f) => {
      const wrap = wrapRow(store.sql, f.id);
      if (wrap === null || wrap.key_id !== key.keyId) throw new InvalidRequest("a factor is not a wrap of the active key");
      if (f.tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
      return wrap.kind;
    });
    if (!kinds.includes("recovery")) throw new InvalidRequest("the upgrade must name a recovery factor");
    for (const f of factors) {
      store.sql.exec("UPDATE key_wraps SET factor_key = ?, tag = ?, tag_key_id = ? WHERE id = ?", f.factorKey, f.tag, f.tagKeyId, f.id);
    }
    store.sql.exec("UPDATE policy SET sessions = 'required', updated_at = ?, updated_by = ?", store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "mailbox-upgraded", { factors: factors.map((f) => f.id).join(",") });
  });
  return null;
}
