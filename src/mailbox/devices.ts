import { DeviceRevoked, InvalidRequest, MailboxNotActive, NotFound, SessionRequired } from "../errors";
import { deviceRow, deviceView, sessionsMode, wrapRow } from "./keyring";
import { p256Point, x25519Key } from "./public-keys";
import type { Access } from "./sessions";
import { type MailboxStore, rows } from "./store";
import type { CallContext, DeviceView } from "./types";
import * as v from "./validate";

/**
 * Changes to the key ring that spec 002 adds (contracts/device-v1.md B5,
 * B7): the upgrade, kept devices, factor keys and the rotation. Each one
 * checks its request's shapes first (the awaits: key imports and hashes),
 * then, with nothing more to await, checks the current state and writes in
 * one transaction: a check that fails changes nothing (M18).
 */

/** B7: at most 20 kept devices per mailbox. */
export const DEVICES_PER_MAILBOX = 20;
/** A4: 0x01 || enc || iv || ct; enc is 65 bytes to a device (P-256), 32 to a factor or a successor (X25519). */
export const DEVICE_SEAL_BYTES = 142;
export const FACTOR_SEAL_BYTES = 109;

const UPGRADE_FIRST = "sessions are not on for this mailbox: upgrade first";

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

function activeKeyOf(store: MailboxStore): { keyId: string; publicKey: Uint8Array } {
  const key = store.activeKey();
  if (key === null) throw new MailboxNotActive();
  return key;
}

function insertSeal(store: MailboxStore, keyId: string, kind: "device" | "factor", toId: string, sealed: string, at: string, by: string): void {
  store.sql.exec("INSERT INTO key_seals (key_id, to_kind, to_id, sealed, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)", keyId, kind, toId, sealed, at, by);
}

// ---- labels that a tag covers -------------------------------------------------------

/**
 * A label a binding tag covers (A5 hashes UTF-8(label)) must come back from
 * storage exactly as the browser tagged it. SQLite keeps UTF-8, and a lone
 * surrogate does not survive the trip (it returns as replacement
 * characters), which would make the tag fail at every unlock (K3).
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const LINE_SEPARATORS = /[\u0085\u2028\u2029]/;

function taggedLabel(label: string, what: string): string {
  if (LONE_SURROGATE.test(label)) throw new InvalidRequest(`${what} must be well-formed text`);
  return label;
}

/** B7: 1 to 40 characters (code points, in any script), on one line. */
function deviceLabel(value: unknown, what: string): string {
  const label = v.text(value, what, { min: 1, max: 80, singleLine: true });
  taggedLabel(label, what);
  if (LINE_SEPARATORS.test(label)) throw new InvalidRequest(`${what} must be one line`);
  if ([...label].length > 40) throw new InvalidRequest(`${what} is too long`);
  return label;
}

// ---- kept devices (B7) ----------------------------------------------------------------

/** B7's DeviceInput, checked: the browser's dev_ id, the label, two P-256 points (the unlock key null for a device that keeps nothing), and its tag. */
export interface DeviceInput {
  id: string;
  label: string;
  signingKey: Uint8Array; // pragma: allowlist secret (a type annotation: a public P-256 point)
  unlockKey: Uint8Array | null;
  tag: string;
  tagKeyId: string;
}

async function parseDeviceInput(value: unknown, what = "device"): Promise<DeviceInput> {
  const d = v.object(value, what, ["id", "label", "signingKey", "unlockKey", "tag", "tagKeyId"]);
  return {
    id: v.id(d.id, `${what} id`, "dev"),
    label: deviceLabel(d.label, `${what} label`),
    signingKey: await p256Point(d.signingKey, `${what} signing key`, "ECDSA"),
    unlockKey: d.unlockKey === null ? null : await p256Point(d.unlockKey, `${what} unlock key`, "ECDH"),
    tag: tag(d.tag, `${what} tag`),
    tagKeyId: keyIdOf(d.tagKeyId, `${what} tag key id`),
  };
}

/** The active key sealed to a device's unlock key: present exactly when there is an unlock key, 142 bytes. */
function deviceSeal(unlockKey: Uint8Array | null, seal: unknown): string | null {
  if (unlockKey === null) {
    if (seal !== null) throw new InvalidRequest("a device without an unlock key has no seal");
    return null;
  }
  return v.base64url(seal, "seal", { bytes: DEVICE_SEAL_BYTES });
}

function insertDevice(store: MailboxStore, ctx: CallContext, device: DeviceInput, seal: string | null, keyId: string, at: string, lastSeenAt: string | null): void {
  store.sql.exec(
    "INSERT INTO devices (id, account_id, label, signing_key, unlock_key, tag, tag_key_id, created_at, created_by, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    device.id,
    ctx.actor.accountId,
    device.label,
    device.signingKey,
    device.unlockKey,
    device.tag,
    device.tagKeyId,
    at,
    ctx.actor.accountId,
    lastSeenAt,
  );
  if (seal !== null) insertSeal(store, keyId, "device", device.id, seal, at, ctx.actor.accountId);
}

/**
 * B7, F1: keeps the calling browser. Needs a factor proof (M17, spent by
 * checkAccess). The device belongs to the calling account (M21), its seal is
 * of the active key (M19), and the caller's session becomes its session.
 */
export async function registerDevice(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<DeviceView> {
  if (access.sessions === "optional") throw new InvalidRequest(UPGRADE_FIRST);
  const session = access.session!;
  const r = v.object(request, "device registration", ["device", "seal"]);
  const device = await parseDeviceInput(r.device);
  const seal = deviceSeal(device.unlockKey, r.seal);
  return store.transaction(() => {
    const key = activeKeyOf(store);
    if (device.tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    if (deviceRow(store.sql, device.id) !== null) throw new InvalidRequest("that device id is in use");
    const kept = rows<{ n: number }>(store.sql, "SELECT COUNT(*) AS n FROM devices")[0]!.n;
    if (kept >= DEVICES_PER_MAILBOX) throw new InvalidRequest(`a mailbox keeps at most ${DEVICES_PER_MAILBOX} devices`);
    // The caller's session becomes this device's session (B7). One that ended meanwhile (a rotation) stops everything.
    if (rows(store.sql, "SELECT 1 FROM mail_sessions WHERE token_hash = ?", session.hash).length === 0) throw new SessionRequired();
    const at = store.now().toISOString();
    insertDevice(store, ctx, device, seal, key.keyId, at, at);
    store.sql.exec("UPDATE mail_sessions SET device_id = ? WHERE token_hash = ?", device.id, session.hash);
    store.audit(ctx.actor.accountId, "device-registered", { device: device.id, label: device.label, unlockKey: device.unlockKey !== null, factor: access.factor?.id ?? null });
    return deviceView(deviceRow(store.sql, device.id)!);
  });
}

/**
 * B7, F3, F4: only from the device's own session. Replaces its unlock key,
 * its tag and its seal, and deletes its earlier seals; null clears them (the
 * device locked).
 */
export async function updateDevice(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<DeviceView> {
  const deviceId = access.session!.deviceId!;
  const r = v.object(request, "device update", ["unlockKey", "tag", "tagKeyId", "seal"]);
  const unlockKey = r.unlockKey === null ? null : await p256Point(r.unlockKey, "unlock key", "ECDH");
  const newTag = tag(r.tag, "tag");
  const tagKeyId = keyIdOf(r.tagKeyId, "tag key id");
  const seal = deviceSeal(unlockKey, r.seal);
  return store.transaction(() => {
    const key = activeKeyOf(store);
    if (tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    if (deviceRow(store.sql, deviceId) === null) throw new DeviceRevoked();
    store.sql.exec("UPDATE devices SET unlock_key = ?, tag = ?, tag_key_id = ? WHERE id = ?", unlockKey, newTag, tagKeyId, deviceId);
    store.sql.exec("DELETE FROM key_seals WHERE to_kind = 'device' AND to_id = ?", deviceId);
    if (seal !== null) insertSeal(store, key.keyId, "device", deviceId, seal, store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "device-unlock-key", { device: deviceId, unlockKey: unlockKey === null ? "cleared" : "set" });
    return deviceView(deviceRow(store.sql, deviceId)!);
  });
}

// ---- factors (B5, B7) -----------------------------------------------------------------

/** A wrap as the Mailbox's parseWrap checks it (envelope v1), the factor before its key. */
export interface WrapInput {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  wrapped: string;
}

/** B7's fields a wrap brings once sessions are required (and at an enrolment with factor keys, B5). */
export interface FactorFields {
  factorKey: Uint8Array;
  tag: string;
  tagKeyId: string;
}

/**
 * Takes B7's factor fields off a wrap, so the wrap itself is parsed exactly as
 * before (the Mailbox's parseWrap). Anything but a plain object is passed on
 * whole, for parseWrap to refuse as it always has.
 */
export function splitFactorFields(value: unknown): { plain: unknown; fields: Record<string, unknown> | null } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { plain: value, fields: null };
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return { plain: value, fields: null };
  const { factorKey, tag: tagged, tagKeyId, ...plain } = value as Record<string, unknown>;
  const present = factorKey !== undefined || tagged !== undefined || tagKeyId !== undefined;
  return { plain, fields: present ? { factorKey, tag: tagged, tagKeyId } : null };
}

async function factorFields(fields: Record<string, unknown> | null, what: string, defaultTagKeyId?: string): Promise<FactorFields> {
  const f = fields ?? {};
  return {
    factorKey: await x25519Key(f.factorKey, `${what} factor key`),
    tag: tag(f.tag, `${what} tag`),
    tagKeyId: f.tagKeyId === undefined && defaultTagKeyId !== undefined ? defaultTagKeyId : keyIdOf(f.tagKeyId, `${what} tag key id`),
  };
}

function insertKeyedWrap(store: MailboxStore, w: WrapInput, f: FactorFields, at: string, by: string): void {
  store.sql.exec(
    "INSERT INTO key_wraps (id, key_id, kind, credential_id, label, wrapped, created_at, created_by, factor_key, tag, tag_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    w.id,
    w.keyId,
    w.kind,
    w.credentialId,
    w.label,
    w.wrapped,
    at,
    by,
    f.factorKey,
    f.tag,
    f.tagKeyId,
  );
}

/**
 * M5′: a recovery factor reaches the active key through its own wrap of that
 * key, or through a seal of that key to its factor key. True when one other
 * than `exceptWrapId` does.
 */
export function recoveryReaches(sql: SqlStorage, activeKeyId: string, exceptWrapId: string | null): boolean {
  return (
    rows(
      sql,
      `SELECT 1 FROM key_wraps w WHERE w.kind = 'recovery' AND w.id IS NOT ? AND (w.key_id = ? OR EXISTS (
         SELECT 1 FROM key_seals s WHERE s.key_id = ? AND s.to_kind = 'factor' AND s.to_id = w.id)) LIMIT 1`,
      exceptWrapId,
      activeKeyId,
      activeKeyId,
    ).length > 0
  );
}

/** B7: addWrap once sessions are required: a wrap of the active key, with its factor key and a tag under that key. */
export async function addKeyedWrap(store: MailboxStore, ctx: CallContext, wrap: WrapInput, fields: Record<string, unknown> | null): Promise<null> {
  const factor = await factorFields(fields, "wrap");
  taggedLabel(wrap.label, "wrap label");
  store.transaction(() => {
    const key = activeKeyOf(store);
    if (wrap.keyId !== key.keyId) throw new InvalidRequest("a wrap must name the mailbox's key");
    if (factor.tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    if (wrapRow(store.sql, wrap.id) !== null) throw new InvalidRequest("that wrap id exists");
    insertKeyedWrap(store, wrap, factor, store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "wrap-added", { wrap: wrap.id, kind: wrap.kind });
  });
  return null;
}

/** B7: removeWrap once sessions are required: the factor and its seals go; never the last recovery factor that reaches the active key (M5′). */
export function removeKeyedWrap(store: MailboxStore, ctx: CallContext, wrapId: string): null {
  store.transaction(() => {
    const wrap = wrapRow(store.sql, wrapId);
    if (wrap === null) throw new NotFound();
    const key = activeKeyOf(store);
    if (wrap.kind === "recovery" && !recoveryReaches(store.sql, key.keyId, wrapId)) {
      throw new InvalidRequest("the last recovery factor that reaches the active key cannot be removed");
    }
    store.sql.exec("DELETE FROM key_seals WHERE to_kind = 'factor' AND to_id = ?", wrapId);
    store.sql.exec("DELETE FROM key_wraps WHERE id = ?", wrapId);
    store.audit(ctx.actor.accountId, "wrap-removed", { wrap: wrapId, kind: wrap.kind });
  });
  return null;
}

/**
 * B7, F9: a factor left out of the upgrade gets its factor key, proved by
 * another factor. When its wrap is of a retired key, it also needs a seal of
 * the active key, or it could not reach the key new mail is sealed to.
 */
export async function setFactorKey(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<null> {
  if (access.sessions === "optional") throw new InvalidRequest(UPGRADE_FIRST);
  const r = v.object(request, "factor key", ["factorId", "factorKey", "tag", "tagKeyId", "seal"]);
  const factorId = v.id(r.factorId, "factor id", "wrp");
  if (access.factor?.id === factorId) throw new InvalidRequest("the factor proof must come from another factor");
  const factorKey = await x25519Key(r.factorKey, "factor key");
  const newTag = tag(r.tag, "tag");
  const tagKeyId = keyIdOf(r.tagKeyId, "tag key id");
  store.transaction(() => {
    const key = activeKeyOf(store);
    const wrap = wrapRow(store.sql, factorId);
    if (wrap === null) throw new InvalidRequest("no such factor");
    if (wrap.factor_key !== null) throw new InvalidRequest("that factor already has a factor key");
    if (tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    let seal: string | null = null;
    if (wrap.key_id !== key.keyId) seal = v.base64url(r.seal, "seal", { bytes: FACTOR_SEAL_BYTES });
    else if (r.seal !== null) throw new InvalidRequest("the factor's wrap is of the active key: it takes no seal");
    store.sql.exec("UPDATE key_wraps SET factor_key = ?, tag = ?, tag_key_id = ? WHERE id = ?", factorKey, newTag, tagKeyId, factorId);
    if (seal !== null) insertSeal(store, key.keyId, "factor", factorId, seal, store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "factor-key-set", { factor: factorId, kind: wrap.kind, seal: seal !== null, via: access.factor!.id });
  });
  return null;
}

// ---- enrolment with factor keys (B5, F12) ------------------------------------------------

/**
 * B5: when every wrap carries a factor key and a tag (made under the new
 * key), the mailbox starts with sessions required; mixing is refused. A
 * wrap's `tagKeyId` may be left out at enrolment: it can only be the new key.
 */
export async function enrolmentFactors(wraps: WrapInput[], fields: (Record<string, unknown> | null)[], keyId: string): Promise<FactorFields[] | null> {
  const carrying = fields.filter((f) => f !== null).length;
  if (carrying === 0) return null;
  if (carrying !== fields.length) throw new InvalidRequest("either every wrap carries a factor key or none does");
  const factors: FactorFields[] = [];
  for (const [i, f] of fields.entries()) {
    const factor = await factorFields(f, `wrap ${i + 1}`, keyId);
    if (factor.tagKeyId !== keyId) throw new InvalidRequest("a tag must be made under the new key");
    taggedLabel(wraps[i]!.label, `wrap ${i + 1} label`);
    factors.push(factor);
  }
  return factors;
}

/** B5: the enrolling browser's device, `{ device: DeviceInput, seal }`, tagged under the new key. */
export async function enrolmentDevice(value: unknown, keyId: string): Promise<{ device: DeviceInput; seal: string | null }> {
  const r = v.object(value, "enrolling device", ["device", "seal"]);
  const device = await parseDeviceInput(r.device);
  const seal = deviceSeal(device.unlockKey, r.seal);
  if (device.tagKeyId !== keyId) throw new InvalidRequest("a tag must be made under the new key");
  return { device, seal };
}

/**
 * The enrolment's own writes for B5, inside the Mailbox's enrolment
 * transaction (so: no transaction of its own): the keyed wraps, sessions
 * required, and the device with its seal.
 */
export function writeKeyedEnrolment(
  store: MailboxStore,
  ctx: CallContext,
  keyId: string,
  wraps: WrapInput[],
  factors: FactorFields[],
  device: { device: DeviceInput; seal: string | null } | null,
  at: string,
): void {
  for (const [i, w] of wraps.entries()) insertKeyedWrap(store, w, factors[i]!, at, ctx.actor.accountId);
  store.sql.exec("UPDATE policy SET sessions = 'required'");
  if (device !== null) {
    insertDevice(store, ctx, device.device, device.seal, keyId, at, null);
    store.audit(ctx.actor.accountId, "device-registered", { device: device.device.id, label: device.device.label, unlockKey: device.device.unlockKey !== null, factor: null });
  }
}
