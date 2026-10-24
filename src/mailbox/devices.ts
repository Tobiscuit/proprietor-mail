import { bootstrapAdmitters, isDeviceLabel, type Statement } from "@proprietor/mail-crypto";
import { DeviceRevoked, InvalidRequest, MailboxNotActive, NotFound, ProofRejected, SessionRequired } from "../errors";
import { attestationProblem, revokeTargets } from "./confirmations";
import { deviceRow, deviceView, keyedFactor, rotationDue, sessionsMode, wrapRow } from "./keyring";
import { ed25519Key, p256Point, x25519Key } from "./public-keys";
import { type Access, type ChallengeRow, rejectProof, refuseSpent } from "./sessions";
import { type MailboxStore, rows } from "./store";
import type { CallContext, DeviceView } from "./types";
import * as v from "./validate";

/**
 * Changes to the key ring that spec 002 adds (contracts/device-v1.md B5,
 * B7, B7a): the upgrade, kept devices, factor keys, the rotation, and
 * (round 3) the email-code revocation. Each one checks its request's shapes
 * and verifies every signature it carries first (the awaits: key imports,
 * hashes, A11's statements, M25), then, with nothing more to await, checks
 * the current state and writes in one transaction: a check that fails
 * changes nothing (M18′).
 */

/** B7: at most 20 kept devices per mailbox; removeDevices and revokeDevices name at most 20. */
export const DEVICES_PER_MAILBOX = 20;
/** A4: 0x01 || enc || iv || ct; enc is 65 bytes to a device (P-256), 32 to a factor or a successor (X25519). */
export const DEVICE_SEAL_BYTES = 142;
export const FACTOR_SEAL_BYTES = 109;
/** A11: an Ed25519 signature (a factor's) and an ECDSA P-256 one in IEEE P1363 form (a device's) are both 64 bytes. */
const SIGNATURE_BYTES = 64;

const UPGRADE_FIRST = "sessions are not on for this mailbox: upgrade first";
const DOES_NOT_VERIFY = "a signature does not verify (A11)";

/** A binding tag (A5): HMAC-SHA-256, 32 bytes. Mail stores it and cannot check it (only key holders can). */
const tag = (value: unknown, what: string) => v.base64url(value, what, { bytes: 32 });
const signature = (value: unknown, what: string) => v.base64url(value, what, { bytes: SIGNATURE_BYTES });

const keyIdOf = (value: unknown, what: string): string => {
  if (typeof value !== "string" || !v.KEY_ID.test(value)) throw new InvalidRequest(`${what} must be a key id`);
  return value;
};

function activeKeyOf(store: MailboxStore): { keyId: string; publicKey: Uint8Array } {
  const key = store.activeKey();
  if (key === null) throw new MailboxNotActive();
  return key;
}

function insertSeal(store: MailboxStore, keyId: string, kind: "device" | "factor", toId: string, sealed: string, at: string, by: string): void {
  store.sql.exec("INSERT INTO key_seals (key_id, to_kind, to_id, sealed, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)", keyId, kind, toId, sealed, at, by);
}

// ---- A11: the statements Mail verifies before it stores anything (M25) ------------------

/** A factor's admission (A11): by its admitter, countersigned by the factor itself. */
export interface Admission {
  by: string;
  signature: string;
  selfSignature: string;
}

function parseAdmission(value: unknown, what: string): Admission {
  const a = v.object(value, what, ["by", "signature", "selfSignature"]);
  return { by: v.id(a.by, `${what} admitter`, "wrp"), signature: signature(a.signature, `${what} signature`), selfSignature: signature(a.selfSignature, `${what} self-signature`) };
}

/** What the admission of a factor names (A11): its record as Mail lists it, with the keys the call brings. */
interface AdmittedFactor {
  id: string;
  kind: "passkey-prf" | "recovery";
  label: string;
  credentialId: string | null;
  factorKey: Uint8Array;
  signingKey: Uint8Array; // pragma: allowlist secret (a field type: a public Ed25519 key)
}

/** A11: the admission of `factor` by `admitter` verifies, both its signature (the admitter's key) and its self-signature (the factor's own). */
async function factorAdmissionVerifies(store: MailboxStore, factor: AdmittedFactor, admission: Admission, admitter: { id: string; signingKey: Uint8Array }): Promise<boolean> { // pragma: allowlist secret (a type: a public Ed25519 key)
  if (admission.by !== admitter.id) return false;
  const statement: Statement = {
    kind: "admit-factor",
    mailboxId: store.mailboxId,
    factorId: factor.id,
    factorKind: factor.kind,
    label: factor.label,
    factorKey: factor.factorKey,
    signingKey: factor.signingKey, // pragma: allowlist secret (a public Ed25519 key)
    credentialId: factor.credentialId, // pragma: allowlist secret (a field name, not a value)
    admitterId: admitter.id,
    admitterSigningKey: admitter.signingKey, // pragma: allowlist secret (a public Ed25519 key)
  };
  return (await store.proofs.verifyStatement(admitter.signingKey, statement, admission.signature)) && (await store.proofs.verifyStatement(factor.signingKey, statement, admission.selfSignature));
}

/**
 * A11 at enrollment and at the upgrade, where every factor is present: each
 * is admitted by the next in id order (the last by the first; one alone by
 * itself), mail-crypto's bootstrapAdmitters, and every admission verifies.
 */
async function bootstrapCycleVerifies(store: MailboxStore, factors: { factor: AdmittedFactor; admission: Admission }[]): Promise<boolean> {
  const byId = new Map(factors.map((f) => [f.factor.id, f]));
  for (const { factorId, admitterId } of bootstrapAdmitters(factors.map((f) => f.factor.id))) {
    const f = byId.get(factorId)!;
    const admitter = byId.get(admitterId)!;
    if (!(await factorAdmissionVerifies(store, f.factor, f.admission, { id: admitter.factor.id, signingKey: admitter.factor.signingKey }))) return false; // pragma: allowlist secret (a public Ed25519 key)
  }
  return true;
}

/** A11: a device's admission by `admitter` verifies, and while it has an unlock key, its own signature over that key. */
async function deviceStatementsVerify(store: MailboxStore, device: DeviceInput, admitter: { id: string; signingKey: Uint8Array }): Promise<boolean> { // pragma: allowlist secret (a type: a public Ed25519 key)
  if (device.admission.by !== admitter.id) return false;
  const admitted = await store.proofs.verifyStatement(
    admitter.signingKey,
    { kind: "admit-device", mailboxId: store.mailboxId, deviceId: device.id, label: device.label, signingKey: device.signingKey, admitterId: admitter.id }, // pragma: allowlist secret (a public P-256 point)
    device.admission.signature,
  );
  if (!admitted) return false;
  return device.unlockKey === null || unlockKeyVerifies(store, device.id, device.signingKey, device.unlockKey, device.unlockSignature!);
}

/** A11: an unlock key is signed by its device's own signing key. */
async function unlockKeyVerifies(store: MailboxStore, deviceId: string, signingKey: Uint8Array, unlockKey: Uint8Array, unlockSignature: string): Promise<boolean> { // pragma: allowlist secret (a parameter type: a public P-256 point)
  return store.proofs.verifyStatement(signingKey, { kind: "unlock-key", mailboxId: store.mailboxId, deviceId, unlockKey }, unlockSignature);
}

/** The factor whose proof the call spent, still a keyed factor at the moment of writing (it may have been removed during an await). */
function stillKeyed(store: MailboxStore, factor: NonNullable<Access["factor"]>): void {
  if (keyedFactor(store.sql, factor.id) === null) throw new InvalidRequest("the factor whose proof this call spent was removed meanwhile");
}

// ---- the upgrade (B5, M20) ------------------------------------------------------------------

interface FactorKeyInput {
  id: string;
  factorKey: Uint8Array;
  signingKey: Uint8Array; // pragma: allowlist secret (a field type: a public Ed25519 key)
  admission: Admission;
  tag: string;
  tagKeyId: string;
}

async function parseFactorKey(value: unknown, what: string): Promise<FactorKeyInput> {
  const f = v.object(value, what, ["id", "factorKey", "signingKey", "admission", "tag", "tagKeyId"]);
  return {
    id: v.id(f.id, `${what} id`, "wrp"),
    factorKey: await x25519Key(f.factorKey, `${what} factor key`),
    signingKey: await ed25519Key(f.signingKey, `${what} signing key`), // pragma: allowlist secret (a public Ed25519 key)
    admission: parseAdmission(f.admission, `${what} admission`),
    tag: tag(f.tag, `${what} tag`),
    tagKeyId: keyIdOf(f.tagKeyId, `${what} tag key id`),
  };
}

/**
 * B5, M20: the one moment an existing mailbox learns factor keys without a
 * factor proof (D26, G30). Only while sessions are optional and no factor has
 * a key, in a live session, with a key proof bound to this very request
 * (round 3: spent by checkAccess, need "key"), naming every wrap of the
 * mailbox exactly once, each a wrap of the active key with a tag under it,
 * and with A11's admissions (each factor by the next in id order, and by
 * itself), every one verified (M25). The factor keys, signing keys,
 * admissions, tags and `sessions = required` are written together, for good
 * (M13).
 */
export async function upgradeMailbox(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<null> {
  if (access.session === null) throw new SessionRequired();
  if (access.sessions === "required") throw new InvalidRequest("the mailbox is already upgraded");
  const r = v.object(request, "upgrade", ["factors"]);
  const listed = v.array(r.factors, "factors", 20);
  const factors: FactorKeyInput[] = [];
  for (const [i, f] of listed.entries()) factors.push(await parseFactorKey(f, `factor ${i + 1}`));
  if (factors.length === 0) throw new InvalidRequest("the upgrade must name every wrap of the mailbox, once each");
  if (new Set(factors.map((f) => f.id)).size !== factors.length) throw new InvalidRequest("a factor is named twice");
  // The admissions name each factor as Mail lists it (kind, label, credential id): read now, checked again below.
  const records = factors.map((f) => {
    const wrap = wrapRow(store.sql, f.id);
    if (wrap === null) throw new InvalidRequest("a factor is not a wrap of the active key");
    return { factor: { id: f.id, kind: wrap.kind, label: wrap.label, credentialId: wrap.credential_id, factorKey: f.factorKey, signingKey: f.signingKey }, admission: f.admission }; // pragma: allowlist secret (field names; public keys only)
  });
  if (!(await bootstrapCycleVerifies(store, records))) throw new InvalidRequest(`${DOES_NOT_VERIFY}: the factors admit each other in id order, each by the next`);

  store.transaction(() => {
    if (sessionsMode(store.sql) === "required") throw new InvalidRequest("the mailbox is already upgraded");
    const key = activeKeyOf(store);
    if (rows(store.sql, "SELECT 1 FROM key_wraps WHERE factor_key IS NOT NULL LIMIT 1").length > 0) throw new InvalidRequest("a factor already has a factor key");
    for (const f of factors) {
      const wrap = wrapRow(store.sql, f.id);
      if (wrap === null || wrap.key_id !== key.keyId) throw new InvalidRequest("a factor is not a wrap of the active key");
      if (f.tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    }
    // Every wrap the mailbox has, once each (names are unique, checked above).
    const wraps = rows<{ id: string }>(store.sql, "SELECT id FROM key_wraps");
    const named = new Set(factors.map((f) => f.id));
    if (wraps.length !== named.size || wraps.some((w) => !named.has(w.id))) throw new InvalidRequest("the upgrade must name every wrap of the mailbox, once each");
    for (const f of factors) {
      store.sql.exec(
        "UPDATE key_wraps SET factor_key = ?, signing_key = ?, admission_by = ?, admission_sig = ?, admission_self_sig = ?, tag = ?, tag_key_id = ? WHERE id = ?",
        f.factorKey,
        f.signingKey,
        f.admission.by,
        f.admission.signature,
        f.admission.selfSignature,
        f.tag,
        f.tagKeyId,
        f.id,
      );
    }
    store.sql.exec("UPDATE policy SET sessions = 'required', updated_at = ?, updated_by = ?", store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "mailbox-upgraded", { factors: factors.map((f) => f.id).join(",") });
  });
  return null;
}

// ---- kept devices (B7) ----------------------------------------------------------------

/** B7, action-descriptor-v1: 1 to 40 code points, one line, well-formed: the label rule a descriptor names a device by. */
function deviceLabel(value: unknown, what: string): string {
  if (!isDeviceLabel(value)) throw new InvalidRequest(`${what} must be 1 to 40 characters on one line, without control characters`);
  return value;
}

/** B7's DeviceInput, checked: the browser's dev_ id, the label, two P-256 points (the unlock key null for a device that keeps nothing), the unlock key's signature, the admission, and its tag. */
export interface DeviceInput {
  id: string;
  label: string;
  signingKey: Uint8Array; // pragma: allowlist secret (a type annotation: a public P-256 point)
  unlockKey: Uint8Array | null;
  unlockSignature: string | null;
  admission: { by: string; signature: string };
  tag: string;
  tagKeyId: string;
}

async function parseDeviceInput(value: unknown, what = "device"): Promise<DeviceInput> {
  const d = v.object(value, what, ["id", "label", "signingKey", "unlockKey", "unlockSignature", "admission", "tag", "tagKeyId"]);
  const unlockKey = d.unlockKey === null ? null : await p256Point(d.unlockKey, `${what} unlock key`, "ECDH");
  const unlockSignature = d.unlockSignature === null ? null : signature(d.unlockSignature, `${what} unlock key signature`);
  if ((unlockKey === null) !== (unlockSignature === null)) throw new InvalidRequest(`${what}: an unlock key comes with its signature, and only with it`);
  const admission = v.object(d.admission, `${what} admission`, ["by", "signature"]);
  return {
    id: v.id(d.id, `${what} id`, "dev"),
    label: deviceLabel(d.label, `${what} label`),
    signingKey: await p256Point(d.signingKey, `${what} signing key`, "ECDSA"),
    unlockKey,
    unlockSignature,
    admission: { by: v.id(admission.by, `${what} admitter`, "wrp"), signature: signature(admission.signature, `${what} admission signature`) },
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
    `INSERT INTO devices (id, account_id, label, signing_key, unlock_key, unlock_sig, admission_by, admission_sig, tag, tag_key_id, created_at, created_by, last_seen_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    device.id,
    ctx.actor.accountId,
    device.label,
    device.signingKey,
    device.unlockKey,
    device.unlockSignature,
    device.admission.by,
    device.admission.signature,
    device.tag,
    device.tagKeyId,
    at,
    ctx.actor.accountId,
    lastSeenAt,
  );
  if (seal !== null) insertSeal(store, keyId, "device", device.id, seal, at, ctx.actor.accountId);
}

/**
 * B7, F1: keeps the calling browser. Needs a factor proof bound to this very
 * request (M17′, spent by checkAccess). The device is admitted by that factor
 * and signs its own unlock key; Mail verifies both before it writes (M25).
 * The device belongs to the calling account (M21′), its seal is of the active
 * key (M19), and the caller's session becomes its session.
 */
export async function registerDevice(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<DeviceView> {
  if (access.sessions === "optional") throw new InvalidRequest(UPGRADE_FIRST);
  const session = access.session!;
  const factor = access.factor!;
  const r = v.object(request, "device registration", ["device", "seal"]);
  const device = await parseDeviceInput(r.device);
  const seal = deviceSeal(device.unlockKey, r.seal);
  if (device.admission.by !== factor.id) throw new InvalidRequest("a device is admitted by the factor whose proof the call spends");
  if (!(await deviceStatementsVerify(store, device, factor))) throw new InvalidRequest(DOES_NOT_VERIFY);
  return store.transaction(() => {
    const key = activeKeyOf(store);
    if (device.tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    if (deviceRow(store.sql, device.id) !== null) throw new InvalidRequest("that device id is in use");
    const kept = rows<{ n: number }>(store.sql, "SELECT COUNT(*) AS n FROM devices")[0]!.n;
    if (kept >= DEVICES_PER_MAILBOX) throw new InvalidRequest(`a mailbox keeps at most ${DEVICES_PER_MAILBOX} devices`);
    stillKeyed(store, factor);
    // The caller's session becomes this device's session (B7). One that ended meanwhile (a rotation) stops everything.
    if (rows(store.sql, "SELECT 1 FROM mail_sessions WHERE token_hash = ?", session.hash).length === 0) throw new SessionRequired();
    const at = store.now().toISOString();
    insertDevice(store, ctx, device, seal, key.keyId, at, at);
    store.sql.exec("UPDATE mail_sessions SET device_id = ? WHERE token_hash = ?", device.id, session.hash);
    store.audit(ctx.actor.accountId, "device-registered", { device: device.id, label: device.label, unlockKey: device.unlockKey !== null, factor: factor.id });
    return deviceView(deviceRow(store.sql, device.id)!);
  });
}

/**
 * B7, F3, F4: only from the device's own session. Replaces its unlock key,
 * the key's signature (verified with the device's signing key, M25), its tag
 * and its seal, and deletes its earlier seals; null clears them (the device
 * locked).
 */
export async function updateDevice(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<DeviceView> {
  const deviceId = access.session!.deviceId!;
  const r = v.object(request, "device update", ["unlockKey", "unlockSignature", "tag", "tagKeyId", "seal"]);
  const unlockKey = r.unlockKey === null ? null : await p256Point(r.unlockKey, "unlock key", "ECDH");
  const unlockSignature = r.unlockSignature === null ? null : signature(r.unlockSignature, "unlock key signature");
  if ((unlockKey === null) !== (unlockSignature === null)) throw new InvalidRequest("an unlock key comes with its signature, and only with it");
  const newTag = tag(r.tag, "tag");
  const tagKeyId = keyIdOf(r.tagKeyId, "tag key id");
  const seal = deviceSeal(unlockKey, r.seal);
  const device = deviceRow(store.sql, deviceId);
  if (device === null) throw new DeviceRevoked();
  if (unlockKey !== null && !(await unlockKeyVerifies(store, deviceId, new Uint8Array(device.signing_key), unlockKey, unlockSignature!))) throw new InvalidRequest(DOES_NOT_VERIFY);
  return store.transaction(() => {
    const key = activeKeyOf(store);
    if (tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    if (deviceRow(store.sql, deviceId) === null) throw new DeviceRevoked();
    store.sql.exec("UPDATE devices SET unlock_key = ?, unlock_sig = ?, tag = ?, tag_key_id = ? WHERE id = ?", unlockKey, unlockSignature, newTag, tagKeyId, deviceId);
    store.sql.exec("DELETE FROM key_seals WHERE to_kind = 'device' AND to_id = ?", deviceId);
    if (seal !== null) insertSeal(store, key.keyId, "device", deviceId, seal, store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "device-unlock-key", { device: deviceId, unlockKey: unlockKey === null ? "cleared" : "set" });
    return deviceView(deviceRow(store.sql, deviceId)!);
  });
}

// ---- factors (B5, B7, M24) -----------------------------------------------------------------

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
  signingKey: Uint8Array; // pragma: allowlist secret (a field type: a public Ed25519 key)
  admission: Admission;
  tag: string;
  tagKeyId: string;
}

const FACTOR_FIELDS = ["factorKey", "signingKey", "admission", "tag", "tagKeyId"] as const;

/**
 * Takes B7's factor fields off a wrap, so the wrap itself is parsed exactly as
 * before (the Mailbox's parseWrap). Anything but a plain object is passed on
 * whole, for parseWrap to refuse as it always has.
 */
export function splitFactorFields(value: unknown): { plain: unknown; fields: Record<string, unknown> | null } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return { plain: value, fields: null };
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) return { plain: value, fields: null };
  const plain: Record<string, unknown> = {};
  const fields: Record<string, unknown> = {};
  for (const [name, x] of Object.entries(value as Record<string, unknown>)) {
    if ((FACTOR_FIELDS as readonly string[]).includes(name)) fields[name] = x;
    else plain[name] = x;
  }
  return { plain, fields: Object.values(fields).some((x) => x !== undefined) ? fields : null };
}

async function factorFields(fields: Record<string, unknown> | null, what: string, defaultTagKeyId?: string): Promise<FactorFields> {
  const f = fields ?? {};
  return {
    factorKey: await x25519Key(f.factorKey, `${what} factor key`),
    signingKey: await ed25519Key(f.signingKey, `${what} signing key`), // pragma: allowlist secret (a public Ed25519 key)
    admission: parseAdmission(f.admission, `${what} admission`),
    tag: tag(f.tag, `${what} tag`),
    tagKeyId: f.tagKeyId === undefined && defaultTagKeyId !== undefined ? defaultTagKeyId : keyIdOf(f.tagKeyId, `${what} tag key id`),
  };
}

const admitted = (w: WrapInput, f: FactorFields): AdmittedFactor => ({
  id: w.id,
  kind: w.kind,
  label: w.label,
  credentialId: w.credentialId, // pragma: allowlist secret (a field name, not a value)
  factorKey: f.factorKey,
  signingKey: f.signingKey, // pragma: allowlist secret (a public Ed25519 key)
});

function insertKeyedWrap(store: MailboxStore, w: WrapInput, f: FactorFields, at: string, by: string): void {
  store.sql.exec(
    `INSERT INTO key_wraps (id, key_id, kind, credential_id, label, wrapped, created_at, created_by,
       factor_key, signing_key, admission_by, admission_sig, admission_self_sig, tag, tag_key_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    w.id,
    w.keyId,
    w.kind,
    w.credentialId,
    w.label,
    w.wrapped,
    at,
    by,
    f.factorKey,
    f.signingKey,
    f.admission.by,
    f.admission.signature,
    f.admission.selfSignature,
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

/**
 * B7: addWrap once sessions are required: a wrap of the active key, with its
 * factor key, signing key, a tag under that key, and its admission by the
 * factor whose proof the call spent and by itself, both verified (M25).
 */
export async function addKeyedWrap(store: MailboxStore, ctx: CallContext, access: Access, wrap: WrapInput, fields: Record<string, unknown> | null): Promise<null> {
  const factor = access.factor!;
  const f = await factorFields(fields, "wrap");
  if (f.admission.by !== factor.id) throw new InvalidRequest("a factor is admitted by the factor whose proof the call spends");
  if (!(await factorAdmissionVerifies(store, admitted(wrap, f), f.admission, factor))) throw new InvalidRequest(DOES_NOT_VERIFY);
  store.transaction(() => {
    const key = activeKeyOf(store);
    if (wrap.keyId !== key.keyId) throw new InvalidRequest("a wrap must name the mailbox's key");
    if (f.tagKeyId !== key.keyId) throw new InvalidRequest("a tag must be made under the active key");
    if (wrapRow(store.sql, wrap.id) !== null || rows(store.sql, "SELECT 1 FROM removed_factors WHERE id = ?", wrap.id).length > 0) throw new InvalidRequest("that wrap id exists");
    stillKeyed(store, factor);
    insertKeyedWrap(store, wrap, f, store.now().toISOString(), ctx.actor.accountId);
    store.audit(ctx.actor.accountId, "wrap-added", { wrap: wrap.id, kind: wrap.kind });
  });
  return null;
}

/**
 * B7, M24: removeWrap once sessions are required: the factor's wrap and seals
 * go, and its record moves to removed_factors (its keys and admission stay,
 * so the signatures it made keep verifying; Mail never accepts its proof
 * again: a proof needs a factor in key_wraps). Never the last recovery
 * factor that reaches the active key (M5′).
 */
export function removeKeyedWrap(store: MailboxStore, ctx: CallContext, wrapId: string): null {
  store.transaction(() => {
    const wrap = wrapRow(store.sql, wrapId);
    if (wrap === null) throw new NotFound();
    const key = activeKeyOf(store);
    if (wrap.kind === "recovery" && !recoveryReaches(store.sql, key.keyId, wrapId)) {
      throw new InvalidRequest("the last recovery factor that reaches the active key cannot be removed");
    }
    const at = store.now().toISOString();
    if (wrap.factor_key !== null && wrap.signing_key !== null && wrap.admission_by !== null && wrap.admission_sig !== null && wrap.admission_self_sig !== null) {
      store.sql.exec(
        `INSERT INTO removed_factors (id, kind, credential_id, label, factor_key, signing_key, admission_by, admission_sig, admission_self_sig, created_at, created_by, removed_at, removed_by)
         SELECT id, kind, credential_id, label, factor_key, signing_key, admission_by, admission_sig, admission_self_sig, created_at, created_by, ?, ? FROM key_wraps WHERE id = ?`,
        at,
        ctx.actor.accountId,
        wrapId,
      );
    }
    store.sql.exec("DELETE FROM key_seals WHERE to_kind = 'factor' AND to_id = ?", wrapId);
    store.sql.exec("DELETE FROM key_wraps WHERE id = ?", wrapId);
    store.audit(ctx.actor.accountId, "wrap-removed", { wrap: wrapId, kind: wrap.kind });
  });
  return null;
}

// ---- enrolment with factor keys (B5, F12) ------------------------------------------------

/**
 * B5: when every wrap carries a factor key, a signing key, an admission and a
 * tag (made under the new key), the mailbox starts with sessions required;
 * mixing is refused. A wrap's `tagKeyId` may be left out at enrolment: it can
 * only be the new key. The admissions follow A11's cycle (each factor by the
 * next in id order, and by itself), every one verified (M25).
 */
export async function enrolmentFactors(wraps: WrapInput[], fields: (Record<string, unknown> | null)[], keyId: string, store: MailboxStore): Promise<FactorFields[] | null> {
  const carrying = fields.filter((f) => f !== null).length;
  if (carrying === 0) return null;
  if (carrying !== fields.length) throw new InvalidRequest("either every wrap carries a factor key or none does");
  const factors: FactorFields[] = [];
  for (const [i, f] of fields.entries()) {
    const factor = await factorFields(f, `wrap ${i + 1}`, keyId);
    if (factor.tagKeyId !== keyId) throw new InvalidRequest("a tag must be made under the new key");
    factors.push(factor);
  }
  const cycle = wraps.map((w, i) => ({ factor: admitted(w, factors[i]!), admission: factors[i]!.admission }));
  if (!(await bootstrapCycleVerifies(store, cycle))) throw new InvalidRequest(`${DOES_NOT_VERIFY}: the factors admit each other in id order, each by the next`);
  return factors;
}

/** B5: the enrolling browser's device, `{ device: DeviceInput, seal }`, tagged under the new key, admitted by one of the enrolling factors (M25). */
export async function enrolmentDevice(
  value: unknown,
  keyId: string,
  wraps: WrapInput[],
  factors: FactorFields[] | null,
  store: MailboxStore,
): Promise<{ device: DeviceInput; seal: string | null }> {
  const r = v.object(value, "enrolling device", ["device", "seal"]);
  const device = await parseDeviceInput(r.device);
  const seal = deviceSeal(device.unlockKey, r.seal);
  if (device.tagKeyId !== keyId) throw new InvalidRequest("a tag must be made under the new key");
  if (factors === null) throw new InvalidRequest("a device needs factor keys");
  const at = wraps.findIndex((w) => w.id === device.admission.by);
  if (at < 0) throw new InvalidRequest("the enrolling device is admitted by one of the enrolling factors");
  if (!(await deviceStatementsVerify(store, device, { id: wraps[at]!.id, signingKey: factors[at]!.signingKey }))) throw new InvalidRequest(DOES_NOT_VERIFY);
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
    store.audit(ctx.actor.accountId, "device-registered", { device: device.device.id, label: device.device.label, unlockKey: device.device.unlockKey !== null, factor: device.device.admission.by });
  }
}

// ---- removeDevices and the rotation (B7, F6, F14, M18′, M19, M23) ------------------------------------------

/** A seal's or a tag's recipient in a rotation (B7). */
type Recipient = { kind: "device" | "factor"; id: string };

function recipient(value: unknown, what: string): Recipient {
  const to = v.object(value, what, ["kind", "id"]);
  const kind = v.oneOf(to.kind, `${what} kind`, ["device", "factor"] as const);
  return { kind, id: v.id(to.id, `${what} id`, kind === "device" ? "dev" : "wrp") };
}

/** The new key sealed to one remaining recipient: 142 bytes to a device (P-256), 109 to a factor (X25519). */
function rotationSeal(value: unknown, what: string): { to: Recipient; sealed: string } {
  const s = v.object(value, what, ["to", "sealed"]);
  const to = recipient(s.to, `${what} recipient`);
  return { to, sealed: v.base64url(s.sealed, what, { bytes: to.kind === "device" ? DEVICE_SEAL_BYTES : FACTOR_SEAL_BYTES }) };
}

function rotationTag(value: unknown, what: string): { to: Recipient; tag: string } {
  const t = v.object(value, what, ["to", "tag"]);
  return { to: recipient(t.to, `${what} recipient`), tag: tag(t.tag, what) };
}

/** B7's exact coverage: every expected recipient once, and nothing else. */
function namesExactly(named: Recipient[], expected: Recipient[], what: string): void {
  const names = named.map((r) => `${r.kind}:${r.id}`);
  const unique = new Set(names);
  if (unique.size !== names.length) throw new InvalidRequest(`${what} name a recipient twice`);
  if (unique.size !== expected.length || expected.some((r) => !unique.has(`${r.kind}:${r.id}`))) {
    throw new InvalidRequest(`${what} must name exactly the remaining recipients`);
  }
}

/** 0 to 20 distinct device ids (B7, B7a). */
function deviceIdList(value: unknown, what: string, min: number): string[] {
  const ids = v.array(value, what, DEVICES_PER_MAILBOX).map((id, i) => v.id(id, `${what} ${i + 1}`, "dev"));
  if (ids.length < min) throw new InvalidRequest(`${what} names at least ${min}`);
  if (new Set(ids).size !== ids.length) throw new InvalidRequest(`${what} names a device twice`);
  return ids;
}

/**
 * B7, F6, F14, M18′ and M23: the named devices (0 to 20; none only while a
 * rotation is due), their seals and their sessions are deleted; the new key
 * becomes active and the old one is retired with its successor seal and the
 * transition, which the factor whose proof the call spent signed (verified
 * first, M25); every seal of the old key is deleted (M19) and the new seals
 * and tags are stored; every other session ends, because each was opened
 * with a proof of the old key; no rotation is due any more. Every check runs
 * before the first write, and all of it is one transaction: a check that
 * fails answers InvalidRequest and changes nothing. A removed device is never
 * sent the new key: no seal may name it.
 */
export async function removeDevices(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): Promise<{ keyId: string }> {
  if (access.sessions === "optional") throw new InvalidRequest(UPGRADE_FIRST);
  const caller = access.session!;
  const factor = access.factor!;
  const r = v.object(request, "device removal", ["deviceIds", "rotation"]);
  const deviceIds = deviceIdList(r.deviceIds, "deviceIds", 0);
  const rot = v.object(r.rotation, "rotation", ["from", "publicKey", "successorSeal", "transition", "seals", "tags"]);
  const from = keyIdOf(rot.from, "rotation from");
  const publicKey = await x25519Key(rot.publicKey, "the new public key");
  const newKeyId = await store.keyIdOf(publicKey);
  const successorSeal = v.base64url(rot.successorSeal, "successor seal", { bytes: FACTOR_SEAL_BYTES });
  const t = v.object(rot.transition, "transition", ["signedBy", "signature"]);
  const transition = { signedBy: v.id(t.signedBy, "transition signer", "wrp"), signature: signature(t.signature, "transition signature") };
  const seals = v.array(rot.seals, "seals", DEVICES_PER_MAILBOX + 100).map((x, i) => rotationSeal(x, `seal ${i + 1}`));
  const tags = v.array(rot.tags, "tags", DEVICES_PER_MAILBOX + 100).map((x, i) => rotationTag(x, `tag ${i + 1}`));
  // M23, M25: the transition is signed by the factor whose proof this call spent, and by no other.
  if (transition.signedBy !== factor.id) throw new InvalidRequest("the transition is signed by the factor whose proof the call spends");
  const signed = await store.proofs.verifyStatement(
    factor.signingKey,
    { kind: "transition", mailboxId: store.mailboxId, fromKeyId: from, toKeyId: newKeyId, toPublicKey: publicKey, signerId: factor.id },
    transition.signature,
  );
  if (!signed) throw new InvalidRequest(DOES_NOT_VERIFY);

  return store.transaction(() => {
    // 1. The devices exist (none only while a rotation is due), `from` is the active key, the new key is new to the mailbox.
    const named = deviceIds.map((id) => deviceRow(store.sql, id) ?? invalid("no such device"));
    const due = rotationDue(store.sql);
    if (named.length === 0 && due === null) throw new InvalidRequest("removeDevices names no device only to finish a rotation that is due");
    const key = activeKeyOf(store);
    if (from !== key.keyId) throw new InvalidRequest("the rotation is from a key that is not active");
    if (rows(store.sql, "SELECT 1 FROM keys WHERE key_id = ?", newKeyId).length > 0) throw new InvalidRequest("the new key is not new to the mailbox");
    stillKeyed(store, factor);

    // 2, 3. Seals name exactly every other device with an unlock key and every keyed factor; tags every other device and keyed factor.
    const removing = new Set(deviceIds);
    const others = rows<{ id: string; unlocked: number }>(store.sql, "SELECT id, unlock_key IS NOT NULL AS unlocked FROM devices").filter((d) => !removing.has(d.id));
    const factors = rows<{ id: string; kind: string }>(store.sql, "SELECT id, kind FROM key_wraps WHERE factor_key IS NOT NULL");
    const keyedFactors = factors.map((f): Recipient => ({ kind: "factor", id: f.id }));
    namesExactly(
      seals.map((s) => s.to),
      [...others.filter((d) => d.unlocked === 1).map((d): Recipient => ({ kind: "device", id: d.id })), ...keyedFactors],
      "the seals",
    );
    namesExactly(tags.map((x) => x.to), [...others.map((d): Recipient => ({ kind: "device", id: d.id })), ...keyedFactors], "the tags");

    // 4. M5′: the new key reaches a recovery factor.
    if (!factors.some((f) => f.kind === "recovery")) throw new InvalidRequest("the new key must reach a recovery factor (M5′)");

    // 5. Every write.
    const at = store.now().toISOString();
    const by = ctx.actor.accountId;
    const ended: Record<string, number> = {};
    for (const d of named) {
      ended[d.id] = rows<{ n: number }>(store.sql, "SELECT COUNT(*) AS n FROM mail_sessions WHERE device_id = ?", d.id)[0]!.n;
      store.sql.exec("DELETE FROM mail_sessions WHERE device_id = ?", d.id);
      store.sql.exec("DELETE FROM devices WHERE id = ?", d.id);
    }
    store.sql.exec("DELETE FROM key_seals WHERE key_id = ?", key.keyId);
    store.sql.exec("INSERT INTO keys (key_id, public_key, created_at, created_by) VALUES (?, ?, ?, ?)", newKeyId, publicKey, at, by);
    store.sql.exec(
      "UPDATE keys SET retired_at = ?, successor_key_id = ?, successor_seal = ?, successor_signed_by = ?, successor_sig = ? WHERE key_id = ?",
      at,
      newKeyId,
      successorSeal,
      transition.signedBy,
      transition.signature,
      key.keyId,
    );
    for (const s of seals) insertSeal(store, newKeyId, s.to.kind, s.to.id, s.sealed, at, by);
    for (const x of tags) {
      if (x.to.kind === "device") store.sql.exec("UPDATE devices SET tag = ?, tag_key_id = ? WHERE id = ?", x.tag, newKeyId, x.to.id);
      else store.sql.exec("UPDATE key_wraps SET tag = ?, tag_key_id = ? WHERE id = ?", x.tag, newKeyId, x.to.id);
    }
    // Every other session ends; the caller's stays, unless it was a removed device's (deleted above).
    const othersEnded = rows<{ n: number }>(store.sql, "SELECT COUNT(*) AS n FROM mail_sessions WHERE token_hash != ?", caller.hash)[0]!.n;
    store.sql.exec("DELETE FROM mail_sessions WHERE token_hash != ?", caller.hash);
    // A session or key challenge sealed to the old key proves nothing from now on (openSession and upgrade refuse it too).
    store.sql.exec("DELETE FROM challenges WHERE purpose IN ('session', 'key') AND target_id = ?", key.keyId);
    // M23: the rotation that was due is done.
    store.sql.exec("DELETE FROM rotation_due");
    for (const d of named) store.audit(by, "device-removed", { device: d.id, label: d.label, sessions: ended[d.id]! });
    store.audit(by, "key-rotated", { from: key.keyId, to: newKeyId, seals: seals.length, sessions: othersEnded, factor: factor.id, due: due !== null });
    return { keyId: newKeyId };
  });
}

function invalid(problem: string): never {
  throw new InvalidRequest(problem);
}

// ---- revokeDevices: an email code revokes, and nothing else (B7a, M22) --------------------------

/**
 * B7a, M22, D35: the devices, their seals and their sessions go, and a
 * rotation is due; no key, seal, tag or factor is written. Confirmed by the
 * dashboard's attestation of an email code in the capability (`ctx.confirmation`,
 * which MailService hands to this method only), checked by every rule of
 * action-descriptor-v1's attestation table.
 *
 * Take first: the email challenge the attestation names (by its descriptor's
 * digest, of this account, live and unspent) is marked used by one
 * statement before any rule is compared, so the first call that presents an
 * attestation spends it, whatever that call's outcome, and a second call with
 * the same attestation is ProofRejected. The rest is synchronous: the
 * revocation is written in the same step, in one transaction.
 */
export function revokeDevices(store: MailboxStore, ctx: CallContext, access: Access, request: unknown): { revoked: string[] } {
  if (access.sessions === "optional") throw new InvalidRequest(UPGRADE_FIRST);
  const attestation = ctx.confirmation;
  if (attestation === undefined) throw new ProofRejected();
  const now = store.now();
  const at = now.toISOString();
  const c = rows<ChallengeRow>(
    store.sql,
    "UPDATE challenges SET used_at = ? WHERE action_digest = ? AND account_id = ? AND purpose = 'email' AND used_at IS NULL AND expires_at > ? RETURNING *",
    at,
    attestation.actionDigest,
    ctx.actor.accountId,
    at,
  )[0];
  if (c === undefined) {
    const spent = rows<ChallengeRow>(store.sql, "SELECT * FROM challenges WHERE action_digest = ? AND account_id = ? AND purpose = 'email'", attestation.actionDigest, ctx.actor.accountId)[0];
    // No email challenge of this account has that digest: nothing is spent and nothing written (anyone could repeat it).
    if (spent === undefined) throw new ProofRejected();
    refuseSpent(store, ctx, spent, spent.used_at !== null ? "used" : "expired", now);
  }
  const described = c.descriptor === null ? null : revokeTargets(c.descriptor);
  if (described === null) rejectProof(store, ctx, c, "action");
  const problem = attestationProblem(attestation, {
    sub: ctx.actor.accountId,
    nowSeconds: Math.floor(now.getTime() / 1000),
    issuedAt: described.issuedAt,
    descriptorKind: described.kind,
  });
  if (problem !== null) rejectProof(store, ctx, c, problem);
  const r = v.object(request, "revocation", ["deviceIds"]);
  const deviceIds = deviceIdList(r.deviceIds, "deviceIds", 1);
  const sorted = [...deviceIds].sort();
  if (JSON.stringify(sorted) !== JSON.stringify(described.deviceIds)) rejectProof(store, ctx, c, "devices");

  return store.transaction(() => {
    const named = sorted.map((id) => deviceRow(store.sql, id) ?? invalid("no such device"));
    const by = ctx.actor.accountId;
    const ended: Record<string, number> = {};
    for (const d of named) {
      ended[d.id] = rows<{ n: number }>(store.sql, "SELECT COUNT(*) AS n FROM mail_sessions WHERE device_id = ?", d.id)[0]!.n;
      store.sql.exec("DELETE FROM mail_sessions WHERE device_id = ?", d.id);
      store.sql.exec("DELETE FROM key_seals WHERE to_kind = 'device' AND to_id = ?", d.id);
      store.sql.exec("DELETE FROM devices WHERE id = ?", d.id);
    }
    const before = rotationDue(store.sql);
    const devices = [...(before?.devices ?? []), ...sorted.filter((id) => !(before?.devices ?? []).includes(id))];
    const since = before?.since ?? at;
    store.sql.exec(
      "INSERT INTO rotation_due (one, since, by_account, devices) VALUES (1, ?, ?, ?) ON CONFLICT (one) DO UPDATE SET by_account = excluded.by_account, devices = excluded.devices",
      since,
      by,
      JSON.stringify(devices),
    );
    for (const d of named) store.audit(by, "device-revoked", { device: d.id, label: d.label, sessions: ended[d.id]!, method: attestation.method, codeId: attestation.codeId });
    store.audit(by, "rotation-due", { devices: devices.join(","), since });
    return { revoked: sorted };
  });
}
