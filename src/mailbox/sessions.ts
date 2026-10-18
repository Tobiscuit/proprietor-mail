import { DeviceRevoked, InvalidRequest, MailboxNotActive, NotFound, ProofRejected, RateLimited, SessionRequired } from "../errors";
import { type DeviceRow, deviceRow, type SessionsMode, sessionsMode, wrapRow } from "./keyring";
import { type MailboxStore, rows } from "./store";
import type { CallAuth, CallContext, ChallengeView, SessionView } from "./types";
import * as v from "./validate";

/**
 * Mail sessions, challenges and proofs (contracts/device-v1.md B1-B3, B6;
 * domain-model M13-M17). Mail learns from a challenge's answer that the
 * caller holds the mailbox key now (a key proof) or just used a factor (a
 * factor proof), and from a signature that the call comes from a kept device.
 * It stores the SHA-256 of every answer and token, so nothing at rest opens
 * a session (M1). A challenge's nonce is stored as it is: it is not a
 * secret (Mail sends it with the challenge, for the device to sign).
 */

/**
 * What a MailService method needs (B3):
 * - "bootstrap": nothing; it shows the mailbox before an unlock, or opens a session;
 * - "session": a live session of the calling account once sessions are
 *   required (while optional, none is asked, but one that is sent must be live);
 * - "factor": that, and a fresh factor proof, spent by the call, once required;
 * - "device-session": a live session of a kept device, always.
 */
export type Need = "bootstrap" | "session" | "device-session" | "factor";

/**
 * Every MailService method and what it needs: the one table, enforced in one
 * place (`checkAccess`, through `Mailbox.enter`). A MailService method that is
 * missing from it fails the fitness test (test/device-sessions.test.ts).
 */
export const SESSION_NEEDS = {
  mailboxes: "bootstrap",
  mailbox: "bootstrap",
  unread: "bootstrap",
  enroll: "bootstrap",
  challenge: "bootstrap",
  openSession: "bootstrap",
  upgrade: "session",
  list: "session",
  body: "session",
  update: "session",
  purge: "session",
  drafts: "session",
  saveDraft: "session",
  deleteDraft: "session",
  send: "session",
  setPolicy: "session",
  audit: "session",
  addWrap: "factor",
  removeWrap: "factor",
  registerDevice: "factor",
  updateDevice: "device-session",
  removeDevice: "factor",
  setFactorKey: "factor",
} as const satisfies Record<string, Need>;

export type MailServiceMethod = keyof typeof SESSION_NEEDS;

/** B6: a challenge lives 2 minutes, at most 20 are live per mailbox, a session lives 60 minutes. */
export const CHALLENGE_LIFETIME_MS = 2 * 60 * 1000;
export const LIVE_CHALLENGES = 20;
export const SESSION_LIFETIME_MS = 60 * 60 * 1000;

/** A session as sent: 32 random bytes, base64url without padding (A8). */
const SESSION_SHAPE = /^[A-Za-z0-9_-]{43}$/;

export const NO_AUTH: CallAuth = Object.freeze({ session: null, factorProof: null });

/**
 * B1's `auth`, in shape only: MailService calls this on the method's last
 * argument (for `send`, on `{ session: request.session }`). What the token and
 * the proof are worth, the Mailbox decides (`checkAccess`).
 */
export function parseAuth(value: unknown): CallAuth {
  if (value === undefined || value === null) return NO_AUTH;
  const a = v.object(value, "auth", ["session", "factorProof"]);
  let session: string | null = null;
  if (a.session !== undefined && a.session !== null) {
    if (typeof a.session !== "string") throw new InvalidRequest("auth session must be a string");
    session = a.session;
  }
  let factorProof: CallAuth["factorProof"] = null;
  if (a.factorProof !== undefined && a.factorProof !== null) {
    const p = v.object(a.factorProof, "factor proof", ["challengeId", "answer"]);
    if (typeof p.challengeId !== "string" || typeof p.answer !== "string") throw new InvalidRequest("a factor proof names a challenge and its answer");
    factorProof = { challengeId: p.challengeId, answer: p.answer };
  }
  return { session, factorProof };
}

/** What a call may do, once `checkAccess` let it in. */
export interface Access {
  sessions: SessionsMode;
  /** The live session the call carried; null only where none is needed (bootstrap, or while sessions are optional). */
  session: { hash: string; accountId: string; deviceId: string | null } | null;
  /** The factor whose proof the call carried and spent; null when it needed none. */
  factor: { id: string; kind: "passkey-prf" | "recovery" } | null;
}

interface ChallengeRow {
  id: string;
  purpose: "session" | "factor";
  target_id: string;
  answer_hash: string;
  nonce: string;
  account_id: string;
  created_at: string;
  expires_at: string;
  used_at: string | null;
}

interface SessionRow {
  token_hash: string;
  account_id: string;
  device_id: string | null;
  created_at: string;
  expires_at: string;
}

/**
 * The session and factor checks every MailService method gets (B2, B3; M14,
 * M17), after its identity and role. Every hash is computed first; from then
 * on nothing awaits, so the session is read and the factor proof spent
 * against one state, with no other call in between.
 */
export async function checkAccess(store: MailboxStore, ctx: CallContext, method: MailServiceMethod): Promise<Access> {
  const need = SESSION_NEEDS[method] as Need;
  const mode = sessionsMode(store.sql);
  if (need === "bootstrap") return { sessions: mode, session: null, factor: null };
  const auth = ctx.auth ?? NO_AUTH;
  if (need !== "factor" && auth.factorProof !== null) throw new InvalidRequest("this call takes no factor proof");
  const sessionHash = auth.session !== null && SESSION_SHAPE.test(auth.session) ? await sha256(v.decodeBase64url(auth.session)) : null;
  const proof = need === "factor" && auth.factorProof !== null ? await preparedProof(auth.factorProof) : null;

  const now = store.now();
  let session: Access["session"] = null;
  if (auth.session === null) {
    if (mode === "required" || need === "device-session") throw new SessionRequired();
  } else {
    // A token that is sent is checked, even while sessions are optional: it is never silently ignored (B2).
    session = liveSession(store, ctx, sessionHash, now);
    if (need === "device-session" && session.deviceId === null) throw new SessionRequired();
  }
  let factor: Access["factor"] = null;
  if (need === "factor") {
    if (proof !== null) factor = spendFactorProof(store, ctx, proof, now);
    else if (mode === "required") throw new ProofRejected();
  }
  return { sessions: mode, session, factor };
}

function liveSession(store: MailboxStore, ctx: CallContext, sessionHash: string | null, now: Date): NonNullable<Access["session"]> {
  const row = sessionHash === null ? undefined : rows<SessionRow>(store.sql, "SELECT * FROM mail_sessions WHERE token_hash = ?", sessionHash)[0];
  if (row === undefined || row.expires_at <= now.toISOString() || row.account_id !== ctx.actor.accountId) throw new SessionRequired();
  if (row.device_id !== null && deviceRow(store.sql, row.device_id) === null) {
    // B2: a session tied to a device that no longer exists is deleted. A plain write, outside any transaction: the refusal does not undo it.
    store.sql.exec("DELETE FROM mail_sessions WHERE token_hash = ?", row.token_hash);
    throw new DeviceRevoked();
  }
  return { hash: row.token_hash, accountId: row.account_id, deviceId: row.device_id };
}

interface PreparedProof {
  challengeId: string;
  answerHash: string;
}

async function preparedProof(proof: { challengeId: string; answer: string }): Promise<PreparedProof> {
  const challengeId = v.id(proof.challengeId, "factor proof challenge", "chl");
  const answer = v.decodeBase64url(v.base64url(proof.answer, "factor proof answer", { bytes: 32 }));
  return { challengeId, answerHash: await sha256(answer) };
}

/** M17: a live factor challenge of this account, answered, for a factor that has a factor key; spent here, whatever the call then does. */
function spendFactorProof(store: MailboxStore, ctx: CallContext, proof: PreparedProof, now: Date): NonNullable<Access["factor"]> {
  const c = takeChallenge(store, ctx, proof.challengeId, now);
  if (c.purpose !== "factor") rejectProof(store, ctx, c, "purpose");
  if (!sameHash(proof.answerHash, c.answer_hash)) rejectProof(store, ctx, c, "answer");
  const factor = wrapRow(store.sql, c.target_id);
  if (factor === null || factor.factor_key === null) rejectProof(store, ctx, c, "factor");
  return { id: factor.id, kind: factor.kind };
}

/**
 * A challenge presented by this account, live, and consumed now (M16): before
 * its answer is looked at, so a wrong answer spends it too. Another account's
 * challenge is refused and left alone: it is not this account's to spend.
 */
function takeChallenge(store: MailboxStore, ctx: CallContext, id: string, now: Date): ChallengeRow {
  const c = rows<ChallengeRow>(store.sql, "SELECT * FROM challenges WHERE id = ?", id)[0];
  if (c === undefined) rejectProof(store, ctx, { id, purpose: null }, "unknown");
  if (c.account_id !== ctx.actor.accountId) rejectProof(store, ctx, c, "account");
  if (c.used_at !== null) rejectProof(store, ctx, c, "used");
  if (c.expires_at <= now.toISOString()) rejectProof(store, ctx, c, "expired");
  // A plain write, outside any transaction, so the refusals that may follow cannot roll it back.
  store.sql.exec("UPDATE challenges SET used_at = ? WHERE id = ?", now.toISOString(), id);
  return c;
}

/** B6: ProofRejected, audited as proof-rejected with the reason (the caller is told none). */
function rejectProof(store: MailboxStore, ctx: CallContext, c: { id: string; purpose: string | null }, reason: string): never {
  store.audit(ctx.actor.accountId, "proof-rejected", { challenge: c.id, purpose: c.purpose, reason });
  throw new ProofRejected();
}

// ---- challenge() and openSession() --------------------------------------------------------

/** B6: a challenge sealed to the active key ("session") or to a factor's key ("factor"). */
export async function issueChallenge(store: MailboxStore, ctx: CallContext, request: unknown): Promise<ChallengeView> {
  const r = v.object(request, "challenge request", ["purpose", "factorId"]);
  const purpose = v.oneOf(r.purpose, "purpose", ["session", "factor"] as const);
  let target: { keyId: string | null; factorId: string | null; targetId: string; publicKey: Uint8Array };
  if (purpose === "session") {
    if (r.factorId !== undefined) throw new InvalidRequest("a session challenge names no factor");
    const key = store.activeKey();
    if (key === null) throw new MailboxNotActive();
    target = { keyId: key.keyId, factorId: null, targetId: key.keyId, publicKey: key.publicKey };
  } else {
    const factorId = v.id(r.factorId, "factor id", "wrp");
    const factor = wrapRow(store.sql, factorId);
    if (factor === null || factor.factor_key === null) throw new NotFound();
    target = { keyId: null, factorId, targetId: factorId, publicKey: new Uint8Array(factor.factor_key) };
  }
  const now = store.now();
  ensureRoomForChallenge(store, now);

  const id = store.newChallengeId();
  const { sealed, answer } = await store.proofs.sealChallenge(
    { publicKey: target.publicKey },
    { mailboxId: store.mailboxId, challengeId: id, purpose, targetId: target.targetId },
  );
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const answerHash = await sha256(answer);
  answer.fill(0);

  // Other challenges may have been made during those awaits: the limit is checked again, then the row written.
  ensureRoomForChallenge(store, now);
  const expiresAt = new Date(now.getTime() + CHALLENGE_LIFETIME_MS).toISOString();
  store.sql.exec(
    "INSERT INTO challenges (id, purpose, target_id, answer_hash, nonce, account_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    id,
    purpose,
    target.targetId,
    answerHash,
    v.encodeBase64url(nonce),
    ctx.actor.accountId,
    now.toISOString(),
    expiresAt,
  );
  return { id, purpose, keyId: target.keyId, factorId: target.factorId, nonce: v.encodeBase64url(nonce), sealed, expiresAt };
}

function ensureRoomForChallenge(store: MailboxStore, now: Date): void {
  const live = rows<{ expires_at: string }>(
    store.sql,
    "SELECT expires_at FROM challenges WHERE used_at IS NULL AND expires_at > ? ORDER BY expires_at ASC",
    now.toISOString(),
  );
  if (live.length >= LIVE_CHALLENGES) {
    const wait = Date.parse(live[0]!.expires_at) - now.getTime();
    throw new RateLimited(Math.max(1, Math.ceil(wait / 1000)), "too many challenges are open; try again shortly");
  }
}

/**
 * B6, M15: a session from a key proof, and for a kept device its signature
 * (A7). The challenge is spent whether or not the answer is right. A session
 * lives 60 minutes, records its device, and is stored as SHA-256(token).
 */
export async function openMailSession(store: MailboxStore, ctx: CallContext, request: unknown): Promise<SessionView> {
  const r = v.object(request, "session request", ["challengeId", "answer", "device"]);
  const challengeId = v.id(r.challengeId, "challenge id", "chl");
  const answer = v.decodeBase64url(v.base64url(r.answer, "answer", { bytes: 32 }));
  const device = v.optional(r.device, (d) => {
    const x = v.object(d, "device proof", ["id", "signature"]);
    return { id: v.id(x.id, "device id", "dev"), signature: v.decodeBase64url(v.base64url(x.signature, "device signature", { bytes: 64 })) };
  });
  // Every hash first, as in checkAccess; the session is drawn now and kept only as its hash.
  const answerHash = await sha256(answer);
  const sessionBytes = crypto.getRandomValues(new Uint8Array(32));
  const sessionHash = await sha256(sessionBytes);
  const now = store.now();

  const c = takeChallenge(store, ctx, challengeId, now);
  if (c.purpose !== "session") rejectProof(store, ctx, c, "purpose");
  if (!sameHash(answerHash, c.answer_hash)) rejectProof(store, ctx, c, "answer");
  // A proof of a key that is no longer active proves nothing now: the rotation ended every session opened with it.
  if (store.activeKey()?.keyId !== c.target_id) rejectProof(store, ctx, c, "key");
  let signer: DeviceRow | null = null;
  if (device !== undefined) {
    // M21: a device works only for the account that kept it; for anyone else it is not in the mailbox (G42).
    signer = deviceRow(store.sql, device.id);
    if (signer === null || signer.account_id !== ctx.actor.accountId) throw new DeviceRevoked();
    const nonce = v.decodeBase64url(c.nonce);
    const signed = await store.proofs.verifyDeviceProof(
      new Uint8Array(signer.signing_key),
      { mailboxId: store.mailboxId, deviceId: signer.id, challengeId, nonce },
      device.signature,
    );
    if (!signed) rejectProof(store, ctx, c, "signature");
    // Checked again after that await: the device may have been removed, and the key rotated, meanwhile.
    if (deviceRow(store.sql, signer.id) === null) throw new DeviceRevoked();
    if (store.activeKey()?.keyId !== c.target_id) rejectProof(store, ctx, c, "key");
  }
  const expiresAt = new Date(now.getTime() + SESSION_LIFETIME_MS).toISOString();
  const deviceId = signer?.id ?? null;
  store.transaction(() => {
    store.sql.exec(
      "INSERT INTO mail_sessions (token_hash, account_id, device_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
      sessionHash,
      ctx.actor.accountId,
      deviceId,
      now.toISOString(),
      expiresAt,
    );
    if (deviceId !== null) store.sql.exec("UPDATE devices SET last_seen_at = ? WHERE id = ?", now.toISOString(), deviceId);
  });
  return { session: v.encodeBase64url(sessionBytes), expiresAt, device: deviceId };
}

/**
 * B9: the daily housekeeping deletes challenges and sessions that have
 * expired (a challenge is live while now < expiresAt; so is a session).
 */
export function deleteExpired(sql: SqlStorage, now: Date): { challenges: number; sessions: number } {
  const at = now.toISOString();
  return {
    challenges: rows(sql, "DELETE FROM challenges WHERE expires_at <= ? RETURNING 1", at).length,
    sessions: rows(sql, "DELETE FROM mail_sessions WHERE expires_at <= ? RETURNING 1", at).length,
  };
}

// ---- bytes ----------------------------------------------------------------------------------------

async function sha256(bytes: Uint8Array): Promise<string> {
  return v.encodeBase64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** Equal-length hashes compared without an early exit. */
function sameHash(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

