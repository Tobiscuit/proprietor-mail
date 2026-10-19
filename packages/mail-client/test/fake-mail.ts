// A Mail Worker for the Node tests: contracts/device-v1.md Part B's key ring, devices, challenges
// and sessions, kept in memory. It is STRICT about shapes, as the real Worker is: a request with an
// unknown or missing field, a wrong base64url length or a malformed id is refused, so every request
// the API builds is checked against Part B here. Its challenge sealer and device-proof verifier are
// written from the contract (A6, A7) for the tests; the Worker's are src/proofs.ts (slice D2).
// Refusals are thrown as FakeMailError with Part B's error names.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { keyIdOf, newId, sealMessage, type MessageHeader } from "@proprietor/mail-crypto";
import type {
  Auth,
  ChallengeRequest,
  ChallengeView,
  DeviceView,
  EnrollRequest,
  KeyView,
  MailboxView,
  MessageItem,
  OpenSessionRequest,
  OpenSessionResult,
  RegisterDeviceRequest,
  RemoveDeviceRequest,
  SealView,
  UpdateDeviceRequest,
  UpgradeRequest,
  WrapInput,
  WrapView,
} from "../src/index";
import { b64url, fromB64url, sampleHeader, sampleRaw, utf8 } from "./support";

export class FakeMailError extends Error {
  constructor(name: string, message = name) {
    super(`${name}: ${message}`);
    this.name = name;
  }
}

const refuse = (name: string, message?: string): never => {
  throw new FakeMailError(name, message);
};
const invalid = (message: string): never => refuse("InvalidRequest", message);

const ID = (prefix: string) => new RegExp(`^${prefix}_[0-9a-hjkmnp-tv-z]{26}$`);
const KEY_ID = /^[0-9a-f]{32}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;

function exactly(value: unknown, what: string, fields: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return invalid(`${what} must be an object`);
  for (const key of Object.keys(value)) if (!fields.includes(key) && !optional.includes(key)) invalid(`unexpected field ${key} in ${what}`);
  for (const key of fields) if (!(key in value)) invalid(`missing ${key} in ${what}`);
  return value as Record<string, unknown>;
}
function b64(value: unknown, what: string, bytes: number): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value) || value.length % 4 === 1) return invalid(`${what} must be base64url`);
  if (fromB64url(value).length !== bytes || b64url(fromB64url(value)) !== value) invalid(`${what} must be ${bytes} bytes`);
  return value;
}
function id(value: unknown, what: string, prefix: string): string {
  return typeof value === "string" && ID(prefix).test(value) ? value : invalid(`${what} must be a ${prefix}_ id`);
}
function label(value: unknown, what: string, max: number): string {
  return typeof value === "string" && value.length >= 1 && value.length <= max && !CONTROL.test(value) ? value : invalid(`${what} label`);
}
async function sha256(bytes: Uint8Array): Promise<string> {
  return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))));
}

const challengeSuite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

/** A6, written from the contract for the tests. */
async function sealChallenge(publicKey: Uint8Array, aad: string): Promise<{ sealed: string; answer: Uint8Array }> {
  const answer = crypto.getRandomValues(new Uint8Array(32));
  const recipientPublicKey = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), { name: "X25519" }, true, []);
  const { enc, ct } = await challengeSuite.seal({ recipientPublicKey, info: utf8("proprietor-mail/v1/challenge") }, answer, utf8(aad));
  return { sealed: b64url(new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)])), answer };
}

/** A7, written from the contract for the tests. */
async function verifyDeviceProof(signingKey: string, message: string, signature: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", fromB64url(signingKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const sig = fromB64url(signature);
  return sig.length === 64 && crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, utf8(message));
}

interface Challenge {
  purpose: "session" | "factor";
  targetId: string;
  answerHash: string;
  nonce: string;
  accountId: string;
  expiresAt: number;
  used: boolean;
}
interface MailSession {
  accountId: string;
  deviceId: string | null;
  expiresAt: number;
}
type Device = DeviceView & { accountId: string };

export interface FakeMailOptions {
  mailboxId: string;
  accountId?: string;
  now?: () => number;
}

export class FakeMail {
  readonly mailboxId: string;
  accountId: string;
  now: () => number;
  sessionsMode: "optional" | "required" = "optional";
  keys: KeyView[] = [];
  wraps: WrapView[] = [];
  devices: Device[] = [];
  seals: SealView[] = [];
  readonly challenges = new Map<string, Challenge>();
  readonly mailSessions = new Map<string, MailSession>();
  /** Every request the fake accepted, by method, for tests that look at what was sent. */
  readonly accepted: { method: string; request: unknown }[] = [];

  constructor(options: FakeMailOptions) {
    this.mailboxId = options.mailboxId;
    this.accountId = options.accountId ?? "acc_owner";
    this.now = options.now ?? Date.now;
  }

  private at(): string {
    return new Date(this.now()).toISOString();
  }

  get activeKey(): KeyView {
    return this.keys.find((k) => k.retiredAt === null)!;
  }

  /** B4: what mailbox() answers. */
  mailbox(): MailboxView {
    return structuredClone({
      id: this.mailboxId,
      address: "hello@example.com",
      addresses: ["hello@example.com", "team@example.com"],
      status: "active" as const,
      displayName: "Example",
      sessions: this.sessionsMode,
      keys: this.keys,
      wraps: this.wraps,
      devices: this.devices.map(({ accountId: _a, ...d }) => d),
      seals: this.seals,
    });
  }

  /** A view as a Mail Worker without spec 002 answers it (a rollback, spec 002 §8). */
  legacyMailbox(): MailboxView {
    const v = this.mailbox();
    return {
      id: v.id,
      address: v.address,
      addresses: v.addresses,
      status: v.status,
      displayName: v.displayName,
      keys: v.keys.map(({ successor: _s, ...k }) => k),
      wraps: v.wraps.map(({ factorKey: _f, tag: _t, tagKeyId: _k, ...w }) => w),
    };
  }

  // ---- B5 ----

  async enroll(input: EnrollRequest): Promise<{ keyId: string }> {
    const req = exactly(input, "enrolment", ["publicKey", "wraps"], ["device"]);
    const publicKey = b64(req.publicKey, "public key", 32);
    const keyId = await keyIdOf(fromB64url(publicKey));
    if (!Array.isArray(req.wraps) || req.wraps.length === 0) invalid("wraps");
    const wraps = (req.wraps as unknown[]).map((w, i) => this.parseWrap(w, `wrap ${i + 1}`, keyId));
    if (!wraps.some((w) => w.kind === "recovery")) invalid("a recovery wrap is required");
    const keyed = wraps.filter((w) => w.factorKey !== null);
    if (keyed.length !== 0 && keyed.length !== wraps.length) invalid("mixing wraps with and without factor keys");
    this.keys = [{ keyId, publicKey, createdAt: this.at(), createdBy: this.accountId, retiredAt: null, successor: null }];
    this.wraps = wraps.map((w) => ({ ...w, createdAt: this.at(), createdBy: this.accountId }));
    if (keyed.length > 0) {
      for (const w of keyed) if (w.tagKeyId !== keyId) invalid("a tag is made under the new key");
      this.sessionsMode = "required";
    }
    if (req.device !== undefined) {
      if (this.sessionsMode !== "required") invalid("a device needs factor keys");
      this.addDevice(req.device as RegisterDeviceRequest, null);
    }
    this.accepted.push({ method: "enroll", request: input });
    return { keyId };
  }

  private parseWrap(value: unknown, what: string, activeKeyId: string): Omit<WrapView, "createdAt" | "createdBy"> {
    const w = exactly(value, what, ["id", "keyId", "kind", "credentialId", "label", "wrapped"], ["factorKey", "tag", "tagKeyId"]);
    const kind = w.kind === "passkey-prf" || w.kind === "recovery" ? w.kind : invalid(`${what} kind`);
    if (w.keyId !== activeKeyId) invalid(`${what} names another key`);
    const credentialId = kind === "passkey-prf" ? (typeof w.credentialId === "string" && w.credentialId.length > 0 ? w.credentialId : invalid("credential id")) : w.credentialId === null ? null : invalid("credential id");
    const keyed = w.factorKey !== undefined || w.tag !== undefined || w.tagKeyId !== undefined;
    if (keyed && (w.factorKey === undefined || w.tag === undefined || w.tagKeyId === undefined)) invalid(`${what}: factorKey, tag and tagKeyId come together`);
    return {
      id: id(w.id, `${what} id`, "wrp"),
      keyId: activeKeyId,
      kind,
      credentialId,
      label: label(w.label, what, 100),
      wrapped: b64(w.wrapped, `${what} wrapped`, 77),
      factorKey: keyed ? b64(w.factorKey, "factor key", 32) : null,
      tag: keyed ? b64(w.tag, "tag", 32) : null,
      tagKeyId: keyed ? (typeof w.tagKeyId === "string" && KEY_ID.test(w.tagKeyId) ? w.tagKeyId : invalid("tagKeyId")) : null,
    };
  }

  async upgrade(input: UpgradeRequest, auth: Auth = {}): Promise<null> {
    // B5: the upgrade needs a live session even while sessions are optional (it was opened with a key proof).
    if ((await this.checkAuth(auth, { session: true })) === null) refuse("SessionRequired");
    const req = exactly(input, "upgrade", ["factors"]);
    if (this.sessionsMode !== "optional") invalid("already upgraded");
    if (this.wraps.some((w) => w.factorKey !== null)) invalid("a factor already has a key");
    if (!Array.isArray(req.factors) || req.factors.length === 0) invalid("factors");
    const active = this.activeKey.keyId;
    const factors = (req.factors as unknown[]).map((f, i) => {
      const x = exactly(f, `factor ${i + 1}`, ["id", "factorKey", "tag", "tagKeyId"]);
      const wrap = this.wraps.find((w) => w.id === x.id && w.keyId === active) ?? invalid("not a wrap of the active key");
      if (x.tagKeyId !== active) invalid("tagKeyId");
      return { wrap, factorKey: b64(x.factorKey, "factor key", 32), tag: b64(x.tag, "tag", 32) };
    });
    if (new Set(factors.map((f) => f.wrap.id)).size !== factors.length) invalid("a factor is named twice");
    // B5 and M20 as amended on 2026-10-19: the list names every wrap the mailbox has, exactly once.
    if (factors.length !== this.wraps.length) invalid("M20: the upgrade names every wrap of the mailbox");
    for (const f of factors) Object.assign(f.wrap, { factorKey: f.factorKey, tag: f.tag, tagKeyId: active });
    this.sessionsMode = "required";
    this.accepted.push({ method: "upgrade", request: input });
    return null;
  }

  // ---- B6 ----

  async challenge(input: ChallengeRequest): Promise<ChallengeView> {
    const req = exactly(input, "challenge", ["purpose"], ["factorId"]);
    const live = [...this.challenges.values()].filter((c) => !c.used && c.expiresAt > this.now());
    if (live.length >= 20) refuse("RateLimited");
    const challengeId = newId("chl");
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    let target: { publicKey: Uint8Array; targetId: string };
    if (req.purpose === "session") {
      if (req.factorId !== undefined) invalid("a session challenge names no factor");
      target = { publicKey: fromB64url(this.activeKey.publicKey), targetId: this.activeKey.keyId };
    } else if (req.purpose === "factor") {
      const wrap = this.wraps.find((w) => w.id === req.factorId);
      if (wrap === undefined || wrap.factorKey === null) refuse("NotFound");
      target = { publicKey: fromB64url(wrap!.factorKey!), targetId: wrap!.id };
    } else {
      return invalid("purpose");
    }
    const { sealed, answer } = await sealChallenge(target.publicKey, `proprietor-mail/v1/challenge|${this.mailboxId}|${challengeId}|${req.purpose}|${target.targetId}`);
    const expiresAt = this.now() + 120_000;
    this.challenges.set(challengeId, { purpose: req.purpose, targetId: target.targetId, answerHash: await sha256(answer), nonce: b64url(nonce), accountId: this.accountId, expiresAt, used: false });
    return {
      id: challengeId,
      purpose: req.purpose,
      keyId: req.purpose === "session" ? target.targetId : null,
      factorId: req.purpose === "factor" ? target.targetId : null,
      nonce: b64url(nonce),
      sealed,
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  private async consume(challengeId: unknown, answer: unknown, purpose: "session" | "factor"): Promise<Challenge> {
    const c = typeof challengeId === "string" ? this.challenges.get(challengeId) : undefined;
    if (c === undefined || c.used || c.expiresAt <= this.now() || c.purpose !== purpose || c.accountId !== this.accountId) refuse("ProofRejected");
    c!.used = true; // consumed whether or not the answer is right
    if ((await sha256(fromB64url(b64(answer, "answer", 32)))) !== c!.answerHash) refuse("ProofRejected");
    return c!;
  }

  async openSession(input: OpenSessionRequest): Promise<OpenSessionResult> {
    const req = exactly(input, "openSession", ["challengeId", "answer"], ["device"]);
    const challenge = await this.consume(req.challengeId, req.answer, "session");
    let deviceId: string | null = null;
    if (req.device !== undefined) {
      const d = exactly(req.device, "device", ["id", "signature"]);
      const device = this.devices.find((x) => x.id === d.id);
      if (device === undefined || device.accountId !== this.accountId) refuse("DeviceRevoked");
      const message = `proprietor-mail/v1/device-proof|${this.mailboxId}|${device!.id}|${req.challengeId}|${challenge.nonce}`;
      if (!(await verifyDeviceProof(device!.signingKey, message, b64(d.signature, "signature", 64)))) refuse("ProofRejected");
      device!.lastSeenAt = this.at();
      deviceId = device!.id;
    }
    const token = b64url(crypto.getRandomValues(new Uint8Array(32))); // pragma: allowlist secret (field names and public values, not secrets)
    const expiresAt = this.now() + 60 * 60_000;
    this.mailSessions.set(await sha256(fromB64url(token)), { accountId: this.accountId, deviceId, expiresAt });
    this.accepted.push({ method: "openSession", request: input });
    return { session: token, expiresAt: new Date(expiresAt).toISOString(), device: deviceId };
  }

  /** B2: the session (and, for "factor" methods, the factor proof) a call needs. Returns the session's record. */
  private async checkAuth(auth: Auth, needs: { session: boolean; factor?: boolean; device?: boolean }): Promise<MailSession | null> {
    const a = exactly(auth, "auth", [], ["session", "factorProof"]);
    let session: MailSession | null = null;
    if (a.session !== undefined) {
      const hash = await sha256(fromB64url(b64(a.session, "session", 32)));
      const s = this.mailSessions.get(hash);
      if (s === undefined || s.expiresAt <= this.now() || s.accountId !== this.accountId) refuse("SessionRequired");
      if (s!.deviceId !== null && !this.devices.some((d) => d.id === s!.deviceId)) {
        this.mailSessions.delete(hash);
        refuse("DeviceRevoked");
      }
      session = s!;
    } else if (needs.session && this.sessionsMode === "required") {
      refuse("SessionRequired");
    }
    if (needs.factor && this.sessionsMode === "required") {
      const proof = a.factorProof === undefined ? refuse("ProofRejected", "a factor proof is required") : exactly(a.factorProof, "factorProof", ["challengeId", "answer"]);
      const c = await this.consume(proof.challengeId, proof.answer, "factor");
      const factor = this.wraps.find((w) => w.id === c.targetId);
      if (factor === undefined || factor.factorKey === null) refuse("ProofRejected");
    }
    if (needs.device && (session === null || session.deviceId === null)) refuse("SessionRequired", "a device's session");
    return session;
  }

  /** A factor proof, checked and consumed as the "factor" methods check it; answers the factor's id. (A test hook, not Part B.) */
  async checkFactorProof(proof: unknown): Promise<string> {
    const p = exactly(proof, "factorProof", ["challengeId", "answer"]);
    const c = await this.consume(p.challengeId, p.answer, "factor");
    const factor = this.wraps.find((w) => w.id === c.targetId);
    if (factor === undefined || factor.factorKey === null) refuse("ProofRejected");
    return c.targetId;
  }

  // ---- B7 ----

  private addDevice(input: RegisterDeviceRequest, session: MailSession | null): Device {
    const req = exactly(input, "registerDevice", ["device", "seal"]);
    const d = exactly(req.device, "device", ["id", "label", "signingKey", "unlockKey", "tag", "tagKeyId"]);
    const active = this.activeKey.keyId;
    const device: Device = {
      id: id(d.id, "device id", "dev"),
      label: label(d.label, "device", 40),
      signingKey: b64(d.signingKey, "signing key", 65), // pragma: allowlist secret (field names and public values, not secrets)
      unlockKey: d.unlockKey === null ? null : b64(d.unlockKey, "unlock key", 65),
      tag: b64(d.tag, "tag", 32),
      tagKeyId: d.tagKeyId === active ? active : invalid("tagKeyId must be the active key"),
      createdAt: this.at(),
      createdBy: this.accountId,
      lastSeenAt: null,
      accountId: this.accountId,
    };
    if (this.devices.some((x) => x.id === device.id)) invalid("that device id exists");
    if ((req.seal === null) !== (device.unlockKey === null)) invalid("a seal comes exactly with an unlock key");
    if (this.devices.length >= 20) invalid("at most 20 devices");
    this.devices.push(device);
    if (req.seal !== null) this.seals.push({ keyId: active, to: { kind: "device", id: device.id }, sealed: b64(req.seal, "seal", 142) });
    if (session !== null) session.deviceId = device.id; // the caller's session becomes this device's
    return device;
  }

  async registerDevice(input: RegisterDeviceRequest, auth: Auth = {}): Promise<DeviceView> {
    if (this.sessionsMode !== "required") invalid("upgrade first");
    const session = await this.checkAuth(auth, { session: true, factor: true });
    const { accountId: _a, ...view } = this.addDevice(input, session);
    this.accepted.push({ method: "registerDevice", request: input });
    return view;
  }

  async updateDevice(input: UpdateDeviceRequest, auth: Auth = {}): Promise<DeviceView> {
    const session = (await this.checkAuth(auth, { session: true, device: true }))!;
    const req = exactly(input, "updateDevice", ["unlockKey", "tag", "tagKeyId", "seal"]);
    const device = this.devices.find((d) => d.id === session.deviceId)!;
    const active = this.activeKey.keyId;
    const unlockKey = req.unlockKey === null ? null : b64(req.unlockKey, "unlock key", 65);
    if ((req.seal === null) !== (unlockKey === null)) invalid("a seal comes exactly with an unlock key");
    if (req.tagKeyId !== active) invalid("tagKeyId must be the active key");
    const tag = b64(req.tag, "tag", 32);
    const seal = req.seal === null ? null : b64(req.seal, "seal", 142);
    Object.assign(device, { unlockKey, tag, tagKeyId: active });
    this.seals = this.seals.filter((s) => !(s.to.kind === "device" && s.to.id === device.id));
    if (seal !== null) this.seals.push({ keyId: active, to: { kind: "device", id: device.id }, sealed: seal });
    this.accepted.push({ method: "updateDevice", request: input });
    const { accountId: _a, ...view } = device;
    return structuredClone(view);
  }

  async addWrap(input: WrapInput, auth: Auth = {}): Promise<null> {
    await this.checkAuth(auth, { session: true, factor: true });
    const w = this.parseWrap(input, "wrap", this.activeKey.keyId);
    if (this.sessionsMode === "required" && (w.factorKey === null || w.tagKeyId !== this.activeKey.keyId)) invalid("a wrap carries its factor key once sessions are required");
    if (this.sessionsMode === "optional" && w.factorKey !== null) invalid("no factor key before the upgrade");
    if (this.wraps.some((x) => x.id === w.id)) invalid("that wrap id exists");
    this.wraps.push({ ...w, createdAt: this.at(), createdBy: this.accountId });
    this.accepted.push({ method: "addWrap", request: input });
    return null;
  }

  async removeWrap(wrapId: string, auth: Auth = {}): Promise<null> {
    await this.checkAuth(auth, { session: true, factor: true });
    const wrap = this.wraps.find((w) => w.id === wrapId) ?? refuse("NotFound");
    const rest = this.wraps.filter((w) => w.id !== wrapId);
    const active = this.activeKey.keyId;
    const reaches = (w: WrapView) => w.kind === "recovery" && (w.keyId === active || this.seals.some((s) => s.keyId === active && s.to.kind === "factor" && s.to.id === w.id));
    if (reaches(wrap) && !rest.some(reaches)) invalid("M5′: the last recovery factor that reaches the active key stays");
    this.wraps = rest;
    this.seals = this.seals.filter((s) => !(s.to.kind === "factor" && s.to.id === wrapId));
    return null;
  }

  async removeDevice(input: RemoveDeviceRequest, auth: Auth = {}): Promise<{ keyId: string }> {
    if (this.sessionsMode !== "required") invalid("upgrade first");
    const caller = await this.checkAuth(auth, { session: true, factor: true });
    const req = exactly(input, "removeDevice", ["deviceId", "rotation"]);
    const r = exactly(req.rotation, "rotation", ["from", "publicKey", "successorSeal", "seals", "tags"]);
    const device = this.devices.find((d) => d.id === req.deviceId) ?? invalid("no such device");
    const active = this.activeKey;
    if (r.from !== active.keyId) invalid("stale rotation: from is not the active key");
    const publicKey = b64(r.publicKey, "new public key", 32);
    const newKeyId = await keyIdOf(fromB64url(publicKey));
    if (this.keys.some((k) => k.keyId === newKeyId)) invalid("the new key is not new");
    const successorSeal = b64(r.successorSeal, "successor seal", 109);
    const remainingDevices = this.devices.filter((d) => d.id !== device.id);
    const sealTargets = [
      ...remainingDevices.filter((d) => d.unlockKey !== null).map((d) => `device:${d.id}`),
      ...this.wraps.filter((w) => w.factorKey !== null).map((w) => `factor:${w.id}`),
    ].sort();
    const tagTargets = [...remainingDevices.map((d) => `device:${d.id}`), ...this.wraps.filter((w) => w.factorKey !== null).map((w) => `factor:${w.id}`)].sort();
    if (!Array.isArray(r.seals) || !Array.isArray(r.tags)) invalid("seals and tags are lists");
    const seals = (r.seals as unknown[]).map((s, i) => {
      const x = exactly(s, `seal ${i + 1}`, ["to", "sealed"]);
      const to = exactly(x.to, `seal ${i + 1} to`, ["kind", "id"]);
      if (to.kind !== "device" && to.kind !== "factor") invalid("kind");
      return { to: { kind: to.kind as "device" | "factor", id: to.id as string }, sealed: b64(x.sealed, `seal ${i + 1}`, to.kind === "device" ? 142 : 109) };
    });
    const tags = (r.tags as unknown[]).map((t, i) => {
      const x = exactly(t, `tag ${i + 1}`, ["to", "tag"]);
      const to = exactly(x.to, `tag ${i + 1} to`, ["kind", "id"]);
      return { to: { kind: to.kind as "device" | "factor", id: to.id as string }, tag: b64(x.tag, `tag ${i + 1}`, 32) };
    });
    const named = (list: { to: { kind: string; id: string } }[]) => list.map((x) => `${x.to.kind}:${x.to.id}`).sort();
    if (JSON.stringify(named(seals)) !== JSON.stringify(sealTargets)) invalid("the seals must name exactly the remaining recipients");
    if (JSON.stringify(named(tags)) !== JSON.stringify(tagTargets)) invalid("the tags must name exactly the remaining recipients");
    if (!this.wraps.some((w) => w.kind === "recovery" && w.factorKey !== null)) invalid("M5′: a keyed recovery factor must receive the new key");
    // Effect, all at once (M18).
    this.devices = remainingDevices;
    this.seals = seals.map((s) => ({ keyId: newKeyId, to: s.to, sealed: s.sealed }));
    Object.assign(active, { retiredAt: this.at(), successor: { keyId: newKeyId, sealed: successorSeal } });
    this.keys.push({ keyId: newKeyId, publicKey, createdAt: this.at(), createdBy: this.accountId, retiredAt: null, successor: null });
    for (const t of tags) {
      const target = t.to.kind === "device" ? this.devices.find((d) => d.id === t.to.id)! : this.wraps.find((w) => w.id === t.to.id)!;
      Object.assign(target, { tag: t.tag, tagKeyId: newKeyId });
    }
    // Every other session ends, and the removed device's with it (the caller's too, when it removed itself).
    for (const [hash, s] of [...this.mailSessions]) if (s !== caller || s.deviceId === device.id) this.mailSessions.delete(hash);
    this.accepted.push({ method: "removeDevice", request: input });
    return { keyId: newKeyId };
  }

  // ---- Mail arriving ----

  /** A message as the Worker seals it, to the active key. */
  async deliver(header: MessageHeader = sampleHeader, raw: Uint8Array = sampleRaw): Promise<{ item: MessageItem; body: Uint8Array }> {
    const active = this.activeKey;
    const messageId = newId("msg");
    const sealed = await sealMessage({ keyId: active.keyId, publicKey: fromB64url(active.publicKey) }, { mailboxId: this.mailboxId, messageId }, header, raw);
    return {
      item: { id: messageId, folder: "inbox", direction: header.direction, receivedAt: this.at(), size: raw.length, seen: false, flagged: false, keyId: sealed.keyId, keyEnvelope: sealed.keyEnvelope, header: sealed.header },
      body: sealed.body,
    };
  }
}
