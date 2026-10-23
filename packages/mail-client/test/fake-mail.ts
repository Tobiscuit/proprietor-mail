// A Mail Worker for the Node tests: contracts/device-v1.md Part B's key ring, devices, challenges and
// sessions, kept in memory, as round 3 amends them. It is STRICT about shapes, as the real Worker is: a
// request with an unknown or missing field, a wrong base64url length or a malformed id is refused, so
// every request the API builds is checked against Part B here. Round 3: every challenge but a session's
// carries an action descriptor (A10, built with @proprietor/mail-crypto as the Worker builds it), its
// associated data ends with the descriptor's digest (A6), a factor or key proof counts only for the call
// its descriptor names (the request's digest recomputed here), and every signature of A11 is verified
// before anything is stored (M25). Its challenge sealer and device-proof verifier are written from the
// contract (A6, A7) for the tests; the Worker's are src/proofs.ts. Refusals are thrown as FakeMailError
// with Part B's error names.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  actionDescriptorFor,
  actionDigest,
  actionPurpose,
  bootstrapAdmitters,
  buildActionDescriptor,
  keyIdOf,
  newId,
  readActionDescriptor,
  requestDigest,
  sealMessage,
  verifyStatement,
  type ActionInput,
  type MessageHeader,
} from "@proprietor/mail-crypto";
import type {
  Auth,
  ChallengeRequest,
  ChallengeView,
  DeviceView,
  EnrollRequest,
  FactorAdmission,
  KeyView,
  MailboxView,
  MessageItem,
  OpenSessionRequest,
  OpenSessionResult,
  RegisterDeviceRequest,
  RemovedFactorView,
  RemoveDevicesRequest,
  RevokeDevicesRequest,
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
  purpose: "session" | "factor" | "key" | "email";
  targetId: string;
  answerHash: string | null;
  nonce: string;
  accountId: string;
  expiresAt: number;
  used: boolean;
  /** Round 3: the descriptor's bytes and digest (null for purpose session). */
  descriptor: Uint8Array | null;
  digest: string | null;
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

/** What a call's factor proof must confirm (A10): its kind, the request as the call sends it, the devices it names. */
interface Bound {
  kind: ActionInput["kind"];
  request: Record<string, unknown>;
  deviceIds?: readonly string[];
  device?: { id: string; label: string };
}

export class FakeMail {
  readonly mailboxId: string;
  /** The capability's `sub` of the current call: tests switch it to act as another account. */
  accountId: string;
  now: () => number;
  sessionsMode: "optional" | "required" = "optional";
  keys: KeyView[] = [];
  wraps: WrapView[] = [];
  removedFactors: RemovedFactorView[] = [];
  devices: Device[] = [];
  seals: SealView[] = [];
  rotationDue: { since: string; by: string; devices: string[] } | null = null;
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
      removedFactors: this.removedFactors,
      devices: this.devices.map(({ accountId, ...d }) => ({ ...d, createdBy: accountId })),
      seals: this.seals,
      rotationDue: this.rotationDue,
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
      wraps: v.wraps.map(({ factorKey: _f, signingKey: _sk, admission: _a, tag: _t, tagKeyId: _k, ...w }) => w),
    };
  }

  // ---- A11: the signatures Mail checks before it stores anything (M25) ----

  /** An admission of `factor` by the factor `admitter` (both as Mail would list them). */
  private async admissionVerifies(factor: Pick<WrapView, "id" | "kind" | "label" | "credentialId" | "factorKey" | "signingKey">, admission: FactorAdmission, admitter: { id: string; signingKey: string }): Promise<boolean> {
    if (admission.by !== admitter.id) return false;
    const statement = {
      kind: "admit-factor" as const,
      mailboxId: this.mailboxId,
      factorId: factor.id,
      factorKind: factor.kind,
      label: factor.label,
      factorKey: fromB64url(factor.factorKey!),
      signingKey: fromB64url(factor.signingKey!), // pragma: allowlist secret (a public key)
      credentialId: factor.credentialId, // pragma: allowlist secret (field names and public keys)
      admitterId: admitter.id,
      admitterSigningKey: fromB64url(admitter.signingKey), // pragma: allowlist secret (field names and public keys)
    };
    return (await verifyStatement(fromB64url(admitter.signingKey), statement, admission.signature)) && (await verifyStatement(fromB64url(factor.signingKey!), statement, admission.selfSignature));
  }

  /** A device's admission by `admitter`, and its unlock key's signature by itself (present exactly when its unlock key is). */
  private async deviceVerifies(d: { id: string; label: string; signingKey: string; unlockKey: string | null; unlockSignature: string | null; admission: { by: string; signature: string } }, admitter: { id: string; signingKey: string }): Promise<boolean> {
    if (d.admission.by !== admitter.id) return false;
    const admitted = await verifyStatement(
      fromB64url(admitter.signingKey),
      { kind: "admit-device", mailboxId: this.mailboxId, deviceId: d.id, label: d.label, signingKey: fromB64url(d.signingKey), admitterId: admitter.id }, // pragma: allowlist secret (field names and public keys)
      d.admission.signature,
    );
    if (!admitted || (d.unlockKey === null) !== (d.unlockSignature === null)) return false;
    return d.unlockKey === null || verifyStatement(fromB64url(d.signingKey), { kind: "unlock-key", mailboxId: this.mailboxId, deviceId: d.id, unlockKey: fromB64url(d.unlockKey) }, d.unlockSignature!);
  }

  private parseAdmission(value: unknown, what: string): FactorAdmission {
    const a = exactly(value, `${what} admission`, ["by", "signature", "selfSignature"]);
    return { by: id(a.by, `${what} admitter`, "wrp"), signature: b64(a.signature, "signature", 64), selfSignature: b64(a.selfSignature, "selfSignature", 64) };
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
    if (keyed.length > 0) {
      for (const w of keyed) if (w.tagKeyId !== keyId) invalid("a tag is made under the new key");
      // A11: at enrollment each factor is admitted by the next in id order, the last by the first.
      const cycle = new Map(bootstrapAdmitters(wraps.map((w) => w.id)).map((c) => [c.factorId, c.admitterId]));
      for (const w of wraps) {
        const admitter = wraps.find((x) => x.id === cycle.get(w.id))!;
        if (!(await this.admissionVerifies(w, w.admission!, { id: admitter.id, signingKey: admitter.signingKey! }))) invalid("an admission does not verify, or does not follow A11's rule");
      }
    }
    let device: Device | null = null;
    if (req.device !== undefined) {
      if (keyed.length === 0) invalid("a device needs factor keys");
      device = this.parseDevice(req.device as RegisterDeviceRequest, keyId);
      const admitter = wraps.find((w) => w.id === device!.admission!.by) ?? invalid("the device's admitter is not a factor of this enrollment");
      if (!(await this.deviceVerifies(device as never, { id: admitter.id, signingKey: admitter.signingKey! }))) invalid("the device's admission or unlock signature does not verify");
    }
    this.keys = [{ keyId, publicKey, createdAt: this.at(), createdBy: this.accountId, retiredAt: null, successor: null }];
    this.wraps = wraps.map((w) => ({ ...w, createdAt: this.at(), createdBy: this.accountId }));
    if (keyed.length > 0) this.sessionsMode = "required";
    if (device !== null) this.storeDevice(device, (req.device as RegisterDeviceRequest).seal, keyId);
    this.accepted.push({ method: "enroll", request: input });
    return { keyId };
  }

  private parseWrap(value: unknown, what: string, activeKeyId: string): Omit<WrapView, "createdAt" | "createdBy"> {
    const w = exactly(value, what, ["id", "keyId", "kind", "credentialId", "label", "wrapped"], ["factorKey", "signingKey", "admission", "tag", "tagKeyId"]);
    const kind = w.kind === "passkey-prf" || w.kind === "recovery" ? w.kind : invalid(`${what} kind`);
    if (w.keyId !== activeKeyId) invalid(`${what} names another key`);
    const credentialId = kind === "passkey-prf" ? (typeof w.credentialId === "string" && w.credentialId.length > 0 ? w.credentialId : invalid("credential id")) : w.credentialId === null ? null : invalid("credential id");
    const parts = ["factorKey", "signingKey", "admission", "tag", "tagKeyId"].filter((k) => w[k] !== undefined).length;
    if (parts !== 0 && parts !== 5) invalid(`${what}: factorKey, signingKey, admission, tag and tagKeyId come together`);
    const keyed = parts === 5;
    return {
      id: id(w.id, `${what} id`, "wrp"),
      keyId: activeKeyId,
      kind,
      credentialId,
      label: label(w.label, what, 100),
      wrapped: b64(w.wrapped, `${what} wrapped`, 77),
      factorKey: keyed ? b64(w.factorKey, "factor key", 32) : null,
      signingKey: keyed ? b64(w.signingKey, "signing key", 32) : null, // pragma: allowlist secret (a public key)
      admission: keyed ? this.parseAdmission(w.admission, what) : null,
      tag: keyed ? b64(w.tag, "tag", 32) : null,
      tagKeyId: keyed ? (typeof w.tagKeyId === "string" && KEY_ID.test(w.tagKeyId) ? w.tagKeyId : invalid("tagKeyId")) : null,
    };
  }

  async upgrade(input: UpgradeRequest, auth: Auth = {}): Promise<null> {
    // B5: the upgrade needs a live session even while sessions are optional (it was opened with a key proof).
    if ((await this.checkAuth(auth, { session: true })) === null) refuse("SessionRequired");
    const req = exactly(input, "upgrade", ["factors"]);
    if (this.sessionsMode !== "optional") invalid("already upgraded");
    // Round 3: a key proof bound to this very upgrade.
    await this.keyProof(auth, { kind: "upgrade", request: { factors: req.factors } });
    if (this.wraps.some((w) => w.factorKey !== null)) invalid("a factor already has a key");
    if (!Array.isArray(req.factors) || req.factors.length === 0) invalid("factors");
    const active = this.activeKey.keyId;
    const factors = (req.factors as unknown[]).map((f, i) => {
      const x = exactly(f, `factor ${i + 1}`, ["id", "factorKey", "signingKey", "admission", "tag", "tagKeyId"]);
      const wrap = this.wraps.find((w) => w.id === x.id && w.keyId === active) ?? invalid("not a wrap of the active key");
      if (x.tagKeyId !== active) invalid("tagKeyId");
      return { wrap, factorKey: b64(x.factorKey, "factor key", 32), signingKey: b64(x.signingKey, "signing key", 32), admission: this.parseAdmission(x.admission, `factor ${i + 1}`), tag: b64(x.tag, "tag", 32) }; // pragma: allowlist secret (public keys)
    });
    if (new Set(factors.map((f) => f.wrap.id)).size !== factors.length) invalid("a factor is named twice");
    // B5 and M20 as amended: the list names every wrap the mailbox has, exactly once.
    if (factors.length !== this.wraps.length) invalid("M20: the upgrade names every wrap of the mailbox");
    const cycle = new Map(bootstrapAdmitters(factors.map((f) => f.wrap.id)).map((c) => [c.factorId, c.admitterId]));
    for (const f of factors) {
      const admitter = factors.find((x) => x.wrap.id === cycle.get(f.wrap.id))!;
      const listed = { ...f.wrap, factorKey: f.factorKey, signingKey: f.signingKey }; // pragma: allowlist secret (public keys)
      if (!(await this.admissionVerifies(listed, f.admission, { id: admitter.wrap.id, signingKey: admitter.signingKey }))) invalid("an admission does not verify, or does not follow A11's rule");
    }
    for (const f of factors) Object.assign(f.wrap, { factorKey: f.factorKey, signingKey: f.signingKey, admission: f.admission, tag: f.tag, tagKeyId: active }); // pragma: allowlist secret (public keys)
    this.sessionsMode = "required";
    this.accepted.push({ method: "upgrade", request: input });
    return null;
  }

  // ---- B6 ----

  async challenge(input: ChallengeRequest): Promise<ChallengeView> {
    const req = exactly(input, "challenge", ["purpose"], ["factorId", "action"]);
    const live = [...this.challenges.values()].filter((c) => !c.used && c.expiresAt > this.now());
    if (live.length >= 20) refuse("RateLimited");
    const challengeId = newId("chl");
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    let target: { publicKey: Uint8Array; targetId: string } | null;
    const purpose = req.purpose;
    if (purpose === "session") {
      if (req.factorId !== undefined || req.action !== undefined) invalid("a session challenge names no factor and no action");
      target = { publicKey: fromB64url(this.activeKey.publicKey), targetId: this.activeKey.keyId };
    } else if (purpose === "factor") {
      const wrap = this.wraps.find((w) => w.id === req.factorId);
      if (wrap === undefined || wrap.factorKey === null) refuse("NotFound");
      target = { publicKey: fromB64url(wrap!.factorKey!), targetId: wrap!.id };
    } else if (purpose === "key") {
      if (req.factorId !== undefined) invalid("a key challenge names no factor");
      target = { publicKey: fromB64url(this.activeKey.publicKey), targetId: this.activeKey.keyId };
    } else if (purpose === "email") {
      if (req.factorId !== undefined) invalid("an email challenge names no factor");
      target = null;
    } else {
      return invalid("purpose");
    }
    // Round 3 (A10, B6): every purpose but session describes its action; Mail takes the labels from its records.
    let descriptor: Uint8Array | null = null;
    let digest: string | null = null;
    if (purpose !== "session") {
      const action = req.action as ActionInput;
      let kindPurpose: string;
      try {
        kindPurpose = actionPurpose(action?.kind);
      } catch {
        return invalid("an unknown action kind");
      }
      if (kindPurpose !== purpose) invalid("the action's kind does not belong to this purpose");
      const labels = new Map(this.devices.map((d) => [d.id, d.label]));
      try {
        descriptor = buildActionDescriptor(actionDescriptorFor(action, { mailboxId: this.mailboxId, nonce: b64url(crypto.getRandomValues(new Uint8Array(32))), issuedAt: Math.floor(this.now() / 1000), labels }));
      } catch {
        return invalid("the action does not describe (a device Mail does not hold, or a malformed action)");
      }
      digest = await actionDigest(descriptor);
    }
    let sealed: string | null = null;
    let answerHash: string | null = null;
    if (target !== null) {
      const aad = `proprietor-mail/v1/challenge|${this.mailboxId}|${challengeId}|${purpose}|${target.targetId}${digest === null ? "" : `|${digest}`}`;
      const s = await sealChallenge(target.publicKey, aad);
      sealed = s.sealed;
      answerHash = await sha256(s.answer);
    }
    const expiresAt = this.now() + (purpose === "email" ? 600_000 : 120_000);
    this.challenges.set(challengeId, { purpose, targetId: target?.targetId ?? "", answerHash, nonce: b64url(nonce), accountId: this.accountId, expiresAt, used: false, descriptor, digest });
    return {
      id: challengeId,
      purpose,
      keyId: purpose === "session" || purpose === "key" ? target!.targetId : null,
      factorId: purpose === "factor" ? target!.targetId : null,
      nonce: b64url(nonce),
      sealed,
      descriptor: descriptor === null ? null : b64url(descriptor),
      expiresAt: new Date(expiresAt).toISOString(),
    };
  }

  /** A live challenge of `purpose` for this account, spent now, whatever the answer; then the answer is checked. */
  private async consume(challengeId: unknown, answer: unknown, purpose: Challenge["purpose"]): Promise<Challenge> {
    const c = typeof challengeId === "string" ? this.challenges.get(challengeId) : undefined;
    if (c === undefined || c.used || c.expiresAt <= this.now() || c.purpose !== purpose || c.accountId !== this.accountId) refuse("ProofRejected");
    c!.used = true; // consumed whether or not the answer is right
    if ((await sha256(fromB64url(b64(answer, "answer", 32)))) !== c!.answerHash) refuse("ProofRejected");
    return c!;
  }

  /** Round 3 (B3, A10): the challenge's descriptor names THIS call: its kind, its devices, and the digest of its request as sent. */
  private async boundTo(c: Challenge, bound: Bound): Promise<void> {
    const d = c.descriptor === null ? null : readActionDescriptor(c.descriptor);
    if (d === null || d.kind !== bound.kind) refuse("ProofRejected", "the proof's challenge is for another kind of action");
    let digest: string;
    try {
      digest = await requestDigest(bound.request);
    } catch {
      return invalid("the request does not serialize (A10)");
    }
    if (d!.request !== digest) refuse("ProofRejected", "the proof's challenge is for another request");
    if (bound.deviceIds !== undefined && JSON.stringify(d!.targets.map((t) => t.deviceId)) !== JSON.stringify([...bound.deviceIds].sort())) refuse("ProofRejected", "the proof's challenge names other devices");
    if (bound.device !== undefined && JSON.stringify(d!.targets) !== JSON.stringify([{ deviceId: bound.device.id, label: bound.device.label }])) refuse("ProofRejected", "the proof's challenge names another device");
  }

  /** A factor proof for the call `bound` describes: consumed, checked, and bound; answers the factor (keyed, not removed). */
  private async factorProof(auth: Auth, bound: Bound): Promise<WrapView> {
    const proof = auth.factorProof === undefined ? refuse("ProofRejected", "a factor proof is required") : exactly(auth.factorProof, "factorProof", ["challengeId", "answer"]);
    const c = await this.consume(proof.challengeId, proof.answer, "factor");
    const factor = this.wraps.find((w) => w.id === c.targetId);
    if (factor === undefined || factor.factorKey === null) refuse("ProofRejected");
    await this.boundTo(c, bound);
    return factor!;
  }

  /** A key proof for the call `bound` describes (round 3: the upgrade). */
  private async keyProof(auth: Auth, bound: Bound): Promise<void> {
    const proof = auth.keyProof === undefined ? refuse("ProofRejected", "a key proof is required") : exactly(auth.keyProof, "keyProof", ["challengeId", "answer"]);
    const c = await this.consume(proof.challengeId, proof.answer, "key");
    if (c.targetId !== this.activeKey.keyId) refuse("ProofRejected");
    await this.boundTo(c, bound);
  }

  async openSession(input: OpenSessionRequest): Promise<OpenSessionResult> {
    const req = exactly(input, "openSession", ["challengeId", "answer"], ["device", "factorProof"]);
    if (this.sessionsMode === "required" && (req.device === undefined) === (req.factorProof === undefined)) invalid("D38: exactly one of device and factorProof");
    if (this.sessionsMode === "optional" && req.factorProof !== undefined) invalid("no factor proof while sessions are optional");
    // M21′, D37: a device of another account is Forbidden, and nothing is written or spent.
    if (req.device !== undefined) {
      const d = exactly(req.device, "device", ["id", "signature"]);
      const device = this.devices.find((x) => x.id === d.id);
      if (device !== undefined && device.accountId !== this.accountId) refuse("Forbidden");
    }
    const challenge = await this.consume(req.challengeId, req.answer, "session");
    let deviceId: string | null = null;
    if (req.device !== undefined) {
      const d = req.device as { id: string; signature: unknown };
      const device = this.devices.find((x) => x.id === d.id);
      if (device === undefined) refuse("DeviceRevoked");
      const message = `proprietor-mail/v1/device-proof|${this.mailboxId}|${device!.id}|${req.challengeId}|${challenge.nonce}`;
      if (!(await verifyDeviceProof(device!.signingKey, message, b64(d.signature, "signature", 64)))) refuse("ProofRejected");
      device!.lastSeenAt = this.at();
      deviceId = device!.id;
    } else if (req.factorProof !== undefined) {
      // D38: a factor proof bound to open-session for this very session challenge.
      await this.factorProof({ factorProof: req.factorProof as never }, { kind: "open-session", request: { challengeId: req.challengeId } });
    }
    const token = b64url(crypto.getRandomValues(new Uint8Array(32))); // pragma: allowlist secret (field names and public values, not secrets)
    const expiresAt = this.now() + 60 * 60_000;
    this.mailSessions.set(await sha256(fromB64url(token)), { accountId: this.accountId, deviceId, expiresAt });
    this.accepted.push({ method: "openSession", request: input });
    return { session: token, expiresAt: new Date(expiresAt).toISOString(), device: deviceId };
  }

  /** B2: the session a call needs. Returns the session's record. */
  private async checkAuth(auth: Auth, needs: { session: boolean; device?: boolean }): Promise<MailSession | null> {
    const a = exactly(auth, "auth", [], ["session", "factorProof", "keyProof"]);
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
    if (needs.device && (session === null || session.deviceId === null)) refuse("SessionRequired", "a device's session");
    return session;
  }

  // ---- B7 ----

  private parseDevice(input: RegisterDeviceRequest, active: string): Device {
    const req = exactly(input, "registerDevice", ["device", "seal"]);
    const d = exactly(req.device, "device", ["id", "label", "signingKey", "unlockKey", "unlockSignature", "admission", "tag", "tagKeyId"]);
    const admission = exactly(d.admission, "device admission", ["by", "signature"]);
    const unlockKey = d.unlockKey === null ? null : b64(d.unlockKey, "unlock key", 65);
    const device: Device = {
      id: id(d.id, "device id", "dev"),
      label: label(d.label, "device", 40),
      signingKey: b64(d.signingKey, "signing key", 65), // pragma: allowlist secret (field names and public values, not secrets)
      unlockKey,
      unlockSignature: d.unlockSignature === null ? null : b64(d.unlockSignature, "unlock signature", 64),
      admission: { by: id(admission.by, "admitter", "wrp"), signature: b64(admission.signature, "admission signature", 64) },
      tag: b64(d.tag, "tag", 32),
      tagKeyId: d.tagKeyId === active ? active : invalid("tagKeyId must be the active key"),
      createdAt: this.at(),
      createdBy: this.accountId,
      lastSeenAt: null,
      accountId: this.accountId,
    };
    if ((d.unlockSignature === null) !== (unlockKey === null)) invalid("an unlock signature comes exactly with an unlock key");
    if (this.devices.some((x) => x.id === device.id)) invalid("that device id exists");
    if ((req.seal === null) !== (device.unlockKey === null)) invalid("a seal comes exactly with an unlock key");
    if (this.devices.length >= 20) invalid("at most 20 devices");
    if (req.seal !== null) b64(req.seal, "seal", 142);
    return device;
  }

  private storeDevice(device: Device, seal: string | null, active: string): void {
    this.devices.push(device);
    if (seal !== null) this.seals.push({ keyId: active, to: { kind: "device", id: device.id }, sealed: seal });
  }

  async registerDevice(input: RegisterDeviceRequest, auth: Auth = {}): Promise<DeviceView> {
    if (this.sessionsMode !== "required") invalid("upgrade first");
    const session = await this.checkAuth(auth, { session: true });
    const active = this.activeKey.keyId;
    const device = this.parseDevice(input, active);
    const factor = await this.factorProof(auth, { kind: "register-device", request: { device: input.device, seal: input.seal }, device: { id: device.id, label: device.label } });
    // M25: admitted by the factor whose proof the call spends, and its unlock key signed by itself.
    if (device.admission!.by !== factor.id || !(await this.deviceVerifies(device as never, { id: factor.id, signingKey: factor.signingKey! }))) invalid("the admission or the unlock signature does not verify");
    this.storeDevice(device, input.seal, active);
    if (session !== null) session.deviceId = device.id; // the caller's session becomes this device's
    this.accepted.push({ method: "registerDevice", request: input });
    const { accountId: _a, ...view } = device;
    return view;
  }

  async updateDevice(input: UpdateDeviceRequest, auth: Auth = {}): Promise<DeviceView> {
    const session = (await this.checkAuth(auth, { session: true, device: true }))!;
    const req = exactly(input, "updateDevice", ["unlockKey", "unlockSignature", "tag", "tagKeyId", "seal"]);
    const device = this.devices.find((d) => d.id === session.deviceId)!;
    const active = this.activeKey.keyId;
    const unlockKey = req.unlockKey === null ? null : b64(req.unlockKey, "unlock key", 65);
    const unlockSignature = req.unlockSignature === null ? null : b64(req.unlockSignature, "unlock signature", 64);
    if ((req.seal === null) !== (unlockKey === null) || (unlockSignature === null) !== (unlockKey === null)) invalid("a seal and a signature come exactly with an unlock key");
    if (req.tagKeyId !== active) invalid("tagKeyId must be the active key");
    if (unlockKey !== null && !(await verifyStatement(fromB64url(device.signingKey), { kind: "unlock-key", mailboxId: this.mailboxId, deviceId: device.id, unlockKey: fromB64url(unlockKey) }, unlockSignature!))) {
      invalid("the unlock key's signature does not verify");
    }
    const tag = b64(req.tag, "tag", 32);
    const seal = req.seal === null ? null : b64(req.seal, "seal", 142);
    Object.assign(device, { unlockKey, unlockSignature, tag, tagKeyId: active });
    this.seals = this.seals.filter((s) => !(s.to.kind === "device" && s.to.id === device.id));
    if (seal !== null) this.seals.push({ keyId: active, to: { kind: "device", id: device.id }, sealed: seal });
    this.accepted.push({ method: "updateDevice", request: input });
    const { accountId: _a, ...view } = device;
    return structuredClone(view);
  }

  async addWrap(input: WrapInput, auth: Auth = {}): Promise<null> {
    await this.checkAuth(auth, { session: true });
    const w = this.parseWrap(input, "wrap", this.activeKey.keyId);
    if (this.sessionsMode === "required") {
      const factor = await this.factorProof(auth, { kind: "add-factor", request: { ...input } });
      if (w.factorKey === null || w.tagKeyId !== this.activeKey.keyId) invalid("a wrap carries its factor key once sessions are required");
      // M25: admitted by the factor whose proof the call spends, and by itself.
      if (!(await this.admissionVerifies(w, w.admission!, { id: factor.id, signingKey: factor.signingKey! }))) invalid("the admission does not verify");
    }
    if (this.sessionsMode === "optional" && w.factorKey !== null) invalid("no factor key before the upgrade");
    if (this.wraps.some((x) => x.id === w.id)) invalid("that wrap id exists");
    this.wraps.push({ ...w, createdAt: this.at(), createdBy: this.accountId });
    this.accepted.push({ method: "addWrap", request: input });
    return null;
  }

  async removeWrap(wrapId: string, auth: Auth = {}): Promise<null> {
    await this.checkAuth(auth, { session: true });
    if (this.sessionsMode === "required") await this.factorProof(auth, { kind: "remove-factor", request: { wrapId } });
    const wrap = this.wraps.find((w) => w.id === wrapId) ?? refuse("NotFound");
    const rest = this.wraps.filter((w) => w.id !== wrapId);
    const active = this.activeKey.keyId;
    const reaches = (w: WrapView) => w.kind === "recovery" && (w.keyId === active || this.seals.some((s) => s.keyId === active && s.to.kind === "factor" && s.to.id === w.id));
    if (reaches(wrap) && !rest.some(reaches)) invalid("M5′: the last recovery factor that reaches the active key stays");
    this.wraps = rest;
    this.seals = this.seals.filter((s) => !(s.to.kind === "factor" && s.to.id === wrapId));
    // M24: a keyed factor's record stays, for the signatures it made.
    if (wrap.factorKey !== null && wrap.signingKey && wrap.admission) {
      this.removedFactors.push({ id: wrap.id, kind: wrap.kind, credentialId: wrap.credentialId, label: wrap.label, factorKey: wrap.factorKey!, signingKey: wrap.signingKey, admission: wrap.admission, removedAt: this.at() }); // pragma: allowlist secret (public keys)
    }
    this.accepted.push({ method: "removeWrap", request: { wrapId } });
    return null;
  }

  async removeDevices(input: RemoveDevicesRequest, auth: Auth = {}): Promise<{ keyId: string }> {
    if (this.sessionsMode !== "required") invalid("upgrade first");
    const caller = await this.checkAuth(auth, { session: true });
    const req = exactly(input, "removeDevices", ["deviceIds", "rotation"]);
    if (!Array.isArray(req.deviceIds) || req.deviceIds.length > 20) invalid("0 to 20 devices");
    const deviceIds = req.deviceIds as string[];
    if (new Set(deviceIds).size !== deviceIds.length) invalid("each device once");
    const named = deviceIds.map((x) => this.devices.find((d) => d.id === x) ?? invalid("no such device"));
    if (named.length === 0 && this.rotationDue === null) invalid("no device: only while a rotation is due");
    const factor = await this.factorProof(auth, { kind: "remove-devices", request: { deviceIds: input.deviceIds, rotation: input.rotation }, deviceIds });
    const r = exactly(req.rotation, "rotation", ["from", "publicKey", "successorSeal", "transition", "seals", "tags"]);
    const active = this.activeKey;
    if (r.from !== active.keyId) invalid("stale rotation: from is not the active key");
    const publicKey = b64(r.publicKey, "new public key", 32);
    const newKeyId = await keyIdOf(fromB64url(publicKey));
    if (this.keys.some((k) => k.keyId === newKeyId)) invalid("the new key is not new");
    const successorSeal = b64(r.successorSeal, "successor seal", 109);
    // M23, M25: the transition, signed by the factor whose proof the call spends.
    const t = exactly(r.transition, "transition", ["signedBy", "signature"]);
    if (t.signedBy !== factor.id) invalid("the transition is signed by the factor whose proof the call spends");
    const transitionOk = await verifyStatement(
      fromB64url(factor.signingKey!),
      { kind: "transition", mailboxId: this.mailboxId, fromKeyId: active.keyId, toKeyId: newKeyId, toPublicKey: fromB64url(publicKey), signerId: factor.id },
      b64(t.signature, "transition signature", 64),
    );
    if (!transitionOk) invalid("the transition does not verify");
    const remainingDevices = this.devices.filter((d) => !deviceIds.includes(d.id));
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
    const tags = (r.tags as unknown[]).map((tg, i) => {
      const x = exactly(tg, `tag ${i + 1}`, ["to", "tag"]);
      const to = exactly(x.to, `tag ${i + 1} to`, ["kind", "id"]);
      return { to: { kind: to.kind as "device" | "factor", id: to.id as string }, tag: b64(x.tag, `tag ${i + 1}`, 32) };
    });
    const names = (list: { to: { kind: string; id: string } }[]) => list.map((x) => `${x.to.kind}:${x.to.id}`).sort();
    if (JSON.stringify(names(seals)) !== JSON.stringify(sealTargets)) invalid("the seals must name exactly the remaining recipients");
    if (JSON.stringify(names(tags)) !== JSON.stringify(tagTargets)) invalid("the tags must name exactly the remaining recipients");
    if (!this.wraps.some((w) => w.kind === "recovery" && w.factorKey !== null)) invalid("M5′: a keyed recovery factor must receive the new key");
    // Effect, all at once (M18′).
    this.devices = remainingDevices;
    this.seals = seals.map((s) => ({ keyId: newKeyId, to: s.to, sealed: s.sealed }));
    Object.assign(active, { retiredAt: this.at(), successor: { keyId: newKeyId, sealed: successorSeal, signedBy: factor.id, signature: t.signature as string } });
    this.keys.push({ keyId: newKeyId, publicKey, createdAt: this.at(), createdBy: this.accountId, retiredAt: null, successor: null });
    for (const tg of tags) {
      const target = tg.to.kind === "device" ? this.devices.find((d) => d.id === tg.to.id)! : this.wraps.find((w) => w.id === tg.to.id)!;
      Object.assign(target, { tag: tg.tag, tagKeyId: newKeyId });
    }
    this.rotationDue = null;
    // Every other session ends, and the removed devices' with them (the caller's too, when it removed itself).
    for (const [hash, s] of [...this.mailSessions]) if (s !== caller || (s.deviceId !== null && deviceIds.includes(s.deviceId))) this.mailSessions.delete(hash);
    this.accepted.push({ method: "removeDevices", request: input });
    return { keyId: newKeyId };
  }

  /**
   * B7a: an email code revokes and does nothing else. `confirmed` stands for the dashboard's attestation
   * of the code (capability-v1 `confirmation`): the email challenge whose descriptor it names. The
   * devices, their seals and sessions go, and a rotation is due; no key, seal, tag or factor is written.
   */
  async revokeDevices(input: RevokeDevicesRequest, confirmed: { challengeId: string }): Promise<{ revoked: string[] }> {
    const req = exactly(input, "revokeDevices", ["deviceIds"]);
    if (this.sessionsMode !== "required") invalid("upgrade first");
    const c = this.challenges.get(confirmed.challengeId);
    if (c === undefined || c.used || c.expiresAt <= this.now() || c.purpose !== "email" || c.accountId !== this.accountId) refuse("ProofRejected");
    c!.used = true;
    const d = readActionDescriptor(c!.descriptor!)!;
    const ids = (req.deviceIds as string[]).slice().sort();
    if (d.kind !== "revoke-device" || JSON.stringify(d.targets.map((x) => x.deviceId)) !== JSON.stringify(ids)) refuse("ProofRejected", "the attestation names other devices");
    for (const x of ids) if (!this.devices.some((dev) => dev.id === x)) invalid("no such device");
    this.devices = this.devices.filter((dev) => !ids.includes(dev.id));
    this.seals = this.seals.filter((s) => !(s.to.kind === "device" && ids.includes(s.to.id)));
    for (const [hash, s] of [...this.mailSessions]) if (s.deviceId !== null && ids.includes(s.deviceId)) this.mailSessions.delete(hash);
    this.rotationDue = { since: this.rotationDue?.since ?? this.at(), by: this.accountId, devices: [...new Set([...(this.rotationDue?.devices ?? []), ...ids])] };
    this.accepted.push({ method: "revokeDevices", request: input });
    return { revoked: ids };
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
