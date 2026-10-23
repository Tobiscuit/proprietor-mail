import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { newId } from "@proprietor/mail-crypto";
import { exports } from "cloudflare:workers";
import type { Role } from "../../src/capability";
import { base64urlFromBytes, bytesFromBase64url } from "./capability-tokens";
import { capFor, newKeyPair, passkeyWrap, provisionMailbox, recoveryWrap, type TestKey, type TestMailbox } from "./mailbox";
import { valueOf } from "./results";

/**
 * The browser's half of contracts/device-v1.md, done by the tests themselves
 * (the Worker's half is under test): opening challenges (A6) with a mailbox
 * private key or a factor's key, straight on @hpke/core; signing device
 * proofs (A7) and, round 3, the statements of A11 (a factor's admission and
 * transitions with an Ed25519 key, a device's unlock key with its P-256
 * signing key) with Web Crypto; the request digests and descriptors of A10;
 * and well-formed key seals (A4) and binding tags (A5). The Worker checks
 * only the lengths and shapes of seals and tags, so random bytes of the right
 * length stand in for them.
 *
 * `ctx()` and `canonical()` are this file's own copies of the contract's
 * rules (A1's ctx, RFC 8785 for the values a request holds), so a mistake the
 * Worker shares with mail-crypto cannot make a test pass.
 */

const mail = () => exports.MailService;
const utf8 = (s: string) => new TextEncoder().encode(s);
const b64u = base64urlFromBytes;

export const ctx = (label: string, ...parts: string[]) => utf8(`proprietor-mail/v1/${label}|${parts.join("|")}`);

/**
 * RFC 8785 for what a request holds (A10: strings, null, arrays, objects):
 * members sorted by UTF-16 code units, no whitespace, strings as
 * ECMAScript's JSON.stringify writes them. A member whose value is
 * undefined is left out, as JSON.stringify leaves it out (only the tests'
 * malformed requests have one; Mail refuses those).
 */
export function canonical(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .filter((k) => record[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(record[k])}`)
      .join(",")}}`;
  }
  throw new TypeError(`a request holds no ${typeof value}`);
}

export async function sha256b64u(bytes: Uint8Array): Promise<string> {
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** A10: base64url of SHA-256 over the RFC 8785 serialization of a request, exactly as the call sends it. */
export const requestDigestOf = (request: unknown) => sha256b64u(utf8(canonical(request)));

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

/** PKCS #8 PrivateKeyInfo prefix for an X25519 key (RFC 8410), then the 32-byte scalar. */
const PKCS8_X25519 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);

export interface ChallengeView {
  id: string;
  purpose: "session" | "factor" | "key" | "email";
  keyId: string | null;
  factorId: string | null;
  nonce: string;
  sealed: string | null;
  descriptor: string | null;
  expiresAt: string;
}

export interface Proof {
  challengeId: string;
  answer: string;
}

/** An X25519 key pair as HPKE wants it: the mailbox key of a test mailbox, or a factor key. */
export async function x25519Pair(privateScalar: Uint8Array, publicKey: Uint8Array): Promise<CryptoKeyPair> {
  const pkcs8 = new Uint8Array(PKCS8_X25519.length + 32);
  pkcs8.set(PKCS8_X25519);
  pkcs8.set(privateScalar, PKCS8_X25519.length);
  return {
    privateKey: await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, false, ["deriveBits"]),
    publicKey: await crypto.subtle.importKey("raw", publicKey, { name: "X25519" }, true, []),
  };
}

export const mailboxKeyPair = (key: TestKey) => x25519Pair(key.privateKey, key.publicKey);

/** A factor (A2, A2b): its X25519 key pair and its Ed25519 signing key pair (derived from its secret in a browser; here simply fresh), and its record as Mail lists it. */
export interface TestFactor {
  /** The factor's id: its wrap's id. */
  id: string;
  kind: "passkey-prf" | "recovery";
  label: string;
  credentialId: string | null;
  pair: CryptoKeyPair;
  /** The raw 32-byte X25519 public key, the factorKey Mail stores. */
  publicKey: Uint8Array;
  signing: CryptoKeyPair;
  /** The raw 32-byte Ed25519 public key, the signingKey Mail stores. */
  signingKey: Uint8Array; // pragma: allowlist secret (a type annotation: a public Ed25519 key)
}

export async function newFactorKey(
  id: string,
  kind: TestFactor["kind"],
  record: { label?: string; credentialId?: string | null } = {},
): Promise<TestFactor> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const signing = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  return {
    id,
    kind,
    label: record.label ?? (kind === "recovery" ? "Recovery key" : "Phone"),
    credentialId: record.credentialId ?? null, // pragma: allowlist secret (a field name, not a value)
    pair,
    publicKey: new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer),
    signing,
    signingKey: new Uint8Array((await crypto.subtle.exportKey("raw", signing.publicKey)) as ArrayBuffer), // pragma: allowlist secret (a public Ed25519 key)
  };
}

/** The factor of a wrap as Mail lists it (its id, kind, label and credential id), with fresh keys. */
export const factorOf = (wrap: { id: string; kind: string; label: string; credentialId?: string | null }) =>
  newFactorKey(wrap.id, wrap.kind as TestFactor["kind"], { label: wrap.label, credentialId: wrap.credentialId ?? null }); // pragma: allowlist secret (a field name, not a value)

/** The digest of the descriptor Mail issued with a challenge (A10): what a factor or key challenge's aad ends with. */
export async function descriptorDigest(challenge: ChallengeView): Promise<string> {
  if (challenge.descriptor === null) throw new Error("this challenge has no descriptor");
  return sha256b64u(bytesFromBase64url(challenge.descriptor));
}

/** The descriptor Mail issued, as an object (its bytes are RFC 8785 JSON). */
export function descriptorOf(challenge: ChallengeView): Record<string, unknown> {
  if (challenge.descriptor === null) throw new Error("this challenge has no descriptor");
  return JSON.parse(new TextDecoder().decode(bytesFromBase64url(challenge.descriptor))) as Record<string, unknown>;
}

/**
 * Opens a challenge exactly as A6 says: HPKE base mode, info
 * "proprietor-mail/v1/challenge", the challenge's aad: for "factor" and "key"
 * challenges ending with `actionDigest` (by default the digest of the
 * descriptor Mail sent). Returns the answer, base64url.
 */
export async function openChallenge(mailboxId: string, challenge: ChallengeView, recipient: CryptoKeyPair, actionDigest?: string): Promise<string> {
  if (challenge.sealed === null) throw new Error("an email challenge has nothing to open");
  const bytes = bytesFromBase64url(challenge.sealed);
  const targetId = challenge.purpose === "factor" ? challenge.factorId! : challenge.keyId!;
  const parts = [mailboxId, challenge.id, challenge.purpose, targetId];
  if (challenge.purpose !== "session") parts.push(actionDigest ?? (await descriptorDigest(challenge)));
  const answer = await suite.open({ recipientKey: recipient, enc: bytes.slice(0, 32), info: utf8("proprietor-mail/v1/challenge") }, bytes.slice(32), ctx("challenge", ...parts));
  return b64u(new Uint8Array(answer));
}

// ---- A11: what factors and devices sign -----------------------------------------------------

async function ed25519(factor: TestFactor, message: Uint8Array): Promise<string> {
  return b64u(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, factor.signing.privateKey, message)));
}

async function ecdsa(pair: CryptoKeyPair, message: Uint8Array): Promise<string> {
  return b64u(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, message)));
}

export interface FactorAdmission {
  by: string;
  signature: string;
  selfSignature: string;
}

/** A11: the admission of `factor` by `admitter`, signed by both. */
export async function admitFactor(mailboxId: string, factor: TestFactor, admitter: TestFactor): Promise<FactorAdmission> {
  const message = ctx(
    "admit-factor",
    mailboxId,
    factor.id,
    factor.kind,
    b64u(utf8(factor.label)),
    b64u(factor.publicKey),
    b64u(factor.signingKey),
    factor.credentialId ?? "-",
    admitter.id,
    b64u(admitter.signingKey),
  );
  return { by: admitter.id, signature: await ed25519(admitter, message), selfSignature: await ed25519(factor, message) };
}

/** A11 at enrollment and the upgrade: the factors sorted by id, each admitted by the next, the last by the first; one alone by itself. */
export async function cycleAdmissions(mailboxId: string, factors: TestFactor[]): Promise<Map<string, FactorAdmission>> {
  const sorted = [...factors].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const out = new Map<string, FactorAdmission>();
  for (const [i, f] of sorted.entries()) out.set(f.id, await admitFactor(mailboxId, f, sorted[(i + 1) % sorted.length]!));
  return out;
}

/** A11: a device's admission by the factor that keeps it. */
export async function admitDevice(mailboxId: string, device: TestDevice, admitter: TestFactor): Promise<{ by: string; signature: string }> {
  const message = ctx("admit-device", mailboxId, device.id, b64u(utf8(device.label)), b64u(device.signingKey), admitter.id);
  return { by: admitter.id, signature: await ed25519(admitter, message) };
}

/** A11: an unlock key, signed by the device's own signing key. */
export async function signUnlockKey(mailboxId: string, device: TestDevice, unlockKey: Uint8Array): Promise<string> {
  return ecdsa(device.signing, ctx("unlock-key", mailboxId, device.id, b64u(unlockKey)));
}

/** A11: "this key's successor is that key", signed by `signer`. */
export async function signTransition(mailboxId: string, signer: TestFactor, fromKeyId: string, to: TestKey): Promise<{ signedBy: string; signature: string }> {
  return { signedBy: signer.id, signature: await ed25519(signer, ctx("transition", mailboxId, fromKeyId, to.keyId, b64u(to.publicKey), signer.id)) };
}

// ---- devices ---------------------------------------------------------------------

export interface TestDevice {
  id: string;
  label: string;
  signing: CryptoKeyPair;
  /** Raw 65-byte P-256 points. */
  signingKey: Uint8Array; // pragma: allowlist secret (a type annotation: a public P-256 point)
  unlockKey: Uint8Array | null;
}

const p256Point = async (pair: CryptoKeyPair) => new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);

export async function newDevice(opts: { label?: string; keepsNothing?: boolean } = {}): Promise<TestDevice> {
  const signing = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const unlock = opts.keepsNothing ? null : ((await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair);
  return {
    id: newId("dev"),
    label: opts.label ?? "Office laptop",
    signing,
    signingKey: await p256Point(signing), // pragma: allowlist secret (a public P-256 point)
    unlockKey: unlock === null ? null : await p256Point(unlock),
  };
}

/** A fresh unlock key (A3), for updateDevice. */
export async function newUnlockKey(): Promise<Uint8Array> {
  return p256Point((await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair);
}

/** A7: the device's signature over ctx("device-proof", mailboxId, deviceId, challengeId, b64u(nonce)), base64url. */
export async function signProof(mailboxId: string, device: TestDevice, challenge: ChallengeView, signer: CryptoKeyPair = device.signing): Promise<string> {
  return ecdsa(signer, ctx("device-proof", mailboxId, device.id, challenge.id, challenge.nonce));
}

/** A seal of the right shape (A4): 0x01 || enc || iv || ct. 142 bytes to a device (P-256), 109 to a factor or a successor (X25519). */
export function fakeSeal(bytes: 142 | 109): string {
  const seal = crypto.getRandomValues(new Uint8Array(bytes));
  seal[0] = 1;
  return b64u(seal);
}

/** A binding tag of the right shape (A5): 32 bytes. */
export const fakeTag = () => b64u(crypto.getRandomValues(new Uint8Array(32)));

/** DeviceInput (B7, round 3) for a device, tagged under `tagKeyId`, admitted by `admitter`, its unlock key signed by itself. */
export async function deviceInput(mailboxId: string, device: TestDevice, tagKeyId: string, admitter: TestFactor, over: Record<string, unknown> = {}) {
  return {
    id: device.id,
    label: device.label,
    signingKey: b64u(device.signingKey), // pragma: allowlist secret (a public P-256 point)
    unlockKey: device.unlockKey === null ? null : b64u(device.unlockKey),
    unlockSignature: device.unlockKey === null ? null : await signUnlockKey(mailboxId, device, device.unlockKey),
    admission: await admitDevice(mailboxId, device, admitter),
    tag: fakeTag(),
    tagKeyId,
    ...over,
  };
}

// ---- A10: the action each call's proof confirms ----------------------------------------------

/** What a factor or key proof confirms (A10): the kind, the request exactly as the call sends it, and the devices it names. */
export interface Action {
  kind: "remove-devices" | "register-device" | "add-factor" | "remove-factor" | "open-session" | "upgrade";
  request: Record<string, unknown>;
  deviceIds?: string[];
  device?: { id: string; label: string };
}

export const registerAction = (request: { device: { id: string; label: string }; seal: unknown }): Action => ({
  kind: "register-device",
  request: { device: request.device, seal: request.seal },
  device: { id: request.device.id, label: request.device.label },
});
export const addFactorAction = (wrap: Record<string, unknown>): Action => ({ kind: "add-factor", request: wrap });
export const removeFactorAction = (wrapId: string): Action => ({ kind: "remove-factor", request: { wrapId } });
export const removeDevicesAction = (request: { deviceIds: string[]; rotation: unknown }): Action => ({
  kind: "remove-devices",
  request: { deviceIds: request.deviceIds, rotation: request.rotation },
  deviceIds: request.deviceIds,
});
export const openSessionAction = (challengeId: string): Action => ({ kind: "open-session", request: { challengeId } });
export const upgradeAction = (request: { factors: unknown }): Action => ({ kind: "upgrade", request: { factors: request.factors } });

/** A10's ActionInput for `action`, the request's digest computed here. */
export async function actionInput(action: Action): Promise<Record<string, unknown>> {
  const request = await requestDigestOf(action.request);
  if (action.kind === "remove-devices") return { kind: action.kind, deviceIds: action.deviceIds ?? [], request };
  if (action.kind === "register-device") return { kind: action.kind, device: action.device!, request };
  return { kind: action.kind, request };
}

/** K12, as a browser does it: the descriptor Mail issued names our own action, or we answer nothing. */
function expectDescribes(mailboxId: string, challenge: ChallengeView, input: Record<string, unknown>): void {
  const d = descriptorOf(challenge);
  const ids = (d.targets as { deviceId: string }[]).map((t) => t.deviceId);
  const want =
    input.kind === "remove-devices" || input.kind === "revoke-device"
      ? [...(input.deviceIds as string[])].sort()
      : input.kind === "register-device"
        ? [(input.device as { id: string }).id]
        : [];
  if (d.kind !== input.kind || d.mailboxId !== mailboxId || d.request !== input.request || JSON.stringify(ids) !== JSON.stringify(want)) {
    throw new Error(`Mail's descriptor does not name this action: ${JSON.stringify(d)}`);
  }
}

// ---- the flows, through MailService --------------------------------------------------

export interface Who {
  /** The capability's sub; "acc_owner" by default, as in capFor. */
  sub?: string;
  role?: Role;
}

export async function challenge(mb: TestMailbox, request: Record<string, unknown>, who: Who = {}): Promise<ChallengeView> {
  return valueOf(await mail().challenge(await capFor(mb, who), request)) as ChallengeView;
}

/** A factor proof (B6, round 3): a factor challenge for `action`, its descriptor checked, opened with the factor's key and the descriptor's digest. */
export async function factorProof(mb: TestMailbox, factor: TestFactor, action: Action, who: Who = {}): Promise<Proof> {
  const input = await actionInput(action);
  const c = await challenge(mb, { purpose: "factor", factorId: factor.id, action: input }, who);
  expectDescribes(mb.id, c, input);
  return { challengeId: c.id, answer: await openChallenge(mb.id, c, factor.pair) };
}

/** The upgrade's key proof (B5, round 3): a key challenge for the upgrade request, opened with the mailbox key and the descriptor's digest. */
export async function keyProof(mb: TestMailbox, mailboxKey: CryptoKeyPair, request: { factors: unknown }, who: Who = {}): Promise<Proof> {
  const input = await actionInput(upgradeAction(request));
  const c = await challenge(mb, { purpose: "key", action: input }, who);
  expectDescribes(mb.id, c, input);
  return { challengeId: c.id, answer: await openChallenge(mb.id, c, mailboxKey) };
}

/**
 * A key proof turned into a session (B6): with a kept device's signature
 * (F2), or with a factor proof bound to open-session for this very session
 * challenge (F1, F11; D38), or, while sessions are optional, alone.
 */
export async function openSession(
  mb: TestMailbox,
  mailboxKey: CryptoKeyPair,
  opts: Who & { device?: TestDevice; factor?: TestFactor } = {},
): Promise<{ session: string; expiresAt: string; device: string | null }> {
  const c = await challenge(mb, { purpose: "session" }, opts);
  const answer = await openChallenge(mb.id, c, mailboxKey);
  const device = opts.device === undefined ? {} : { device: { id: opts.device.id, signature: await signProof(mb.id, opts.device, c) } };
  const factor = opts.factor === undefined ? {} : { factorProof: await factorProof(mb, opts.factor, openSessionAction(c.id), opts) };
  return valueOf(await mail().openSession(await capFor(mb, opts), { challengeId: c.id, answer, ...device, ...factor }));
}

/** The upgrade's entry for one factor (B5): its keys, its admission, and a tag under the active key. */
export function factorInput(factor: TestFactor, tagKeyId: string, admission: FactorAdmission, over: Record<string, unknown> = {}) {
  return { id: factor.id, factorKey: b64u(factor.publicKey), signingKey: b64u(factor.signingKey), admission, tag: fakeTag(), tagKeyId, ...over }; // pragma: allowlist secret (a public Ed25519 key)
}

/** B5's upgrade request for `factors`, with A11's cycle of admissions. */
export async function upgradeRequest(mb: TestMailbox, factors: TestFactor[], tagKeyId: string) {
  const admissions = await cycleAdmissions(mb.id, factors);
  return { factors: factors.map((f) => factorInput(f, tagKeyId, admissions.get(f.id)!)) };
}

/** A mailbox enrolled under spec 001: one key, a recovery wrap and a passkey wrap, sessions optional. */
export async function legacyMailbox(): Promise<{
  mb: TestMailbox;
  mailboxKey: CryptoKeyPair;
  recoveryId: string;
  passkeyId: string;
  recovery: () => Promise<TestFactor>;
  passkey: () => Promise<TestFactor>;
}> {
  const mb = await provisionMailbox();
  const passkey = passkeyWrap(mb.key!.keyId, { label: "Phone" });
  valueOf(await mail().addWrap(await capFor(mb), passkey));
  const view = valueOf(await mail().mailbox(await capFor(mb)));
  const recovery = view.wraps.find((w) => w.kind === "recovery")!;
  return {
    mb,
    mailboxKey: await mailboxKeyPair(mb.key!),
    recoveryId: recovery.id,
    passkeyId: passkey.id,
    recovery: () => factorOf(recovery),
    passkey: () => factorOf(passkey),
  };
}

export interface Upgraded {
  mb: TestMailbox;
  mailboxKey: CryptoKeyPair;
  /** The session the upgrade ran in (F5), of acc_owner. */
  session: string;
  recovery: TestFactor;
  passkey: TestFactor;
}

/** F5: a legacy mailbox, a session opened with a key proof, then the upgrade (every factor, B5) with a key proof bound to it. */
export async function upgradedMailbox(): Promise<Upgraded> {
  const legacy = await legacyMailbox();
  const recovery = await legacy.recovery();
  const passkey = await legacy.passkey();
  const { mb, mailboxKey } = legacy;
  const { session } = await openSession(mb, mailboxKey);
  const request = await upgradeRequest(mb, [recovery, passkey], mb.key!.keyId);
  valueOf(await mail().upgrade(await capFor(mb), request, { session, keyProof: await keyProof(mb, mailboxKey, request) }));
  return { mb, mailboxKey, session, recovery, passkey };
}

/** F11: a session with a key proof and a factor proof (a browser unlocked with the recovery key alone, R5). */
export const plainSession = async (u: Upgraded, factor: TestFactor = u.recovery, who: Who = {}) => (await openSession(u.mb, u.mailboxKey, { factor, ...who })).session;

/** The key new mail is sealed to, as mailbox() shows it. */
export async function activeKeyId(mb: TestMailbox): Promise<string> {
  return valueOf(await mail().mailbox(await capFor(mb))).keys.find((k) => k.retiredAt === null)!.keyId;
}

/** F1's request: the device admitted by `factor`, its unlock key signed, a seal of the active key. */
export async function registerRequest(u: Pick<Upgraded, "mb">, device: TestDevice, factor: TestFactor, over: Record<string, unknown> = {}) {
  return {
    device: await deviceInput(u.mb.id, device, await activeKeyId(u.mb), factor, over),
    seal: device.unlockKey === null ? null : fakeSeal(142),
  };
}

/** F1's last step: registerDevice with a factor proof bound to it, in `session` (the upgrade's own by default). */
export async function keepDevice(
  u: Upgraded,
  opts: { device?: TestDevice; factor?: TestFactor; session?: string; sub?: string } = {},
): Promise<TestDevice> {
  const device = opts.device ?? (await newDevice());
  const factor = opts.factor ?? u.recovery;
  const request = await registerRequest(u, device, factor);
  const who = opts.sub === undefined ? {} : { sub: opts.sub };
  const proof = await factorProof(u.mb, factor, registerAction(request), who);
  valueOf(await mail().registerDevice(await capFor(u.mb, who), request, { session: opts.session ?? u.session, factorProof: proof }));
  return device;
}

/**
 * F6's request, made as the browser makes it from a fresh view: a new key
 * pair, its successor seal, the transition signed by `signer`, a seal of the
 * new key to every remaining device with an unlock key and every factor with
 * a factor key, and a tag for every remaining device and keyed factor. Seals
 * and tags are of the right shape only; Mail checks shapes and coverage,
 * never their contents.
 */
export async function rotationFor(mb: TestMailbox, removed: string | string[], signer: TestFactor) {
  const deviceIds = typeof removed === "string" ? [removed] : removed;
  const view = valueOf(await mail().mailbox(await capFor(mb)));
  const from = view.keys.find((k) => k.retiredAt === null)!.keyId;
  const next = await newKeyPair();
  const others = view.devices.filter((d) => !deviceIds.includes(d.id));
  const factors = view.wraps.filter((w) => w.factorKey !== null);
  const rotation = {
    from,
    publicKey: b64u(next.publicKey),
    successorSeal: fakeSeal(109),
    transition: await signTransition(mb.id, signer, from, next),
    seals: [
      ...others.filter((d) => d.unlockKey !== null).map((d) => ({ to: { kind: "device" as const, id: d.id }, sealed: fakeSeal(142) })),
      ...factors.map((f) => ({ to: { kind: "factor" as const, id: f.id }, sealed: fakeSeal(109) })),
    ],
    tags: [
      ...others.map((d) => ({ to: { kind: "device" as const, id: d.id }, tag: fakeTag() })),
      ...factors.map((f) => ({ to: { kind: "factor" as const, id: f.id }, tag: fakeTag() })),
    ],
  };
  return { next, rotation, deviceIds };
}

/** F6: removeDevices with `factor`'s proof bound to exactly this request. */
export async function removeDevices(u: Pick<Upgraded, "mb">, request: { deviceIds: string[]; rotation: unknown }, session: string, factor: TestFactor, who: Who = {}) {
  return mail().removeDevices(await capFor(u.mb, who), request, { session, factorProof: await factorProof(u.mb, factor, removeDevicesAction(request), who) });
}

/** A wrap a browser adds once sessions are required (B7): of the active key, with its keys, its admission by `admitter` and by itself, and a tag. */
export async function keyedWrap(
  mb: TestMailbox,
  kind: "passkey-prf" | "recovery",
  keyId: string,
  admitter: TestFactor,
  over: Record<string, unknown> = {},
  record: { id?: string } = {},
) {
  const named = record.id === undefined ? {} : { id: record.id };
  const plain = kind === "recovery" ? recoveryWrap(keyId, { label: "Printed sheet", ...named }) : passkeyWrap(keyId, { label: "Laptop", ...named });
  const factor = await factorOf(plain as { id: string; kind: string; label: string; credentialId?: string | null });
  const admission = await admitFactor(mb.id, factor, admitter);
  return { factor, wrap: { ...plain, factorKey: b64u(factor.publicKey), signingKey: b64u(factor.signingKey), admission, tag: fakeTag(), tagKeyId: keyId, ...over } }; // pragma: allowlist secret (a public Ed25519 key)
}

// ---- B7a: an email code, as the dashboard attests it (capability-v1 `confirmation`) ----------------

/** The attestation the dashboard copies into the capability (action-descriptor-v1), for a challenge's descriptor. */
export interface TestAttestation {
  method: string;
  accountId: string;
  actionKind: string;
  actionDigest: string;
  at: number;
  codeId: string;
}

/**
 * F13 up to the dashboard: an email challenge for revoking `deviceIds`, and the attestation the dashboard
 * makes once the person typed the code (checked moments ago, by Mail's clock), for `who`'s account.
 */
export async function emailConfirmation(
  mb: TestMailbox,
  deviceIds: string[],
  who: Who = {},
): Promise<{ challenge: ChallengeView; attestation: TestAttestation }> {
  const c = await challenge(mb, { purpose: "email", action: { kind: "revoke-device", deviceIds } }, who);
  const attestation = {
    method: "email-code",
    accountId: who.sub ?? "acc_owner",
    actionKind: "revoke-device",
    actionDigest: await descriptorDigest(c),
    at: Math.floor(mb.ports.clock.now().getTime() / 1000),
    codeId: `code_${crypto.randomUUID().replace(/-/g, "")}`,
  };
  return { challenge: c, attestation };
}

/** A capability carrying an email code's attestation for revoking `deviceIds` (the dashboard's one server action, F13). */
export async function emailCode(u: Pick<Upgraded, "mb">, deviceIds: string[], who: Who = {}): Promise<string> {
  const { attestation } = await emailConfirmation(u.mb, deviceIds, who);
  return capFor(u.mb, { ...who, confirmation: attestation });
}
