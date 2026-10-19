import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { newId } from "@proprietor/mail-crypto";
import { exports } from "cloudflare:workers";
import type { Role } from "../../src/capability";
import { base64urlFromBytes, bytesFromBase64url } from "./capability-tokens";
import { capFor, newKeyPair, passkeyWrap, provisionMailbox, type TestKey, type TestMailbox } from "./mailbox";
import { valueOf } from "./results";

/**
 * The browser's half of contracts/device-v1.md, done by the tests themselves
 * (the Worker's half is under test): opening challenges (A6) with a mailbox
 * private key or a factor's key, straight on @hpke/core; signing device
 * proofs (A7) with Web Crypto; and well-formed key seals (A4) and binding
 * tags (A5). The Worker checks only the lengths and shapes of seals and tags,
 * so random bytes of the right length stand in for them.
 *
 * `ctx()` is this file's own copy of the contract's rule, so a mistake the
 * Worker shares with mail-crypto cannot make a test pass.
 */

const mail = () => exports.MailService;
const utf8 = (s: string) => new TextEncoder().encode(s);

export const ctx = (label: string, ...parts: string[]) => utf8(`proprietor-mail/v1/${label}|${parts.join("|")}`);

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

/** PKCS #8 PrivateKeyInfo prefix for an X25519 key (RFC 8410), then the 32-byte scalar. */
const PKCS8_X25519 = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20);

export interface ChallengeView {
  id: string;
  purpose: "session" | "factor";
  keyId: string | null;
  factorId: string | null;
  nonce: string;
  sealed: string;
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

/** A factor's key pair (A2 derives it from the factor's secret; here it is simply fresh). */
export interface TestFactor {
  /** The factor's id: its wrap's id. */
  id: string;
  kind: "passkey-prf" | "recovery";
  pair: CryptoKeyPair;
  /** The raw 32-byte X25519 public key, the factorKey Mail stores. */
  publicKey: Uint8Array;
}

export async function newFactorKey(id: string, kind: TestFactor["kind"]): Promise<TestFactor> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  return { id, kind, pair, publicKey: new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer) };
}

/** Opens a challenge exactly as A6 says: HPKE base mode, info "proprietor-mail/v1/challenge", the challenge's aad. Returns the answer, base64url. */
export async function openChallenge(mailboxId: string, challenge: ChallengeView, recipient: CryptoKeyPair): Promise<string> {
  const bytes = bytesFromBase64url(challenge.sealed);
  const targetId = challenge.purpose === "session" ? challenge.keyId! : challenge.factorId!;
  const aad = ctx("challenge", mailboxId, challenge.id, challenge.purpose, targetId);
  const answer = await suite.open({ recipientKey: recipient, enc: bytes.slice(0, 32), info: utf8("proprietor-mail/v1/challenge") }, bytes.slice(32), aad);
  return base64urlFromBytes(new Uint8Array(answer));
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

/** A7: the device's signature over ctx("device-proof", mailboxId, deviceId, challengeId, b64u(nonce)), base64url. */
export async function signProof(mailboxId: string, device: TestDevice, challenge: ChallengeView, signer: CryptoKeyPair = device.signing): Promise<string> {
  const message = ctx("device-proof", mailboxId, device.id, challenge.id, challenge.nonce);
  return base64urlFromBytes(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, message)));
}

/** A seal of the right shape (A4): 0x01 || enc || iv || ct. 142 bytes to a device (P-256), 109 to a factor or a successor (X25519). */
export function fakeSeal(bytes: 142 | 109): string {
  const seal = crypto.getRandomValues(new Uint8Array(bytes));
  seal[0] = 1;
  return base64urlFromBytes(seal);
}

/** A binding tag of the right shape (A5): 32 bytes. */
export const fakeTag = () => base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));

/** DeviceInput (B7) for a device, tagged under `tagKeyId`. */
export function deviceInput(device: TestDevice, tagKeyId: string, over: Record<string, unknown> = {}) {
  return {
    id: device.id,
    label: device.label,
    signingKey: base64urlFromBytes(device.signingKey), // pragma: allowlist secret (a public P-256 point)
    unlockKey: device.unlockKey === null ? null : base64urlFromBytes(device.unlockKey),
    tag: fakeTag(),
    tagKeyId,
    ...over,
  };
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

/** A key proof (and, for a device, its signature) turned into a session: F11, or F2 with `device`. */
export async function openSession(
  mb: TestMailbox,
  mailboxKey: CryptoKeyPair,
  opts: Who & { device?: TestDevice } = {},
): Promise<{ session: string; expiresAt: string; device: string | null }> {
  const c = await challenge(mb, { purpose: "session" }, opts);
  const answer = await openChallenge(mb.id, c, mailboxKey);
  const device = opts.device === undefined ? {} : { device: { id: opts.device.id, signature: await signProof(mb.id, opts.device, c) } };
  return valueOf(await mail().openSession(await capFor(mb, opts), { challengeId: c.id, answer, ...device }));
}

/** A factor proof (B6): a factor challenge, opened with the factor's key. */
export async function factorProof(mb: TestMailbox, factor: TestFactor, who: Who = {}): Promise<Proof> {
  const c = await challenge(mb, { purpose: "factor", factorId: factor.id }, who);
  return { challengeId: c.id, answer: await openChallenge(mb.id, c, factor.pair) };
}

/** The upgrade's entry for one factor (B5): its key and a tag under the active key. */
export function factorInput(factor: TestFactor, tagKeyId: string, over: Record<string, unknown> = {}) {
  return { id: factor.id, factorKey: base64urlFromBytes(factor.publicKey), tag: fakeTag(), tagKeyId, ...over };
}

/** A mailbox enrolled under spec 001: one key, a recovery wrap and a passkey wrap, sessions optional. */
export async function legacyMailbox(): Promise<{ mb: TestMailbox; mailboxKey: CryptoKeyPair; recoveryId: string; passkeyId: string }> {
  const mb = await provisionMailbox();
  const passkey = passkeyWrap(mb.key!.keyId, { label: "Security key" });
  valueOf(await mail().addWrap(await capFor(mb), passkey));
  const view = valueOf(await mail().mailbox(await capFor(mb)));
  return { mb, mailboxKey: await mailboxKeyPair(mb.key!), recoveryId: view.wraps.find((w) => w.kind === "recovery")!.id, passkeyId: passkey.id };
}

export interface Upgraded {
  mb: TestMailbox;
  mailboxKey: CryptoKeyPair;
  /** The session the upgrade ran in (F5), of acc_owner. */
  session: string;
  recovery: TestFactor;
  passkey: TestFactor;
}

/** F5: a legacy mailbox, a session opened with a key proof, then the upgrade, which names every factor (B5). */
export async function upgradedMailbox(): Promise<Upgraded> {
  const { mb, mailboxKey, recoveryId, passkeyId } = await legacyMailbox();
  const recovery = await newFactorKey(recoveryId, "recovery");
  const passkey = await newFactorKey(passkeyId, "passkey-prf");
  const { session } = await openSession(mb, mailboxKey);
  const keyId = mb.key!.keyId;
  valueOf(await mail().upgrade(await capFor(mb), { factors: [factorInput(recovery, keyId), factorInput(passkey, keyId)] }, { session }));
  return { mb, mailboxKey, session, recovery, passkey };
}

/** The key new mail is sealed to, as mailbox() shows it. */
export async function activeKeyId(mb: TestMailbox): Promise<string> {
  return valueOf(await mail().mailbox(await capFor(mb))).keys.find((k) => k.retiredAt === null)!.keyId;
}

/** F1's last step: registerDevice with a factor proof, in `session` (the upgrade's own by default). */
export async function keepDevice(
  u: Upgraded,
  opts: { device?: TestDevice; factor?: TestFactor; session?: string } = {},
): Promise<TestDevice> {
  const device = opts.device ?? (await newDevice());
  const factorProofOf = await factorProof(u.mb, opts.factor ?? u.recovery);
  valueOf(
    await mail().registerDevice(
      await capFor(u.mb),
      { device: deviceInput(device, await activeKeyId(u.mb)), seal: device.unlockKey === null ? null : fakeSeal(142) },
      { session: opts.session ?? u.session, factorProof: factorProofOf },
    ),
  );
  return device;
}

/**
 * F6's request, made as the browser makes it from a fresh view: a new key
 * pair, its successor seal, a seal of the new key to every remaining device
 * with an unlock key and every factor with a factor key, and a tag for every
 * remaining device and keyed factor. Seals and tags are of the right shape
 * only; Mail checks shapes and coverage, never their contents.
 */
export async function rotationFor(mb: TestMailbox, removedDeviceId: string) {
  const view = valueOf(await mail().mailbox(await capFor(mb)));
  const from = view.keys.find((k) => k.retiredAt === null)!.keyId;
  const next = await newKeyPair();
  const others = view.devices.filter((d) => d.id !== removedDeviceId);
  const factors = view.wraps.filter((w) => w.factorKey !== null);
  const rotation = {
    from,
    publicKey: base64urlFromBytes(next.publicKey),
    successorSeal: fakeSeal(109),
    seals: [
      ...others.filter((d) => d.unlockKey !== null).map((d) => ({ to: { kind: "device" as const, id: d.id }, sealed: fakeSeal(142) })),
      ...factors.map((f) => ({ to: { kind: "factor" as const, id: f.id }, sealed: fakeSeal(109) })),
    ],
    tags: [
      ...others.map((d) => ({ to: { kind: "device" as const, id: d.id }, tag: fakeTag() })),
      ...factors.map((f) => ({ to: { kind: "factor" as const, id: f.id }, tag: fakeTag() })),
    ],
  };
  return { next, rotation };
}
