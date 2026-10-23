// Test support for spec 002: a mailbox enrolled on the fake Mail, and key-ring changes made
// straight from mail-crypto, independently of mail-client's own code: an honest rotation (as
// another browser that holds the key and the recovery key would make it, per device-v1 A4/A5/B7,
// its transition signed by the recovery factor, A11), a server that substitutes a key of its own (it
// can seal to any public key, and tag under a key it made), and round 3's attacks: a fork made with
// a key copied from a removed device, and a device planted with a genuine tag but no admission.
import {
  bindingKey,
  bindingTag,
  deriveFactorKey,
  factorPublicKey,
  factorSigningKey,
  generateMailboxKey,
  generateSigningKey,
  generateUnlockKey,
  bootstrapAdmitters,
  newId,
  openKeySeal,
  parseRecoveryKey,
  prfInput,
  sealKey,
  signStatement,
  unwrapPrivateKey,
  type FactorPrivateKey,
  type MailboxPrivateKey,
} from "@proprietor/mail-crypto";
import { startEnrollment, type DeviceView, type EnrollRequest } from "../src/index";
import { FakeMail } from "./fake-mail";
import { b64url, CredentialsDouble, fromB64url, passkeyOptions } from "./support";

/** A clock the tests move by hand, in milliseconds since the epoch. */
export function testClock(start = Date.parse("2026-10-16T12:00:00.000Z")) {
  let t = start;
  const now = () => t;
  return Object.assign(now, { advance: (ms: number) => void (t += ms), set: (ms: number) => void (t = ms) });
}

export interface Enrolled {
  fake: FakeMail;
  mailboxId: string;
  recoveryKey: string;
  credentials: CredentialsDouble; // pragma: allowlist secret (field names and public values, not secrets)
  request: EnrollRequest;
}

/**
 * A mailbox enrolled through startEnrollment and the fake. `legacy` strips the factor keys, as a
 * mailbox enrolled under spec 001 has none (sessions stay optional).
 */
export async function enrolledMailbox(options: { passkey?: boolean; legacy?: boolean; now?: () => number } = {}): Promise<Enrolled> {
  const credentials = new CredentialsDouble();
  const mailboxId = newId("mbx");
  const enrollment = await startEnrollment({ id: mailboxId, address: "hello@example.com", status: "provisioned" }, options.passkey === false ? null : passkeyOptions(credentials));
  const symbols = enrollment.recoveryKey.replace(/-/g, "");
  enrollment.confirmRecovery(enrollment.recoveryCheck.positions.map((p) => symbols[p - 1]).join(""));
  let request = enrollment.request();
  if (options.legacy) {
    request = { publicKey: request.publicKey, wraps: request.wraps.map(({ factorKey: _f, signingKey: _s, admission: _a, tag: _t, tagKeyId: _k, ...w }) => w) };
  }
  const fake = new FakeMail({ mailboxId, ...(options.now ? { now: options.now } : {}) });
  await fake.enroll(request);
  const recoveryKey = enrollment.recoveryKey;
  enrollment.discard();
  return { fake, mailboxId, recoveryKey, credentials, request };
}

/** The active key, wrappable, as the holder of the recovery key opens it (its wrap, or its seal). */
export async function activeKeyByRecovery(fake: FakeMail, recoveryKey: string): Promise<MailboxPrivateKey> {
  const secret = parseRecoveryKey(recoveryKey); // pragma: allowlist secret (a test variable)
  const active = fake.activeKey;
  for (const w of fake.wraps.filter((x) => x.kind === "recovery")) {
    try {
      if (w.keyId === active.keyId) return await unwrapPrivateKey({ id: w.id, keyId: w.keyId, kind: "recovery", wrapped: w.wrapped }, { mailboxId: fake.mailboxId, secret }, { wrappable: true });
      const seal = fake.seals.find((s) => s.keyId === active.keyId && s.to.kind === "factor" && s.to.id === w.id);
      if (seal === undefined) continue;
      const factorKey = await deriveFactorKey({ mailboxId: fake.mailboxId, factorId: w.id, kind: "recovery", secret });
      return await openKeySeal({ kind: "factor", key: factorKey }, { mailboxId: fake.mailboxId, sealedKeyId: active.keyId }, seal.sealed, { wrappable: true });
    } catch {
      // another recovery wrap
    }
  }
  throw new Error("the recovery key reaches no active key");
}

/** The recovery factor's own key, as the holder of the recovery key derives it (A2, A2b). */
export async function recoveryFactorKey(fake: FakeMail, recoveryKey: string): Promise<FactorPrivateKey> {
  const secret = parseRecoveryKey(recoveryKey); // pragma: allowlist secret (a test variable)
  for (const w of fake.wraps.filter((x) => x.kind === "recovery")) {
    const key = await deriveFactorKey({ mailboxId: fake.mailboxId, factorId: w.id, kind: "recovery", secret });
    if (w.signingKey === b64url(factorSigningKey(key))) return key;
  }
  throw new Error("no recovery factor of this key");
}

/** Seals `key` to every device with an unlock key and every keyed factor, and tags all of them under it. */
async function sealAndTagAll(fake: FakeMail, key: MailboxPrivateKey, keyId: string): Promise<void> {
  const mailboxId = fake.mailboxId;
  const bk = await bindingKey(key, { mailboxId });
  fake.seals = [];
  for (const d of fake.devices) {
    if (d.unlockKey !== null) {
      fake.seals.push({ keyId, to: { kind: "device", id: d.id }, sealed: await sealKey(key, { mailboxId }, { kind: "device", deviceId: d.id, publicKey: fromB64url(d.unlockKey) }) });
    }
    d.tag = await bindingTag(bk, { kind: "device", deviceId: d.id, label: d.label, signingKey: fromB64url(d.signingKey), unlockKey: d.unlockKey === null ? null : fromB64url(d.unlockKey) }); // pragma: allowlist secret (public keys)
    d.tagKeyId = keyId;
  }
  for (const w of fake.wraps) {
    if (w.factorKey === null || w.factorKey === undefined) continue;
    fake.seals.push({ keyId, to: { kind: "factor", id: w.id }, sealed: await sealKey(key, { mailboxId }, { kind: "factor", factorId: w.id, publicKey: fromB64url(w.factorKey) }) });
    w.tag = await bindingTag(bk, { kind: "factor", factorId: w.id, factorKind: w.kind, label: w.label, factorKey: fromB64url(w.factorKey), credentialId: w.credentialId }); // pragma: allowlist secret (field names and public values, not secrets)
    w.tagKeyId = keyId;
  }
}

/**
 * An honest rotation, made from the contract with mail-crypto: a new key, the old key's successor
 * seal to it, its transition signed by the recovery factor (A11), and a seal and a tag for every
 * recipient. Returns the new key (wrappable).
 */
export async function rotateByHand(fake: FakeMail, recoveryKey: string): Promise<MailboxPrivateKey> {
  const old = fake.activeKey;
  const oldKey = await activeKeyByRecovery(fake, recoveryKey);
  const signer = await recoveryFactorKey(fake, recoveryKey);
  const next = await generateMailboxKey();
  const successorSeal = await sealKey(oldKey, { mailboxId: fake.mailboxId }, { kind: "successor", publicKey: next.publicKey.publicKey });
  const signature = await signStatement(signer, { kind: "transition", mailboxId: fake.mailboxId, fromKeyId: old.keyId, toKeyId: next.publicKey.keyId, toPublicKey: next.publicKey.publicKey, signerId: signer.factorId });
  await sealAndTagAll(fake, next.privateKey, next.publicKey.keyId);
  old.retiredAt = new Date(fake.now()).toISOString();
  old.successor = { keyId: next.publicKey.keyId, sealed: successorSeal, signedBy: signer.factorId, signature };
  fake.keys.push({ keyId: next.publicKey.keyId, publicKey: b64url(next.publicKey.publicKey), createdAt: old.retiredAt, createdBy: fake.accountId, retiredAt: null, successor: null });
  return next.privateKey;
}

/**
 * Round 3, model finding 1 (K2″): someone who copied the key `copied` from a device (since removed) and
 * controls the server forks the chain from it. They make a key of their own, a REAL successor seal of
 * the copied key to it (they hold the copied key), seal it to every recipient and tag everything under
 * it, and show a key ring in which the honest successor of the copied key is gone. No factor signed the
 * step: `transition` says what they put there instead.
 */
export async function forkFrom(fake: FakeMail, copied: { keyId: string; key: MailboxPrivateKey }, transition: "none" | "signed by a key of their own" = "none"): Promise<void> {
  const base = fake.keys.find((k) => k.keyId === copied.keyId)!;
  const mine = await generateMailboxKey();
  const successorSeal = await sealKey(copied.key, { mailboxId: fake.mailboxId }, { kind: "successor", publicKey: mine.publicKey.publicKey });
  // The honest keys after the copied one are dropped from the view; the fork takes their place.
  fake.keys = fake.keys.slice(0, fake.keys.indexOf(base) + 1);
  await sealAndTagAll(fake, mine.privateKey, mine.publicKey.keyId);
  base.retiredAt = new Date(fake.now()).toISOString();
  base.successor = { keyId: mine.publicKey.keyId, sealed: successorSeal };
  if (transition === "signed by a key of their own") {
    // A signing key of their own, named as an existing factor: it is not that factor's listed key.
    const theirs = await deriveFactorKey({ mailboxId: fake.mailboxId, factorId: fake.wraps[0]!.id, kind: fake.wraps[0]!.kind, secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (a random test value)
    base.successor.signedBy = theirs.factorId;
    base.successor.signature = await signStatement(theirs, { kind: "transition", mailboxId: fake.mailboxId, fromKeyId: base.keyId, toKeyId: mine.publicKey.keyId, toPublicKey: mine.publicKey.publicKey, signerId: theirs.factorId });
  }
  fake.keys.push({ keyId: mine.publicKey.keyId, publicKey: b64url(mine.publicKey.publicKey), createdAt: base.retiredAt, createdBy: "server", retiredAt: null, successor: null });
}

/**
 * Round 3, model finding 2 (K3′): someone who holds the active key (a stolen unlocked device, or a copy)
 * and controls the server plants a device with a GENUINE tag under the active key, and an admission no
 * trusted factor made (none, or one signed by a factor key of their own). Its seal is real too.
 */
export async function plantDevice(fake: FakeMail, activeKey: MailboxPrivateKey, admission: "none" | "signed by a key of their own"): Promise<DeviceView> {
  const mailboxId = fake.mailboxId;
  const deviceId = newId("dev");
  const signing = await generateSigningKey();
  const unlock = await generateUnlockKey();
  const bk = await bindingKey(activeKey, { mailboxId });
  const keyId = fake.activeKey.keyId;
  const label = "Planted laptop";
  const unlockSignature = await signStatement(signing.privateKey, { kind: "unlock-key", mailboxId, deviceId, unlockKey: unlock.publicKey });
  let signed: { by: string; signature: string } | null = null;
  if (admission === "signed by a key of their own") {
    const theirs = await deriveFactorKey({ mailboxId, factorId: fake.wraps[0]!.id, kind: fake.wraps[0]!.kind, secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (a random test value)
    signed = { by: theirs.factorId, signature: await signStatement(theirs, { kind: "admit-device", mailboxId, deviceId, label, signingKey: signing.publicKey, admitterId: theirs.factorId }) }; // pragma: allowlist secret (field names and public keys)
  }
  const device = {
    id: deviceId,
    label,
    signingKey: b64url(signing.publicKey), // pragma: allowlist secret (a public key)
    unlockKey: b64url(unlock.publicKey),
    unlockSignature,
    admission: signed,
    tag: await bindingTag(bk, { kind: "device", deviceId, label, signingKey: signing.publicKey, unlockKey: unlock.publicKey }), // pragma: allowlist secret (field names and public keys)
    tagKeyId: keyId,
    createdAt: new Date(fake.now()).toISOString(),
    createdBy: fake.accountId,
    lastSeenAt: null,
    accountId: fake.accountId,
  };
  fake.devices.push(device as never);
  fake.seals.push({ keyId, to: { kind: "device", id: deviceId }, sealed: await sealKey(activeKey, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey }) });
  const { accountId: _a, ...view } = device;
  return view as DeviceView;
}

/**
 * The attack K2′ stops: the server makes a key of its own, seals it to every recipient and tags
 * every recipient under it (it holds that key, so the tags verify), and advertises it as the new
 * active key. It cannot make a real successor seal (that needs the old private key): `successor`
 * says what it puts there instead.
 */
export async function substituteKey(fake: FakeMail, successor: "none" | "a key of its own" | "copied from a real rotation", copied?: { keyId: string; sealed: string }): Promise<void> {
  const old = fake.activeKey;
  const mine = await generateMailboxKey();
  await sealAndTagAll(fake, mine.privateKey, mine.publicKey.keyId);
  old.retiredAt = new Date(fake.now()).toISOString();
  if (successor === "a key of its own") {
    // Its own key, sealed to its new key under info that names the old keyId.
    const other = await generateMailboxKey();
    old.successor = { keyId: mine.publicKey.keyId, sealed: await sealKey(other.privateKey, { mailboxId: fake.mailboxId }, { kind: "successor", publicKey: mine.publicKey.publicKey }) };
  } else if (successor === "copied from a real rotation") {
    old.successor = { keyId: mine.publicKey.keyId, sealed: copied!.sealed };
  } else {
    old.successor = null;
  }
  fake.keys.push({ keyId: mine.publicKey.keyId, publicKey: b64url(mine.publicKey.publicKey), createdAt: old.retiredAt, createdBy: "server", retiredAt: null, successor: null });
}

/** Every factor's own key (A2, A2b), as its holder derives it: the recovery key, and the passkey through the credentials double's PRF. */
export async function factorKeysOf(e: Enrolled): Promise<Map<string, FactorPrivateKey>> {
  const keys = new Map<string, FactorPrivateKey>();
  for (const w of e.fake.wraps) {
    const secret = w.kind === "recovery" ? parseRecoveryKey(e.recoveryKey) : await e.credentials.evaluate(w.credentialId!, await prfInput(e.fake.mailboxId, w.id)); // pragma: allowlist secret (a test variable)
    keys.set(w.id, await deriveFactorKey({ mailboxId: e.fake.mailboxId, factorId: w.id, kind: w.kind, secret }));
  }
  return keys;
}

/**
 * What a buggy registration would leave (K9): the factor `wrapId` listed with a factor key and a signing
 * key that are not the ones its secret derives (they come from another secret), every admission of the
 * cycle made with those keys as a buggy enrollment would make them (so each verifies, A11), and a tag
 * made correctly under the active key. K3′ passes; only the factor itself, when used, can tell. Returns
 * the wrong factor key.
 */
export async function misregisterFactor(e: Enrolled, wrapId: string): Promise<string> {
  const fake = e.fake;
  const active = await activeKeyByRecovery(fake, e.recoveryKey);
  const bk = await bindingKey(active, { mailboxId: fake.mailboxId });
  const keys = await factorKeysOf(e);
  const target = fake.wraps.find((w) => w.id === wrapId)!;
  const wrong = await deriveFactorKey({ mailboxId: fake.mailboxId, factorId: target.id, kind: target.kind, secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (a random test value)
  keys.set(wrapId, wrong);
  target.factorKey = b64url(factorPublicKey(wrong));
  target.signingKey = b64url(factorSigningKey(wrong)); // pragma: allowlist secret (a public key)
  target.tag = await bindingTag(bk, { kind: "factor", factorId: target.id, factorKind: target.kind, label: target.label, factorKey: factorPublicKey(wrong), credentialId: target.credentialId }); // pragma: allowlist secret (field names and public values, not secrets)
  target.tagKeyId = fake.activeKey.keyId;
  // A11's cycle again, with the keys as listed now.
  for (const { factorId, admitterId } of bootstrapAdmitters(fake.wraps.map((w) => w.id))) {
    const w = fake.wraps.find((x) => x.id === factorId)!;
    const admitter = keys.get(admitterId)!;
    const statement = {
      kind: "admit-factor" as const,
      mailboxId: fake.mailboxId,
      factorId,
      factorKind: w.kind,
      label: w.label,
      factorKey: fromB64url(w.factorKey!),
      signingKey: fromB64url(w.signingKey!), // pragma: allowlist secret (a public key)
      credentialId: w.credentialId, // pragma: allowlist secret (field names and public keys)
      admitterId,
      admitterSigningKey: factorSigningKey(admitter), // pragma: allowlist secret (field names and public keys)
    };
    w.admission = { by: admitterId, signature: await signStatement(admitter, statement), selfSignature: await signStatement(keys.get(factorId)!, statement) };
  }
  return target.factorKey;
}
