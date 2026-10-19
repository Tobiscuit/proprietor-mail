// Test support for spec 002: a mailbox enrolled on the fake Mail, and key-ring changes made
// straight from mail-crypto, independently of mail-client's own code: an honest rotation (as
// another browser that holds the key would make it, per device-v1 A4/A5/B7) and a server that
// substitutes a key of its own (it can seal to any public key, and tag under a key it made).
import {
  bindingKey,
  bindingTag,
  deriveFactorKey,
  factorPublicKey,
  generateMailboxKey,
  newId,
  openKeySeal,
  parseRecoveryKey,
  sealKey,
  unwrapPrivateKey,
  type MailboxPrivateKey,
} from "@proprietor/mail-crypto";
import { startEnrollment, type EnrollRequest } from "../src/index";
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
    request = { publicKey: request.publicKey, wraps: request.wraps.map(({ factorKey: _f, tag: _t, tagKeyId: _k, ...w }) => w) };
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
 * seal to it, and a seal and a tag for every recipient. Returns the new key (wrappable).
 */
export async function rotateByHand(fake: FakeMail, recoveryKey: string): Promise<MailboxPrivateKey> {
  const old = fake.activeKey;
  const oldKey = await activeKeyByRecovery(fake, recoveryKey);
  const next = await generateMailboxKey();
  const successorSeal = await sealKey(oldKey, { mailboxId: fake.mailboxId }, { kind: "successor", publicKey: next.publicKey.publicKey });
  await sealAndTagAll(fake, next.privateKey, next.publicKey.keyId);
  old.retiredAt = new Date(fake.now()).toISOString();
  old.successor = { keyId: next.publicKey.keyId, sealed: successorSeal };
  fake.keys.push({ keyId: next.publicKey.keyId, publicKey: b64url(next.publicKey.publicKey), createdAt: old.retiredAt, createdBy: fake.accountId, retiredAt: null, successor: null });
  return next.privateKey;
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

/**
 * What a buggy registration would leave (K9): the factor `wrapId` listed with a factor key that is not
 * the one its secret derives, and a tag over that wrong key made correctly, under the active key, by a
 * holder of it. K3 passes; only the factor itself, when used, can tell. Returns the wrong key.
 */
export async function misregisterFactor(fake: FakeMail, recoveryKey: string, wrapId: string): Promise<string> {
  const active = await activeKeyByRecovery(fake, recoveryKey);
  const bk = await bindingKey(active, { mailboxId: fake.mailboxId });
  const wrap = fake.wraps.find((w) => w.id === wrapId)!;
  const someoneElse = await deriveFactorKey({ mailboxId: fake.mailboxId, factorId: wrap.id, kind: wrap.kind, secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (a random test value)
  const wrong = factorPublicKey(someoneElse);
  wrap.factorKey = b64url(wrong);
  wrap.tag = await bindingTag(bk, { kind: "factor", factorId: wrap.id, factorKind: wrap.kind, label: wrap.label, factorKey: wrong, credentialId: wrap.credentialId }); // pragma: allowlist secret (field names and public values, not secrets)
  wrap.tagKeyId = fake.activeKey.keyId;
  return wrap.factorKey;
}
