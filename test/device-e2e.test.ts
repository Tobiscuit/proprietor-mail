import * as mailCrypto from "@proprietor/mail-crypto";
import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { productionPorts } from "../src/wiring";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { incomingEmail, sampleMessage } from "./support/email";
import { capFor, injectPorts, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Spec 002, slices D4 and R3-4 (tasks.md): the two halves together, with real
// crypto on both sides. The browser here is @proprietor/mail-client itself,
// running in workerd with an in-memory device store; the Worker is the real
// MailService and Mailbox with the real sealer and proofs. Nothing is faked
// between them, so every byte format of contracts/device-v1.md and
// action-descriptor-v1, and every request shape of device-v1 Part B as round 3
// amends it, crosses for real: F12, F1, F2, F5, F6, F10 and the planted device
// (plan.md §3, §10.2), and round 3's F13 and F14, the account check (D37,
// K10), a relayed proof (D36), a forked chain (D39) and a copied key without
// a device or factor (D38).
//
// The factor is the recovery key throughout: workerd has no WebAuthn, so a
// passkey's PRF output cannot be had here (mail-client's browser tests use
// passkeys). Where a step stands for the dashboard (minting the capability,
// attesting an email code), the test does it as the dashboard's contract says.

const mail = () => exports.MailService;

/** The account that kept the mailbox's devices (the capability's `sub`), and another member of the business. */
const OWNER = "acc_owner";
const OTHER = "acc_other";

// mail-client is a browser package: its sources need the DOM lib, which this
// workerd program does not have. So it is imported at run time by its name,
// and the calls this test makes are typed here, as contracts/mail-client-v1.md
// (amended 2026-10-22, round 3) gives them. A change to its API still fails
// the run, which is what this test is for.
type View = Record<string, unknown>;
interface ChallengeView {
  id: string;
  purpose: "session" | "factor" | "key" | "email";
  sealed: string | null;
  descriptor: string | null;
  nonce: string;
}
interface FactorProof {
  challengeId: string;
  answer: string;
}
interface Confirmation {
  readonly action: Record<string, unknown>;
  readonly labels: Readonly<Record<string, string>>;
}
interface FreshFactor {
  readonly factorId: string;
  answer(challenge: ChallengeView, confirmation: Confirmation): Promise<FactorProof>;
  dispose(): void;
}
interface ConfirmedChange<T = Record<string, unknown>> {
  readonly request: T;
  readonly confirmation: Confirmation;
  commit(): Promise<void>;
}
interface RemoveDevicesRequest {
  deviceIds: string[];
  rotation: { publicKey: string; seals: { to: { kind: string; id: string } }[] } & Record<string, unknown>;
}
interface UnlockedMailbox {
  readonly keyId: string;
  readonly keyIds: readonly string[];
  readonly device: { readonly id: string; readonly label: string } | null;
  readonly freshFactor: FreshFactor | null;
  readonly flagged: { readonly devices: readonly string[]; readonly factors: readonly string[] };
  readonly rotationDue: { since: string; by: string; devices: string[] } | null;
  sessionConfirmation(challenge: ChallengeView): Promise<Confirmation>;
  sessionProof(challenge: ChallengeView, factorProof?: FactorProof): Promise<Record<string, unknown>>;
  keyProof(challenge: ChallengeView, confirmation: Confirmation): Promise<FactorProof>;
  reauthenticate(reauth: { recoveryKey: string }): Promise<FreshFactor>;
  keepThisDevice(options: { label: string; lockAfter?: "sign-out" }, freshFactor: FreshFactor): Promise<ConfirmedChange>;
  removeDevices(view: View, deviceIds: readonly string[], freshFactor: FreshFactor): Promise<ConfirmedChange<RemoveDevicesRequest>>;
  upgradeRequest(factors: readonly FreshFactor[]): Promise<ConfirmedChange>;
  openMessages(items: unknown[]): Promise<{ undecryptable: boolean; header: { subject: string } | null }[]>;
}
interface KeptDevice {
  mailboxId: string;
  accountId: string;
  deviceId: string;
  signingKey: CryptoKey; // pragma: allowlist secret (a type annotation: a non-extractable key handle)
  unlockKey: CryptoKey | null;
  signingPublic: string;
  unlockPublic: string | null;
  lastKeyId: string;
  trustRoot: string;
  [field: string]: unknown;
}
type KeptDeviceChange = Partial<KeptDevice>;
interface DeviceStore {
  get(mailboxId: string, accountId: string): Promise<KeptDevice | null>;
  put(record: KeptDevice): Promise<void>;
  update(mailboxId: string, accountId: string, deviceId: string, change: KeptDeviceChange): Promise<KeptDevice | null>;
  swapLastKeyId(
    mailboxId: string,
    accountId: string,
    deviceId: string,
    expectedLastKeyId: string,
    change: KeptDeviceChange & { lastKeyId: string },
  ): Promise<{ swapped: boolean; record: KeptDevice | null }>;
  delete(mailboxId: string, accountId: string, deviceId?: string): Promise<void>;
}
type Resumed = { state: "none" | "locked" | "removed" } | { state: "unlocked"; mailbox: UnlockedMailbox };
interface MailClient {
  startEnrollment(
    mailbox: { id: string; address: string; status: "provisioned" },
    passkey: null,
    options: { keep: { store: DeviceStore; accountId: string; label: string; lockAfter: "sign-out"; signInId: string } },
  ): Promise<{
    readonly recoveryKey: string;
    readonly recoveryCheck: { readonly positions: readonly number[] };
    confirmRecovery(characters: string): boolean;
    request(): unknown;
    commit(): Promise<void>;
    unlocked(): UnlockedMailbox;
  }>;
  unlockWithRecoveryKey(view: View, recoveryKey: string, options: { store: DeviceStore; accountId: string; signInId: string }): Promise<UnlockedMailbox>;
  resumeDevice(view: View, options: { store: DeviceStore; accountId: string; signInId: string }): Promise<Resumed>;
  revokeRequest(view: View, deviceIds: readonly string[]): { action: Record<string, unknown>; request: { deviceIds: string[] } };
}
const MAIL_CLIENT: string = "@proprietor/mail-client";
const { startEnrollment, unlockWithRecoveryKey, resumeDevice, revokeRequest } = (await import(/* @vite-ignore */ MAIL_CLIENT)) as MailClient;

/**
 * A kept-device store for this test, keyed by mailbox and account (round 3,
 * K10), with swapLastKeyId's compare-and-swap (K11). mail-client's own
 * memoryDeviceStore() copies records with structuredClone, as IndexedDB does,
 * and workerd cannot clone a CryptoKey; a CryptoKey cannot change, so a
 * shallow copy is the same thing here. The browser itself uses IndexedDB
 * (mail-client's browser tests).
 */
function deviceStore(): DeviceStore & { records: Map<string, KeptDevice> } {
  const records = new Map<string, KeptDevice>();
  const slot = (mailboxId: string, accountId: string) => JSON.stringify([mailboxId, accountId]);
  return {
    records,
    async get(mailboxId, accountId) {
      const r = records.get(slot(mailboxId, accountId));
      return r === undefined ? null : { ...r };
    },
    async put(record) {
      records.set(slot(record.mailboxId, record.accountId), { ...record });
    },
    async update(mailboxId, accountId, deviceId, change) {
      const current = records.get(slot(mailboxId, accountId));
      if (current === undefined || current.deviceId !== deviceId) return null;
      const next = { ...current, ...change };
      records.set(slot(mailboxId, accountId), next);
      return { ...next };
    },
    async swapLastKeyId(mailboxId, accountId, deviceId, expectedLastKeyId, change) {
      const current = records.get(slot(mailboxId, accountId));
      if (current === undefined || current.deviceId !== deviceId || current.lastKeyId !== expectedLastKeyId) {
        return { swapped: false, record: current === undefined ? null : { ...current } };
      }
      const next = { ...current, ...change };
      records.set(slot(mailboxId, accountId), next);
      return { swapped: true, record: { ...next } };
    },
    async delete(mailboxId, accountId, deviceId) {
      const current = records.get(slot(mailboxId, accountId));
      if (current !== undefined && (deviceId === undefined || current.deviceId === deviceId)) records.delete(slot(mailboxId, accountId));
    },
  };
}

/** The real envelope v1 sealer, ids and device-v1 proofs (A6, A7, A11) behind the Mailbox; fake SES and signal, and a clock the test reads. */
async function withRealPorts(mb: TestMailbox): Promise<void> {
  const real = productionPorts(env);
  mb.ports = { ...mb.ports, sealer: real.sealer as typeof mb.ports.sealer, ids: real.ids, proofs: real.proofs };
  await injectPorts(mb.stub, mb.ports);
}

type MailboxView = Awaited<ReturnType<typeof viewOf>>;
async function viewOf(mb: TestMailbox) {
  return valueOf(await mail().mailbox(await capFor(mb)));
}
const asView = (v: unknown): View => v as View;
const activeKeyId = (v: MailboxView) => v.keys.find((k) => k.retiredAt === null)!.keyId;
const mailNow = (mb: TestMailbox) => Math.floor(mb.ports.clock.now().getTime() / 1000);

async function challenge(mb: TestMailbox, request: Record<string, unknown>, sub = OWNER): Promise<ChallengeView> {
  return valueOf(await mail().challenge(await capFor(mb, { sub }), request)) as ChallengeView;
}

/** A factor proof bound to `change` (A10, K4, K12): a factor challenge for its action, answered only for it. */
async function proofFor(mb: TestMailbox, ff: FreshFactor, change: Pick<ConfirmedChange, "confirmation">, sub = OWNER): Promise<FactorProof> {
  return ff.answer(await challenge(mb, { purpose: "factor", factorId: ff.factorId, action: change.confirmation.action }, sub), change.confirmation);
}

/**
 * The mail session for `page` (B6): a kept device's signature (F2); without a
 * device while sessions are required, a factor proof of kind open-session
 * from `ff` (F11, D38); while sessions are optional, the key proof alone.
 */
async function openSession(mb: TestMailbox, page: UnlockedMailbox, opts: { ff?: FreshFactor | null; sub?: string } = {}): Promise<string> {
  const sub = opts.sub ?? OWNER;
  const c = await challenge(mb, { purpose: "session" }, sub);
  let request: Record<string, unknown>;
  if (page.device !== null || (await viewOf(mb)).sessions === "optional") {
    request = await page.sessionProof(c);
  } else {
    const ff = opts.ff === undefined ? page.freshFactor : opts.ff;
    if (ff === null) throw new Error("a deviceless session needs a FreshFactor (D38)");
    const confirmation = await page.sessionConfirmation(c);
    const factorChallenge = await challenge(mb, { purpose: "factor", factorId: ff.factorId, action: confirmation.action }, sub);
    request = await page.sessionProof(c, await ff.answer(factorChallenge, confirmation));
  }
  return valueOf(await mail().openSession(await capFor(mb, { sub }), request)).session;
}

async function deliver(mb: TestMailbox, subject: string): Promise<void> {
  const email = incomingEmail(sampleMessage({ to: mb.address, subject }), { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  expect(email.rejects).toEqual([]);
}

async function inboxItems(mb: TestMailbox, mailSession: string, sub = OWNER) {
  return valueOf(await mail().list(await capFor(mb, { sub }), { folder: "inbox" }, { session: mailSession })).items;
}

async function inboxSubjects(mb: TestMailbox, page: UnlockedMailbox, mailSession: string): Promise<(string | null)[]> {
  const opened = await page.openMessages(await inboxItems(mb, mailSession));
  return opened.map((o) => (o.undecryptable ? null : o.header!.subject)).sort();
}

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

interface Browser {
  store: DeviceStore & { records: Map<string, KeptDevice> };
  page: UnlockedMailbox;
  token: string;
  deviceId: string;
  signInId: string;
}

/** F12: a new mailbox, set up with the recovery key alone, "this device is mine" (A, "Laptop"). */
async function enrolledByClient(): Promise<{ mb: TestMailbox; recoveryKey: string; a: Browser }> {
  const mb = await provisionMailbox({ status: "provisioned" });
  await withRealPorts(mb);
  const store = deviceStore();
  const enrollment = await startEnrollment({ id: mb.id, address: mb.address, status: "provisioned" }, null, {
    keep: { store, accountId: OWNER, label: "Laptop", lockAfter: "sign-out", signInId: "sign-in-a" },
  });
  const symbols = enrollment.recoveryKey.replace(/-/g, "");
  expect(enrollment.confirmRecovery(enrollment.recoveryCheck.positions.map((p) => symbols[p - 1]).join(""))).toBe(true);
  valueOf(await mail().enroll(await capFor(mb), enrollment.request()));
  await enrollment.commit();
  const page = enrollment.unlocked();
  const token = await openSession(mb, page);
  return { mb, recoveryKey: enrollment.recoveryKey, a: { store, page, token, deviceId: page.device!.id, signInId: "sign-in-a" } };
}

/** F1: another browser, unlocked with the recovery key, a session opened with a factor proof (D38), then kept with another (K12). */
async function keptWithRecoveryKey(
  mb: TestMailbox,
  recoveryKey: string,
  label: string,
  signInId: string,
  opts: { store?: Browser["store"]; sub?: string } = {},
): Promise<Browser> {
  const sub = opts.sub ?? OWNER;
  const store = opts.store ?? deviceStore();
  const page = await unlockWithRecoveryKey(asView(await viewOf(mb)), recoveryKey, { store, accountId: sub, signInId });
  const token = await openSession(mb, page, { sub });
  const ff = page.freshFactor!;
  const keep = await page.keepThisDevice({ label, lockAfter: "sign-out" }, ff);
  const device = valueOf(await mail().registerDevice(await capFor(mb, { sub }), keep.request, { session: token, factorProof: await proofFor(mb, ff, keep, sub) }));
  await keep.commit();
  return { store, page, token, deviceId: device.id, signInId };
}

/** F2: the browser comes back on a new page: no prompt, its seal at Mail, its signature on the session. */
async function resumed(mb: TestMailbox, b: Browser, sub = OWNER): Promise<UnlockedMailbox> {
  const r = await resumeDevice(asView(await viewOf(mb)), { store: b.store, accountId: sub, signInId: b.signInId });
  if (r.state !== "unlocked") throw new Error(`expected the device to resume, it is ${r.state}`);
  return r.mailbox;
}

/** A copy of the active key, as code on the page of a kept device could take one (K1′, D24's stated trade): its seal opened with its own unlock key. */
async function keyCopiedFrom(mb: TestMailbox, b: Browser, v: MailboxView, opts: { wrappable?: boolean } = {}) {
  const record = (await b.store.get(mb.id, OWNER))!;
  const keyId = activeKeyId(v);
  const seal = v.seals.find((s) => s.keyId === keyId && s.to.kind === "device" && s.to.id === b.deviceId)!;
  return mailCrypto.openKeySeal(
    { kind: "device", deviceId: b.deviceId, privateKey: record.unlockKey!, publicKey: bytesFromBase64url(record.unlockPublic!) }, // pragma: allowlist secret (a variable holding a non-extractable key handle from the test's own store)
    { mailboxId: mb.id, sealedKeyId: keyId },
    seal.sealed,
    opts,
  );
}

describe("spec 002 end to end: mail-client against the Mail Worker, real crypto both sides", () => {
  it("F12, F2, F1, F6, F10: enroll and keep, keep two more by recovery key, remove one with a factor-signed rotation, the rest walk the chain, the removed one wipes", async () => {
    // F12: the enrolling browser (A) is kept, and the mailbox requires sessions from the start.
    const { mb, recoveryKey, a } = await enrolledByClient();
    expect((await viewOf(mb)).sessions).toBe("required");
    await deliver(mb, "before the removal");
    expect(await inboxSubjects(mb, a.page, a.token)).toEqual(["before the removal"]);

    // F2: A comes back on a new page.
    const resumedA = await resumed(mb, a);
    expect(resumedA.device?.id).toBe(a.deviceId);

    // F1 twice: B (the one that will remove A) and C (a bystander), each with the recovery key alone.
    const b = await keptWithRecoveryKey(mb, recoveryKey, "Work computer", "sign-in-b");
    const c = await keptWithRecoveryKey(mb, recoveryKey, "Home computer", "sign-in-c");
    const before = await viewOf(mb);
    expect(before.devices.map((d) => d.label).sort()).toEqual(["Home computer", "Laptop", "Work computer"]);
    // Every device is admitted by the recovery factor and signed its own unlock key (A11, M25).
    const recoveryId = before.wraps.find((w) => w.kind === "recovery")!.id;
    expect(before.devices.map((d) => d.admission.by)).toEqual([recoveryId, recoveryId, recoveryId]);

    // F6: B removes A, re-authenticated with the recovery key; the transition is the recovery factor's (D39).
    const oldKeyId = activeKeyId(before);
    const ff = await b.page.reauthenticate({ recoveryKey });
    const removal = await b.page.removeDevices(asView(before), [a.deviceId], ff);
    expect(removal.request.deviceIds).toEqual([a.deviceId]);
    const rotated = valueOf(await mail().removeDevices(await capFor(mb), removal.request, { session: b.token, factorProof: await proofFor(mb, ff, removal) }));
    await removal.commit();
    ff.dispose();
    expect(rotated.keyId).not.toBe(oldKeyId);
    expect(b.page.keyId).toBe(rotated.keyId);
    expect((await viewOf(mb)).keys.find((k) => k.keyId === oldKeyId)!.successor).toMatchObject({ keyId: rotated.keyId, signedBy: recoveryId });

    // New mail is sealed to the new key; B reads old and new mail.
    await deliver(mb, "after the removal");
    expect(await inboxSubjects(mb, b.page, b.token)).toEqual(["after the removal", "before the removal"]);

    // C, a bystander, loads: its seal is of the new key, and the signed successor step leads back to the key it knew.
    const resumedC = await resumed(mb, c);
    expect(resumedC.keyId).toBe(rotated.keyId);
    expect(resumedC.keyIds).toContain(oldKeyId);
    // C's old session ended with the rotation; a new one opens with the new key.
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "inbox" }, { session: c.token })).name).toBe("SessionRequired");
    expect(await inboxSubjects(mb, resumedC, await openSession(mb, resumedC))).toEqual(["after the removal", "before the removal"]);

    // F10: A is refused at once, whatever it still holds in memory, and its next load wipes it.
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "inbox" }, { session: a.token })).name).toMatch(/^(SessionRequired|DeviceRevoked)$/);
    // Its page still holds the old key, but a session challenge is sealed to the new key: it cannot answer.
    await expect(resumedA.sessionProof(await challenge(mb, { purpose: "session" }))).rejects.toThrow();
    expect((await resumeDevice(asView(await viewOf(mb)), { store: a.store, accountId: OWNER, signInId: a.signInId })).state).toBe("removed");
    expect(await a.store.get(mb.id, OWNER)).toBeNull();
    // The removed device was never sent the new key.
    expect((await viewOf(mb)).seals.some((s) => s.to.kind === "device" && s.to.id === a.deviceId)).toBe(false);
  });

  it("K3′: a device planted in Mail's storage with a genuine tag but no factor's admission is flagged, never sealed to, and goes with the next removal (D39, D40)", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    const b = await keptWithRecoveryKey(mb, recoveryKey, "Work computer", "sign-in-b");
    await deliver(mb, "readable while flagged");

    // Someone holding a copy of the mailbox key (K1′) and Mail's storage adds a device: its own keys, its own
    // unlock-key signature, a binding tag made with the real key (A5 cannot tell), and an admission no factor made.
    const v = await viewOf(mb);
    const keyId = activeKeyId(v);
    const copy = await keyCopiedFrom(mb, a, v);
    const signing = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const unlock = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])) as CryptoKeyPair;
    const signingKey = new Uint8Array((await crypto.subtle.exportKey("raw", signing.publicKey)) as ArrayBuffer);
    const unlockKey = new Uint8Array((await crypto.subtle.exportKey("raw", unlock.publicKey)) as ArrayBuffer);
    const planted = mailCrypto.newId("dev");
    const tag = await mailCrypto.bindingTag(await mailCrypto.bindingKey(copy, { mailboxId: mb.id }), { kind: "device", deviceId: planted, label: "Laptop", signingKey, unlockKey });
    const unlockMessage = new TextEncoder().encode(`proprietor-mail/v1/unlock-key|${mb.id}|${planted}|${base64urlFromBytes(unlockKey)}`);
    const unlockSig = base64urlFromBytes(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signing.privateKey, unlockMessage)));
    const recoveryId = v.wraps.find((w) => w.kind === "recovery")!.id;
    await sql(
      mb,
      "INSERT INTO devices (id, account_id, label, signing_key, unlock_key, unlock_sig, admission_by, admission_sig, tag, tag_key_id, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      planted,
      OWNER,
      "Laptop",
      signingKey,
      unlockKey,
      unlockSig,
      recoveryId,
      base64urlFromBytes(crypto.getRandomValues(new Uint8Array(64))),
      tag,
      keyId,
      "2026-10-23T00:00:00.000Z",
      OWNER,
    );

    // B loads: no stop screen. The planted device is flagged, and the inbox reads mail as before.
    const resumedB = await resumed(mb, b);
    expect(resumedB.flagged.devices).toEqual([planted]);
    const tokenB = await openSession(mb, resumedB);
    expect(await inboxSubjects(mb, resumedB, tokenB)).toEqual(["readable while flagged"]);

    // Removing A takes every flagged device with it (D40), and seals the new key to neither.
    const ff = await resumedB.reauthenticate({ recoveryKey });
    const removal = await resumedB.removeDevices(asView(await viewOf(mb)), [a.deviceId], ff);
    expect(removal.request.deviceIds).toEqual([a.deviceId, planted].sort());
    expect(removal.request.rotation.seals.map((s) => s.to.id)).not.toContain(planted);
    valueOf(await mail().removeDevices(await capFor(mb), removal.request, { session: tokenB, factorProof: await proofFor(mb, ff, removal) }));
    await removal.commit();
    ff.dispose();
    const after = await viewOf(mb);
    expect(after.devices.map((d) => d.id)).toEqual([b.deviceId]);
    expect(after.seals.some((s) => s.to.id === planted || s.to.id === a.deviceId)).toBe(false);

    // B reads old and new mail on the new key, with nothing flagged.
    await deliver(mb, "after the planted one went");
    const again = await resumed(mb, b);
    expect(again.flagged).toEqual({ devices: [], factors: [] });
    expect(await inboxSubjects(mb, again, await openSession(mb, again))).toEqual(["after the planted one went", "readable while flagged"]);
  });

  it("F5: a mailbox enrolled before spec 002 upgrades with the recovery key and a key proof bound to the upgrade, then keeps the browser", async () => {
    // Enrolled as 001's ceremony does: one key, one envelope v1 recovery wrap, no factor keys.
    const mb = await provisionMailbox({ status: "provisioned" });
    await withRealPorts(mb);
    const { publicKey, privateKey } = await mailCrypto.generateMailboxKey();
    const recovery = mailCrypto.newRecoveryKey();
    const wrap = await mailCrypto.wrapPrivateKey(privateKey, { mailboxId: mb.id, wrapId: mailCrypto.newId("wrp"), kind: "recovery", secret: recovery.secret }); // pragma: allowlist secret (S1's parameter name; a fresh test recovery key)
    valueOf(await mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(publicKey.publicKey), wraps: [{ ...wrap, label: "Recovery key" }] }));
    expect((await viewOf(mb)).sessions).toBe("optional");
    await deliver(mb, "from before the upgrade");

    const store = deviceStore();
    const page = await unlockWithRecoveryKey(asView(await viewOf(mb)), recovery.display, { store, accountId: OWNER, signInId: "sign-in" });
    // While sessions are optional the key proof alone opens one.
    const token = await openSession(mb, page);
    const ff = page.freshFactor!;
    const upgrade = await page.upgradeRequest([ff]);
    // Round 3 (B5, D36): a key challenge whose descriptor names this very upgrade, opened with the mailbox key and its digest.
    const keyProof = await page.keyProof(await challenge(mb, { purpose: "key", action: upgrade.confirmation.action }), upgrade.confirmation);
    valueOf(await mail().upgrade(await capFor(mb), upgrade.request, { session: token, keyProof }));
    await upgrade.commit();
    const upgraded = await viewOf(mb);
    expect(upgraded.sessions).toBe("required");
    // A single factor admits itself (A11).
    expect(upgraded.wraps.map((w) => [w.kind, w.admission?.by])).toEqual([["recovery", wrap.id]]);

    // Now a session is required, and the browser is kept with a factor proof from the factor just upgraded.
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "inbox" })).name).toBe("SessionRequired");
    const keep = await page.keepThisDevice({ label: "Laptop" }, ff);
    valueOf(await mail().registerDevice(await capFor(mb), keep.request, { session: token, factorProof: await proofFor(mb, ff, keep) }));
    await keep.commit();

    const back = await resumeDevice(asView(await viewOf(mb)), { store, accountId: OWNER, signInId: "sign-in" });
    expect(back.state).toBe("unlocked");
    if (back.state !== "unlocked") return;
    expect(await inboxSubjects(mb, back.mailbox, await openSession(mb, back.mailbox))).toEqual(["from before the upgrade"]);
  });

  it("F13 and D38: an email code revokes a device; it is refused at once, a copy of the key opens no session, and a rotation is due", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    const b = await keptWithRecoveryKey(mb, recoveryKey, "Work computer", "sign-in-b");
    const c = await keptWithRecoveryKey(mb, recoveryKey, "Home computer", "sign-in-c");
    const before = await viewOf(mb);
    // What code on B's page could take before B is revoked (K1′): a copy of the active key.
    const copied = await keyCopiedFrom(mb, b, before);

    // F13, on any browser where the owner is signed in, unlocked or not: the devices chosen, Mail's descriptor.
    const revoke = revokeRequest(asView(before), [b.deviceId]);
    const email = await challenge(mb, { purpose: "email", action: revoke.action });
    expect([email.sealed, typeof email.descriptor]).toEqual([null, "string"]);
    // The dashboard reads the action from the very bytes it hashes: the kind, and the labels as Mail holds them.
    const bytes = bytesFromBase64url(email.descriptor!);
    const described = mailCrypto.readActionDescriptor(bytes)!;
    expect([described.kind, described.mailboxId, described.targets]).toEqual(["revoke-device", mb.id, [{ deviceId: b.deviceId, label: "Work computer" }]]);
    // The person types the code; the dashboard checks it and, in the same server action, mints the capability with
    // its attestation (action-descriptor-v1): the account that acts, the kind, the digest of those exact bytes, now.
    const attestation = {
      method: "email-code",
      accountId: OWNER,
      actionKind: described.kind,
      actionDigest: await mailCrypto.actionDigest(bytes),
      at: mailNow(mb),
      codeId: "code_e2e_1",
    };
    const answer = valueOf(await mail().revokeDevices(await capFor(mb, { sub: OWNER, confirmation: attestation }), revoke.request));
    expect(answer).toEqual({ revoked: [b.deviceId] });

    // The device, its seal and its sessions are gone; a rotation is due; no key changed (M22).
    const after = await viewOf(mb);
    expect(after.devices.map((d) => d.id).sort()).toEqual([a.deviceId, c.deviceId].sort());
    expect(after.seals.some((s) => s.to.id === b.deviceId)).toBe(false);
    expect(after.rotationDue).toEqual({ since: mb.ports.clock.now().toISOString(), by: OWNER, devices: [b.deviceId] });
    expect(after.keys).toEqual(before.keys);
    // The same attestation does nothing twice.
    expect(refusalOf(await mail().revokeDevices(await capFor(mb, { sub: OWNER, confirmation: attestation }), revoke.request)).name).toBe("ProofRejected");

    // B is refused at once: its session is gone, its signature names no device, and its next load wipes it.
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "inbox" }, { session: b.token })).name).toBe("SessionRequired");
    const signed = await b.page.sessionProof(await challenge(mb, { purpose: "session" }));
    expect(refusalOf(await mail().openSession(await capFor(mb), signed)).name).toBe("DeviceRevoked");
    expect((await resumeDevice(asView(after), { store: b.store, accountId: OWNER, signInId: b.signInId })).state).toBe("removed");
    expect(await b.store.get(mb.id, OWNER)).toBeNull();

    // D38: the copied key answers a key proof, but with no device and no factor it opens nothing.
    const sessionsBefore = await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions");
    const c1 = await challenge(mb, { purpose: "session" });
    const keyAlone = { challengeId: c1.id, answer: base64urlFromBytes(await mailCrypto.openChallenge(copied, { mailboxId: mb.id, challengeId: c1.id }, c1.sealed!)) };
    expect(refusalOf(await mail().openSession(await capFor(mb), keyAlone)).name).toBe("InvalidRequest");
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual(sessionsBefore);

    // Mail that arrives while the rotation is due still opens on the remaining devices; C sees the rotation due (K13).
    await deliver(mb, "while the rotation is due");
    const resumedC = await resumed(mb, c);
    expect(resumedC.rotationDue).toEqual(after.rotationDue);
    expect(await inboxSubjects(mb, resumedC, await openSession(mb, resumedC))).toEqual(["while the rotation is due"]);
  });

  it("F14: a remaining device's FreshFactor finishes the due rotation; mail from then on opens there, and not with the revoked device's key", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    const b = await keptWithRecoveryKey(mb, recoveryKey, "Work computer", "sign-in-b");
    const c = await keptWithRecoveryKey(mb, recoveryKey, "Home computer", "sign-in-c");
    const before = await viewOf(mb);
    const copied = await keyCopiedFrom(mb, b, before);
    const revoke = revokeRequest(asView(before), [b.deviceId]);
    const email = await challenge(mb, { purpose: "email", action: revoke.action });
    const bytes = bytesFromBase64url(email.descriptor!);
    const attestation = { method: "email-code", accountId: OWNER, actionKind: "revoke-device", actionDigest: await mailCrypto.actionDigest(bytes), at: mailNow(mb), codeId: "code_e2e_2" };
    valueOf(await mail().revokeDevices(await capFor(mb, { confirmation: attestation }), revoke.request));
    await deliver(mb, "during the window");

    // C holds a FreshFactor (it re-authenticates with the recovery key) and finishes the rotation first (K13): no devices.
    const resumedC = await resumed(mb, c);
    expect(resumedC.rotationDue).not.toBeNull();
    const tokenC = await openSession(mb, resumedC);
    const ff = await resumedC.reauthenticate({ recoveryKey });
    const finish = await resumedC.removeDevices(asView(await viewOf(mb)), [], ff);
    expect(finish.request.deviceIds).toEqual([]);
    const rotated = valueOf(await mail().removeDevices(await capFor(mb), finish.request, { session: tokenC, factorProof: await proofFor(mb, ff, finish) }));
    await finish.commit();
    ff.dispose();
    expect(resumedC.rotationDue).toBeNull();
    const after = await viewOf(mb);
    expect(after.rotationDue).toBeNull();
    expect(activeKeyId(after)).toBe(rotated.keyId);
    expect(after.keys.find((k) => k.keyId === activeKeyId(before))!.successor).toMatchObject({ keyId: rotated.keyId, signedBy: after.wraps.find((w) => w.kind === "recovery")!.id });

    // Mail that arrives now opens on C, and on A after it walks the signed step; not with the revoked device's key.
    await deliver(mb, "after the rotation");
    expect(await inboxSubjects(mb, resumedC, tokenC)).toEqual(["after the rotation", "during the window"]);
    const resumedA = await resumed(mb, a);
    expect(resumedA.keyId).toBe(rotated.keyId);
    expect(await inboxSubjects(mb, resumedA, await openSession(mb, resumedA))).toEqual(["after the rotation", "during the window"]);
    const items = await inboxItems(mb, tokenC);
    const newest = items.find((m) => m.keyId === rotated.keyId)!;
    const windowed = items.find((m) => m.keyId === activeKeyId(before))!;
    // The copy opens what arrived during the window (spec §4 states that window) and nothing after it.
    expect((await mailCrypto.openHeader(copied, { mailboxId: mb.id, messageId: windowed.id }, windowed)).subject).toBe("during the window");
    await expect(mailCrypto.openHeader(copied, { mailboxId: mb.id, messageId: newest.id }, newest)).rejects.toThrow();
    // B's page, which still holds the old key in memory, opens the new mail as undecryptable.
    expect((await b.page.openMessages([newest])).map((o) => o.undecryptable)).toEqual([true]);
  });

  it("D37, K10: two accounts on one browser: the second's resume never opens or wipes the first's record, and a forced session with its device is Forbidden", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    const owners = (await a.store.get(mb.id, OWNER))!;

    // Another member, signed in to the dashboard on the same browser profile: one store, another account.
    const resumedOther = await resumeDevice(asView(await viewOf(mb)), { store: a.store, accountId: OTHER, signInId: "sign-in-other" });
    expect(resumedOther.state).toBe("none");
    expect(await a.store.get(mb.id, OWNER)).toEqual(owners);

    // Unlocked with the recovery key on that browser, it binds no device: the owner's record is not opened or touched.
    const otherPage = await unlockWithRecoveryKey(asView(await viewOf(mb)), recoveryKey, { store: a.store, accountId: OTHER, signInId: "sign-in-other" });
    expect(otherPage.device).toBeNull();
    expect([...a.store.records.keys()]).toEqual([JSON.stringify([mb.id, OWNER])]);
    expect(await a.store.get(mb.id, OWNER)).toEqual(owners);

    // A forced session: the other account presents the owner's device with a good signature (made on the owner's page).
    const theirs = await challenge(mb, { purpose: "session" }, OTHER);
    const forced = await a.page.sessionProof(theirs);
    expect((forced as { device?: { id: string } }).device?.id).toBe(a.deviceId);
    const sessions = await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions");
    expect(refusalOf(await mail().openSession(await capFor(mb, { sub: OTHER }), forced))).toEqual({ name: "Forbidden", message: "forbidden" });
    // Forbidden wipes nothing and writes nothing: the record survives, and the owner's device still opens.
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual(sessions);
    expect(await a.store.get(mb.id, OWNER)).toEqual(owners);
    const again = await resumed(mb, a);
    expect(again.device?.id).toBe(a.deviceId);
    await openSession(mb, again);

    // The other account keeps its own device in the same store; each account opens only its own.
    const other = await keptWithRecoveryKey(mb, recoveryKey, "Shared office computer", "sign-in-other", { store: a.store, sub: OTHER });
    expect(a.store.records.size).toBe(2);
    expect((await viewOf(mb)).devices.find((d) => d.id === other.deviceId)!.createdBy).toBe(OTHER);
    expect((await resumed(mb, other, OTHER)).device?.id).toBe(other.deviceId);
    expect((await resumed(mb, a, OWNER)).device?.id).toBe(a.deviceId);
  });

  it("D36: the owner's factor answer for one removal, relayed with another removal or a rotation to another key, is refused and changes nothing", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    const b = await keptWithRecoveryKey(mb, recoveryKey, "Work computer", "sign-in-b");
    const c = await keptWithRecoveryKey(mb, recoveryKey, "Home computer", "sign-in-c");
    const v = await viewOf(mb);
    const ff = await b.page.reauthenticate({ recoveryKey });
    // The owner confirms removing A; whoever relays the answer prepares removing C, and a rotation to a key of its own.
    const removeA = await b.page.removeDevices(asView(v), [a.deviceId], ff);
    const removeC = await b.page.removeDevices(asView(v), [c.deviceId], ff);
    const state = async () => ({ view: await viewOf(mb), keys: await sql(mb, "SELECT * FROM keys ORDER BY created_at"), seals: await sql(mb, "SELECT * FROM key_seals ORDER BY to_kind, to_id") });
    const unchanged = await state();

    const forA = await proofFor(mb, ff, removeA);
    expect(refusalOf(await mail().removeDevices(await capFor(mb), removeC.request, { session: b.token, factorProof: forA })).name).toBe("ProofRejected");
    const anotherKey = { ...removeA.request, rotation: { ...removeA.request.rotation, publicKey: removeC.request.rotation.publicKey } };
    const forAAgain = await proofFor(mb, ff, removeA);
    expect(refusalOf(await mail().removeDevices(await capFor(mb), anotherKey, { session: b.token, factorProof: forAAgain })).name).toBe("ProofRejected");
    expect(await state()).toEqual(unchanged);

    // The browser itself answers nothing for an action it is not sending (K4): A's confirmation does not open C's challenge.
    const forC = await challenge(mb, { purpose: "factor", factorId: ff.factorId, action: removeC.confirmation.action });
    await expect(ff.answer(forC, removeA.confirmation)).rejects.toMatchObject({ name: "InvalidChallenge" });

    // The owner's own request, with a fresh proof for it, goes through.
    valueOf(await mail().removeDevices(await capFor(mb), removeA.request, { session: b.token, factorProof: await proofFor(mb, ff, removeA) }));
    await removeA.commit();
    ff.dispose();
    expect((await viewOf(mb)).devices.map((d) => d.id).sort()).toEqual([b.deviceId, c.deviceId].sort());
  });

  it("D39: a chain forked from a removed device's old key, with genuine seals and tags, is refused at a recovery-key unlock; nothing is sealed to the planted key", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    const b = await keptWithRecoveryKey(mb, recoveryKey, "Work computer", "sign-in-b");
    const v1 = await viewOf(mb);
    const k1 = activeKeyId(v1);
    // Taken from A's page while A was kept (K1′): the key it could open, wrappable, as any code on its origin could ask.
    const oldKey = await keyCopiedFrom(mb, a, v1, { wrappable: true });

    // B removes A: the key rotates to K2, the step signed by the recovery factor.
    const ff = await b.page.reauthenticate({ recoveryKey });
    const removal = await b.page.removeDevices(asView(v1), [a.deviceId], ff);
    valueOf(await mail().removeDevices(await capFor(mb), removal.request, { session: b.token, factorProof: await proofFor(mb, ff, removal) }));
    await removal.commit();
    ff.dispose();
    const v2 = await viewOf(mb);
    const k2 = activeKeyId(v2);

    // Whoever controls Mail's storage, with the old key, forks the chain at K1: a key of its own made K1's successor,
    // sealed to the recovery factor's key and to B, with binding tags made under it. Every seal and tag is genuine;
    // only K1's transition is not one any factor signed for this key (the real one names K2).
    const forked = await mailCrypto.generateMailboxKey();
    const kf = forked.publicKey.keyId;
    const recovery = v2.wraps.find((w) => w.kind === "recovery")!;
    const bListed = v2.devices.find((d) => d.id === b.deviceId)!;
    const successorSeal = await mailCrypto.sealKey(oldKey, { mailboxId: mb.id }, { kind: "successor", publicKey: forked.publicKey.publicKey });
    const toFactor = await mailCrypto.sealKey(forked.privateKey, { mailboxId: mb.id }, { kind: "factor", factorId: recovery.id, publicKey: bytesFromBase64url(recovery.factorKey!) });
    const toB = await mailCrypto.sealKey(forked.privateKey, { mailboxId: mb.id }, { kind: "device", deviceId: b.deviceId, publicKey: bytesFromBase64url(bListed.unlockKey!) });
    const bk = await mailCrypto.bindingKey(forked.privateKey, { mailboxId: mb.id });
    const recoveryTag = await mailCrypto.bindingTag(bk, {
      kind: "factor",
      factorId: recovery.id,
      factorKind: "recovery",
      label: recovery.label,
      factorKey: bytesFromBase64url(recovery.factorKey!),
      credentialId: recovery.credentialId, // pragma: allowlist secret (a field name, not a value)
    });
    const bTag = await mailCrypto.bindingTag(bk, {
      kind: "device",
      deviceId: b.deviceId,
      label: bListed.label,
      signingKey: bytesFromBase64url(bListed.signingKey), // pragma: allowlist secret (a public P-256 point)
      unlockKey: bytesFromBase64url(bListed.unlockKey!),
    });
    await runInDurableObject(mb.stub, (_i, state) => {
      const exec = (q: string, ...args: unknown[]) => state.storage.sql.exec(q, ...args);
      state.storage.transactionSync(() => {
        exec("DELETE FROM key_seals WHERE key_id = ?", k2);
        exec("DELETE FROM keys WHERE key_id = ?", k2);
        exec("UPDATE keys SET successor_key_id = ?, successor_seal = ? WHERE key_id = ?", kf, successorSeal, k1);
        exec("INSERT INTO keys (key_id, public_key, created_at, created_by) VALUES (?, ?, ?, ?)", kf, forked.publicKey.publicKey, "2026-10-23T00:00:00.000Z", OWNER);
        exec("INSERT INTO key_seals (key_id, to_kind, to_id, sealed, created_at, created_by) VALUES (?, 'factor', ?, ?, ?, ?)", kf, recovery.id, toFactor, "2026-10-23T00:00:00.000Z", OWNER);
        exec("INSERT INTO key_seals (key_id, to_kind, to_id, sealed, created_at, created_by) VALUES (?, 'device', ?, ?, ?, ?)", kf, b.deviceId, toB, "2026-10-23T00:00:00.000Z", OWNER);
        exec("UPDATE key_wraps SET tag = ?, tag_key_id = ? WHERE id = ?", recoveryTag, kf, recovery.id);
        exec("UPDATE devices SET tag = ?, tag_key_id = ? WHERE id = ?", bTag, kf, b.deviceId);
      });
    });
    const forkedView = await viewOf(mb);
    expect(activeKeyId(forkedView)).toBe(kf);
    expect(forkedView.keys.find((k) => k.keyId === k1)!.successor).toMatchObject({ keyId: kf, signedBy: recovery.id });
    const sealsPlanted = await sql(mb, "SELECT key_id, to_kind, to_id, sealed FROM key_seals ORDER BY to_kind, to_id");

    // A recovery-key unlock on a new browser refuses it (K2″): the step to the planted key is signed by no factor.
    const fresh = deviceStore();
    await expect(unlockWithRecoveryKey(asView(forkedView), recoveryKey, { store: fresh, accountId: OWNER, signInId: "sign-in-new" })).rejects.toMatchObject({
      name: "KeySubstitutionDetected",
    });
    // So does B, the kept device, which last accepted K2.
    await expect(resumeDevice(asView(forkedView), { store: b.store, accountId: OWNER, signInId: b.signInId })).rejects.toMatchObject({ name: "KeySubstitutionDetected" });
    // Nothing was kept, and nothing was sealed to the planted key but what was planted.
    expect(fresh.records.size).toBe(0);
    expect(await sql(mb, "SELECT key_id, to_kind, to_id, sealed FROM key_seals ORDER BY to_kind, to_id")).toEqual(sealsPlanted);

    // The control: the same planted chain with K1's transition signed by the recovery factor itself is accepted.
    // The signature is the one thing that refused it, and only a holder of a factor can make one.
    const factorKey = await mailCrypto.deriveFactorKey({ mailboxId: mb.id, factorId: recovery.id, kind: "recovery", secret: mailCrypto.parseRecoveryKey(recoveryKey) }); // pragma: allowlist secret (the test's own recovery key, generated at run time)
    const signature = await mailCrypto.signStatement(factorKey, { kind: "transition", mailboxId: mb.id, fromKeyId: k1, toKeyId: kf, toPublicKey: forked.publicKey.publicKey, signerId: recovery.id });
    await sql(mb, "UPDATE keys SET successor_sig = ? WHERE key_id = ?", signature, k1);
    const control = await unlockWithRecoveryKey(asView(await viewOf(mb)), recoveryKey, { store: deviceStore(), accountId: OWNER, signInId: "sign-in-control" });
    expect(control.keyId).toBe(kf);
  });

  it("D38: a page with the mailbox key but no kept device and no factor cannot open a session", async () => {
    const { mb, recoveryKey, a } = await enrolledByClient();
    // A shared computer (no record in its store): unlocked with the recovery key, its FreshFactor then gone.
    const page = await unlockWithRecoveryKey(asView(await viewOf(mb)), recoveryKey, { store: deviceStore(), accountId: OWNER, signInId: "sign-in-shared" });
    expect(page.device).toBeNull();
    page.freshFactor!.dispose();
    const c = await challenge(mb, { purpose: "session" });
    // The browser does not build a session request from the key alone while sessions are required…
    await expect(page.sessionProof(c)).rejects.toThrow();
    // …and Mail refuses one built anyway, from a copy of the mailbox key (K1′): it answers the key proof, and nothing else.
    const copied = await keyCopiedFrom(mb, a, await viewOf(mb));
    const answer = base64urlFromBytes(await mailCrypto.openChallenge(copied, { mailboxId: mb.id, challengeId: c.id }, c.sealed!));
    const sessions = await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions");
    expect(refusalOf(await mail().openSession(await capFor(mb), { challengeId: c.id, answer }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: while sessions are required, a session needs a kept device's signature or a factor proof, exactly one (D38)",
    });
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual(sessions);
    // With a factor proof, the same answer opens one: the factor is what the copy lacks.
    const withFactor = await unlockWithRecoveryKey(asView(await viewOf(mb)), recoveryKey, { store: deviceStore(), accountId: OWNER, signInId: "sign-in-shared" });
    await openSession(mb, withFactor);
  });
});
