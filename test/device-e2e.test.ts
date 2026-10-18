import * as mailCrypto from "@proprietor/mail-crypto";
import { createExecutionContext } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import type { MailboxPorts } from "../src/ports";
import { productionPorts } from "../src/wiring";
import { base64urlFromBytes } from "./support/capability-tokens";
import { incomingEmail, sampleMessage } from "./support/email";
import { fakePorts } from "./support/fakes";
import { capFor, injectPorts, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Spec 002, slice D4 (tasks.md): the two halves together, with real crypto on
// both sides. The browser here is @proprietor/mail-client itself (slice D1),
// running in workerd with an in-memory device store; the Worker is the real
// MailService and Mailbox (slice D2) with the real sealer and proofs. Nothing
// is faked between them, so every byte format of contracts/device-v1.md and
// every request shape of its Part B crosses for real: F12, F1, F2, F6, F10
// and F5 of plan.md §3.

const mail = () => exports.MailService;

// mail-client is a browser package: its sources need the DOM lib, which this
// workerd program does not have. So it is imported at run time by its name,
// and the few calls this test makes are typed here. A change to its API still
// fails the run, which is what this test is for.
type View = Record<string, unknown>;
interface ChallengeView {
  id: string;
  purpose: "session" | "factor";
}
interface FactorProof {
  challengeId: string;
  answer: string;
}
interface FreshFactor {
  readonly factorId: string;
  answer(challenge: ChallengeView): Promise<FactorProof>;
  dispose(): void;
}
interface PendingChange {
  readonly request: unknown;
  commit(): Promise<void>;
}
interface UnlockedMailbox {
  readonly keyId: string;
  readonly keyIds: readonly string[];
  readonly device: { readonly id: string } | null;
  readonly freshFactor: FreshFactor | null;
  sessionProof(challenge: ChallengeView): Promise<unknown>;
  reauthenticate(reauth: { recoveryKey: string }): Promise<FreshFactor>;
  keepThisDevice(options: { label: string; lockAfter?: "sign-out" }, freshFactor: FreshFactor): Promise<PendingChange>;
  removeDevice(view: View, deviceId: string, freshFactor: FreshFactor): Promise<PendingChange>;
  upgradeRequest(factors: readonly FreshFactor[]): Promise<PendingChange>;
  openMessages(items: unknown[]): Promise<{ undecryptable: boolean; header: { subject: string } | null }[]>;
}
interface KeptDevice {
  mailboxId: string;
  deviceId: string;
}
interface DeviceStore {
  get(mailboxId: string): Promise<KeptDevice | null>;
  put(record: KeptDevice): Promise<void>;
  update(mailboxId: string, deviceId: string, change: Partial<KeptDevice>): Promise<KeptDevice | null>;
  delete(mailboxId: string, deviceId?: string): Promise<void>;
}
interface MailClient {
  startEnrollment(
    mailbox: { id: string; address: string; status: "provisioned" },
    passkey: null,
    options: { keep: { store: DeviceStore; label: string; lockAfter: "sign-out"; signInId: string } },
  ): Promise<{
    readonly recoveryKey: string;
    readonly recoveryCheck: { readonly positions: readonly number[] };
    confirmRecovery(characters: string): boolean;
    request(): unknown;
    commit(): Promise<void>;
    unlocked(): UnlockedMailbox;
  }>;
  unlockWithRecoveryKey(view: View, recoveryKey: string, options: { store: DeviceStore; signInId: string }): Promise<UnlockedMailbox>;
  resumeDevice(view: View, options: { store: DeviceStore; signInId: string }): Promise<{ state: "none" | "locked" | "removed" } | { state: "unlocked"; mailbox: UnlockedMailbox }>;
}
const MAIL_CLIENT: string = "@proprietor/mail-client";
const { startEnrollment, unlockWithRecoveryKey, resumeDevice } = (await import(/* @vite-ignore */ MAIL_CLIENT)) as MailClient;

/**
 * A kept-device store for this test. mail-client's own memoryDeviceStore()
 * copies records with structuredClone, as IndexedDB does, and workerd cannot
 * clone a CryptoKey; a CryptoKey cannot change, so a shallow copy is the same
 * thing here. The browser itself uses IndexedDB (mail-client's browser tests).
 */
function deviceStore(): DeviceStore & { records: Map<string, KeptDevice> } {
  const records = new Map<string, KeptDevice>();
  return {
    records,
    async get(mailboxId) {
      const r = records.get(mailboxId);
      return r === undefined ? null : { ...r };
    },
    async put(record) {
      records.set(record.mailboxId, { ...record });
    },
    async update(mailboxId, deviceId, change) {
      const current = records.get(mailboxId);
      if (current === undefined || current.deviceId !== deviceId) return null;
      const next = { ...current, ...change };
      records.set(mailboxId, next);
      return { ...next };
    },
    async delete(mailboxId, deviceId) {
      const current = records.get(mailboxId);
      if (current !== undefined && (deviceId === undefined || current.deviceId === deviceId)) records.delete(mailboxId);
    },
  };
}

/** The real envelope v1 sealer, ids and device-v1 proofs; fake SES, signal and clock. */
function realPorts(): MailboxPorts {
  const real = productionPorts(env);
  return { ...fakePorts(), sealer: real.sealer, ids: real.ids, proofs: real.proofs };
}

const view = async (mb: TestMailbox) => valueOf(await mail().mailbox(await capFor(mb)));
const asView = (v: unknown): View => v as View;

async function challenge(mb: TestMailbox, request: { purpose: "session" } | { purpose: "factor"; factorId: string }): Promise<ChallengeView> {
  return valueOf(await mail().challenge(await capFor(mb), request));
}

/** F2's tail: a key proof (and the device's signature on a kept device) → a mail session token. */
async function openSession(mb: TestMailbox, session: UnlockedMailbox): Promise<string> {
  const proof = await session.sessionProof(await challenge(mb, { purpose: "session" }));
  return valueOf(await mail().openSession(await capFor(mb), proof)).session;
}

async function deliver(mb: TestMailbox, subject: string): Promise<void> {
  const email = incomingEmail(sampleMessage({ to: mb.address, subject }), { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  expect(email.rejects).toEqual([]);
}

async function inboxSubjects(mb: TestMailbox, session: UnlockedMailbox, mailSession: string): Promise<(string | null)[]> {
  const items = valueOf(await mail().list(await capFor(mb), { folder: "inbox" }, { session: mailSession })).items;
  const opened = await session.openMessages(items);
  return opened.map((o) => (o.undecryptable ? null : o.header!.subject)).sort();
}

/** F12: a new mailbox, set up with the recovery key alone, "this device is mine". */
async function enrolledByClient(): Promise<{ mb: TestMailbox; recoveryKey: string; store: DeviceStore; session: UnlockedMailbox }> {
  const mb = await provisionMailbox({ status: "provisioned" });
  await injectPorts(mb.stub, realPorts());
  const store = deviceStore();
  const enrollment = await startEnrollment({ id: mb.id, address: mb.address, status: "provisioned" }, null, {
    keep: { store, label: "Laptop", lockAfter: "sign-out", signInId: "sign-in-a" },
  });
  const symbols = enrollment.recoveryKey.replace(/-/g, "");
  expect(enrollment.confirmRecovery(enrollment.recoveryCheck.positions.map((p) => symbols[p - 1]).join(""))).toBe(true);
  valueOf(await mail().enroll(await capFor(mb), enrollment.request()));
  await enrollment.commit();
  return { mb, recoveryKey: enrollment.recoveryKey, store, session: enrollment.unlocked() };
}

/** F1: a second browser, unlocked with the recovery key, then kept with a factor proof. */
async function keptWithRecoveryKey(mb: TestMailbox, recoveryKey: string, label: string, signInId: string) {
  const store = deviceStore();
  const session = await unlockWithRecoveryKey(asView(await view(mb)), recoveryKey, { store, signInId });
  const token = await openSession(mb, session);
  const freshFactor = session.freshFactor!;
  const factorProof = await freshFactor.answer(await challenge(mb, { purpose: "factor", factorId: freshFactor.factorId }));
  const pending = await session.keepThisDevice({ label, lockAfter: "sign-out" }, freshFactor);
  const device = valueOf(await mail().registerDevice(await capFor(mb), pending.request, { session: token, factorProof }));
  await pending.commit();
  return { store, session, token, device };
}

describe("spec 002 end to end: mail-client (D1) against the Mail Worker (D2), real crypto both sides", () => {
  it("F12, F1, F2, F6, F10: enroll and keep, keep two more by recovery key, remove one, the rest walk the chain, the removed one wipes", async () => {
    // F12: the enrolling browser (A) is kept, and the mailbox requires sessions from the start.
    const a = await enrolledByClient();
    expect((await view(a.mb)).sessions).toBe("required");
    const tokenA = await openSession(a.mb, a.session);
    await deliver(a.mb, "before the removal");
    expect(await inboxSubjects(a.mb, a.session, tokenA)).toEqual(["before the removal"]);

    // F2: A comes back on a new page: no prompt, its seal at Mail, its signature on the session.
    const resumedA = await resumeDevice(asView(await view(a.mb)), { store: a.store, signInId: "sign-in-a" });
    expect(resumedA.state).toBe("unlocked");
    if (resumedA.state !== "unlocked") return;
    expect(resumedA.mailbox.device?.id).toBe(a.session.device?.id);

    // F1 twice: B (the one that will remove A) and C (a bystander), each with the recovery key alone.
    const b = await keptWithRecoveryKey(a.mb, a.recoveryKey, "Work computer", "sign-in-b");
    const c = await keptWithRecoveryKey(a.mb, a.recoveryKey, "Home computer", "sign-in-c");
    expect((await view(a.mb)).devices.map((d) => d.label).sort()).toEqual(["Home computer", "Laptop", "Work computer"]);

    // F6: B removes A, re-authenticated with the recovery key (no passkey anywhere), and the key rotates.
    const oldKeyId = (await view(a.mb)).keys.find((k) => k.retiredAt === null)!.keyId;
    const freshFactor = await b.session.reauthenticate({ recoveryKey: a.recoveryKey });
    const factorProof = await freshFactor.answer(await challenge(a.mb, { purpose: "factor", factorId: freshFactor.factorId }));
    const removal = await b.session.removeDevice(asView(await view(a.mb)), a.session.device!.id, freshFactor);
    const rotated = valueOf(await mail().removeDevice(await capFor(a.mb), removal.request, { session: b.token, factorProof }));
    await removal.commit();
    freshFactor.dispose();
    expect(rotated.keyId).not.toBe(oldKeyId);
    expect(b.session.keyId).toBe(rotated.keyId);

    // New mail is sealed to the new key; B reads old and new mail.
    await deliver(a.mb, "after the removal");
    expect(await inboxSubjects(a.mb, b.session, b.token)).toEqual(["after the removal", "before the removal"]);

    // C, a bystander, loads: its seal is of the new key, and the successor seal leads back to the key it knew.
    const resumedC = await resumeDevice(asView(await view(a.mb)), { store: c.store, signInId: "sign-in-c" });
    expect(resumedC.state).toBe("unlocked");
    if (resumedC.state !== "unlocked") return;
    expect(resumedC.mailbox.keyId).toBe(rotated.keyId);
    expect(resumedC.mailbox.keyIds).toContain(oldKeyId);
    // C's old session ended with the rotation; a new one opens with the new key.
    expect(refusalOf(await mail().list(await capFor(a.mb), { folder: "inbox" }, { session: c.token })).name).toBe("SessionRequired");
    const tokenC = await openSession(a.mb, resumedC.mailbox);
    expect(await inboxSubjects(a.mb, resumedC.mailbox, tokenC)).toEqual(["after the removal", "before the removal"]);

    // F10: A is refused at once, whatever it still holds in memory, and its next load wipes it.
    expect(refusalOf(await mail().list(await capFor(a.mb), { folder: "inbox" }, { session: tokenA })).name).toMatch(/^(SessionRequired|DeviceRevoked)$/);
    // Its page still holds the old key in memory, but a session challenge is sealed to the new key: it cannot answer.
    await expect(resumedA.mailbox.sessionProof(await challenge(a.mb, { purpose: "session" }))).rejects.toThrow();
    expect((await resumeDevice(asView(await view(a.mb)), { store: a.store, signInId: "sign-in-a" })).state).toBe("removed");
    expect(await a.store.get(a.mb.id)).toBeNull();
    // The removed device was never sent the new key.
    expect((await view(a.mb)).seals.some((s) => s.to.kind === "device" && s.to.id === a.session.device!.id)).toBe(false);
  });

  it("F5: a mailbox enrolled before spec 002 upgrades with the recovery key, then keeps the browser", async () => {
    // Enrolled as 001's ceremony does: one key, one envelope v1 recovery wrap, no factor keys.
    const mb = await provisionMailbox({ status: "provisioned" });
    await injectPorts(mb.stub, realPorts());
    const { publicKey, privateKey } = await mailCrypto.generateMailboxKey();
    const recovery = mailCrypto.newRecoveryKey();
    const wrap = await mailCrypto.wrapPrivateKey(privateKey, { mailboxId: mb.id, wrapId: mailCrypto.newId("wrp"), kind: "recovery", secret: recovery.secret }); // pragma: allowlist secret (S1's parameter name; a fresh test recovery key)
    valueOf(await mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(publicKey.publicKey), wraps: [{ ...wrap, label: "Recovery key" }] }));
    expect((await view(mb)).sessions).toBe("optional");
    await deliver(mb, "from before the upgrade");

    const store = deviceStore();
    const session = await unlockWithRecoveryKey(asView(await view(mb)), recovery.display, { store, signInId: "sign-in" });
    const token = await openSession(mb, session);
    const freshFactor = session.freshFactor!;
    const upgrade = await session.upgradeRequest([freshFactor]);
    valueOf(await mail().upgrade(await capFor(mb), upgrade.request, { session: token }));
    await upgrade.commit();
    expect((await view(mb)).sessions).toBe("required");

    // Now a session is required, and the browser is kept with a factor proof from the factor just upgraded.
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "inbox" })).name).toBe("SessionRequired");
    const factorProof = await freshFactor.answer(await challenge(mb, { purpose: "factor", factorId: freshFactor.factorId }));
    const keep = await session.keepThisDevice({ label: "Laptop" }, freshFactor);
    valueOf(await mail().registerDevice(await capFor(mb), keep.request, { session: token, factorProof }));
    await keep.commit();

    const resumed = await resumeDevice(asView(await view(mb)), { store, signInId: "sign-in" });
    expect(resumed.state).toBe("unlocked");
    if (resumed.state !== "unlocked") return;
    expect(await inboxSubjects(mb, resumed.mailbox, await openSession(mb, resumed.mailbox))).toEqual(["from before the upgrade"]);
  });
});
