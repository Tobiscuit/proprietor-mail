// D1e: removing a device rotates the mailbox key (plan.md F6, F10; contracts/device-v1.md B7, M18, M5′).
// The rotating browser checks every remaining recipient's tag (K3), makes a new key, seals the old one
// to it (the successor seal), seals the new one to every remaining device unlock key and factor key, and
// tags them all under it. Mail (the strict fake) applies it in one step; the other kept devices find
// their seal of the new key at their next load, and the removed one wipes itself.
import { describe, expect, test } from "vitest";
import {
  FlaggedRecipient,
  MailboxChanged,
  memoryDeviceStore,
  NoRecoveryFactor,
  resumeDevice,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type DeviceStore,
  type LockAfter,
  type UnlockedMailbox,
} from "../src/index";
import type { FakeMail } from "./fake-mail";
import { enrolledMailbox, testClock, type Enrolled } from "./keyring-support";
import { b64url, fromB64url, sampleHeader } from "./support";

async function openSession(fake: FakeMail, unlocked: UnlockedMailbox) {
  return (await fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })))).session;
}

/** F1 in one browser (its own store): unlock with the recovery key, keep it. */
async function keepBrowser(e: Enrolled, label: string, lockAfter: LockAfter = "sign-out", now?: () => number) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "s", ...(now ? { now } : {}) });
  const session = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label, lockAfter }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId })) });
  await pending.commit();
  return { store, unlocked, session, deviceId: pending.request.device.id };
}

/** F6 from `from`: a fresh factor, a fresh view, the factor proof, the rotation; Mail applies it; commit. */
async function removeFrom(e: Enrolled, from: { unlocked: UnlockedMailbox; session: string }, deviceId: string) {
  const ff = await from.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
  const view = e.fake.mailbox();
  const factorProof = await ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId }));
  const pending = await from.unlocked.removeDevice(view, deviceId, ff);
  const result = await e.fake.removeDevice(pending.request, { session: from.session, factorProof });
  await pending.commit();
  return { pending, result, ff };
}

describe("removeDevice (F6): the rotation", () => {
  test("names exactly the remaining recipients, with Part B's shapes and lengths, and Mail applies it (M18)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const c = await keepBrowser(e, "Library computer", "right-away");
    const old = e.fake.activeKey.keyId;
    const { pending, result } = await removeFrom(e, a, b.deviceId);
    const r = pending.request;
    expect(Object.keys(r).sort()).toEqual(["deviceId", "rotation"]);
    expect(Object.keys(r.rotation).sort()).toEqual(["from", "publicKey", "seals", "successorSeal", "tags"]);
    expect(r.deviceId).toBe(b.deviceId);
    expect(r.rotation.from).toBe(old);
    expect(fromB64url(r.rotation.publicKey).length).toBe(32);
    expect(fromB64url(r.rotation.successorSeal).length).toBe(109);
    const factorIds = e.fake.wraps.map((w) => w.id).sort();
    const named = (list: { to: { kind: string; id: string } }[]) => list.map((x) => `${x.to.kind}:${x.to.id}`).sort();
    // Seals: the devices that keep an unlock key, and every factor with a factor key. Never the removed device; never C (it keeps none).
    expect(named(r.rotation.seals)).toEqual([`device:${a.deviceId}`, ...factorIds.map((id) => `factor:${id}`)].sort());
    for (const s of r.rotation.seals) expect(fromB64url(s.sealed).length).toBe(s.to.kind === "device" ? 142 : 109);
    // Tags: every other device, and every factor with a factor key.
    expect(named(r.rotation.tags)).toEqual([`device:${a.deviceId}`, `device:${c.deviceId}`, ...factorIds.map((id) => `factor:${id}`)].sort());
    expect(result.keyId).toBe(e.fake.activeKey.keyId);
    expect(e.fake.keys.find((k) => k.keyId === old)!.successor!.keyId).toBe(result.keyId);
    expect(e.fake.devices.map((d) => d.id).sort()).toEqual([a.deviceId, c.deviceId].sort());
  });

  test("commit moves this session to the new key: new mail and drafts use it, old mail still opens; this device accepts it", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const before = await e.fake.deliver();
    const old = e.fake.activeKey.keyId;
    const { result } = await removeFrom(e, a, b.deviceId);
    expect(a.unlocked.keyId).toBe(result.keyId);
    expect(a.unlocked.keyIds).toEqual([result.keyId, old]);
    const after = await e.fake.deliver();
    expect(after.item.keyId).toBe(result.keyId);
    const opened = await a.unlocked.openMessages([before.item, after.item]);
    expect(opened.map((m) => m.header?.subject)).toEqual([sampleHeader.subject, sampleHeader.subject]);
    expect((await a.unlocked.sealDraft(null, { to: [], cc: [], bcc: [], subject: "", text: "", inReplyTo: null, references: [] })).keyId).toBe(result.keyId);
    expect((await a.store.get(e.mailboxId))!.lastKeyId).toBe(result.keyId);
    // The caller's own session survives the rotation at Mail; every other session ended.
    expect([...e.fake.mailSessions.values()].map((s) => s.deviceId)).toEqual([a.deviceId]);
    // Lock now still works under the new key: its tag is made under it.
    const { updateDevice } = await a.unlocked.lock();
    await e.fake.updateDevice(updateDevice!, { session: a.session });
  });

  test("the other kept devices open their seal of the new key at their next load and walk back to the key they knew (F2); the removed one wipes itself (F10)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const d = await keepBrowser(e, "Home desktop");
    const old = await e.fake.deliver();
    await removeFrom(e, a, b.deviceId);
    const rd = await resumeDevice(e.fake.mailbox(), { store: d.store, signInId: "s" });
    if (rd.state !== "unlocked") throw new Error(rd.state);
    expect(rd.mailbox.keyIds.length).toBe(2);
    expect((await rd.mailbox.openMessages([old.item]))[0]!.undecryptable).toBe(false);
    // D's old mail session ended with the rotation; a new one opens with the new key.
    expect(typeof (await openSession(e.fake, rd.mailbox))).toBe("string");
    expect(await resumeDevice(e.fake.mailbox(), { store: b.store, signInId: "s" })).toEqual({ state: "removed" });
    expect(await b.store.get(e.mailboxId)).toBeNull();
    // The recovery key and the passkey still reach the new key (their seals), and every older one.
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).keyIds.length).toBe(2);
    expect((await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials })).keyIds.length).toBe(2); // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
  });

  test("removing this device itself: commit wipes it here, and the session goes on with the new key as a shared computer's", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    await keepBrowser(e, "Other");
    const { result } = await removeFrom(e, a, a.deviceId);
    expect(await a.store.get(e.mailboxId)).toBeNull();
    expect(a.unlocked.device).toBeNull();
    expect(a.unlocked.keyId).toBe(result.keyId);
    // Its mail session ended with the device: a new one opens with a key proof alone.
    const proof = await a.unlocked.sessionProof(await e.fake.challenge({ purpose: "session" }));
    expect(proof.device).toBeUndefined();
    expect((await e.fake.openSession(proof)).device).toBeNull();
  });

  test("the FreshFactor follows the rotation: a second removal within its 2 minutes needs no new prompt", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const a = await keepBrowser(e, "Office laptop", "sign-out", clock);
    const b = await keepBrowser(e, "Phone", "sign-out", clock);
    const c = await keepBrowser(e, "Tablet", "sign-out", clock);
    const { ff } = await removeFrom(e, a, b.deviceId);
    const pending = await a.unlocked.removeDevice(e.fake.mailbox(), c.deviceId, ff);
    const factorProof = await ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId }));
    await e.fake.removeDevice(pending.request, { session: a.session, factorProof });
    await pending.commit();
    expect(a.unlocked.keyIds.length).toBe(3);
  });
});

describe("removeDevice refuses before anything is made", () => {
  test("K3: while a remaining recipient's tag fails, nothing is sealed to anyone (FlaggedRecipient)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const view = e.fake.mailbox();
    const forged = { ...view, devices: [...view.devices!, { ...view.devices![0]!, id: "dev_00000000000000000000000000", tag: b64url(new Uint8Array(32)) }] };
    await expect(a.unlocked.removeDevice(forged, b.deviceId, ff)).rejects.toBeInstanceOf(FlaggedRecipient);
    const renamed = { ...view, wraps: view.wraps.map((w) => (w.kind === "passkey-prf" ? { ...w, label: "Renamed by someone" } : w)) };
    await expect(a.unlocked.removeDevice(renamed, b.deviceId, ff)).rejects.toBeInstanceOf(FlaggedRecipient);
  });

  test("M5′: with no recovery factor that has its key, the rotation is refused (NoRecoveryFactor)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const ff = await a.unlocked.reauthenticate({ passkey: { rpId: "example.com", credentials: e.credentials } }); // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
    const view = e.fake.mailbox();
    const noRecoveryKey = { ...view, wraps: view.wraps.map((w) => (w.kind === "recovery" ? { ...w, factorKey: null, tag: null, tagKeyId: null } : w)) };
    await expect(a.unlocked.removeDevice(noRecoveryKey, b.deviceId, ff)).rejects.toBeInstanceOf(NoRecoveryFactor);
  });

  test("a view of another key (another browser rotated first) or without the device is MailboxChanged", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const c = await keepBrowser(e, "Tablet");
    const stale = e.fake.mailbox();
    await removeFrom(e, b, c.deviceId); // B rotates first
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    await expect(a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff)).rejects.toBeInstanceOf(MailboxChanged);
    await expect(a.unlocked.removeDevice(stale, "dev_00000000000000000000000000", ff)).rejects.toBeInstanceOf(MailboxChanged);
  });

  test("Mail refuses a rotation that misses a recipient, names the removed device, or comes from a stale key", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const pending = await a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff);
    const proof = async () => ({ session: a.session, factorProof: await ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId })) });
    const r = pending.request;
    for (const bad of [
      { ...r, rotation: { ...r.rotation, seals: r.rotation.seals.slice(1) } },
      { ...r, rotation: { ...r.rotation, tags: [...r.rotation.tags, { to: { kind: "device" as const, id: b.deviceId }, tag: r.rotation.tags[0]!.tag }] } },
      { ...r, rotation: { ...r.rotation, from: "0".repeat(32) } },
    ]) {
      await expect(e.fake.removeDevice(bad, await proof())).rejects.toThrow(/InvalidRequest/);
    }
    // Nothing changed at Mail, and the real request still applies.
    await e.fake.removeDevice(r, await proof());
    await pending.commit();
  });
});

describe("the session without a store still rotates (a shared computer, with the recovery key)", () => {
  test("R7: the recovery key alone unlocks a new browser and removes a device", async () => {
    const e = await enrolledMailbox();
    const lost = await keepBrowser(e, "Lost laptop");
    const shared = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const session = await openSession(e.fake, shared);
    const ff = shared.freshFactor!;
    const factorProof = await ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId }));
    const pending = await shared.removeDevice(e.fake.mailbox(), lost.deviceId, ff);
    await e.fake.removeDevice(pending.request, { session, factorProof });
    await pending.commit();
    expect(await resumeDevice(e.fake.mailbox(), { store: lost.store as DeviceStore, signInId: "s" })).toEqual({ state: "removed" });
  });
});
