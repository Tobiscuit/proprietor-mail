// D1d/D1e and round 3, the edges: refresh(view), a lock made by another page of the same browser,
// FreshFactors dropped at lock, the upgrade's preconditions (M20), and F6's K3′ on the remaining
// recipients (a device the server slipped in after the unlock is flagged, and goes in the rotation).
import { describe, expect, test } from "vitest";
import { MailboxChanged, memoryDeviceStore, resumeDevice, unlockWithRecoveryKey } from "../src/index";
import { openSession, OWNER, proofFor } from "./flows";
import { enrolledMailbox, rotateByHand, testClock, type Enrolled } from "./keyring-support";
import { b64url, passkeyOptions } from "./support";

async function keep(e: Enrolled, store = memoryDeviceStore(), now?: () => number, lockAfter?: "15-minutes") {
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "s", ...(now ? { now } : {}) });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label: "Laptop", ...(lockAfter ? { lockAfter } : {}) }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return { unlocked, session, store, deviceId: pending.request.device.id };
}

describe("refresh(view)", () => {
  test("adopts a newer view of the same key after K3′: a passkey added by another browser can then be used here", async () => {
    const e = await enrolledMailbox();
    const here = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const elsewhere = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const { session } = await openSession(e.fake, elsewhere);
    const ff = elsewhere.freshFactor!;
    const added = await elsewhere.addPasskey(passkeyOptions(e.credentials, { label: "New key" }), ff);
    await e.fake.addWrap(added.request, { session, factorProof: await proofFor(e.fake, ff, added) });
    await here.refresh(e.fake.mailbox());
    expect(here.flagged).toEqual({ devices: [], factors: [] }); // admitted by a factor this session trusts
    e.credentials.options = { pick: 1 }; // the person uses the new key, listed second
    const viaNew = await here.reauthenticate({ passkey: { rpId: "example.com", credentials: e.credentials } }); // pragma: allowlist secret (a test double or a public test key, not a secret)
    expect(viaNew.factorId).toBe(added.request.id);
  });

  test("a view with forged tags is taken with its recipients flagged (K3′); a view of another key is MailboxChanged", async () => {
    const e = await enrolledMailbox();
    const here = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const view = e.fake.mailbox();
    await here.refresh({ ...view, wraps: view.wraps.map((w) => ({ ...w, tag: b64url(new Uint8Array(32)) })) });
    expect([...here.flagged.factors].sort()).toEqual(view.wraps.map((w) => w.id).sort());
    await here.refresh(view);
    expect(here.flagged).toEqual({ devices: [], factors: [] });
    await rotateByHand(e.fake, e.recoveryKey);
    await expect(here.refresh(e.fake.mailbox())).rejects.toBeInstanceOf(MailboxChanged);
  });
});

describe("the lock engine across pages of one browser", () => {
  test("Lock now in one page reaches another page of the same browser at its next use (K6)", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const store = memoryDeviceStore();
    const a = await keep(e, store, clock);
    const b = await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "s", now: clock });
    if (b.state !== "unlocked") throw new Error(b.state);
    await a.unlocked.lock();
    clock.advance(31_000); // the next activity write is due
    b.mailbox.touch();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(b.mailbox.locked).toBe(true);
  });

  test("a device another page forgot is forgotten here too at the next use", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const store = memoryDeviceStore();
    const a = await keep(e, store, clock);
    await store.delete(e.mailboxId, OWNER);
    clock.advance(31_000);
    a.unlocked.touch();
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(a.unlocked.locked).toBe(true);
    expect(a.unlocked.device).toBeNull();
  });

  test("activity is written to the record, so a timed lock at the next load counts from the last use", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const store = memoryDeviceStore();
    const { unlocked } = await keep(e, store, clock, "15-minutes");
    clock.advance(14 * 60_000);
    unlocked.touch(); // a use, written
    await new Promise((resolve) => setTimeout(resolve, 10));
    clock.advance(14 * 60_000); // 28 minutes after keeping, 14 after the last use
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "s", now: clock })).state).toBe("unlocked");
  });

  test("locking drops the FreshFactors this session made", async () => {
    const e = await enrolledMailbox();
    const here = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const again = await here.reauthenticate({ recoveryKey: e.recoveryKey });
    await here.lock();
    expect(here.freshFactor!.expired).toBe(true);
    expect(again.expired).toBe(true);
  });
});

describe("preconditions the Worker would refuse, refused here first", () => {
  test("keeping a device needs the upgrade first; the upgrade needs that no factor has a key yet (M20)", async () => {
    const legacy = await enrolledMailbox({ legacy: true });
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(legacy.fake.mailbox(), legacy.recoveryKey, { store, accountId: OWNER });
    await expect(unlocked.keepThisDevice({ label: "Laptop" }, unlocked.freshFactor!)).rejects.toBeInstanceOf(TypeError);
    const view = legacy.fake.mailbox();
    const halfDone = { ...view, wraps: view.wraps.map((w, i) => (i === 0 ? { ...w, factorKey: b64url(new Uint8Array(32)) } : w)) };
    // A factor key without its tag is K3′'s anomaly: that factor is flagged, and the upgrade refuses (a factor has a key).
    const other = await unlockWithRecoveryKey(halfDone, legacy.recoveryKey);
    expect(other.flagged).toEqual({ devices: [], factors: [view.wraps[0]!.id] });
    await expect(other.upgradeRequest([other.freshFactor!])).rejects.toBeInstanceOf(TypeError);
  });
});

describe("F6: K3′ on the remaining recipients", () => {
  test("a device the server slipped in after the unlock is flagged and goes in the rotation (D40), never sealed or tagged to", async () => {
    const e = await enrolledMailbox();
    const a = await keep(e);
    const signing = new Uint8Array(65).fill(5);
    signing[0] = 4;
    const intruder = {
      id: "dev_00000000000000000000000000",
      label: "Not the owner's",
      signingKey: b64url(signing), // pragma: allowlist secret (a test double or a public test key, not a secret)
      unlockKey: null,
      unlockSignature: null,
      admission: null,
      tag: b64url(new Uint8Array(32)),
      tagKeyId: e.fake.activeKey.keyId,
      createdAt: "2026-10-16T12:00:00.000Z",
      createdBy: "server",
      lastSeenAt: null,
      accountId: "acc_owner",
    };
    e.fake.devices.push(intruder);
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const pending = await a.unlocked.removeDevices(e.fake.mailbox(), [intruder.id], ff);
    expect(pending.request.rotation.tags.map((t) => t.to.id)).not.toContain(intruder.id);
    await e.fake.removeDevices(pending.request, { session: a.session, factorProof: await proofFor(e.fake, ff, pending) });
    await pending.commit();
    // Now that it is gone, nothing is flagged at a fresh unlock.
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).flagged).toEqual({ devices: [], factors: [] });
  });
});
