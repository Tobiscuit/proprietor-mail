// Round 3, model finding 1 (spec 002 D39; contracts/device-v1.md Part C K2″): someone who copied the
// mailbox key from a device before it was removed, together with whoever controls the server, forks the
// key chain from that copied key. Every cryptographic check of round 2 passes for the fork: the successor
// seal of the copied key is real (they hold it), the new key is sealed to every recipient and every tag
// is made under it (they hold that too). Only K2″ refuses it: no factor the browser trusts signed the step.
import { describe, expect, test } from "vitest";
import { KeySubstitutionDetected, memoryDeviceStore, resumeDevice, unlockWithPasskey, unlockWithRecoveryKey, type LockAfter } from "../src/index";
import { openSession, OWNER, proofFor } from "./flows";
import { activeKeyByRecovery, enrolledMailbox, forkFrom, type Enrolled } from "./keyring-support";

async function keepBrowser(e: Enrolled, label: string, lockAfter: LockAfter = "sign-out") {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "s" });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label, lockAfter }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return { store, unlocked, session, deviceId: pending.request.device.id };
}

/** The setting: devices A, X and Y kept under K1; X's key K1 is copied; A removes X (K1 → K2); Y has not loaded since. */
async function afterRemoval() {
  const e = await enrolledMailbox();
  const a = await keepBrowser(e, "Office laptop");
  const x = await keepBrowser(e, "Stolen laptop");
  const y = await keepBrowser(e, "Home desktop");
  const k1 = { keyId: e.fake.activeKey.keyId, key: await activeKeyByRecovery(e.fake, e.recoveryKey) }; // what X's holder copied
  const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
  const pending = await a.unlocked.removeDevices(e.fake.mailbox(), [x.deviceId], ff);
  await e.fake.removeDevices(pending.request, { session: a.session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return { e, a, x, y, k1 };
}

describe("K2″: a forked chain from a key copied off a removed device is refused", () => {
  test("the honest chain is accepted: Y resumes onto K2, each step signed by a trusted factor", async () => {
    const { e, y } = await afterRemoval();
    const r = await resumeDevice(e.fake.mailbox(), { store: y.store, accountId: OWNER, signInId: "s" });
    expect(r.state).toBe("unlocked");
  });

  test.each(["none", "signed by a key of their own"] as const)("at resume: Y opens its seal of the fork's key and the chain back to K1 opens, but the step's transition (%s) is no trusted factor's: KeySubstitutionDetected", async (transition) => {
    const { e, y, k1 } = await afterRemoval();
    await forkFrom(e.fake, k1, transition);
    const view = e.fake.mailbox();
    expect(view.keys.map((k) => k.keyId)).toContain(k1.keyId);
    await expect(resumeDevice(view, { store: y.store, accountId: OWNER, signInId: "s" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
    // Y's record still holds K1: nothing was accepted.
    expect((await y.store.get(e.mailboxId, OWNER))!.lastKeyId).toBe(k1.keyId);
  });

  test.each(["none", "signed by a key of their own"] as const)("at a factor unlock: the recovery key's wrap is of K1, its seal of the fork's key opens, the chain opens, and the step (%s) is refused", async (transition) => {
    const { e, k1 } = await afterRemoval();
    await forkFrom(e.fake, k1, transition);
    await expect(unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).rejects.toBeInstanceOf(KeySubstitutionDetected);
    await expect(unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials as never })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });
});
