// D1e: the factors' side of spec 002 (plan.md F5, F7, F8, F9; contracts/device-v1.md B5, B7): the
// one-time upgrade of a mailbox enrolled under spec 001, giving a left-out security key its factor key
// later, adding a passkey and replacing the recovery key with factor keys. Every request goes to the
// strict fake Mail with the session and the factor proofs Part B asks for.
import { describe, expect, test } from "vitest";
import {
  FactorExpired,
  memoryDeviceStore,
  NoRecoveryFactor,
  resumeDevice,
  StaleFactor,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type FreshFactor,
  type UnlockedMailbox,
} from "../src/index";
import type { FakeMail } from "./fake-mail";
import { enrolledMailbox, rotateByHand, testClock } from "./keyring-support";
import { fromB64url, passkeyOptions } from "./support";

const prompt = (credentials: unknown) => ({ rpId: "example.com", credentials: credentials as never });

async function openSession(fake: FakeMail, unlocked: UnlockedMailbox) {
  return (await fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })))).session;
}
async function proofOf(fake: FakeMail, ff: FreshFactor) {
  return ff.answer(await fake.challenge({ purpose: "factor", factorId: ff.factorId }));
}

describe("the upgrade (F5, D26): a mailbox enrolled under spec 001", () => {
  test("with the recovery key: factor keys and tags under the active key; Mail turns sessions on; then the browser is kept (F1)", async () => {
    const e = await enrolledMailbox({ legacy: true });
    expect(e.fake.sessionsMode).toBe("optional");
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "s" });
    const session = await openSession(e.fake, unlocked); // a session opens while sessions are optional
    const ff = unlocked.freshFactor!;
    const upgrade = await unlocked.upgradeRequest([ff]);
    expect(Object.keys(upgrade.request)).toEqual(["factors"]);
    expect(upgrade.request.factors.length).toBe(1);
    const [f] = upgrade.request.factors;
    expect(Object.keys(f!).sort()).toEqual(["factorKey", "id", "tag", "tagKeyId"]);
    expect(f!.id).toBe(ff.factorId);
    expect(fromB64url(f!.factorKey).length).toBe(32);
    expect(f!.tagKeyId).toBe(e.fake.activeKey.keyId);
    await e.fake.upgrade(upgrade.request, { session });
    await upgrade.commit();
    expect(e.fake.sessionsMode).toBe("required");
    // F1 from the factor challenge on: the recovery key now has a factor key Mail can check.
    const keep = await unlocked.keepThisDevice({ label: "Office laptop" }, ff);
    await e.fake.registerDevice(keep.request, { session, factorProof: await proofOf(e.fake, ff) });
    await keep.commit();
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: "s" })).state).toBe("unlocked");
  });

  test("with the security key: the screen asks for the recovery key once, and both factors get their keys", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    const session = await openSession(e.fake, unlocked);
    const recovery = await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const upgrade = await unlocked.upgradeRequest([recovery, unlocked.freshFactor!]);
    expect(upgrade.request.factors.map((f) => f.id).sort()).toEqual(e.fake.wraps.map((w) => w.id).sort());
    await e.fake.upgrade(upgrade.request, { session });
    await upgrade.commit();
    // Every tag Mail now holds verifies at the next unlock (K3).
    await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
  });

  test("an upgrade must include a recovery factor (M20): the security key alone is NoRecoveryFactor", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    await expect(unlocked.upgradeRequest([unlocked.freshFactor!])).rejects.toBeInstanceOf(NoRecoveryFactor);
    await expect(unlocked.upgradeRequest([])).rejects.toBeInstanceOf(NoRecoveryFactor);
  });

  test("an expired FreshFactor cannot be used: FactorExpired", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ legacy: true, now: clock });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { now: clock });
    clock.advance(120_000);
    await expect(unlocked.upgradeRequest([unlocked.freshFactor!])).rejects.toBeInstanceOf(FactorExpired);
  });
});

describe("setFactorKey (F9): a security key left out of the upgrade gets its key later", () => {
  test("while its wrap is of the active key: its factor key and tag, no seal; the proof comes from the recovery key", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const session = await openSession(e.fake, unlocked);
    const recovery = unlocked.freshFactor!;
    const up = await unlocked.upgradeRequest([recovery]);
    await e.fake.upgrade(up.request, { session });
    await up.commit();
    const securityKey = await unlocked.reauthenticate({ passkey: prompt(e.credentials) });
    const change = await unlocked.setFactorKey(securityKey, recovery);
    expect(Object.keys(change.request).sort()).toEqual(["factorId", "factorKey", "seal", "tag", "tagKeyId"]);
    expect(change.request.factorId).toBe(securityKey.factorId);
    expect(change.request.seal).toBeNull();
    await e.fake.setFactorKey(change.request, { session, factorProof: await proofOf(e.fake, recovery) });
    await change.commit();
    expect(e.fake.wraps.every((w) => w.factorKey !== null)).toBe(true);
    await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials)); // K3 accepts its tag
  });

  test("after a rotation its wrap is of a retired key: the request seals the active key to it, and then it unlocks the mailbox", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const first = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const s1 = await openSession(e.fake, first);
    const up = await first.upgradeRequest([first.freshFactor!]);
    await e.fake.upgrade(up.request, { session: s1 });
    await rotateByHand(e.fake, e.recoveryKey); // a device removal elsewhere; the security key has no factor key, so no seal
    await expect(unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials))).rejects.toBeInstanceOf(StaleFactor);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const session = await openSession(e.fake, unlocked);
    const securityKey = await unlocked.reauthenticate({ passkey: prompt(e.credentials) });
    const change = await unlocked.setFactorKey(securityKey, unlocked.freshFactor!);
    expect(fromB64url(change.request.seal!).length).toBe(109);
    await e.fake.setFactorKey(change.request, { session, factorProof: await proofOf(e.fake, unlocked.freshFactor!) });
    await change.commit();
    expect((await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials))).keyIds.length).toBe(2);
  });

  test("the proof must come from another factor", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const ff = unlocked.freshFactor!;
    await expect(unlocked.setFactorKey(ff, ff)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("adding a passkey (F8) and replacing the recovery key (F7), with factor keys", () => {
  test("addPasskey: one more prompt; a wrap of the active key with its factor key and tag; Mail adds it with a factor proof; it then reaches every older key", async () => {
    const e = await enrolledMailbox();
    await rotateByHand(e.fake, e.recoveryKey);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const session = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    const wrap = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Phone passkey" }), ff);
    expect(wrap).toMatchObject({ kind: "passkey-prf", keyId: e.fake.activeKey.keyId, label: "Phone passkey", tagKeyId: e.fake.activeKey.keyId });
    expect(fromB64url(wrap.factorKey!).length).toBe(32);
    await e.fake.addWrap(wrap, { session, factorProof: await proofOf(e.fake, ff) });
    // The prompt lists the wraps of the active key first: the new passkey is the one the double "uses".
    const viaPhone = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    expect(viaPhone.keyIds.length).toBe(2);
    expect(viaPhone.freshFactor!.factorId).toBe(wrap.id);
  });

  test("replaceRecoveryKey: a new key shown once, its wrap with its factor key; addWrap then removeWrap of the old, each with a proof from the same FreshFactor", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    const session = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    const old = e.fake.wraps.find((w) => w.kind === "recovery")!.id;
    const { recoveryKey, wrap } = await unlocked.replaceRecoveryKey(ff);
    expect(recoveryKey).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}$/);
    expect(wrap).toMatchObject({ kind: "recovery", credentialId: null, label: "Recovery key" });
    expect(fromB64url(wrap.tag!).length).toBe(32);
    await e.fake.addWrap(wrap, { session, factorProof: await proofOf(e.fake, ff) });
    await e.fake.removeWrap(old, { session, factorProof: await proofOf(e.fake, ff) });
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), recoveryKey)).keyId).toBe(e.fake.activeKey.keyId);
  });

  test("on a mailbox whose sessions are optional, the wraps carry no factor key, as before", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const wrap = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Second" }), unlocked.freshFactor!);
    expect("factorKey" in wrap || "tag" in wrap || "tagKeyId" in wrap).toBe(false);
    await e.fake.addWrap(wrap, {});
  });

  test("an expired FreshFactor is FactorExpired, before any prompt", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { now: clock });
    clock.advance(120_000);
    const before = e.credentials.created.length;
    await expect(unlocked.addPasskey(passkeyOptions(e.credentials), unlocked.freshFactor!)).rejects.toBeInstanceOf(FactorExpired);
    await expect(unlocked.replaceRecoveryKey(unlocked.freshFactor!)).rejects.toBeInstanceOf(FactorExpired);
    expect(e.credentials.created.length).toBe(before);
  });
});
