// R2-1, contracts/device-v1.md Part C K3 as amended on 2026-10-19: a device or factor whose tag fails
// is FLAGGED, not trusted. It is never sealed to, the session shows it (`flagged`), and it can be
// removed: removing a flagged device is the only rotation allowed while it is there, and a flagged
// factor is removed with removeWrap (a proof from a good factor). The rest of the inbox keeps working,
// because the key itself is trusted (K2′). Only a failure of the key itself (K2, K2′) stops everything.
import { describe, expect, test } from "vitest";
import { newId } from "@proprietor/mail-crypto";
import {
  FlaggedRecipient,
  memoryDeviceStore,
  resumeDevice,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type FreshFactor,
  type UnlockedMailbox,
} from "../src/index";
import type { FakeMail } from "./fake-mail";
import { enrolledMailbox, type Enrolled } from "./keyring-support";
import { b64url, passkeyOptions, sampleHeader } from "./support";

const prompt = (e: Enrolled) => ({ rpId: "example.com", credentials: e.credentials as never });

async function openSession(fake: FakeMail, unlocked: UnlockedMailbox) {
  return (await fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })))).session;
}
async function proofOf(fake: FakeMail, ff: FreshFactor) {
  return ff.answer(await fake.challenge({ purpose: "factor", factorId: ff.factorId }));
}

/** F1 in one browser of its own: unlock with the recovery key, keep it. */
async function keepBrowser(e: Enrolled, label: string) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "s" });
  const session = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofOf(e.fake, ff) });
  await pending.commit();
  return { store, unlocked, session, deviceId: pending.request.device.id };
}

/** A device the server added: its keys are its own, and it cannot make a tag under the mailbox key. */
function serverDevice(fake: FakeMail, withUnlockKey = true): string {
  const point = () => {
    const p = crypto.getRandomValues(new Uint8Array(65));
    p[0] = 0x04;
    return b64url(p);
  };
  const id = newId("dev");
  fake.devices.push({
    id,
    label: "Not the owner's",
    signingKey: point(), // pragma: allowlist secret (random public test values)
    unlockKey: withUnlockKey ? point() : null,
    tag: b64url(crypto.getRandomValues(new Uint8Array(32))),
    tagKeyId: fake.activeKey.keyId,
    createdAt: "2026-10-19T12:00:00.000Z",
    createdBy: "server",
    lastSeenAt: null,
    accountId: fake.accountId,
  });
  return id;
}

/** A factor the server added (a passkey wrap that opens nothing, with a factor key it holds): its tag is forged. */
function serverFactor(fake: FakeMail): string {
  const id = newId("wrp");
  fake.wraps.push({
    id,
    keyId: fake.activeKey.keyId,
    kind: "passkey-prf",
    credentialId: b64url(crypto.getRandomValues(new Uint8Array(16))), // pragma: allowlist secret (random public test values)
    label: "Planted passkey",
    wrapped: b64url(new Uint8Array([1, ...crypto.getRandomValues(new Uint8Array(76))])),
    factorKey: b64url(crypto.getRandomValues(new Uint8Array(32))),
    tag: b64url(crypto.getRandomValues(new Uint8Array(32))),
    tagKeyId: fake.activeKey.keyId,
    createdAt: "2026-10-19T12:00:00.000Z",
    createdBy: "server",
  });
  return id;
}

describe("K3: a device whose tag fails is flagged, and the rest of the inbox works", () => {
  test.each(["recovery key", "passkey"] as const)("a device the server added: an unlock with the %s succeeds, flags it, and opens mail", async (factor) => {
    const e = await enrolledMailbox();
    const intruder = serverDevice(e.fake);
    const view = e.fake.mailbox();
    const unlocked = factor === "passkey" ? await unlockWithPasskey(view, prompt(e)) : await unlockWithRecoveryKey(view, e.recoveryKey);
    expect(unlocked.flagged).toEqual({ devices: [intruder], factors: [] });
    expect(Object.isFrozen(unlocked.flagged)).toBe(true);
    const { item } = await e.fake.deliver();
    expect((await unlocked.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
  });

  test("at resumeDevice on a kept device, the same: it unlocks with no prompt, and the server's device is flagged", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const intruder = serverDevice(e.fake);
    const r = await resumeDevice(e.fake.mailbox(), { store: a.store, signInId: "s" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.flagged).toEqual({ devices: [intruder], factors: [] });
    const { item } = await e.fake.deliver();
    expect((await r.mailbox.openMessages([item]))[0]!.undecryptable).toBe(false);
  });

  test("an honest key ring flags nothing", async () => {
    const e = await enrolledMailbox();
    await keepBrowser(e, "Office laptop");
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).flagged).toEqual({ devices: [], factors: [] });
  });

  test("refresh(view) flags too, where it refused the view before", async () => {
    const e = await enrolledMailbox();
    const here = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const intruder = serverDevice(e.fake, false);
    await here.refresh(e.fake.mailbox());
    expect(here.flagged.devices).toEqual([intruder]);
  });

  test("removing it is the rotation allowed: nothing is sealed or tagged to it, Mail applies the rotation, and the flag is gone", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const intruder = serverDevice(e.fake);
    await a.unlocked.refresh(e.fake.mailbox());
    expect(a.unlocked.flagged.devices).toEqual([intruder]);
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const pending = await a.unlocked.removeDevice(e.fake.mailbox(), intruder, ff);
    const named = [...pending.request.rotation.seals, ...pending.request.rotation.tags].map((x) => x.to.id);
    expect(named).not.toContain(intruder);
    await e.fake.removeDevice(pending.request, { session: a.session, factorProof: await proofOf(e.fake, ff) });
    await pending.commit();
    expect(a.unlocked.flagged).toEqual({ devices: [], factors: [] });
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).flagged).toEqual({ devices: [], factors: [] });
  });

  test("any other rotation is refused while it is there: FlaggedRecipient, naming it", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const intruder = serverDevice(e.fake);
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const refused = await a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff).catch((x: unknown) => x);
    expect(refused).toBeInstanceOf(FlaggedRecipient);
    expect((refused as FlaggedRecipient).name).toBe("FlaggedRecipient");
    expect((refused as FlaggedRecipient).flagged).toEqual({ devices: [intruder], factors: [] });
  });

  test("two flagged devices: removing one would seal the new key to the other, so that is refused too", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const first = serverDevice(e.fake);
    const second = serverDevice(e.fake);
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const refused = await a.unlocked.removeDevice(e.fake.mailbox(), first, ff).catch((x: unknown) => x);
    expect(refused).toBeInstanceOf(FlaggedRecipient);
    expect((refused as FlaggedRecipient).flagged).toEqual({ devices: [second], factors: [] });
  });
});

describe("K3: a factor whose tag fails is flagged the same way", () => {
  test("a factor the server added: flagged; every rotation, addPasskey and replaceRecoveryKey refuse with FlaggedRecipient, before any prompt", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const stranger = serverFactor(e.fake);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(unlocked.flagged).toEqual({ devices: [], factors: [stranger] });
    const ff = unlocked.freshFactor!;
    for (const deviceId of [a.deviceId, b.deviceId]) {
      const refused = await unlocked.removeDevice(e.fake.mailbox(), deviceId, ff).catch((x: unknown) => x);
      expect(refused).toBeInstanceOf(FlaggedRecipient);
      expect((refused as FlaggedRecipient).flagged).toEqual({ devices: [], factors: [stranger] });
    }
    const prompts = e.credentials.created.length;
    await expect(unlocked.addPasskey(passkeyOptions(e.credentials), ff)).rejects.toBeInstanceOf(FlaggedRecipient);
    await expect(unlocked.replaceRecoveryKey(ff)).rejects.toBeInstanceOf(FlaggedRecipient);
    expect(e.credentials.created.length).toBe(prompts);
  });

  test("removing it with a proof from a good factor clears the flag, and a rotation goes through again", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const stranger = serverFactor(e.fake);
    await a.unlocked.refresh(e.fake.mailbox());
    expect(a.unlocked.flagged.factors).toEqual([stranger]);
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    await e.fake.removeWrap(stranger, { session: a.session, factorProof: await proofOf(e.fake, ff) });
    await a.unlocked.refresh(e.fake.mailbox());
    expect(a.unlocked.flagged).toEqual({ devices: [], factors: [] });
    const pending = await a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff);
    await e.fake.removeDevice(pending.request, { session: a.session, factorProof: await proofOf(e.fake, ff) });
    await pending.commit();
  });

  test("a flagged recovery factor can be replaced (M5′ refuses to remove the only one first): the new recovery key goes in, the flagged one goes out", async () => {
    const e = await enrolledMailbox();
    const recovery = e.fake.wraps.find((w) => w.kind === "recovery")!;
    recovery.label = "Renamed by someone";
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(unlocked.flagged).toEqual({ devices: [], factors: [recovery.id] });
    const session = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    // Removing the only recovery factor first is refused by Mail (M5′), so the replacement must be allowed.
    await expect(e.fake.removeWrap(recovery.id, { session, factorProof: await proofOf(e.fake, ff) })).rejects.toThrow(/M5/);
    await expect(unlocked.addPasskey(passkeyOptions(e.credentials), ff)).rejects.toBeInstanceOf(FlaggedRecipient);
    const { recoveryKey, wrap } = await unlocked.replaceRecoveryKey(ff);
    await e.fake.addWrap(wrap, { session, factorProof: await proofOf(e.fake, ff) });
    await e.fake.removeWrap(recovery.id, { session, factorProof: await proofOf(e.fake, ff) });
    const again = await unlockWithRecoveryKey(e.fake.mailbox(), recoveryKey);
    expect(again.flagged).toEqual({ devices: [], factors: [] });
  });
});
