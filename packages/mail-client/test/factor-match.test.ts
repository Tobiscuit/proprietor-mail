// R2-3, contracts/device-v1.md Part C K9 (new on 2026-10-19): the factor just used is the one Mail
// lists. After a factor is used, the browser derives its factor key (A2) and compares it with the
// `factorKey` the key ring lists for that factor. A mismatch flags the factor as in K3: nothing is
// sealed to it, the session shows it, and the owner removes it and adds it again. The unlock itself
// still goes on: the factor's envelope v1 wrap is its anchor (K2′ (a)).
//
// The case: a factor key that is wrong but well tagged, as a buggy registration would leave it (the tag
// is made under the active key over the wrong key, so K3 passes and only the factor itself can tell).
import { describe, expect, test } from "vitest";
import {
  FlaggedRecipient,
  InvalidChallenge,
  memoryDeviceStore,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type FreshFactor,
  type UnlockedMailbox,
} from "../src/index";
import type { FakeMail } from "./fake-mail";
import { enrolledMailbox, misregisterFactor, type Enrolled } from "./keyring-support";
import { passkeyOptions, sampleHeader } from "./support";

const prompt = (e: Enrolled) => ({ rpId: "example.com", credentials: e.credentials as never });

async function openSession(fake: FakeMail, unlocked: UnlockedMailbox) {
  return (await fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })))).session;
}
async function proofOf(fake: FakeMail, ff: FreshFactor) {
  return ff.answer(await fake.challenge({ purpose: "factor", factorId: ff.factorId }));
}

/** A second kept browser, so that there is a device to remove. */
async function keepBrowser(e: Enrolled) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "s" });
  const session = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label: "Phone" }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofOf(e.fake, ff) });
  await pending.commit();
  return pending.request.device.id;
}

describe("K9: a factor whose listed key is not the one it derives", () => {
  test("a passkey listed with a wrong but well-tagged factor key: its unlock goes on, and flags it; mail opens", async () => {
    const e = await enrolledMailbox();
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await misregisterFactor(e.fake, e.recoveryKey, passkey);
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e));
    expect(unlocked.freshFactor!.factorId).toBe(passkey);
    expect(unlocked.flagged).toEqual({ devices: [], factors: [passkey] });
    const { item } = await e.fake.deliver();
    expect((await unlocked.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
  });

  test("only the factor itself can tell: an unlock with the recovery key flags nothing, until the passkey is used (reauthenticate)", async () => {
    const e = await enrolledMailbox();
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await misregisterFactor(e.fake, e.recoveryKey, passkey);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(unlocked.flagged).toEqual({ devices: [], factors: [] });
    await unlocked.reauthenticate({ passkey: prompt(e) });
    expect(unlocked.flagged).toEqual({ devices: [], factors: [passkey] });
    // A newer view of the same ring keeps the flag: the listed key is still not the passkey's.
    await unlocked.refresh(e.fake.mailbox());
    expect(unlocked.flagged.factors).toEqual([passkey]);
  });

  test("nothing is sealed to it: every rotation is FlaggedRecipient; its own proof cannot answer (Mail seals to the listed key); removing it with the recovery key's proof, then adding it again, clears it", async () => {
    const e = await enrolledMailbox();
    const phone = await keepBrowser(e);
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await misregisterFactor(e.fake, e.recoveryKey, passkey);
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e));
    const session = await openSession(e.fake, unlocked);
    const byPasskey = unlocked.freshFactor!;
    const refused = await unlocked.removeDevice(e.fake.mailbox(), phone, byPasskey).catch((x: unknown) => x);
    expect(refused).toBeInstanceOf(FlaggedRecipient);
    expect((refused as FlaggedRecipient).flagged).toEqual({ devices: [], factors: [passkey] });
    await expect(proofOf(e.fake, byPasskey)).rejects.toBeInstanceOf(InvalidChallenge);
    await expect(unlocked.addPasskey(passkeyOptions(e.credentials), byPasskey)).rejects.toBeInstanceOf(FlaggedRecipient);
    const byRecovery = await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    await e.fake.removeWrap(passkey, { session, factorProof: await proofOf(e.fake, byRecovery) });
    await unlocked.refresh(e.fake.mailbox());
    expect(unlocked.flagged).toEqual({ devices: [], factors: [] });
    const wrap = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Laptop passkey" }), byRecovery);
    await e.fake.addWrap(wrap, { session, factorProof: await proofOf(e.fake, byRecovery) });
    const pending = await unlocked.removeDevice(e.fake.mailbox(), phone, byRecovery);
    await e.fake.removeDevice(pending.request, { session, factorProof: await proofOf(e.fake, byRecovery) });
    await pending.commit();
  });

  test("a recovery key listed with a wrong key: flagged at its own unlock; it is replaced, the passkey's proof carrying the change; the new one matches", async () => {
    const e = await enrolledMailbox();
    const recovery = e.fake.wraps.find((w) => w.kind === "recovery")!.id;
    await misregisterFactor(e.fake, e.recoveryKey, recovery);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(unlocked.flagged).toEqual({ devices: [], factors: [recovery] });
    const session = await openSession(e.fake, unlocked);
    const byPasskey = await unlocked.reauthenticate({ passkey: prompt(e) });
    const { recoveryKey, wrap } = await unlocked.replaceRecoveryKey(unlocked.freshFactor!);
    await e.fake.addWrap(wrap, { session, factorProof: await proofOf(e.fake, byPasskey) });
    await e.fake.removeWrap(recovery, { session, factorProof: await proofOf(e.fake, byPasskey) });
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), recoveryKey)).flagged).toEqual({ devices: [], factors: [] });
  });
});
