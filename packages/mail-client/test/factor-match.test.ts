// R2-3 and round 3, contracts/device-v1.md Part C K9: the factor just used is the one Mail lists. After
// a factor is used, the browser derives its factor key and signing key (A2, A2b) and compares them with
// the ones the key ring lists for that factor. A mismatch flags the factor as in K3′: nothing is sealed
// to it, it signs nothing (K12), the session shows it, and the owner removes it and adds it again. The
// unlock itself still goes on (its envelope v1 wrap is its anchor, K2″ (a)), but trust starts only from
// a factor whose keys K9 confirms (A11): a session unlocked by a mismatched factor trusts nothing until
// a matching one is used.
//
// The case: keys that are wrong but consistent everywhere, as a buggy registration would leave them (every
// admission of the cycle and the tag made with them, so K3′ passes and only the factor itself can tell).
import { describe, expect, test } from "vitest";
import { FlaggedRecipient, InvalidChallenge, memoryDeviceStore, unlockWithPasskey, unlockWithRecoveryKey } from "../src/index";
import { openSession, OWNER, proofFor } from "./flows";
import { enrolledMailbox, misregisterFactor, type Enrolled } from "./keyring-support";
import { passkeyOptions, sampleHeader } from "./support";

const prompt = (e: Enrolled) => ({ rpId: "example.com", credentials: e.credentials as never });

/** A second kept browser, so that there is a device to remove. */
async function keepBrowser(e: Enrolled) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "s" });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label: "Phone" }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return pending.request.device.id;
}

describe("K9: a factor whose listed keys are not the ones it derives", () => {
  test("a passkey listed with wrong but consistent keys: its unlock goes on and flags it; trusting nothing, it flags every recipient; mail opens", async () => {
    const e = await enrolledMailbox();
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    const recovery = e.fake.wraps.find((w) => w.kind === "recovery")!.id;
    await misregisterFactor(e, passkey);
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e));
    expect(unlocked.freshFactor!.factorId).toBe(passkey);
    expect([...unlocked.flagged.factors].sort()).toEqual([passkey, recovery].sort());
    const { item } = await e.fake.deliver();
    expect((await unlocked.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
    // The recovery key, whose keys match, becomes the session's start: only the passkey stays flagged.
    await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    expect(unlocked.flagged).toEqual({ devices: [], factors: [passkey] });
  });

  test("only the factor itself can tell: an unlock with the recovery key flags nothing, until the passkey is used (reauthenticate)", async () => {
    const e = await enrolledMailbox();
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await misregisterFactor(e, passkey);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(unlocked.flagged).toEqual({ devices: [], factors: [] });
    await unlocked.reauthenticate({ passkey: prompt(e) });
    expect(unlocked.flagged).toEqual({ devices: [], factors: [passkey] });
    // A newer view of the same ring keeps the flag: the listed keys are still not the passkey's.
    await unlocked.refresh(e.fake.mailbox());
    expect(unlocked.flagged.factors).toEqual([passkey]);
  });

  test("nothing is sealed to it and it signs nothing: a rotation it would sign is FlaggedRecipient; its own proof cannot answer (Mail seals to the listed key); removing it with the recovery key's proof, then adding it again, clears it", async () => {
    const e = await enrolledMailbox();
    const phone = await keepBrowser(e);
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await misregisterFactor(e, passkey);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const { session } = await openSession(e.fake, unlocked);
    const byPasskey = await unlocked.reauthenticate({ passkey: prompt(e) });
    const refused = await unlocked.removeDevices(e.fake.mailbox(), [phone], byPasskey).catch((x: unknown) => x);
    expect(refused).toBeInstanceOf(FlaggedRecipient);
    expect((refused as FlaggedRecipient).flagged.factors).toContain(passkey);
    const removal = await unlocked.removeFactor(passkey);
    await expect(proofFor(e.fake, byPasskey, removal)).rejects.toBeInstanceOf(InvalidChallenge);
    await expect(unlocked.addPasskey(passkeyOptions(e.credentials), byPasskey)).rejects.toBeInstanceOf(FlaggedRecipient);
    const byRecovery = await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    await e.fake.removeWrap(passkey, { session, factorProof: await proofFor(e.fake, byRecovery, removal) });
    await removal.commit();
    await unlocked.refresh(e.fake.mailbox());
    expect(unlocked.flagged).toEqual({ devices: [], factors: [] });
    const added = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Laptop passkey" }), byRecovery);
    await e.fake.addWrap(added.request, { session, factorProof: await proofFor(e.fake, byRecovery, added) });
    await added.commit();
    const pending = await unlocked.removeDevices(e.fake.mailbox(), [phone], byRecovery);
    await e.fake.removeDevices(pending.request, { session, factorProof: await proofFor(e.fake, byRecovery, pending) });
    await pending.commit();
  });

  test("a recovery key listed with wrong keys: at its own unlock it trusts nothing; the passkey becomes the start, it is replaced with the passkey's proof, and the new one matches", async () => {
    const e = await enrolledMailbox();
    const recovery = e.fake.wraps.find((w) => w.kind === "recovery")!.id;
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await misregisterFactor(e, recovery);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect([...unlocked.flagged.factors].sort()).toEqual([passkey, recovery].sort());
    const byPasskey = await unlocked.reauthenticate({ passkey: prompt(e) });
    expect(unlocked.flagged).toEqual({ devices: [], factors: [recovery] });
    const { session } = await openSession(e.fake, unlocked, byPasskey);
    const replacement = await unlocked.replaceRecoveryKey(byPasskey);
    await e.fake.addWrap(replacement.request, { session, factorProof: await proofFor(e.fake, byPasskey, replacement) });
    await replacement.commit();
    const removal = await unlocked.removeFactor(recovery);
    await e.fake.removeWrap(recovery, { session, factorProof: await proofFor(e.fake, byPasskey, removal) });
    await removal.commit();
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), replacement.recoveryKey)).flagged).toEqual({ devices: [], factors: [] });
  });
});
