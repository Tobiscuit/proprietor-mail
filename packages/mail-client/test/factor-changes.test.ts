// D1e and round 3: the factors' side of spec 002 (plan.md F5, F7, F8; contracts/device-v1.md B5, B7, A11):
// the one-time upgrade of a mailbox enrolled under spec 001, which names every factor of the mailbox at
// once (B5, M20), gives each its signing key and an admission by A11's cycle, and is confirmed by a key
// proof bound to it (round 3); adding a passkey and replacing the recovery key, each new factor admitted
// by the FreshFactor's factor and countersigned by itself (K12). Every request goes to the strict fake
// Mail with the session and the proofs Part B asks for, each bound to its own request.
import { describe, expect, test } from "vitest";
import { bootstrapAdmitters, requestDigest } from "@proprietor/mail-crypto";
import {
  FactorExpired,
  InvalidChallenge,
  memoryDeviceStore,
  MissingFactors,
  resumeDevice,
  unlockWithPasskey,
  unlockWithRecoveryKey,
} from "../src/index";
import { keyProofFor, openSession, OWNER, proofFor } from "./flows";
import { enrolledMailbox, rotateByHand, testClock } from "./keyring-support";
import { fromB64url, passkeyOptions } from "./support";

const prompt = (credentials: unknown) => ({ rpId: "example.com", credentials: credentials as never });

describe("the upgrade (F5, D26): a mailbox enrolled under spec 001, every factor at once", () => {
  test("a mailbox with only its recovery key: its factor key, signing key, admission (by itself) and tag under the active key; Mail checks the key proof bound to it and turns sessions on; then the browser is kept (F1)", async () => {
    const e = await enrolledMailbox({ legacy: true, passkey: false });
    expect(e.fake.sessionsMode).toBe("optional");
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "s" });
    const { session } = await openSession(e.fake, unlocked); // a session opens with a key proof while sessions are optional
    const ff = unlocked.freshFactor!;
    const upgrade = await unlocked.upgradeRequest([ff]);
    expect(Object.keys(upgrade.request)).toEqual(["factors"]);
    expect(upgrade.request.factors.length).toBe(1);
    const [f] = upgrade.request.factors;
    expect(Object.keys(f!).sort()).toEqual(["admission", "factorKey", "id", "signingKey", "tag", "tagKeyId"]);
    expect(f!.id).toBe(ff.factorId);
    expect(fromB64url(f!.factorKey).length).toBe(32);
    expect(fromB64url(f!.signingKey).length).toBe(32);
    expect(f!.admission.by).toBe(ff.factorId); // a single factor admits itself
    expect(f!.tagKeyId).toBe(e.fake.activeKey.keyId);
    expect(upgrade.confirmation.action).toEqual({ kind: "upgrade", request: await requestDigest({ factors: upgrade.request.factors }) });
    // Round 3: the key proof is bound to this upgrade; the session alone, or a proof for another, does not do.
    await expect(e.fake.upgrade(upgrade.request, { session })).rejects.toThrow(/ProofRejected/);
    await e.fake.upgrade(upgrade.request, { session, keyProof: await keyProofFor(e.fake, unlocked, upgrade) });
    await upgrade.commit();
    expect(e.fake.sessionsMode).toBe("required");
    // F1 from the factor challenge on: the recovery key now has keys Mail can check.
    const keep = await unlocked.keepThisDevice({ label: "Office laptop" }, ff);
    await e.fake.registerDevice(keep.request, { session, factorProof: await proofFor(e.fake, ff, keep) });
    await keep.commit();
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "s" })).state).toBe("unlocked");
  });

  test("with the passkey: the screen asks for the recovery key once, and both factors get their keys and admissions by A11's cycle", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    const { session } = await openSession(e.fake, unlocked);
    const recovery = await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const upgrade = await unlocked.upgradeRequest([recovery, unlocked.freshFactor!]);
    expect(upgrade.request.factors.map((f) => f.id).sort()).toEqual(e.fake.wraps.map((w) => w.id).sort());
    const cycle = new Map(bootstrapAdmitters(upgrade.request.factors.map((f) => f.id)).map((c) => [c.factorId, c.admitterId]));
    for (const f of upgrade.request.factors) expect(f.admission.by).toBe(cycle.get(f.id));
    await e.fake.upgrade(upgrade.request, { session, keyProof: await keyProofFor(e.fake, unlocked, upgrade) });
    await upgrade.commit();
    // Every tag and admission Mail now holds verifies at the next unlock (K3′).
    expect((await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials))).flagged).toEqual({ devices: [], factors: [] });
  });

  test("K4: a key challenge issued for another upgrade request is not answered", async () => {
    const e = await enrolledMailbox({ legacy: true, passkey: false });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const upgrade = await unlocked.upgradeRequest([unlocked.freshFactor!]);
    // Another upgrade request (a relay's own factor keys, say): its digest differs.
    const other = { kind: "upgrade" as const, request: await requestDigest({ factors: upgrade.request.factors.map((f) => ({ ...f, factorKey: f.signingKey })) }) };
    const challenge = await e.fake.challenge({ purpose: "key", action: other });
    await expect(unlocked.keyProof(challenge, upgrade.confirmation)).rejects.toBeInstanceOf(InvalidChallenge);
    await expect(unlocked.keyProof(await e.fake.challenge({ purpose: "key", action: upgrade.confirmation.action }), upgrade.confirmation)).resolves.toBeDefined();
  });

  test("the upgrade names every factor (B5, M20): one left out is MissingFactors, which names it, and nothing is made", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const view = e.fake.mailbox();
    const byId = (kind: string) => view.wraps.find((w) => w.kind === kind)!;
    const named = (x: unknown) => (x as MissingFactors).missing.map((m) => ({ ...m }));
    const unlocked = await unlockWithPasskey(view, prompt(e.credentials));
    const alone = await unlocked.upgradeRequest([unlocked.freshFactor!]).catch((x: unknown) => x);
    expect(alone).toBeInstanceOf(MissingFactors);
    expect((alone as MissingFactors).name).toBe("MissingFactors");
    expect(named(alone)).toEqual([{ id: byId("recovery").id, kind: "recovery", label: byId("recovery").label }]);
    expect(named(await unlocked.upgradeRequest([]).catch((x: unknown) => x))).toEqual(view.wraps.map((w) => ({ id: w.id, kind: w.kind, label: w.label })));
    const byRecovery = await unlockWithRecoveryKey(view, e.recoveryKey);
    expect(named(await byRecovery.upgradeRequest([byRecovery.freshFactor!]).catch((x: unknown) => x))).toEqual([{ id: byId("passkey-prf").id, kind: "passkey-prf", label: byId("passkey-prf").label }]);
  });

  test("a factor the owner no longer has is removed first (removeWrap, no proof while sessions are optional); then the upgrade names the rest", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const { session } = await openSession(e.fake, unlocked);
    await e.fake.removeWrap(e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id, {});
    await unlocked.refresh(e.fake.mailbox());
    const upgrade = await unlocked.upgradeRequest([unlocked.freshFactor!]);
    await e.fake.upgrade(upgrade.request, { session, keyProof: await keyProofFor(e.fake, unlocked, upgrade) });
    await upgrade.commit();
    expect(e.fake.sessionsMode).toBe("required");
  });

  test("Mail refuses an upgrade that leaves a wrap out, as B5 now says (the fake, as the Worker)", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    const { session } = await openSession(e.fake, unlocked);
    const recovery = await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const upgrade = await unlocked.upgradeRequest([recovery, unlocked.freshFactor!]);
    const partial = { factors: upgrade.request.factors.filter((f) => f.id === recovery.factorId) };
    const confirmation = { action: { kind: "upgrade" as const, request: await requestDigest(partial) }, labels: {} };
    await expect(e.fake.upgrade(partial, { session, keyProof: await keyProofFor(e.fake, unlocked, { confirmation }) })).rejects.toThrow(/every wrap/);
    expect(e.fake.sessionsMode).toBe("optional");
  });

  test("an expired FreshFactor cannot be used: FactorExpired", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ legacy: true, now: clock });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { now: clock });
    clock.advance(120_000);
    await expect(unlocked.upgradeRequest([unlocked.freshFactor!])).rejects.toBeInstanceOf(FactorExpired);
  });
});

describe("adding a passkey (F8) and replacing the recovery key (F7), with factor keys and admissions", () => {
  test("addPasskey: one more prompt; a wrap of the active key with its keys, admission and tag; Mail adds it with a bound factor proof; it then reaches every older key", async () => {
    const e = await enrolledMailbox();
    await rotateByHand(e.fake, e.recoveryKey);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const { session } = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    const change = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Phone passkey" }), ff);
    const wrap = change.request;
    expect(wrap).toMatchObject({ kind: "passkey-prf", keyId: e.fake.activeKey.keyId, label: "Phone passkey", tagKeyId: e.fake.activeKey.keyId });
    expect(fromB64url(wrap.factorKey!).length).toBe(32);
    expect(fromB64url(wrap.signingKey!).length).toBe(32);
    expect(wrap.admission!.by).toBe(ff.factorId); // K12: admitted by the FreshFactor's factor, countersigned by itself
    expect(change.confirmation.action).toEqual({ kind: "add-factor", request: await requestDigest({ ...wrap }) });
    await e.fake.addWrap(wrap, { session, factorProof: await proofFor(e.fake, ff, change) });
    await change.commit();
    // The prompt lists the wraps of the active key first: the new passkey is the one the double "uses".
    const viaPhone = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    expect(viaPhone.keyIds.length).toBe(2);
    expect(viaPhone.freshFactor!.factorId).toBe(wrap.id);
    expect(viaPhone.flagged).toEqual({ devices: [], factors: [] });
  });

  test("Mail refuses a new factor whose admission does not verify (a self-signature over other keys)", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const { session } = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    const one = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "One" }), ff);
    const two = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Two" }), ff);
    const forged = { ...one.request, admission: { ...one.request.admission!, selfSignature: two.request.admission!.selfSignature } };
    const confirmation = { action: { kind: "add-factor" as const, request: await requestDigest({ ...forged }) }, labels: {} };
    await expect(e.fake.addWrap(forged, { session, factorProof: await proofFor(e.fake, ff, { confirmation }) })).rejects.toThrow(/admission/);
  });

  test("replaceRecoveryKey: a new key shown once, its wrap with its keys and admission; addWrap then removeWrap of the old, each with a proof from the same FreshFactor bound to it", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e.credentials));
    const { session } = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    const old = e.fake.wraps.find((w) => w.kind === "recovery")!.id;
    const replacement = await unlocked.replaceRecoveryKey(ff);
    expect(replacement.recoveryKey).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}$/);
    expect(replacement.request).toMatchObject({ kind: "recovery", credentialId: null, label: "Recovery key" });
    expect(fromB64url(replacement.request.tag!).length).toBe(32);
    expect(replacement.request.admission!.by).toBe(ff.factorId);
    await e.fake.addWrap(replacement.request, { session, factorProof: await proofFor(e.fake, ff, replacement) });
    await replacement.commit();
    const removal = await unlocked.removeFactor(old);
    expect(removal.request).toEqual({ wrapId: old });
    await e.fake.removeWrap(old, { session, factorProof: await proofFor(e.fake, ff, removal) });
    await removal.commit();
    // M24: the old recovery factor's record stays among the removed factors, for the signatures it made.
    expect(e.fake.removedFactors.map((f) => f.id)).toEqual([old]);
    const again = await unlockWithRecoveryKey(e.fake.mailbox(), replacement.recoveryKey);
    expect(again.keyId).toBe(e.fake.activeKey.keyId);
    expect(again.flagged).toEqual({ devices: [], factors: [] });
  });

  test("on a mailbox whose sessions are optional, the wraps carry no factor keys, as before", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const change = await unlocked.addPasskey(passkeyOptions(e.credentials, { label: "Second" }), unlocked.freshFactor!);
    for (const field of ["factorKey", "signingKey", "admission", "tag", "tagKeyId"]) expect(field in change.request).toBe(false);
    await e.fake.addWrap(change.request, {});
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
