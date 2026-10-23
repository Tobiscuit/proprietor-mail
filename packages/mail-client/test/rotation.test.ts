// D1e and round 3: removing devices rotates the mailbox key (plan.md F6, F10, F13, F14; contracts/device-v1.md
// B7, B7a, M18′, M5′, D40, K12, K13). The rotating browser checks every remaining recipient (K3′), makes a
// new key, seals the old one to it (the successor seal), signs the transition with the factor whose proof
// the call spends (A11), seals the new key to every remaining device unlock key and factor key, and tags
// them all under it. Mail (the strict fake) applies it in one step; the other kept devices find their seal
// of the new key at their next load, and the removed ones wipe themselves.
import { describe, expect, test } from "vitest";
import { factorSigningKey, requestDigest, verifyStatement } from "@proprietor/mail-crypto";
import {
  FlaggedRecipient,
  MailboxChanged,
  memoryDeviceStore,
  NoRecoveryFactor,
  resumeDevice,
  revokeRequest,
  RotationDue,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type Confirmation,
  type FreshFactor,
  type LockAfter,
  type RemoveDevicesRequest,
  type UnlockedMailbox,
} from "../src/index";
import { openSession, OWNER, proofFor } from "./flows";
import { enrolledMailbox, recoveryFactorKey, testClock, type Enrolled } from "./keyring-support";
import { b64url, fromB64url, sampleHeader } from "./support";

/** F1 in one browser (its own store): unlock with the recovery key, keep it. */
async function keepBrowser(e: Enrolled, label: string, lockAfter: LockAfter = "sign-out", now?: () => number) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "s", ...(now ? { now } : {}) });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label, lockAfter }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return { store, unlocked, session, deviceId: pending.request.device.id };
}

/** F6 from `from`: a fresh factor, a fresh view, the rotation, a factor proof bound to it; Mail applies it; commit. */
async function removeFrom(e: Enrolled, from: { unlocked: UnlockedMailbox; session: string }, deviceIds: string[], ff?: FreshFactor) {
  const factor = ff ?? (await from.unlocked.reauthenticate({ recoveryKey: e.recoveryKey }));
  const pending = await from.unlocked.removeDevices(e.fake.mailbox(), deviceIds, factor);
  const result = await e.fake.removeDevices(pending.request, { session: from.session, factorProof: await proofFor(e.fake, factor, pending) });
  await pending.commit();
  return { pending, result, ff: factor };
}

/** A confirmation of an arbitrary removeDevices request, as a browser that made it would hold one. */
async function confirmationOf(request: RemoveDevicesRequest, labels: Record<string, string>): Promise<Confirmation> {
  return { action: { kind: "remove-devices", deviceIds: request.deviceIds, request: await requestDigest({ deviceIds: request.deviceIds, rotation: request.rotation }) }, labels };
}

describe("removeDevices (F6): the rotation", () => {
  test("names exactly the remaining recipients, with Part B's shapes and lengths, its transition signed by the factor whose proof it spends; Mail applies it (M18′)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const c = await keepBrowser(e, "Library computer", "right-away");
    const old = e.fake.activeKey.keyId;
    const { pending, result, ff } = await removeFrom(e, a, [b.deviceId]);
    const r = pending.request;
    expect(Object.keys(r).sort()).toEqual(["deviceIds", "rotation"]);
    expect(Object.keys(r.rotation).sort()).toEqual(["from", "publicKey", "seals", "successorSeal", "tags", "transition"]);
    expect(r.deviceIds).toEqual([b.deviceId]);
    expect(r.rotation.from).toBe(old);
    expect(fromB64url(r.rotation.publicKey).length).toBe(32);
    expect(fromB64url(r.rotation.successorSeal).length).toBe(109);
    // K12: the transition, by the FreshFactor's factor (the recovery key here), verifies with its signing key.
    expect(r.rotation.transition.signedBy).toBe(ff.factorId);
    const recovery = await recoveryFactorKey(e.fake, e.recoveryKey);
    expect(recovery.factorId).toBe(ff.factorId);
    const statement = { kind: "transition" as const, mailboxId: e.mailboxId, fromKeyId: old, toKeyId: result.keyId, toPublicKey: fromB64url(r.rotation.publicKey), signerId: ff.factorId };
    expect(await verifyStatement(factorSigningKey(recovery), statement, r.rotation.transition.signature)).toBe(true);
    // The confirmation names exactly this call (A10).
    expect(pending.confirmation.action).toEqual({ kind: "remove-devices", deviceIds: [b.deviceId], request: await requestDigest({ deviceIds: r.deviceIds, rotation: r.rotation }) });
    const factorIds = e.fake.wraps.map((w) => w.id).sort();
    const named = (list: { to: { kind: string; id: string } }[]) => list.map((x) => `${x.to.kind}:${x.to.id}`).sort();
    // Seals: the devices that keep an unlock key, and every factor with a factor key. Never the removed device; never C (it keeps none).
    expect(named(r.rotation.seals)).toEqual([`device:${a.deviceId}`, ...factorIds.map((id) => `factor:${id}`)].sort());
    for (const s of r.rotation.seals) expect(fromB64url(s.sealed).length).toBe(s.to.kind === "device" ? 142 : 109);
    // Tags: every other device, and every factor with a factor key.
    expect(named(r.rotation.tags)).toEqual([`device:${a.deviceId}`, `device:${c.deviceId}`, ...factorIds.map((id) => `factor:${id}`)].sort());
    expect(result.keyId).toBe(e.fake.activeKey.keyId);
    expect(e.fake.keys.find((k) => k.keyId === old)!.successor).toMatchObject({ keyId: result.keyId, signedBy: ff.factorId, signature: r.rotation.transition.signature });
    expect(e.fake.devices.map((d) => d.id).sort()).toEqual([a.deviceId, c.deviceId].sort());
  });

  test("commit moves this session to the new key: new mail and drafts use it, old mail still opens; this device accepts it", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const before = await e.fake.deliver();
    const old = e.fake.activeKey.keyId;
    const { result } = await removeFrom(e, a, [b.deviceId]);
    expect(a.unlocked.keyId).toBe(result.keyId);
    expect(a.unlocked.keyIds).toEqual([result.keyId, old]);
    const after = await e.fake.deliver();
    expect(after.item.keyId).toBe(result.keyId);
    const opened = await a.unlocked.openMessages([before.item, after.item]);
    expect(opened.map((m) => m.header?.subject)).toEqual([sampleHeader.subject, sampleHeader.subject]);
    expect((await a.unlocked.sealDraft(null, { to: [], cc: [], bcc: [], subject: "", text: "", inReplyTo: null, references: [] })).keyId).toBe(result.keyId);
    expect((await a.store.get(e.mailboxId, OWNER))!.lastKeyId).toBe(result.keyId);
    // The caller's own session survives the rotation at Mail; every other session ended.
    expect([...e.fake.mailSessions.values()].map((s) => s.deviceId)).toEqual([a.deviceId]);
    // Lock now still works under the new key: its tag is made under it.
    const { updateDevice } = await a.unlocked.lock();
    await e.fake.updateDevice(updateDevice!, { session: a.session });
  });

  test("the other kept devices open their seal of the new key at their next load and walk back to the key they knew, the step signed by a trusted factor (F2, K2″); the removed one wipes itself (F10)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const d = await keepBrowser(e, "Home desktop");
    const old = await e.fake.deliver();
    await removeFrom(e, a, [b.deviceId]);
    const rd = await resumeDevice(e.fake.mailbox(), { store: d.store, accountId: OWNER, signInId: "s" });
    if (rd.state !== "unlocked") throw new Error(rd.state);
    expect(rd.mailbox.keyIds.length).toBe(2);
    expect((await rd.mailbox.openMessages([old.item]))[0]!.undecryptable).toBe(false);
    // D's old mail session ended with the rotation; a new one opens with the new key and D's signature.
    expect((await openSession(e.fake, rd.mailbox)).device).toBe(d.deviceId);
    expect(await resumeDevice(e.fake.mailbox(), { store: b.store, accountId: OWNER, signInId: "s" })).toEqual({ state: "removed" });
    expect(await b.store.get(e.mailboxId, OWNER)).toBeNull();
    // The recovery key and the passkey still reach the new key (their seals), and every older one.
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).keyIds.length).toBe(2);
    expect((await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials })).keyIds.length).toBe(2); // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
  });

  test("D40: several devices in one rotation, every one of them wiped at its next load", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const c = await keepBrowser(e, "Tablet");
    const { pending } = await removeFrom(e, a, [c.deviceId, b.deviceId]);
    expect(pending.request.deviceIds).toEqual([b.deviceId, c.deviceId].sort());
    expect(e.fake.devices.map((d) => d.id)).toEqual([a.deviceId]);
    for (const x of [b, c]) expect(await resumeDevice(e.fake.mailbox(), { store: x.store, accountId: OWNER, signInId: "s" })).toEqual({ state: "removed" });
  });

  test("removing this device itself: commit wipes it here, and the session goes on with the new key as a shared computer's", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    await keepBrowser(e, "Other");
    const { result, ff } = await removeFrom(e, a, [a.deviceId]);
    expect(await a.store.get(e.mailboxId, OWNER)).toBeNull();
    expect(a.unlocked.device).toBeNull();
    expect(a.unlocked.keyId).toBe(result.keyId);
    // Its mail session ended with the device: a new one opens with a key proof and a factor proof (D38).
    expect((await openSession(e.fake, a.unlocked, ff)).device).toBeNull();
  });

  test("the FreshFactor follows the rotation: a second removal within its 2 minutes needs no new prompt", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const a = await keepBrowser(e, "Office laptop", "sign-out", clock);
    const b = await keepBrowser(e, "Phone", "sign-out", clock);
    const c = await keepBrowser(e, "Tablet", "sign-out", clock);
    const { ff } = await removeFrom(e, a, [b.deviceId]);
    await removeFrom(e, a, [c.deviceId], ff);
    expect(a.unlocked.keyIds.length).toBe(3);
  });
});

describe("removeDevices refuses before anything is made", () => {
  test("K3′: a flagged factor is in the way (FlaggedRecipient); a renamed one breaks its own admission and is flagged", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const view = e.fake.mailbox();
    const renamed = { ...view, wraps: view.wraps.map((w) => (w.kind === "passkey-prf" ? { ...w, label: "Renamed by someone" } : w)) };
    await expect(a.unlocked.removeDevices(renamed, [b.deviceId], ff)).rejects.toBeInstanceOf(FlaggedRecipient);
  });

  test("M5′: with no recovery factor that has its key, the rotation is refused (NoRecoveryFactor)", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const ff = await a.unlocked.reauthenticate({ passkey: { rpId: "example.com", credentials: e.credentials } }); // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
    const view = e.fake.mailbox();
    const noRecoveryKey = { ...view, wraps: view.wraps.map((w) => (w.kind === "recovery" ? { ...w, factorKey: null, signingKey: null, admission: null, tag: null, tagKeyId: null } : w)) };
    await expect(a.unlocked.removeDevices(noRecoveryKey, [b.deviceId], ff)).rejects.toBeInstanceOf(NoRecoveryFactor);
  });

  test("a view of another key (another browser rotated first) or without the device is MailboxChanged; no device and no rotation due is a TypeError", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const c = await keepBrowser(e, "Tablet");
    const stale = e.fake.mailbox();
    await removeFrom(e, b, [c.deviceId]); // B rotates first
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    await expect(a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff)).rejects.toBeInstanceOf(MailboxChanged);
    await expect(a.unlocked.removeDevices(stale, ["dev_00000000000000000000000000"], ff)).rejects.toBeInstanceOf(MailboxChanged);
    const fresh = await keepBrowser(e, "Fresh");
    await expect(fresh.unlocked.removeDevices(e.fake.mailbox(), [], await fresh.unlocked.reauthenticate({ recoveryKey: e.recoveryKey }))).rejects.toBeInstanceOf(TypeError);
  });

  test("Mail refuses a rotation that misses a recipient, names the removed device, comes from a stale key, or whose transition another factor signed", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const pending = await a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff);
    const labels = Object.fromEntries(e.fake.devices.map((d) => [d.id, d.label]));
    const r = pending.request;
    const passkeyId = e.fake.wraps.find((w) => w.kind === "passkey-prf")!.id;
    for (const bad of [
      { ...r, rotation: { ...r.rotation, seals: r.rotation.seals.slice(1) } },
      { ...r, rotation: { ...r.rotation, tags: [...r.rotation.tags, { to: { kind: "device" as const, id: b.deviceId }, tag: r.rotation.tags[0]!.tag }] } },
      { ...r, rotation: { ...r.rotation, from: "0".repeat(32) } },
      { ...r, rotation: { ...r.rotation, transition: { ...r.rotation.transition, signedBy: passkeyId } } },
      { ...r, rotation: { ...r.rotation, transition: { ...r.rotation.transition, signature: b64url(new Uint8Array(64)) } } },
    ]) {
      const challenge = await e.fake.challenge({ purpose: "factor", factorId: ff.factorId, action: (await confirmationOf(bad, labels)).action });
      await expect(e.fake.removeDevices(bad, { session: a.session, factorProof: await ff.answer(challenge, await confirmationOf(bad, labels)) })).rejects.toThrow(/InvalidRequest/);
    }
    // A proof made for another request does not count for this one (A10).
    await expect(e.fake.removeDevices(r, { session: a.session, factorProof: await proofFor(e.fake, ff, { confirmation: await confirmationOf({ ...r, deviceIds: [] }, labels) }) })).rejects.toThrow(/ProofRejected|InvalidRequest/);
    // Nothing changed at Mail, and the real request still applies.
    await e.fake.removeDevices(r, { session: a.session, factorProof: await proofFor(e.fake, ff, pending) });
    await pending.commit();
  });
});

describe("D35, K13: an email code revokes; the next fresh factor finishes the rotation first", () => {
  test("revokeRequest names the devices; Mail revokes them and nothing else; while the rotation is due every other change is RotationDue; removeDevices with no device finishes it", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const lost = await keepBrowser(e, "Lost phone");
    const keyBefore = e.fake.activeKey.keyId;
    // F13, from any browser: the email challenge's action and revokeDevices' request.
    const revoke = revokeRequest(e.fake.mailbox(), [lost.deviceId]);
    expect(revoke).toEqual({ action: { kind: "revoke-device", deviceIds: [lost.deviceId] }, request: { deviceIds: [lost.deviceId] } });
    const emailChallenge = await e.fake.challenge({ purpose: "email", action: revoke.action });
    expect(emailChallenge.sealed).toBeNull();
    await e.fake.revokeDevices(revoke.request, { challengeId: emailChallenge.id }); // the dashboard attested the code
    expect(e.fake.activeKey.keyId).toBe(keyBefore); // no key written (M22)
    expect(e.fake.rotationDue).toMatchObject({ devices: [lost.deviceId] });
    expect(await resumeDevice(e.fake.mailbox(), { store: lost.store, accountId: OWNER, signInId: "s" })).toEqual({ state: "removed" });

    // K13: a browser holding a FreshFactor while the rotation is due finishes it before any other change.
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    await a.unlocked.refresh(e.fake.mailbox());
    expect(a.unlocked.rotationDue).toMatchObject({ devices: [lost.deviceId] });
    await expect(a.unlocked.replaceRecoveryKey(ff)).rejects.toBeInstanceOf(RotationDue);
    await expect(a.unlocked.removeFactor(e.fake.wraps[0]!.id)).rejects.toBeInstanceOf(RotationDue);
    await expect(a.unlocked.rekeyThisDevice(ff)).rejects.toBeInstanceOf(RotationDue);
    const { result } = await removeFrom(e, a, [], ff);
    expect(result.keyId).not.toBe(keyBefore);
    expect(e.fake.rotationDue).toBeNull();
    expect(a.unlocked.rotationDue).toBeNull();
    // Done: the other changes go through again.
    await expect(a.unlocked.replaceRecoveryKey(ff)).resolves.toBeDefined();
  });

  test("revokeRequest refuses what Mail would: no device, too many, one the view does not list, the same one twice", () => {
    const view = { id: "mbx_00000000000000000000000000", devices: [{ id: "dev_00000000000000000000000001" }] } as never;
    for (const ids of [[], Array.from({ length: 21 }, (_, i) => `dev_${String(i).padStart(26, "0")}`), ["dev_0000000000000000000000000x"], ["dev_00000000000000000000000001", "dev_00000000000000000000000001"]]) {
      expect(() => revokeRequest(view, ids)).toThrow(TypeError);
    }
  });
});

describe("the session without a store still rotates (a shared computer, with the recovery key)", () => {
  test("R7: the recovery key alone unlocks a new browser and removes a device", async () => {
    const e = await enrolledMailbox();
    const lost = await keepBrowser(e, "Lost laptop");
    const shared = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const { session } = await openSession(e.fake, shared);
    const ff = shared.freshFactor!;
    const pending = await shared.removeDevices(e.fake.mailbox(), [lost.deviceId], ff);
    await e.fake.removeDevices(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
    await pending.commit();
    expect(await resumeDevice(e.fake.mailbox(), { store: lost.store, accountId: OWNER, signInId: "s" })).toEqual({ state: "removed" });
  });
});
