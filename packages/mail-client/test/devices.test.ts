// D1c, D1e and round 3: a kept device (contracts/device-v1.md Part C, K5 to K7, K10, K11; plan.md F1 to
// F4, F10): keep it, lock it, rekey it, change its lock setting, forget it, and come back to it with
// resumeDevice in every lock state. Mail is the strict fake; the store is the memory store, which clones
// as IndexedDB does. Round 3: the record is this account's (K10), its last accepted key only moves
// forward (K11), the device is admitted by a factor and signs its own unlock key (K12), and "when I sign
// out" locks on another sign-in id, a null after a non-null included (D34).
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  DeviceRemoved,
  FactorExpired,
  InvalidDeviceLabel,
  KEPT_DEVICE_FIELDS,
  KeySubstitutionDetected,
  MailboxChanged,
  MailboxLocked,
  memoryDeviceStore,
  resumeDevice,
  StorageUnavailable,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type DeviceStore,
  type KeptDevice,
  type LockEvent,
} from "../src/index";
import { keepDevice, openSession, OWNER, proofFor } from "./flows";
import { enrolledMailbox, recoveryFactorKey, rotateByHand, testClock } from "./keyring-support";
import { b64url, fromB64url, sampleHeader } from "./support";
import { factorSigningKey, verifyStatement } from "@proprietor/mail-crypto";

const OTHER = "acc_other";

afterEach(() => {
  vi.useRealTimers();
});

/** Every value in a stored record, recursively: no X25519 key, and every CryptoKey a non-extractable P-256 one. */
function keysIn(value: unknown, found: CryptoKey[] = []): CryptoKey[] {
  if (value instanceof CryptoKey) found.push(value);
  else if (typeof value === "object" && value !== null) for (const v of Object.values(value)) keysIn(v, found);
  return found;
}

describe("keepThisDevice (F1): one prompt, then the browser is kept", () => {
  test("registerDevice's request has Part B's shape, admitted by the factor and its unlock key signed by itself; Mail accepts it with the session and a bound factor proof; commit stores exactly K5's fields", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked, request } = await keepDevice(e, store);
    const active = e.fake.activeKey.keyId;
    expect(Object.keys(request).sort()).toEqual(["device", "seal"]);
    expect(Object.keys(request.device).sort()).toEqual(["admission", "id", "label", "signingKey", "tag", "tagKeyId", "unlockKey", "unlockSignature"]);
    expect(request.device.id).toMatch(/^dev_[0-9a-hjkmnp-tv-z]{26}$/);
    expect(request.device.label).toBe("Kitchen laptop");
    expect(fromB64url(request.device.signingKey).length).toBe(65);
    expect(fromB64url(request.device.unlockKey!).length).toBe(65);
    expect(fromB64url(request.seal!).length).toBe(142);
    expect(request.device.tagKeyId).toBe(active);
    // K12: the recovery factor (the FreshFactor's) admitted the device; the device signed its unlock key.
    const recovery = await recoveryFactorKey(e.fake, e.recoveryKey);
    expect(request.device.admission.by).toBe(recovery.factorId);
    const signingKey = fromB64url(request.device.signingKey); // pragma: allowlist secret (a public key)
    expect(await verifyStatement(factorSigningKey(recovery), { kind: "admit-device", mailboxId: e.mailboxId, deviceId: request.device.id, label: "Kitchen laptop", signingKey, admitterId: recovery.factorId }, request.device.admission.signature)).toBe(true);
    expect(await verifyStatement(signingKey, { kind: "unlock-key", mailboxId: e.mailboxId, deviceId: request.device.id, unlockKey: fromB64url(request.device.unlockKey!) }, request.device.unlockSignature!)).toBe(true);

    const record = (await store.get(e.mailboxId, OWNER))!;
    expect(Object.keys(record).sort()).toEqual([...KEPT_DEVICE_FIELDS].sort());
    expect(record).toMatchObject({ mailboxId: e.mailboxId, accountId: OWNER, deviceId: request.device.id, label: "Kitchen laptop", lastKeyId: active, lockAfter: "sign-out", signInId: "signin-1" });
    expect(record.trustRoot).toBe(b64url(factorSigningKey(recovery)));
    expect(record.signingPublic).toBe(request.device.signingKey);
    expect(record.unlockPublic).toBe(request.device.unlockKey);
    const keys = keysIn(record);
    expect(keys.length).toBe(2);
    for (const k of keys) {
      expect(k.extractable).toBe(false);
      expect((k.algorithm as EcKeyAlgorithm).namedCurve).toBe("P-256");
    }
    expect(keys.some((k) => k.algorithm.name === "X25519")).toBe(false);
    expect(unlocked.device).toEqual({ id: request.device.id, label: "Kitchen laptop", lockAfter: "sign-out", keepsUnlocked: true });
  });

  test("Mail refuses a registration whose factor proof was made for another request (the confirmation is bound)", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER });
    const { session } = await openSession(e.fake, unlocked);
    const ff = unlocked.freshFactor!;
    const one = await unlocked.keepThisDevice({ label: "Laptop" }, ff);
    const two = await unlocked.keepThisDevice({ label: "Laptop" }, ff);
    await expect(e.fake.registerDevice(two.request, { session, factorProof: await proofFor(e.fake, ff, one) })).rejects.toThrow(/ProofRejected/);
  });

  test("from then on the session is this device's: its key proof carries the device's signature, which Mail checks", async () => {
    const e = await enrolledMailbox();
    const { unlocked, request } = await keepDevice(e, memoryDeviceStore());
    const proof = await unlocked.sessionProof(await e.fake.challenge({ purpose: "session" }));
    expect(proof.device!.id).toBe(request.device.id);
    expect(proof.factorProof).toBeUndefined();
    expect(fromB64url(proof.device!.signature).length).toBe(64);
    expect((await e.fake.openSession(proof)).device).toBe(request.device.id);
  });

  test("lock after right away: no unlock key, no unlock signature and no seal are made", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { request } = await keepDevice(e, store, { lockAfter: "right-away" });
    expect(request.device.unlockKey).toBeNull();
    expect(request.device.unlockSignature).toBeNull();
    expect(request.seal).toBeNull();
    expect((await store.get(e.mailboxId, OWNER))!).toMatchObject({ unlockKey: null, unlockPublic: null, lockAfter: "right-away" });
  });

  test("nothing is stored before commit(): a request Mail refused leaves this browser as it was", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER });
    const pending = await unlocked.keepThisDevice({ label: "Laptop" }, unlocked.freshFactor!);
    await expect(e.fake.registerDevice(pending.request, {})).rejects.toThrow(/SessionRequired/);
    expect(await store.get(e.mailboxId, OWNER)).toBeNull();
    expect(unlocked.device).toBeNull();
  });

  test("refusals: a label the Worker would refuse, no store (a shared computer), a stale FreshFactor, a browser already kept, a store without an account", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, now: clock });
    const ff = unlocked.freshFactor!;
    for (const label of ["", "x".repeat(41), "two\nlines"]) await expect(unlocked.keepThisDevice({ label }, ff)).rejects.toBeInstanceOf(InvalidDeviceLabel);
    const shared = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    await expect(shared.keepThisDevice({ label: "Laptop" }, shared.freshFactor!)).rejects.toBeInstanceOf(StorageUnavailable);
    clock.advance(120_000);
    await expect(unlocked.keepThisDevice({ label: "Laptop" }, ff)).rejects.toBeInstanceOf(FactorExpired);
    const kept = await keepDevice(e, store, { now: clock });
    await expect(kept.unlocked.keepThisDevice({ label: "Again" }, await kept.unlocked.reauthenticate({ recoveryKey: e.recoveryKey }))).rejects.toBeInstanceOf(TypeError);
    // K10: a store is always this account's; an unlock that names none cannot use one.
    await expect(unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store })).rejects.toBeInstanceOf(TypeError);
  });
});

describe("lock (K6): Lock now, and the idle lock", () => {
  test("on a kept device: every key dropped at once, the unlock key deleted from the store, and updateDevice's request, which Mail accepts", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked, session } = await keepDevice(e, store);
    const events: LockEvent[] = [];
    unlocked.onLock((event) => events.push(event));
    const result = await unlocked.lock();
    expect(unlocked.locked).toBe(true);
    await expect(unlocked.openMessages([])).rejects.toBeInstanceOf(MailboxLocked);
    expect((await store.get(e.mailboxId, OWNER))!).toMatchObject({ unlockKey: null, unlockPublic: null });
    const request = result.updateDevice!;
    expect(Object.keys(request).sort()).toEqual(["seal", "tag", "tagKeyId", "unlockKey", "unlockSignature"]);
    expect(request).toMatchObject({ unlockKey: null, unlockSignature: null, seal: null, tagKeyId: e.fake.activeKey.keyId });
    expect(events).toEqual([{ reason: "lock", updateDevice: request }]);
    const device = await e.fake.updateDevice(request, { session });
    expect(device.unlockKey).toBeNull();
    // The tag Mail now holds covers "no unlock key": a fresh unlock checks it (K3′).
    const fresh = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(fresh.flagged).toEqual({ devices: [], factors: [] });
    expect((await unlocked.lock()).updateDevice).toBeNull(); // locking twice does nothing more
  });

  test("on a shared computer it only drops the keys", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(await unlocked.lock()).toEqual({ updateDevice: null });
    expect(unlocked.locked).toBe(true);
  });

  test.each([
    ["15-minutes", 15 * 60_000],
    ["1-hour", 60 * 60_000],
  ] as const)("a kept device set to %s locks itself after that long without use while the page is open", async (lockAfter, ms) => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const { unlocked } = await keepDevice(e, store, { lockAfter });
    const events: LockEvent[] = [];
    unlocked.onLock((event) => events.push(event));
    await vi.advanceTimersByTimeAsync(ms - 1000);
    unlocked.touch();
    await vi.advanceTimersByTimeAsync(ms - 1);
    expect(unlocked.locked).toBe(false);
    await vi.advanceTimersByTimeAsync(2);
    expect(unlocked.locked).toBe(true);
    expect(events[0]!.reason).toBe("idle");
    expect(events[0]!.updateDevice!.unlockKey).toBeNull();
    expect((await store.get(e.mailboxId, OWNER))!.unlockKey).toBeNull();
  });

  test("set to \"when I sign out\", it does not lock on idle", async () => {
    const e = await enrolledMailbox();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const { unlocked } = await keepDevice(e, memoryDeviceStore(), { lockAfter: "sign-out" });
    await vi.advanceTimersByTimeAsync(24 * 60 * 60_000);
    expect(unlocked.locked).toBe(false);
  });
});

describe("rekeyThisDevice (F4) and setLockAfter", () => {
  test("after Lock now, a factor unlock binds to the kept device (its trustRoot the factor just used), and a rekey gives it a new unlock key, signed by itself, that Mail accepts from the device's own session", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const first = await keepDevice(e, store);
    await e.fake.updateDevice((await first.unlocked.lock()).updateDevice!, { session: first.session });
    const again = await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials }, { store, accountId: OWNER, signInId: "signin-1" }); // pragma: allowlist secret (a test double)
    expect(again.device).toEqual({ id: first.request.device.id, label: "Kitchen laptop", lockAfter: "sign-out", keepsUnlocked: false });
    const passkeyWrap = e.fake.wraps.find((w) => w.kind === "passkey-prf")!;
    expect((await store.get(e.mailboxId, OWNER))!.trustRoot).toBe(passkeyWrap.signingKey);
    const { session } = await openSession(e.fake, again);
    const pending = await again.rekeyThisDevice(again.freshFactor!);
    expect(Object.keys(pending.request).sort()).toEqual(["seal", "tag", "tagKeyId", "unlockKey", "unlockSignature"]);
    expect(fromB64url(pending.request.seal!).length).toBe(142);
    await e.fake.updateDevice(pending.request, { session });
    await pending.commit();
    const record = (await store.get(e.mailboxId, OWNER))!;
    expect(record.unlockPublic).toBe(pending.request.unlockKey);
    expect(again.device!.keepsUnlocked).toBe(true);
    const resumed = await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" });
    expect(resumed.state).toBe("unlocked");
  });

  test("Mail refuses an unlock key the device did not sign", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const first = await keepDevice(e, store);
    const pending = await first.unlocked.rekeyThisDevice(await first.unlocked.reauthenticate({ recoveryKey: e.recoveryKey }));
    const other = await first.unlocked.rekeyThisDevice(await first.unlocked.reauthenticate({ recoveryKey: e.recoveryKey }));
    await expect(e.fake.updateDevice({ ...pending.request, unlockSignature: other.request.unlockSignature }, { session: first.session })).rejects.toThrow(/InvalidRequest/);
  });

  test("setLockAfter(\"right-away\") drops the unlock key at once; back to a timed setting needs a rekey", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked, session } = await keepDevice(e, store);
    const toRightAway = await unlocked.setLockAfter("right-away");
    expect(toRightAway.updateDevice).toMatchObject({ unlockKey: null, unlockSignature: null, seal: null });
    expect(toRightAway.needsRekey).toBe(false);
    await e.fake.updateDevice(toRightAway.updateDevice!, { session });
    expect((await store.get(e.mailboxId, OWNER))!).toMatchObject({ lockAfter: "right-away", unlockKey: null });
    const back = await unlocked.setLockAfter("1-hour");
    expect(back).toEqual({ updateDevice: null, needsRekey: true });
    expect(unlocked.device).toMatchObject({ lockAfter: "1-hour", keepsUnlocked: false });
  });
});

describe("forget (K7)", () => {
  test("deletes this device's record and drops every key", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked } = await keepDevice(e, store);
    await unlocked.forget();
    expect(await store.get(e.mailboxId, OWNER)).toBeNull();
    expect(unlocked.locked).toBe(true);
    expect(unlocked.device).toBeNull();
  });

  test("an operation on a device another page forgot is DeviceRemoved", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked } = await keepDevice(e, store);
    await store.delete(e.mailboxId, OWNER);
    await expect(unlocked.setLockAfter("1-hour")).rejects.toBeInstanceOf(DeviceRemoved);
    expect(unlocked.device).toBeNull();
  });
});

describe("K10: another account's record is never read, opened, used or deleted", () => {
  /** Two people on one browser profile: the owner keeps a device; then another account of the business signs in. */
  async function sharedProfile() {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const owner = await keepDevice(e, store);
    const before = (await store.get(e.mailboxId, OWNER))!;
    return { e, store, owner, before };
  }
  async function untouched(store: DeviceStore, mailboxId: string, before: KeptDevice) {
    const after = (await store.get(mailboxId, OWNER))!;
    expect(after).not.toBeNull();
    expect([after.deviceId, after.lastKeyId, after.trustRoot, after.unlockPublic, after.signInId]).toEqual([before.deviceId, before.lastKeyId, before.trustRoot, before.unlockPublic, before.signInId]);
    expect(after.unlockKey).not.toBeNull();
  }

  test("resume: for another account the browser keeps nothing (none); the owner's record is not touched, and still opens for the owner", async () => {
    const { e, store, before } = await sharedProfile();
    const reads: string[] = [];
    const spy: DeviceStore = { ...store, get: (m, a) => (reads.push(a), store.get(m, a)) };
    expect(await resumeDevice(e.fake.mailbox(), { store: spy, accountId: OTHER, signInId: "signin-other" })).toEqual({ state: "none" });
    expect(reads).toEqual([OTHER]);
    await untouched(store, e.mailboxId, before);
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked");
  });

  test("unlock: another account's factor unlock binds no device and opens nothing of the owner's; its session proof carries no device", async () => {
    const { e, store, before } = await sharedProfile();
    e.fake.accountId = OTHER;
    const theirs = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OTHER, signInId: "signin-other" });
    expect(theirs.device).toBeNull();
    const challenge = await e.fake.challenge({ purpose: "session" });
    await expect(theirs.sessionProof(challenge)).rejects.toBeInstanceOf(TypeError); // D38: no device, so a factor proof is needed
    const { device } = await openSession(e.fake, theirs);
    expect(device).toBeNull();
    await untouched(store, e.mailboxId, before);
  });

  test("DeviceRevoked: forget() wipes this account's record only", async () => {
    const { e, store, before } = await sharedProfile();
    e.fake.accountId = OTHER;
    const kept = await keepDevice(e, store, { accountId: OTHER, signInId: "signin-other" });
    await kept.unlocked.forget();
    expect(await store.get(e.mailboxId, OTHER)).toBeNull();
    await untouched(store, e.mailboxId, before);
  });

  test("Forbidden: Mail answers another account's device with Forbidden, writes nothing, spends nothing; the browser wipes nothing", async () => {
    const { e, store, owner, before } = await sharedProfile();
    const proof = await owner.unlocked.sessionProof(await e.fake.challenge({ purpose: "session" }));
    e.fake.accountId = OTHER; // the same request, presented for another account (a page that read the owner's record would do this)
    const sessions = e.fake.mailSessions.size;
    await expect(e.fake.openSession(proof)).rejects.toThrow(/Forbidden/);
    expect(e.fake.mailSessions.size).toBe(sessions);
    expect(e.fake.challenges.get(proof.challengeId)!.used).toBe(false); // spends nothing
    await untouched(store, e.mailboxId, before);
    // The owner's device still works for the owner.
    e.fake.accountId = OWNER;
    expect((await e.fake.openSession(proof)).device).toBe(owner.request.device.id);
  });
});

describe("resumeDevice: a kept device loads the inbox (F2), in every lock state", () => {
  test("no record: none", async () => {
    const e = await enrolledMailbox();
    expect(await resumeDevice(e.fake.mailbox(), { store: memoryDeviceStore(), accountId: OWNER, signInId: null })).toEqual({ state: "none" });
  });

  test("unlocked: no prompt; the session holds the key, is this device's, and opens mail", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { request } = await keepDevice(e, store);
    const before = e.fake.mailSessions.size;
    const r = await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.device!.id).toBe(request.device.id);
    expect(r.mailbox.freshFactor).toBeNull();
    expect(r.mailbox.flagged).toEqual({ devices: [], factors: [] });
    const { item } = await e.fake.deliver();
    expect((await r.mailbox.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
    expect((await openSession(e.fake, r.mailbox)).device).toBe(request.device.id);
    expect(e.fake.mailSessions.size).toBe(before + 1);
  });

  test.each([
    ["15-minutes", 15 * 60_000],
    ["1-hour", 60 * 60_000],
  ] as const)("%s: unlocked until that long has passed since its last use, then locked (idle) with its unlock key deleted first", async (lockAfter, ms) => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter, now: clock });
    clock.advance(ms - 1);
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1", now: clock })).state).toBe("unlocked");
    clock.advance(ms); // the resume above was a use; this is ms after it
    const r = await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1", now: clock });
    expect(r).toMatchObject({ state: "locked", reason: "idle", device: { lockAfter, keepsUnlocked: false } });
    expect((await store.get(e.mailboxId, OWNER))!.unlockKey).toBeNull();
    // And it stays locked: the key is gone, not just skipped.
    expect(await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1", now: clock })).toMatchObject({ state: "locked", reason: "locked" });
  });

  test("D34, when I sign out: unlocked under the same sign-in id; locked (signed-out) under another, with its unlock key deleted", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "sign-out", signInId: "signin-1" });
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked");
    expect(await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-2" })).toMatchObject({ state: "locked", reason: "signed-out" });
    expect((await store.get(e.mailboxId, OWNER))!.unlockKey).toBeNull();
  });

  test("D34, when I sign out: no sign-in id after one (signed out) locks too: a fault fails locked", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "sign-out", signInId: "signin-1" });
    expect(await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: null })).toMatchObject({ state: "locked", reason: "signed-out" });
    expect((await store.get(e.mailboxId, OWNER))!.unlockKey).toBeNull();
  });

  test("D34, when I sign out, where the shell gives no sign-in id: two nulls never lock (\"until I lock it\")", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "sign-out", signInId: null });
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: null })).state).toBe("unlocked");
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: null })).state).toBe("unlocked");
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "now-there-is-one" })).state).toBe("locked");
  });

  test("right away: always locked, and nothing to delete", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "right-away" });
    expect(await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "right-away", device: { lockAfter: "right-away" } });
  });

  test("a device missing from the view is wiped (K7): removed", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    e.fake.devices = [];
    expect(await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).toEqual({ state: "removed" });
    expect(await store.get(e.mailboxId, OWNER)).toBeNull();
  });

  test("a device whose seal is of a newer key than it last accepted, each step signed by a trusted factor: unlocked, and it accepts the new key", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const first = e.fake.activeKey.keyId;
    const old = await e.fake.deliver();
    await rotateByHand(e.fake, e.recoveryKey);
    await rotateByHand(e.fake, e.recoveryKey);
    const r = await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.keyIds.length).toBe(3);
    expect(r.mailbox.keyIds.at(-1)).toBe(first);
    expect((await r.mailbox.openMessages([old.item]))[0]!.undecryptable).toBe(false);
    expect((await store.get(e.mailboxId, OWNER))!.lastKeyId).toBe(e.fake.activeKey.keyId);
  });

  test("K2′ rollback: an advertised key older than the one this device last accepted is refused", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const before = e.fake.mailbox(); // the view under the first key, with its seal to this device
    await rotateByHand(e.fake, e.recoveryKey);
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked"); // accepts the new key
    await expect(resumeDevice(before, { store, accountId: OWNER, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
    // The factor path refuses the rollback too, on this kept device.
    await expect(unlockWithRecoveryKey(before, e.recoveryKey, { store, accountId: OWNER, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("K2′: a key the server sealed to this device, with no chain back to the key it last accepted, is refused", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const { substituteKey } = await import("./keyring-support");
    await substituteKey(e.fake, "none");
    await expect(resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("K2′: a view made only of the server's own key, sealed to this device and tagged under it, is refused (every key in it is on its chain; the key this device last accepted is not)", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const { substituteKey } = await import("./keyring-support");
    await substituteKey(e.fake, "none");
    e.fake.keys = e.fake.keys.filter((k) => k.retiredAt === null); // the real key dropped from the view
    await expect(resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("K3′ at resume: a device the server added is flagged, and the device still opens the inbox", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const signing = new Uint8Array(65).fill(7);
    signing[0] = 4;
    e.fake.devices.push({ ...e.fake.devices[0]!, id: "dev_00000000000000000000000000", signingKey: b64url(signing), tag: b64url(new Uint8Array(32)) }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    const r = await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.flagged).toEqual({ devices: ["dev_00000000000000000000000000"], factors: [] });
  });

  test("no seal it can open (none, or one that does not open): locked (no-seal), and the useless unlock key is deleted", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const seals = e.fake.seals;
    e.fake.seals = [];
    expect(await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "no-seal" });
    expect((await store.get(e.mailboxId, OWNER))!.unlockKey).toBeNull();

    const e2 = await enrolledMailbox();
    const store2 = memoryDeviceStore();
    await keepDevice(e2, store2);
    e2.fake.seals = e2.fake.seals.map((s) => ({ ...s, sealed: seals[0]!.sealed })); // another device's seal
    expect(await resumeDevice(e2.fake.mailbox(), { store: store2, accountId: OWNER, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "no-seal" });
  });

  test("Mail listing this device with another signing key, or under another account, stops everything", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const real = e.fake.devices[0]!.signingKey;
    const other = new Uint8Array(65).fill(9);
    other[0] = 4;
    e.fake.devices[0]!.signingKey = b64url(other); // pragma: allowlist secret (public keys and test doubles, not secrets)
    await expect(resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
    e.fake.devices[0]!.signingKey = real; // pragma: allowlist secret (a public key)
    e.fake.devices[0]!.accountId = OTHER;
    await expect(resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("a view from a Mail Worker without spec 002: locked (no-seal), and the record is kept for when it is back", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    expect(await resumeDevice(e.fake.legacyMailbox(), { store, accountId: OWNER, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "no-seal" });
    expect((await store.get(e.mailboxId, OWNER))!.unlockKey).not.toBeNull();
    expect((await resumeDevice(e.fake.mailbox(), { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked");
  });
});

describe("K11: the last accepted key only moves forward, across two pages", () => {
  /** A store whose swaps wait for `gate`, so a test can let one page's write land between another page's read and write. */
  function gatedStore(inner: DeviceStore) {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((ok) => (release = ok));
    let reachedSwap: () => void = () => undefined;
    const atSwap = new Promise<void>((ok) => (reachedSwap = ok));
    const store: DeviceStore = {
      ...inner,
      swapLastKeyId: async (...args) => {
        reachedSwap();
        await gate;
        return inner.swapLastKeyId(...args);
      },
    };
    return { store, release, atSwap };
  }

  test("two pages shown different keys at once: the slower page's write misses, it resumes again from the newer value, and the anchor never moves back", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const k1 = e.fake.activeKey.keyId;
    const older = e.fake.mailbox(); // page B was shown the key ring under K1
    await rotateByHand(e.fake, e.recoveryKey);
    const newer = e.fake.mailbox(); // page A is shown it under K2
    const k2 = e.fake.activeKey.keyId;
    // B reads the record (K1) and walks its view; it reaches its write, and waits there.
    const slow = gatedStore(store);
    const pageB = resumeDevice(older, { store: slow.store, accountId: OWNER, signInId: "signin-1" });
    await slow.atSwap;
    // Meanwhile A resumes from the same record and moves the anchor K1 → K2.
    const pageA = await resumeDevice(newer, { store, accountId: OWNER, signInId: "signin-1" });
    expect(pageA.state).toBe("unlocked");
    expect((await store.get(e.mailboxId, OWNER))!.lastKeyId).toBe(k2);
    // B's write (K1 → K1) misses; B resumes again from the record as it now is (K2), which its older view cannot reach.
    slow.release();
    await expect(pageB).rejects.toBeInstanceOf(MailboxChanged);
    expect((await store.get(e.mailboxId, OWNER))!.lastKeyId).toBe(k2);
    expect(k1).not.toBe(k2);
    // With the newer view, B opens.
    expect((await resumeDevice(newer, { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked");
  });

  test("the same at a factor unlock on a kept device (F4): its write misses, and it never moves the anchor back", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const older = e.fake.mailbox();
    await rotateByHand(e.fake, e.recoveryKey);
    const newer = e.fake.mailbox();
    const k2 = e.fake.activeKey.keyId;
    const slow = gatedStore(store);
    const pageB = unlockWithRecoveryKey(older, e.recoveryKey, { store: slow.store, accountId: OWNER, signInId: "signin-1" });
    await slow.atSwap;
    expect((await resumeDevice(newer, { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked");
    slow.release();
    await expect(pageB).rejects.toBeInstanceOf(MailboxChanged);
    expect((await store.get(e.mailboxId, OWNER))!.lastKeyId).toBe(k2);
  });

  test("a miss whose newer value the page's own view reaches: it resumes again and opens", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    await rotateByHand(e.fake, e.recoveryKey);
    const view = e.fake.mailbox();
    const slow = gatedStore(store);
    const pageB = resumeDevice(view, { store: slow.store, accountId: OWNER, signInId: "signin-1" });
    await slow.atSwap;
    expect((await resumeDevice(view, { store, accountId: OWNER, signInId: "signin-1" })).state).toBe("unlocked");
    slow.release();
    expect((await pageB).state).toBe("unlocked");
  });
});

describe("a factor unlock on a kept device", () => {
  test("a passkey unlock binds to the kept device; a device the view no longer lists is forgotten instead (K7)", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { request } = await keepDevice(e, store);
    const byPasskey = await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials }, { store, accountId: OWNER, signInId: "signin-1" }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    expect(byPasskey.device!.id).toBe(request.device.id);
    e.fake.devices = [];
    const afterRemoval = await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials }, { store, accountId: OWNER, signInId: "signin-1" }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    expect(afterRemoval.device).toBeNull();
    expect(await store.get(e.mailboxId, OWNER)).toBeNull();
  });

  test("K5 holds across the whole life of a kept device: no write ever leaves anything but the listed fields", async () => {
    const e = await enrolledMailbox();
    const inner = memoryDeviceStore();
    const written: KeptDevice[] = [];
    const note = (r: KeptDevice | null) => {
      if (r) written.push(r);
      return r;
    };
    const store: DeviceStore = {
      get: (id, account) => inner.get(id, account),
      put: async (r) => {
        written.push(r);
        return inner.put(r);
      },
      update: async (id, account, dev, change) => note(await inner.update(id, account, dev, change)),
      swapLastKeyId: async (id, account, dev, expected, change) => {
        const result = await inner.swapLastKeyId(id, account, dev, expected, change);
        note(result.record);
        return result;
      },
      delete: (id, account, dev) => inner.delete(id, account, dev),
    };
    const { unlocked } = await keepDevice(e, store);
    await unlocked.lock();
    const again = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "signin-1" });
    const pending = await again.rekeyThisDevice(again.freshFactor!);
    await pending.commit();
    await again.setLockAfter("15-minutes");
    expect(written.length).toBeGreaterThanOrEqual(4);
    for (const r of written) {
      expect(Object.keys(r).sort()).toEqual([...KEPT_DEVICE_FIELDS].sort());
      expect(keysIn(r).every((k) => !k.extractable && k.algorithm.name !== "X25519")).toBe(true);
    }
  });
});

