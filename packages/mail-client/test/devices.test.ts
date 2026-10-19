// D1c and D1e: a kept device (contracts/device-v1.md Part C, K5 to K7; plan.md F1 to F4, F10): keep it,
// lock it, rekey it, change its lock setting, forget it, and come back to it with resumeDevice in every
// lock state. Mail is the strict fake; the store is the memory store, which clones as IndexedDB does.
import { afterEach, describe, expect, test, vi } from "vitest";
import {
  DeviceRemoved,
  FactorExpired,
  InvalidDeviceLabel,
  KEPT_DEVICE_FIELDS,
  KeySubstitutionDetected,
  MailboxLocked,
  memoryDeviceStore,
  resumeDevice,
  StorageUnavailable,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type DeviceStore,
  type KeptDevice,
  type LockAfter,
  type LockEvent,
  type UnlockedMailbox,
} from "../src/index";
import type { FakeMail } from "./fake-mail";
import { enrolledMailbox, rotateByHand, testClock, type Enrolled } from "./keyring-support";
import { b64url, fromB64url, sampleHeader } from "./support";

afterEach(() => {
  vi.useRealTimers();
});

/** openSession with the session's key proof (and the device's signature, on a kept device). */
async function openSession(fake: FakeMail, unlocked: UnlockedMailbox) {
  return fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })));
}

/** F1: unlock with the recovery key, open a session, answer a factor challenge, keep this device. */
async function keepDevice(e: Enrolled, store: DeviceStore, options: { lockAfter?: LockAfter; signInId?: string | null; now?: () => number; label?: string } = {}) {
  const signInId = options.signInId === undefined ? "signin-1" : options.signInId;
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId, ...(options.now ? { now: options.now } : {}) });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const factorProof = await ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId }));
  const pending = await unlocked.keepThisDevice({ label: options.label ?? "Kitchen laptop", ...(options.lockAfter ? { lockAfter: options.lockAfter } : {}) }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof });
  await pending.commit();
  return { unlocked, session, request: pending.request };
}

/** Every value in a stored record, recursively: no X25519 key, and every CryptoKey a non-extractable P-256 one. */
function keysIn(value: unknown, found: CryptoKey[] = []): CryptoKey[] {
  if (value instanceof CryptoKey) found.push(value);
  else if (typeof value === "object" && value !== null) for (const v of Object.values(value)) keysIn(v, found);
  return found;
}

describe("keepThisDevice (F1): one prompt, then the browser is kept", () => {
  test("registerDevice's request has Part B's shape; Mail accepts it with the session and a factor proof; commit stores exactly K5's fields", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked, request } = await keepDevice(e, store);
    const active = e.fake.activeKey.keyId;
    expect(Object.keys(request).sort()).toEqual(["device", "seal"]);
    expect(Object.keys(request.device).sort()).toEqual(["id", "label", "signingKey", "tag", "tagKeyId", "unlockKey"]);
    expect(request.device.id).toMatch(/^dev_[0-9a-hjkmnp-tv-z]{26}$/);
    expect(request.device.label).toBe("Kitchen laptop");
    expect(fromB64url(request.device.signingKey).length).toBe(65);
    expect(fromB64url(request.device.unlockKey!).length).toBe(65);
    expect(fromB64url(request.seal!).length).toBe(142);
    expect(request.device.tagKeyId).toBe(active);

    const record = (await store.get(e.mailboxId))!;
    expect(Object.keys(record).sort()).toEqual([...KEPT_DEVICE_FIELDS].sort());
    expect(record).toMatchObject({ mailboxId: e.mailboxId, deviceId: request.device.id, label: "Kitchen laptop", lastKeyId: active, lockAfter: "sign-out", signInId: "signin-1" });
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

  test("from then on the session is this device's: its key proof carries the device's signature, which Mail checks", async () => {
    const e = await enrolledMailbox();
    const { unlocked, request } = await keepDevice(e, memoryDeviceStore());
    const proof = await unlocked.sessionProof(await e.fake.challenge({ purpose: "session" }));
    expect(proof.device!.id).toBe(request.device.id);
    expect(fromB64url(proof.device!.signature).length).toBe(64);
    expect((await e.fake.openSession(proof)).device).toBe(request.device.id);
  });

  test("lock after right away: no unlock key and no seal are made", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { request } = await keepDevice(e, store, { lockAfter: "right-away" });
    expect(request.device.unlockKey).toBeNull();
    expect(request.seal).toBeNull();
    expect((await store.get(e.mailboxId))!).toMatchObject({ unlockKey: null, unlockPublic: null, lockAfter: "right-away" });
  });

  test("nothing is stored before commit(): a request Mail refused leaves this browser as it was", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store });
    const pending = await unlocked.keepThisDevice({ label: "Laptop" }, unlocked.freshFactor!);
    await expect(e.fake.registerDevice(pending.request, {})).rejects.toThrow(/SessionRequired/);
    expect(await store.get(e.mailboxId)).toBeNull();
    expect(unlocked.device).toBeNull();
  });

  test("refusals: a label the Worker would refuse, no store (a shared computer), a stale FreshFactor, a browser already kept", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const store = memoryDeviceStore();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, now: clock });
    const ff = unlocked.freshFactor!;
    for (const label of ["", "x".repeat(41), "two\nlines"]) await expect(unlocked.keepThisDevice({ label }, ff)).rejects.toBeInstanceOf(InvalidDeviceLabel);
    const shared = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    await expect(shared.keepThisDevice({ label: "Laptop" }, shared.freshFactor!)).rejects.toBeInstanceOf(StorageUnavailable);
    clock.advance(120_000);
    await expect(unlocked.keepThisDevice({ label: "Laptop" }, ff)).rejects.toBeInstanceOf(FactorExpired);
    const kept = await keepDevice(e, store, { now: clock });
    await expect(kept.unlocked.keepThisDevice({ label: "Again" }, await kept.unlocked.reauthenticate({ recoveryKey: e.recoveryKey }))).rejects.toBeInstanceOf(TypeError);
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
    expect((await store.get(e.mailboxId))!).toMatchObject({ unlockKey: null, unlockPublic: null });
    const request = result.updateDevice!;
    expect(Object.keys(request).sort()).toEqual(["seal", "tag", "tagKeyId", "unlockKey"]);
    expect(request).toMatchObject({ unlockKey: null, seal: null, tagKeyId: e.fake.activeKey.keyId });
    expect(events).toEqual([{ reason: "lock", updateDevice: request }]);
    const device = await e.fake.updateDevice(request, { session });
    expect(device.unlockKey).toBeNull();
    // The tag Mail now holds covers "no unlock key": a fresh unlock checks it (K3).
    await expect(unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).resolves.toBeDefined();
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
    expect((await store.get(e.mailboxId))!.unlockKey).toBeNull();
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
  test("after Lock now, a factor unlock binds to the kept device, and a rekey gives it a new unlock key that Mail accepts from the device's own session", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const first = await keepDevice(e, store);
    await e.fake.updateDevice((await first.unlocked.lock()).updateDevice!, { session: first.session });
    const again = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "signin-1" });
    expect(again.device).toEqual({ id: first.request.device.id, label: "Kitchen laptop", lockAfter: "sign-out", keepsUnlocked: false });
    const { session } = await openSession(e.fake, again);
    const pending = await again.rekeyThisDevice(again.freshFactor!);
    expect(Object.keys(pending.request).sort()).toEqual(["seal", "tag", "tagKeyId", "unlockKey"]);
    expect(fromB64url(pending.request.seal!).length).toBe(142);
    await e.fake.updateDevice(pending.request, { session });
    await pending.commit();
    const record = (await store.get(e.mailboxId))!;
    expect(record.unlockPublic).toBe(pending.request.unlockKey);
    expect(again.device!.keepsUnlocked).toBe(true);
    const resumed = await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" });
    expect(resumed.state).toBe("unlocked");
  });

  test("setLockAfter(\"right-away\") drops the unlock key at once; back to a timed setting needs a rekey", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked, session } = await keepDevice(e, store);
    const toRightAway = await unlocked.setLockAfter("right-away");
    expect(toRightAway.updateDevice!.unlockKey).toBeNull();
    expect(toRightAway.needsRekey).toBe(false);
    await e.fake.updateDevice(toRightAway.updateDevice!, { session });
    expect((await store.get(e.mailboxId))!).toMatchObject({ lockAfter: "right-away", unlockKey: null });
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
    expect(await store.get(e.mailboxId)).toBeNull();
    expect(unlocked.locked).toBe(true);
    expect(unlocked.device).toBeNull();
  });

  test("an operation on a device another page forgot is DeviceRemoved", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { unlocked } = await keepDevice(e, store);
    await store.delete(e.mailboxId);
    await expect(unlocked.setLockAfter("1-hour")).rejects.toBeInstanceOf(DeviceRemoved);
    expect(unlocked.device).toBeNull();
  });
});

describe("resumeDevice: a kept device loads the inbox (F2), in every lock state", () => {
  test("no record: none", async () => {
    const e = await enrolledMailbox();
    expect(await resumeDevice(e.fake.mailbox(), { store: memoryDeviceStore(), signInId: null })).toEqual({ state: "none" });
  });

  test("unlocked: no prompt; the session holds the key, is this device's, and opens mail", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { request } = await keepDevice(e, store);
    const before = e.fake.mailSessions.size;
    const r = await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.device!.id).toBe(request.device.id);
    expect(r.mailbox.freshFactor).toBeNull();
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
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1", now: clock })).state).toBe("unlocked");
    clock.advance(ms); // the resume above was a use; this is ms after it
    const r = await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1", now: clock });
    expect(r).toMatchObject({ state: "locked", reason: "idle", device: { lockAfter, keepsUnlocked: false } });
    expect((await store.get(e.mailboxId))!.unlockKey).toBeNull();
    // And it stays locked: the key is gone, not just skipped.
    expect(await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1", now: clock })).toMatchObject({ state: "locked", reason: "locked" });
  });

  test("when I sign out: unlocked under the same sign-in id; locked (signed-out) under another, with its unlock key deleted", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "sign-out", signInId: "signin-1" });
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).state).toBe("unlocked");
    expect(await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-2" })).toMatchObject({ state: "locked", reason: "signed-out" });
    expect((await store.get(e.mailboxId))!.unlockKey).toBeNull();
  });

  test("when I sign out, where the shell gives no sign-in id: \"until I lock it\" (D30)", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "sign-out", signInId: null });
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: null })).state).toBe("unlocked");
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: "now-there-is-one" })).state).toBe("locked");
  });

  test("right away: always locked, and nothing to delete", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store, { lockAfter: "right-away" });
    expect(await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "right-away", device: { lockAfter: "right-away" } });
  });

  test("a device missing from the view is wiped (K7): removed", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    e.fake.devices = [];
    expect(await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).toEqual({ state: "removed" });
    expect(await store.get(e.mailboxId)).toBeNull();
  });

  test("a device whose seal is of a newer key than it last accepted, with a valid chain: unlocked, and it accepts the new key", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const first = e.fake.activeKey.keyId;
    const old = await e.fake.deliver();
    await rotateByHand(e.fake, e.recoveryKey);
    await rotateByHand(e.fake, e.recoveryKey);
    const r = await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.keyIds.length).toBe(3);
    expect(r.mailbox.keyIds.at(-1)).toBe(first);
    expect((await r.mailbox.openMessages([old.item]))[0]!.undecryptable).toBe(false);
    expect((await store.get(e.mailboxId))!.lastKeyId).toBe(e.fake.activeKey.keyId);
  });

  test("K2′ rollback: an advertised key older than the one this device last accepted is refused", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const before = e.fake.mailbox(); // the view under the first key, with its seal to this device
    await rotateByHand(e.fake, e.recoveryKey);
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).state).toBe("unlocked"); // accepts the new key
    await expect(resumeDevice(before, { store, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
    // The factor path refuses the rollback too, on this kept device.
    await expect(unlockWithRecoveryKey(before, e.recoveryKey, { store, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("K2′: a key the server sealed to this device, with no chain back to the key it last accepted, is refused", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const { substituteKey } = await import("./keyring-support");
    await substituteKey(e.fake, "none");
    await expect(resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("K2′: a view made only of the server's own key, sealed to this device and tagged under it, is refused (every key in it is on its chain; the key this device last accepted is not)", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const { substituteKey } = await import("./keyring-support");
    await substituteKey(e.fake, "none");
    e.fake.keys = e.fake.keys.filter((k) => k.retiredAt === null); // the real key dropped from the view
    await expect(resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("K3 at resume: a device the server added is flagged, and the device still opens the inbox", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const signing = new Uint8Array(65).fill(7);
    signing[0] = 4;
    e.fake.devices.push({ ...e.fake.devices[0]!, id: "dev_00000000000000000000000000", signingKey: b64url(signing), tag: b64url(new Uint8Array(32)) }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    const r = await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" });
    if (r.state !== "unlocked") throw new Error(r.state);
    expect(r.mailbox.flagged).toEqual({ devices: ["dev_00000000000000000000000000"], factors: [] });
  });

  test("no seal it can open (none, or one that does not open): locked (no-seal), and the useless unlock key is deleted", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const seals = e.fake.seals;
    e.fake.seals = [];
    expect(await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "no-seal" });
    expect((await store.get(e.mailboxId))!.unlockKey).toBeNull();

    const e2 = await enrolledMailbox();
    const store2 = memoryDeviceStore();
    await keepDevice(e2, store2);
    e2.fake.seals = e2.fake.seals.map((s) => ({ ...s, sealed: seals[0]!.sealed })); // another device's seal
    expect(await resumeDevice(e2.fake.mailbox(), { store: store2, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "no-seal" });
  });

  test("Mail listing this device with another signing key stops everything", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    const other = new Uint8Array(65).fill(9);
    other[0] = 4;
    e.fake.devices[0]!.signingKey = b64url(other); // pragma: allowlist secret (public keys and test doubles, not secrets)
    await expect(resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("a view from a Mail Worker without spec 002: locked (no-seal), and the record is kept for when it is back", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    await keepDevice(e, store);
    expect(await resumeDevice(e.fake.legacyMailbox(), { store, signInId: "signin-1" })).toMatchObject({ state: "locked", reason: "no-seal" });
    expect((await store.get(e.mailboxId))!.unlockKey).not.toBeNull();
    expect((await resumeDevice(e.fake.mailbox(), { store, signInId: "signin-1" })).state).toBe("unlocked");
  });
});

describe("a factor unlock on a kept device", () => {
  test("a passkey unlock binds to the kept device; a device the view no longer lists is forgotten instead (K7)", async () => {
    const e = await enrolledMailbox();
    const store = memoryDeviceStore();
    const { request } = await keepDevice(e, store);
    const byPasskey = await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials }, { store, signInId: "signin-1" }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    expect(byPasskey.device!.id).toBe(request.device.id);
    e.fake.devices = [];
    const afterRemoval = await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials }, { store, signInId: "signin-1" }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    expect(afterRemoval.device).toBeNull();
    expect(await store.get(e.mailboxId)).toBeNull();
  });

  test("K5 holds across the whole life of a kept device: no write ever leaves anything but the listed fields", async () => {
    const e = await enrolledMailbox();
    const inner = memoryDeviceStore();
    const written: KeptDevice[] = [];
    const store: DeviceStore = {
      get: (id) => inner.get(id),
      put: async (r) => {
        written.push(r);
        return inner.put(r);
      },
      update: async (id, dev, change) => {
        const r = await inner.update(id, dev, change);
        if (r) written.push(r);
        return r;
      },
      delete: (id, dev) => inner.delete(id, dev),
    };
    const { unlocked } = await keepDevice(e, store);
    await unlocked.lock();
    const again = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "signin-1" });
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
