// D1c: the kept-device store (contracts/device-v1.md Part C, K5; mail-client rule 3 as amended).
// One record per mailbox with exactly K5's fields, checked on every write; updates and deletes name
// the device they are for. The memory store clones on every read and write, as IndexedDB does, so
// these tests see what a browser would. The IndexedDB store runs in the browser tests.
import { describe, expect, test } from "vitest";
import { generateSigningKey, generateUnlockKey, newId } from "@proprietor/mail-crypto";
import { canKeepDevices, KEPT_DEVICE_FIELDS, memoryDeviceStore, type DeviceStore, type KeptDevice } from "../src/index";
import { b64url } from "./support";

async function record(overrides: Partial<KeptDevice> = {}): Promise<KeptDevice> {
  const signing = await generateSigningKey();
  const unlock = await generateUnlockKey();
  return {
    mailboxId: newId("mbx"),
    deviceId: newId("dev"),
    label: "Kitchen laptop",
    signingKey: signing.privateKey, // pragma: allowlist secret (a CryptoKey reference in a test)
    unlockKey: unlock.privateKey,
    signingPublic: b64url(signing.publicKey),
    unlockPublic: b64url(unlock.publicKey),
    lastKeyId: "0123456789abcdef0123456789abcdef",
    lockAfter: "sign-out",
    lastActiveAt: 1_760_000_000_000,
    signInId: "signin-1",
    ...overrides,
  };
}

describe("K5: exactly the listed fields", () => {
  test("the field list is K5's, in the domain model's order", () => {
    expect(KEPT_DEVICE_FIELDS).toEqual([
      "mailboxId",
      "deviceId",
      "label",
      "signingKey",
      "unlockKey",
      "signingPublic",
      "unlockPublic",
      "lastKeyId",
      "lockAfter",
      "lastActiveAt",
      "signInId",
    ]);
  });

  test("a stored record reads back with exactly those fields, its keys still non-extractable P-256 CryptoKeys", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    const back = (await store.get(r.mailboxId))!;
    expect(Object.keys(back).sort()).toEqual([...KEPT_DEVICE_FIELDS].sort());
    expect(back).not.toBe(r);
    expect(back.signingKey).not.toBe(r.signingKey); // a structured clone, as IndexedDB gives
    expect(back.signingKey).toBeInstanceOf(CryptoKey);
    expect(back.signingKey.extractable).toBe(false);
    expect(back.signingKey.algorithm).toEqual({ name: "ECDSA", namedCurve: "P-256" });
    expect(back.unlockKey!.algorithm).toEqual({ name: "ECDH", namedCurve: "P-256" });
    expect(back.unlockKey!.extractable).toBe(false);
    // The clone still signs, with the same key.
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, back.signingKey, new Uint8Array(1));
    const pub = await crypto.subtle.importKey("raw", Buffer.from(r.signingPublic, "base64url"), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, sig, new Uint8Array(1))).toBe(true);
  });

  test("a write with any other field, or without one of them, is refused: nothing else ever persists", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    const x25519 = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
    await expect(store.put({ ...r, mailboxKey: x25519.privateKey } as unknown as KeptDevice)).rejects.toBeInstanceOf(TypeError);
    await expect(store.put({ ...r, session: "token" } as unknown as KeptDevice)).rejects.toBeInstanceOf(TypeError);
    const { signInId: _drop, ...missing } = r;
    await expect(store.put(missing as KeptDevice)).rejects.toBeInstanceOf(TypeError);
    expect(await store.get(r.mailboxId)).toBeNull();
  });

  test("only non-extractable P-256 keys of the right kind are kept: never X25519, never extractable, never swapped", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    const x25519 = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
    const extractable = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    for (const bad of [
      { signingKey: x25519.privateKey }, // pragma: allowlist secret (a CryptoKey reference in a test)
      { unlockKey: x25519.privateKey },
      { signingKey: extractable.privateKey }, // pragma: allowlist secret (a CryptoKey reference in a test)
      { signingKey: r.unlockKey! }, // pragma: allowlist secret (a CryptoKey reference in a test)
      { unlockKey: r.signingKey },
    ]) {
      await expect(store.put({ ...r, ...bad })).rejects.toBeInstanceOf(TypeError);
    }
  });

  test("plain facts are checked too: ids, label, public forms, keyId, lock setting, time, sign-in id", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    for (const bad of [
      { mailboxId: "mbx_short" },
      { deviceId: newId("wrp") },
      { label: "" },
      { label: "x".repeat(41) },
      { label: "two\nlines" },
      { signingPublic: b64url(new Uint8Array(64)) },
      { unlockPublic: null },
      { unlockKey: null },
      { lastKeyId: "ABC" },
      { lockAfter: "never" as KeptDevice["lockAfter"] },
      { lockAfter: "right-away" as const }, // "right-away" keeps no unlock key
      { lastActiveAt: Number.NaN },
      { signInId: "" },
    ]) {
      await expect(store.put({ ...r, ...bad }), JSON.stringify(Object.keys(bad))).rejects.toBeInstanceOf(TypeError);
    }
    await store.put({ ...r, unlockKey: null, unlockPublic: null, lockAfter: "right-away", signInId: null });
    expect((await store.get(r.mailboxId))!.lockAfter).toBe("right-away");
  });
});

describe("one record per mailbox; updates and deletes name their device", () => {
  test("put replaces the mailbox's record; another mailbox's is separate", async () => {
    const store = memoryDeviceStore();
    const a = await record();
    const b = await record({ mailboxId: a.mailboxId });
    const c = await record();
    await store.put(a);
    await store.put(c);
    await store.put(b);
    expect((await store.get(a.mailboxId))!.deviceId).toBe(b.deviceId);
    expect((await store.get(c.mailboxId))!.deviceId).toBe(c.deviceId);
    expect(await store.get(newId("mbx"))).toBeNull();
  });

  test("update changes only the listed fields, of the named device, and checks the result", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    const updated = await store.update(r.mailboxId, r.deviceId, { unlockKey: null, unlockPublic: null, lastActiveAt: r.lastActiveAt + 1 });
    expect(updated).toMatchObject({ deviceId: r.deviceId, unlockKey: null, unlockPublic: null, lastActiveAt: r.lastActiveAt + 1, label: r.label });
    expect(await store.update(r.mailboxId, newId("dev"), { lastActiveAt: 1 })).toBeNull();
    expect((await store.get(r.mailboxId))!.lastActiveAt).toBe(r.lastActiveAt + 1);
    await expect(store.update(r.mailboxId, r.deviceId, { unlockPublic: r.unlockPublic })).rejects.toBeInstanceOf(TypeError); // a public form without its key
    await expect(store.update(r.mailboxId, r.deviceId, { deviceId: newId("dev") } as never)).rejects.toBeInstanceOf(TypeError);
  });

  test("delete with a device id leaves another device's record alone", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    await store.delete(r.mailboxId, newId("dev"));
    expect(await store.get(r.mailboxId)).not.toBeNull();
    await store.delete(r.mailboxId, r.deviceId);
    expect(await store.get(r.mailboxId)).toBeNull();
    await store.put(r);
    await store.delete(r.mailboxId);
    expect(await store.get(r.mailboxId)).toBeNull();
  });
});

describe("canKeepDevices (D31)", () => {
  test("true for a store that keeps non-extractable P-256 keys and gives them back working; it leaves nothing behind", async () => {
    const seen: string[] = [];
    const inner = memoryDeviceStore();
    const spy: DeviceStore = {
      get: (id) => inner.get(id),
      put: async (r) => {
        seen.push(r.mailboxId);
        return inner.put(r);
      },
      update: (id, dev, change) => inner.update(id, dev, change),
      delete: (id, dev) => inner.delete(id, dev),
    };
    expect(await canKeepDevices(spy)).toBe(true);
    expect(seen.length).toBe(1);
    expect(await inner.get(seen[0]!)).toBeNull();
  });

  test("false, never an exception, where keys cannot be kept: a write refused (a private window), a read that loses them, a read that changes them", async () => {
    const inner = memoryDeviceStore();
    const refusing: DeviceStore = { ...inner, put: async () => Promise.reject(new DOMException("could not clone", "DataCloneError")) };
    const losing: DeviceStore = { ...inner, put: async () => undefined, get: async () => null };
    const garbled: DeviceStore = {
      ...inner,
      put: (r) => inner.put(r),
      get: async (id) => {
        const r = await inner.get(id);
        const other = await generateSigningKey();
        return r && { ...r, signingKey: other.privateKey }; // pragma: allowlist secret (a CryptoKey reference in a test)
      },
      delete: (id, dev) => inner.delete(id, dev),
    };
    const throwing: DeviceStore = { ...inner, get: async () => Promise.reject(new Error("unavailable")), put: async () => Promise.reject(new Error("unavailable")) };
    for (const store of [refusing, losing, garbled, throwing]) expect(await canKeepDevices(store)).toBe(false);
  });
});
