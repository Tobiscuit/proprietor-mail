// D1c and round 3: the kept-device store (contracts/device-v1.md Part C, K5, K10, K11; mail-client rule 3
// as amended). One record per mailbox AND account, with exactly K5's fields, checked on every write;
// updates and deletes name the device they are for; the last accepted key moves only by a swap that
// reads, compares and writes at once. The memory store clones on every read and write, as IndexedDB
// does, so these tests see what a browser would. The IndexedDB store runs in the browser tests.
import { describe, expect, test } from "vitest";
import { generateSigningKey, generateUnlockKey, newId } from "@proprietor/mail-crypto";
import { canKeepDevices, DEVICE_DATABASE, KEPT_DEVICE_FIELDS, memoryDeviceStore, type DeviceStore, type KeptDevice } from "../src/index";
import { b64url } from "./support";

const OWNER = "acc_owner";
const OTHER = "acc_other";
const K1 = "0123456789abcdef0123456789abcdef";
const K2 = "fedcba9876543210fedcba9876543210";

async function record(overrides: Partial<KeptDevice> = {}): Promise<KeptDevice> {
  const signing = await generateSigningKey();
  const unlock = await generateUnlockKey();
  return {
    mailboxId: newId("mbx"),
    accountId: OWNER,
    deviceId: newId("dev"),
    label: "Kitchen laptop",
    signingKey: signing.privateKey, // pragma: allowlist secret (a CryptoKey reference in a test)
    unlockKey: unlock.privateKey,
    signingPublic: b64url(signing.publicKey),
    unlockPublic: b64url(unlock.publicKey),
    lastKeyId: K1,
    trustRoot: b64url(crypto.getRandomValues(new Uint8Array(32))),
    lockAfter: "sign-out",
    lastActiveAt: 1_760_000_000_000,
    signInId: "signin-1",
    ...overrides,
  };
}

describe("K5: exactly the listed fields", () => {
  test("the field list is K5's, in the domain model's order (round 3: the account and the trust root)", () => {
    expect(KEPT_DEVICE_FIELDS).toEqual([
      "mailboxId",
      "accountId",
      "deviceId",
      "label",
      "signingKey",
      "unlockKey",
      "signingPublic",
      "unlockPublic",
      "lastKeyId",
      "trustRoot",
      "lockAfter",
      "lastActiveAt",
      "signInId",
    ]);
  });

  test("version 2 of the one database keys a record by mailbox and account", () => {
    expect(DEVICE_DATABASE).toEqual({ name: "proprietor-mail", version: 2, store: "kept-devices", keyPath: ["mailboxId", "accountId"] });
  });

  test("a stored record reads back with exactly those fields, its keys still non-extractable P-256 CryptoKeys", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    const back = (await store.get(r.mailboxId, OWNER))!;
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
    for (const field of ["signInId", "accountId", "trustRoot"] as const) {
      const { [field]: _drop, ...missing } = r;
      await expect(store.put(missing as KeptDevice), field).rejects.toBeInstanceOf(TypeError);
    }
    expect(await store.get(r.mailboxId, OWNER)).toBeNull();
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

  test("plain facts are checked too: ids, account, label, public forms, keyId, trust root, lock setting, time, sign-in id", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    for (const bad of [
      { mailboxId: "mbx_short" },
      { accountId: "" },
      { accountId: "acc\nother" },
      { accountId: "x".repeat(256) },
      { deviceId: newId("wrp") },
      { label: "" },
      { label: "x".repeat(41) },
      { label: "two\nlines" },
      { label: "two lines" },
      { label: "next\u0085line" },
      { label: "\u{1F3E0}".repeat(41) }, // 41 characters, though 82 UTF-16 units
      { signingPublic: b64url(new Uint8Array(64)) },
      { unlockPublic: null },
      { unlockKey: null },
      { lastKeyId: "ABC" },
      { trustRoot: b64url(new Uint8Array(65)) },
      { trustRoot: "" },
      { lockAfter: "never" as KeptDevice["lockAfter"] },
      { lockAfter: "right-away" as const }, // "right-away" keeps no unlock key
      { lastActiveAt: Number.NaN },
      { signInId: "" },
    ]) {
      await expect(store.put({ ...r, ...bad }), JSON.stringify(Object.keys(bad))).rejects.toBeInstanceOf(TypeError);
    }
    await store.put({ ...r, unlockKey: null, unlockPublic: null, lockAfter: "right-away", signInId: null });
    expect((await store.get(r.mailboxId, OWNER))!.lockAfter).toBe("right-away");
    // 1 to 40 characters counts code points, as the Worker does (device-v1 B7): 40 houses fit.
    await store.put({ ...r, label: "\u{1F3E0}".repeat(40) });
    expect((await store.get(r.mailboxId, OWNER))!.label).toBe("\u{1F3E0}".repeat(40));
  });
});

describe("K10: one record per mailbox and account; another account's is never read, written or deleted", () => {
  test("two accounts on one browser keep two records of one mailbox; each reads only its own", async () => {
    const store = memoryDeviceStore();
    const mine = await record();
    const theirs = await record({ mailboxId: mine.mailboxId, accountId: OTHER });
    await store.put(mine);
    await store.put(theirs);
    expect((await store.get(mine.mailboxId, OWNER))!.deviceId).toBe(mine.deviceId);
    expect((await store.get(mine.mailboxId, OTHER))!.deviceId).toBe(theirs.deviceId);
    expect(await store.get(mine.mailboxId, "acc_third")).toBeNull();
  });

  test("an update, a swap or a delete for one account leaves the other's record exactly as it was", async () => {
    const store = memoryDeviceStore();
    const mine = await record();
    const theirs = await record({ mailboxId: mine.mailboxId, accountId: OTHER });
    await store.put(mine);
    await store.put(theirs);
    // The other account's device id, named under this account, is no record of this account.
    expect(await store.update(mine.mailboxId, OWNER, theirs.deviceId, { lastActiveAt: 1 })).toBeNull();
    expect((await store.swapLastKeyId(mine.mailboxId, OWNER, theirs.deviceId, K1, { lastKeyId: K2 })).swapped).toBe(false);
    await store.delete(mine.mailboxId, OWNER, theirs.deviceId);
    await store.update(mine.mailboxId, OWNER, mine.deviceId, { lastActiveAt: 7 });
    await store.delete(mine.mailboxId, OWNER);
    const back = (await store.get(mine.mailboxId, OTHER))!;
    expect([back.deviceId, back.lastKeyId, back.lastActiveAt, back.unlockPublic]).toEqual([theirs.deviceId, K1, theirs.lastActiveAt, theirs.unlockPublic]);
    expect(await store.get(mine.mailboxId, OWNER)).toBeNull();
  });

  test("every call names a well-formed mailbox and account: anything else is a caller's mistake", async () => {
    const store = memoryDeviceStore();
    await expect(store.get(newId("mbx"), "")).rejects.toBeInstanceOf(TypeError);
    await expect(store.get("mbx_short", OWNER)).rejects.toBeInstanceOf(TypeError);
    await expect(store.delete(newId("mbx"), undefined as never)).rejects.toBeInstanceOf(TypeError);
  });
});

describe("updates and deletes name their device", () => {
  test("put replaces the account's record of the mailbox; another mailbox's is separate", async () => {
    const store = memoryDeviceStore();
    const a = await record();
    const b = await record({ mailboxId: a.mailboxId });
    const c = await record();
    await store.put(a);
    await store.put(c);
    await store.put(b);
    expect((await store.get(a.mailboxId, OWNER))!.deviceId).toBe(b.deviceId);
    expect((await store.get(c.mailboxId, OWNER))!.deviceId).toBe(c.deviceId);
    expect(await store.get(newId("mbx"), OWNER)).toBeNull();
  });

  test("update changes only the listed fields, of the named device, and checks the result", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    const updated = await store.update(r.mailboxId, OWNER, r.deviceId, { unlockKey: null, unlockPublic: null, lastActiveAt: r.lastActiveAt + 1 });
    expect(updated).toMatchObject({ deviceId: r.deviceId, unlockKey: null, unlockPublic: null, lastActiveAt: r.lastActiveAt + 1, label: r.label });
    expect(await store.update(r.mailboxId, OWNER, newId("dev"), { lastActiveAt: 1 })).toBeNull();
    expect((await store.get(r.mailboxId, OWNER))!.lastActiveAt).toBe(r.lastActiveAt + 1);
    await expect(store.update(r.mailboxId, OWNER, r.deviceId, { unlockPublic: r.unlockPublic })).rejects.toBeInstanceOf(TypeError); // a public form without its key
    await expect(store.update(r.mailboxId, OWNER, r.deviceId, { deviceId: newId("dev") } as never)).rejects.toBeInstanceOf(TypeError);
    await expect(store.update(r.mailboxId, OWNER, r.deviceId, { accountId: OTHER } as never)).rejects.toBeInstanceOf(TypeError);
  });

  test("delete with a device id leaves another device's record alone", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    await store.delete(r.mailboxId, OWNER, newId("dev"));
    expect(await store.get(r.mailboxId, OWNER)).not.toBeNull();
    await store.delete(r.mailboxId, OWNER, r.deviceId);
    expect(await store.get(r.mailboxId, OWNER)).toBeNull();
    await store.put(r);
    await store.delete(r.mailboxId, OWNER);
    expect(await store.get(r.mailboxId, OWNER)).toBeNull();
  });
});

describe("K11: the last accepted key moves only from the key the caller read", () => {
  test("swapLastKeyId writes only while the record still holds the expected key, and says which happened", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    const first = await store.swapLastKeyId(r.mailboxId, OWNER, r.deviceId, K1, { lastKeyId: K2, lastActiveAt: 5 });
    expect(first.swapped).toBe(true);
    expect(first.record).toMatchObject({ lastKeyId: K2, lastActiveAt: 5 });
    // A page that read K1 before that write tries to set K1 again: it misses, and sees the record as it now is.
    const second = await store.swapLastKeyId(r.mailboxId, OWNER, r.deviceId, K1, { lastKeyId: K1, lastActiveAt: 6 });
    expect(second.swapped).toBe(false);
    expect(second.record).toMatchObject({ lastKeyId: K2, lastActiveAt: 5 });
    expect((await store.get(r.mailboxId, OWNER))!.lastKeyId).toBe(K2);
    // A device the record is not about, or no record: nothing written, no record.
    expect(await store.swapLastKeyId(r.mailboxId, OWNER, newId("dev"), K2, { lastKeyId: K1 })).toEqual({ swapped: false, record: null });
    expect(await store.swapLastKeyId(newId("mbx"), OWNER, r.deviceId, K2, { lastKeyId: K1 })).toEqual({ swapped: false, record: null });
  });

  test("two swaps from the same read: exactly one wins, whatever their order", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    const results = await Promise.all([
      store.swapLastKeyId(r.mailboxId, OWNER, r.deviceId, K1, { lastKeyId: K2 }),
      store.swapLastKeyId(r.mailboxId, OWNER, r.deviceId, K1, { lastKeyId: K1, lastActiveAt: 9 }),
    ]);
    expect(results.filter((x) => x.swapped).length).toBe(1);
    expect((await store.get(r.mailboxId, OWNER))!.lastKeyId).toBe(K2);
  });

  test("a swap that would break K5 is refused and writes nothing", async () => {
    const store = memoryDeviceStore();
    const r = await record();
    await store.put(r);
    await expect(store.swapLastKeyId(r.mailboxId, OWNER, r.deviceId, K1, { lastKeyId: "not a key id" })).rejects.toBeInstanceOf(TypeError);
    expect((await store.get(r.mailboxId, OWNER))!.lastKeyId).toBe(K1);
  });
});

describe("canKeepDevices (D31)", () => {
  test("true for a store that keeps non-extractable P-256 keys and gives them back working; it leaves nothing behind", async () => {
    const seen: [string, string][] = [];
    const inner = memoryDeviceStore();
    const spy: DeviceStore = {
      get: (id, account) => inner.get(id, account),
      put: async (r) => {
        seen.push([r.mailboxId, r.accountId]);
        return inner.put(r);
      },
      update: (id, account, dev, change) => inner.update(id, account, dev, change),
      swapLastKeyId: (id, account, dev, expected, change) => inner.swapLastKeyId(id, account, dev, expected, change),
      delete: (id, account, dev) => inner.delete(id, account, dev),
    };
    expect(await canKeepDevices(spy)).toBe(true);
    expect(seen.length).toBe(1);
    expect(await inner.get(...seen[0]!)).toBeNull();
  });

  test("false, never an exception, where keys cannot be kept: a write refused (a private window), a read that loses them, a read that changes them", async () => {
    const inner = memoryDeviceStore();
    const refusing: DeviceStore = { ...inner, put: async () => Promise.reject(new DOMException("could not clone", "DataCloneError")) };
    const losing: DeviceStore = { ...inner, put: async () => undefined, get: async () => null };
    const garbled: DeviceStore = {
      ...inner,
      put: (r) => inner.put(r),
      get: async (id, account) => {
        const r = await inner.get(id, account);
        const other = await generateSigningKey();
        return r && { ...r, signingKey: other.privateKey }; // pragma: allowlist secret (a CryptoKey reference in a test)
      },
      delete: (id, account, dev) => inner.delete(id, account, dev),
    };
    const throwing: DeviceStore = { ...inner, get: async () => Promise.reject(new Error("unavailable")), put: async () => Promise.reject(new Error("unavailable")) };
    for (const store of [refusing, losing, garbled, throwing]) expect(await canKeepDevices(store)).toBe(false);
  });
});
