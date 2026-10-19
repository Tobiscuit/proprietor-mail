/**
 * The kept-device store (contracts/device-v1.md Part C, K5; mail-client rule 3
 * as amended by spec 002): the ONE place this package persists anything, and
 * the only module the runtime scan lets touch IndexedDB.
 *
 * One database for the package, one record per mailbox, exactly K5's fields:
 * the device id and label, two non-extractable P-256 private keys and their
 * public forms, the keyId it last accepted, its lock setting, its last
 * activity and the sign-in id it was unlocked under. Every write is checked
 * here, so no caller can persist a mailbox key, a factor secret, a token or
 * decrypted content through it: a record with any other field, or with any
 * key that is not a non-extractable P-256 key of the right kind, is refused.
 * IndexedDB keeps a CryptoKey by structured clone, and a non-extractable key
 * stays non-extractable (MDN, "Storing keys"). P-256 because WebKit cannot read
 * an X25519 key back from IndexedDB (spec 002 §9).
 *
 * Updates and deletes name the device they are for and run in one
 * transaction, so a page that is behind never resurrects a key another page
 * deleted (a lock), or touches a device another page made.
 */
import { generateSigningKey, generateUnlockKey, isDeviceSigningKey, isDeviceUnlockKey, newId } from "@proprietor/mail-crypto";
import { base64url, bytesEqual, fromBase64url, randomBytes } from "./bytes";
import { StorageUnavailable } from "./errors";
import type { DeviceStore, KeptDevice, KeptDeviceChange, LockAfter } from "./types";

/** K5's fields, in the domain model's order (specs/002-device-sessions/domain-model.md). */
export const KEPT_DEVICE_FIELDS = Object.freeze([
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
] as const);

const CHANGEABLE: readonly string[] = ["unlockKey", "unlockPublic", "lastKeyId", "lockAfter", "lastActiveAt", "signInId"];
const LOCK_SETTINGS: readonly string[] = ["right-away", "15-minutes", "1-hour", "sign-out"] satisfies LockAfter[];
const MAILBOX_ID = /^mbx_[0-9a-hjkmnp-tv-z]{26}$/;
const DEVICE_ID = /^dev_[0-9a-hjkmnp-tv-z]{26}$/;
const KEY_ID = /^[0-9a-f]{32}$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const SIGN_IN_ID_MAX = 512;

/** Line breaks beyond the control characters: NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR. */
const LINE_SEPARATORS = /[\u0085\u2028\u2029]/;

/**
 * A device name the Worker accepts (device-v1 B7): 1 to 40 characters,
 * counted as code points as the Worker counts them, on one line, as
 * well-formed Unicode (its tag covers UTF-8(label), A5).
 */
export function deviceLabelOk(label: unknown): label is string {
  if (typeof label !== "string" || CONTROL.test(label) || LINE_SEPARATORS.test(label) || LONE_SURROGATE.test(label)) return false;
  const characters = [...label].length;
  return characters >= 1 && characters <= 40;
}

function point(value: unknown): boolean {
  const bytes = typeof value === "string" ? fromBase64url(value) : null;
  return bytes !== null && bytes.length === 65 && bytes[0] === 0x04;
}

/** K5, checked: a fresh object with exactly the listed fields, or a TypeError naming what is wrong (never a value). */
export function checkKeptDevice(value: unknown): KeptDevice {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new TypeError("a kept device is an object");
  const keys = Object.keys(value);
  const extra = keys.filter((k) => !(KEPT_DEVICE_FIELDS as readonly string[]).includes(k));
  if (extra.length > 0) throw new TypeError("a kept device holds only K5's fields");
  for (const field of KEPT_DEVICE_FIELDS) if (!keys.includes(field)) throw new TypeError(`a kept device has a ${field}`);
  const r = value as Record<string, unknown>;
  const fail = (field: string): never => {
    throw new TypeError(`a kept device's ${field} is not what K5 allows`);
  };
  if (typeof r.mailboxId !== "string" || !MAILBOX_ID.test(r.mailboxId)) fail("mailboxId");
  if (typeof r.deviceId !== "string" || !DEVICE_ID.test(r.deviceId)) fail("deviceId");
  if (!deviceLabelOk(r.label)) fail("label");
  if (!isDeviceSigningKey(r.signingKey)) fail("signingKey");
  if (r.unlockKey !== null && !isDeviceUnlockKey(r.unlockKey)) fail("unlockKey");
  if (!point(r.signingPublic)) fail("signingPublic");
  if (r.unlockKey === null ? r.unlockPublic !== null : !point(r.unlockPublic)) fail("unlockPublic");
  if (typeof r.lastKeyId !== "string" || !KEY_ID.test(r.lastKeyId)) fail("lastKeyId");
  if (typeof r.lockAfter !== "string" || !LOCK_SETTINGS.includes(r.lockAfter)) fail("lockAfter");
  if (r.lockAfter === "right-away" && r.unlockKey !== null) fail("unlockKey (a device locked right away keeps none)");
  if (typeof r.lastActiveAt !== "number" || !Number.isFinite(r.lastActiveAt) || r.lastActiveAt < 0) fail("lastActiveAt");
  if (r.signInId !== null && (typeof r.signInId !== "string" || r.signInId.length === 0 || r.signInId.length > SIGN_IN_ID_MAX)) fail("signInId");
  return {
    mailboxId: r.mailboxId as string,
    deviceId: r.deviceId as string,
    label: r.label as string,
    signingKey: r.signingKey as CryptoKey, // pragma: allowlist secret (a CryptoKey reference)
    unlockKey: r.unlockKey as CryptoKey | null,
    signingPublic: r.signingPublic as string,
    unlockPublic: r.unlockPublic as string | null,
    lastKeyId: r.lastKeyId as string,
    lockAfter: r.lockAfter as LockAfter,
    lastActiveAt: r.lastActiveAt as number,
    signInId: r.signInId as string | null,
  };
}

/** A stored value read back: the record when it is still a valid one, else null (it is never used). */
function readRecord(value: unknown): KeptDevice | null {
  try {
    return value === undefined || value === null ? null : checkKeptDevice(value);
  } catch {
    return null;
  }
}

function applyChange(current: KeptDevice, change: KeptDeviceChange): KeptDevice {
  if (typeof change !== "object" || change === null) throw new TypeError("a change is an object");
  for (const key of Object.keys(change)) if (!CHANGEABLE.includes(key)) throw new TypeError("a kept device's identity never changes");
  return checkKeptDevice({ ...current, ...change });
}

/** A store in memory, for tests and for Node. It clones on every read and write, as IndexedDB does. */
export function memoryDeviceStore(): DeviceStore {
  const records = new Map<string, KeptDevice>();
  return {
    async get(mailboxId) {
      const r = records.get(mailboxId);
      return r === undefined ? null : structuredClone(r);
    },
    async put(record) {
      const checked = checkKeptDevice(record);
      records.set(checked.mailboxId, structuredClone(checked));
    },
    async update(mailboxId, deviceId, change) {
      const current = records.get(mailboxId);
      if (current === undefined || current.deviceId !== deviceId) return null;
      const next = applyChange(current, change);
      records.set(mailboxId, structuredClone(next));
      return structuredClone(next);
    },
    async delete(mailboxId, deviceId) {
      const current = records.get(mailboxId);
      if (current !== undefined && (deviceId === undefined || current.deviceId === deviceId)) records.delete(mailboxId);
    },
  };
}

// ---- IndexedDB ------------------------------------------------------------------------------------

/** The package's one database, and its one object store, keyed by mailbox id. */
export const DEVICE_DATABASE = Object.freeze({ name: "proprietor-mail", version: 1, store: "kept-devices" });

function factory(): IDBFactory {
  const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (idb === undefined || idb === null) throw new StorageUnavailable("this browser has no IndexedDB");
  return idb;
}

function settle(t: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    t.oncomplete = () => resolve();
    t.onerror = () => reject(t.error ?? new StorageUnavailable());
    t.onabort = () => reject(t.error ?? new StorageUnavailable());
  });
}

/**
 * The store in this browser's IndexedDB. Writes ask for "strict" durability,
 * so a lock is on disk before it is reported done where the browser honours
 * the hint. Any failure of IndexedDB itself is StorageUnavailable; a record
 * K5 refuses is a TypeError, before anything is written.
 */
export function indexedDbDeviceStore(): DeviceStore {
  let connection: Promise<IDBDatabase> | null = null;

  function open(): Promise<IDBDatabase> {
    if (connection !== null) return connection;
    const opening = new Promise<IDBDatabase>((resolve, reject) => {
      let req: IDBOpenDBRequest;
      try {
        req = factory().open(DEVICE_DATABASE.name, DEVICE_DATABASE.version);
      } catch (e) {
        reject(e instanceof StorageUnavailable ? e : new StorageUnavailable());
        return;
      }
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains(DEVICE_DATABASE.store)) db.createObjectStore(DEVICE_DATABASE.store, { keyPath: "mailboxId" });
      };
      req.onsuccess = () => {
        const db = req.result;
        db.onversionchange = () => {
          db.close();
          connection = null;
        };
        db.onclose = () => {
          connection = null;
        };
        resolve(db);
      };
      req.onerror = () => reject(new StorageUnavailable());
      req.onblocked = () => reject(new StorageUnavailable("the inbox's storage is busy in another tab"));
    });
    connection = opening;
    opening.catch(() => {
      if (connection === opening) connection = null;
    });
    return opening;
  }

  async function run<T>(mode: IDBTransactionMode, body: (store: IDBObjectStore) => () => T): Promise<T> {
    const db = await open();
    let t: IDBTransaction;
    try {
      t = mode === "readwrite" ? db.transaction(DEVICE_DATABASE.store, mode, { durability: "strict" }) : db.transaction(DEVICE_DATABASE.store, mode);
    } catch {
      connection = null;
      throw new StorageUnavailable();
    }
    const settled = settle(t);
    let result: () => T;
    try {
      result = body(t.objectStore(DEVICE_DATABASE.store));
    } catch (e) {
      try {
        t.abort();
      } catch {
        // already finished
      }
      settled.catch(() => undefined);
      // A record refused by K5 is the caller's TypeError; anything else (DataCloneError for a key this
      // browser cannot keep) is storage that cannot do what is asked.
      throw e instanceof TypeError ? e : new StorageUnavailable();
    }
    try {
      await settled;
    } catch (e) {
      throw e instanceof TypeError ? e : new StorageUnavailable();
    }
    return result();
  }

  return {
    get(mailboxId) {
      return run("readonly", (store) => {
        const req = store.get(mailboxId);
        return () => readRecord(req.result);
      });
    },
    async put(record) {
      const checked = checkKeptDevice(record);
      await run("readwrite", (store) => {
        store.put(checked);
        return () => undefined;
      });
    },
    update(mailboxId, deviceId, change) {
      return run("readwrite", (store) => {
        let updated: KeptDevice | null = null;
        let refusal: unknown = null;
        const req = store.get(mailboxId);
        req.onsuccess = () => {
          const current = readRecord(req.result);
          if (current === null || current.deviceId !== deviceId) return;
          try {
            updated = applyChange(current, change);
          } catch (e) {
            refusal = e; // nothing is written: the transaction completes empty
            return;
          }
          store.put(updated);
        };
        return () => {
          if (refusal !== null) throw refusal;
          return updated;
        };
      });
    },
    async delete(mailboxId, deviceId) {
      await run("readwrite", (store) => {
        if (deviceId === undefined) {
          store.delete(mailboxId);
        } else {
          const req = store.get(mailboxId);
          req.onsuccess = () => {
            const current = req.result as { deviceId?: unknown } | undefined;
            if (current !== undefined && current !== null && current.deviceId === deviceId) store.delete(mailboxId);
          };
        }
        return () => undefined;
      });
    },
  };
}

// ---- The storage check (D31) ----------------------------------------------------------------------

/**
 * True when `store` keeps non-extractable P-256 keys and gives them back as
 * such, still working and still the same keys: a probe record (under a fresh,
 * random mailbox id) is written, read back, used, and deleted. False, never an
 * exception, everywhere else, such as a private window that refuses to store a
 * CryptoKey, or an engine that cannot read one back. A browser where this is
 * false is treated as a shared computer, and the screen says why.
 */
export async function canKeepDevices(store: DeviceStore): Promise<boolean> {
  const mailboxId = newId("mbx");
  try {
    const signing = await generateSigningKey();
    const unlock = await generateUnlockKey();
    await store.put({
      mailboxId,
      deviceId: newId("dev"),
      label: "Storage check",
      signingKey: signing.privateKey, // pragma: allowlist secret (a CryptoKey reference)
      unlockKey: unlock.privateKey,
      signingPublic: base64url(signing.publicKey),
      unlockPublic: base64url(unlock.publicKey),
      lastKeyId: "0".repeat(32),
      lockAfter: "sign-out",
      lastActiveAt: 0,
      signInId: null,
    });
    const back = await store.get(mailboxId);
    if (back === null || !isDeviceSigningKey(back.signingKey) || !isDeviceUnlockKey(back.unlockKey)) return false;
    // The keys read back must still work, and be the keys that were stored.
    const data = randomBytes(32);
    const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, back.signingKey, data);
    const verifier = await crypto.subtle.importKey("raw", signing.publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifier, signature, data))) return false;
    const peer = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"])) as CryptoKeyPair;
    const ours = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer.publicKey }, unlock.privateKey, 256));
    const theirs = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer.publicKey }, back.unlockKey, 256));
    return bytesEqual(ours, theirs);
  } catch {
    return false;
  } finally {
    try {
      await store.delete(mailboxId);
    } catch {
      // nothing more can be done; the probe's random mailbox id names no mailbox
    }
  }
}
