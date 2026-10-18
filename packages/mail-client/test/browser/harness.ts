// The page under test. Bundled by esbuild (server.ts) and served as the one nonce-stamped module
// script of a page that carries the dashboard's exact policy with Trusted Types enforced. It
// exposes `window.harness`, which the Playwright-driven tests call through page.evaluate(); every
// answer is plain JSON. It never uses a DOM sink itself: text goes through textContent, the frame is
// built with createElement/setAttribute, and only showInFrame assigns srcdoc.
import { deriveFactorKey, factorPublicKey, keyIdOf, type MessageHeader } from "@proprietor/mail-crypto";
import {
  canKeepDevices,
  DEVICE_DATABASE,
  encodeSendForm,
  indexedDbDeviceStore,
  pageNonce,
  renderBody,
  resumeDevice,
  showInFrame,
  startEnrollment,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type BodyAttachment,
  type ChallengeView,
  type EnrollRequest,
  type Enrollment,
  type LockAfter,
  type MailboxView,
  type MessageItem,
  type OpenedMessage,
  type PasskeyOptions,
  type PendingChange,
  type RegisterDeviceRequest,
  type RenderedBody,
  type UnlockedMailbox,
} from "@proprietor/mail-client";
import { installRecorder, keyShapes, PROBE_CHECKS, runProbe, takeFailures } from "./crypto-probe";

// Every crypto.subtle call that throws is recorded with its inputs (test code only): a failing flow
// reports which operation failed, and on what.
installRecorder();

// ---- bytes (no Buffer in a browser) ----

function fromBase64(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// ---- a credentials double for browsers without a PRF-capable virtual authenticator ----

class BrowserCredentialsDouble {
  private readonly stored: { rawId: Uint8Array<ArrayBuffer>; key: CryptoKey }[] = [];
  async create(options?: CredentialCreationOptions): Promise<Credential | null> {
    const pk = options!.publicKey!;
    const rawId = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    this.stored.push({ rawId, key });
    const first = pk.extensions?.prf?.eval?.first;
    const prf = first ? { enabled: true, results: { first: await crypto.subtle.sign("HMAC", key, first) } } : { enabled: true };
    return credential(rawId, { prf });
  }
  async get(options?: CredentialRequestOptions): Promise<Credential | null> {
    const pk = options!.publicKey!;
    const allowed = pk.allowCredentials ?? [];
    const chosen = allowed[0]!;
    const id = toBase64url(new Uint8Array(chosen.id as ArrayBuffer));
    const stored = this.stored.find((s) => toBase64url(s.rawId) === id)!;
    const input = pk.extensions?.prf?.evalByCredential?.[id]?.first;
    const prf = input ? { results: { first: await crypto.subtle.sign("HMAC", stored.key, input) } } : {};
    return credential(stored.rawId, { prf });
  }
}
function credential(rawId: Uint8Array<ArrayBuffer>, extensions: AuthenticationExtensionsClientOutputs): Credential {
  return { id: toBase64url(rawId), rawId: rawId.buffer.slice(0), type: "public-key", response: {}, getClientExtensionResults: () => extensions } as unknown as Credential;
}

// ---- state kept between evaluate() calls ----

interface SerializedBody {
  text: string | null;
  html: string | null;
  attachments: { filename: string; mimeType: string; contentId: string | null; inline: boolean; contentBase64: string }[];
}

interface Violation {
  directive: string;
  blocked: string;
  sample: string;
}

const violations: Violation[] = [];
document.addEventListener("securitypolicyviolation", (e) => {
  violations.push({ directive: e.effectiveDirective, blocked: e.blockedURI, sample: e.sample });
});

// Every WebAuthn prompt this page makes is counted: a kept device must open the inbox with none.
const prompts = { get: 0, create: 0 };
const realCredentials = navigator.credentials; // pragma: allowlist secret (the WebAuthn container, not a credential)
if (realCredentials && typeof realCredentials.get === "function") {
  const get = realCredentials.get.bind(realCredentials);
  const create = realCredentials.create.bind(realCredentials);
  realCredentials.get = (options?: CredentialRequestOptions) => { // pragma: allowlist secret (the WebAuthn container, not a credential)
    prompts.get += 1;
    return get(options);
  };
  realCredentials.create = (options?: CredentialCreationOptions) => { // pragma: allowlist secret (the WebAuthn container, not a credential)
    prompts.create += 1;
    return create(options);
  };
}

/** A stored value, described in plain JSON: what kind it is and, for a CryptoKey, everything Web Crypto says about it. */
type Described =
  | { kind: "CryptoKey"; type: string; extractable: boolean; algorithm: Record<string, unknown>; usages: string[] }
  | { kind: "string"; value: string }
  | { kind: "number" | "boolean" | "null" | "undefined"; value: unknown }
  | { kind: "object"; fields: Record<string, Described> }
  | { kind: "other"; tag: string };

function describe(value: unknown): Described {
  if (value instanceof CryptoKey) {
    const algorithm = { ...(value.algorithm as unknown as Record<string, unknown>) };
    return { kind: "CryptoKey", type: value.type, extractable: value.extractable, algorithm, usages: [...value.usages] };
  }
  if (typeof value === "string") return { kind: "string", value };
  if (value === null) return { kind: "null", value: null };
  if (typeof value === "number" || typeof value === "boolean" || value === undefined) return { kind: typeof value as "number" | "boolean" | "undefined", value };
  if (typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype) {
    return { kind: "object", fields: Object.fromEntries(Object.entries(value as object).map(([k, v]) => [k, describe(v)])) };
  }
  return { kind: "other", tag: Object.prototype.toString.call(value) };
}

/**
 * Everything this origin keeps in IndexedDB, read with the raw API (not through the package):
 * every database's name, and every record of the package's database, described. The database is
 * never created here: it is opened only when it is listed, or when the caller knows it exists.
 */
async function dumpIndexedDb(): Promise<{ databases: string[] | null; records: Described[] }> {
  const listed = typeof indexedDB.databases === "function" ? (await indexedDB.databases()).map((d) => d.name ?? "") : null;
  if (listed !== null && !listed.includes(DEVICE_DATABASE.name)) return { databases: listed, records: [] };
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const req = indexedDB.open(DEVICE_DATABASE.name);
    req.onupgradeneeded = () => {
      req.transaction?.abort(); // it did not exist: create nothing
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  }).catch(() => null);
  if (db === null) return { databases: listed, records: [] };
  try {
    if (!db.objectStoreNames.contains(DEVICE_DATABASE.store)) return { databases: listed, records: [] };
    const all = await new Promise<unknown[]>((resolve, reject) => {
      const req = db.transaction(DEVICE_DATABASE.store, "readonly").objectStore(DEVICE_DATABASE.store).getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return { databases: listed, records: all.map(describe) };
  } finally {
    db.close();
  }
}

let deviceSession: UnlockedMailbox | null = null;
let pendingKeep: PendingChange<RegisterDeviceRequest> | null = null;

async function canKeepWithPatch(patch: () => () => void): Promise<boolean> {
  const restore = patch();
  try {
    return await canKeepDevices(indexedDbDeviceStore());
  } finally {
    restore();
  }
}

/** Contains a CryptoKey anywhere: what Safari's private windows refuse to store (spec 002 §9). */
function holdsKey(value: unknown): boolean {
  return value instanceof CryptoKey || (typeof value === "object" && value !== null && Object.values(value).some(holdsKey));
}

let enrollment: Enrollment | null = null;
let unlocked: UnlockedMailbox | null = null;
let rendered: RenderedBody | null = null;
const double = new BrowserCredentialsDouble();

function errorOf(e: unknown): { name: string; message: string } {
  return e instanceof Error ? { name: e.name, message: e.message } : { name: "unknown", message: String(e) };
}

function bodyOf(s: SerializedBody) {
  const attachments: BodyAttachment[] = s.attachments.map((a) => {
    const content = fromBase64(a.contentBase64);
    return { filename: a.filename, mimeType: a.mimeType, size: content.length, contentId: a.contentId, inline: a.inline, content };
  });
  return { raw: new Uint8Array(0), text: s.text, html: s.html, attachments };
}

function frame(sandbox: string | null): HTMLIFrameElement {
  for (const old of Array.from(document.querySelectorAll("iframe"))) old.remove();
  const f = document.createElement("iframe");
  if (sandbox !== null) f.setAttribute("sandbox", sandbox);
  f.setAttribute("id", "reading-pane");
  f.setAttribute("width", "600");
  f.setAttribute("height", "400");
  document.body.appendChild(f);
  return f;
}

function passkeyOptions(rpId: string, useDouble: boolean, label = "Test passkey"): PasskeyOptions {
  return {
    rpId,
    rpName: "Example",
    userName: "Mail key — hello@example.com",
    userDisplayName: "hello@example.com",
    label,
    ...(useDouble ? { credentials: double } : {}),
  };
}

const harness = {
  violations: () => violations,
  trustedTypesPresent: () => typeof (globalThis as { trustedTypes?: unknown }).trustedTypes === "object",
  /** True when a string assigned to a sink throws: Trusted Types are enforced on this page. */
  enforced(): boolean {
    try {
      document.createElement("div").innerHTML = "<b>probe</b>";
      return false;
    } catch {
      return true;
    }
  },
  pageNonce: () => pageNonce(),
  nonceOfScript: () => (document.querySelector("script") as HTMLScriptElement).nonce,

  /** renderBody + showInFrame; the frame's load is awaited so the test can inspect it. */
  async render(body: SerializedBody, sandbox: string | null, nonce: string | null) {
    try {
      rendered?.dispose();
      rendered = renderBody(bodyOf(body), { nonce: nonce ?? pageNonce()! });
      const f = frame(sandbox);
      const loaded = new Promise<void>((resolve) => f.addEventListener("load", () => resolve(), { once: true }));
      showInFrame(f, rendered);
      await loaded;
      return {
        ok: true as const,
        html: rendered.html.toString(),
        remoteImagesBlocked: rendered.remoteImagesBlocked,
        inlineImages: rendered.inlineImages,
        trustedType: Object.prototype.toString.call(rendered.html),
        referrerPolicy: f.getAttribute("referrerpolicy"),
      };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  renderOnly(body: SerializedBody, nonce: string | null) {
    try {
      const r = renderBody(bodyOf(body), { nonce: nonce ?? pageNonce()! });
      return { ok: true as const, html: r.html.toString(), remoteImagesBlocked: r.remoteImagesBlocked, inlineImages: r.inlineImages };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  showForged(sandbox: string) {
    try {
      showInFrame(frame(sandbox), { html: "<p>forged</p>", remoteImagesBlocked: 0, inlineImages: 0, dispose() {} });
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  showDisposed(body: SerializedBody) {
    const r = renderBody(bodyOf(body), { nonce: pageNonce()! });
    r.dispose();
    try {
      showInFrame(frame("allow-popups"), r);
      return { ok: true as const };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  /** A control: the page assigning a plain string to srcdoc, which enforcement must refuse. */
  stringSrcdoc() {
    try {
      frame("allow-popups").srcdoc = "<p>plain string</p>";
      return { threw: false };
    } catch (e) {
      return { threw: true, error: errorOf(e) };
    }
  },

  // ---- the key ceremony ----
  async enroll(mailboxId: string, rpId: string, useDouble: boolean, withPasskey: boolean) {
    try {
      enrollment = await startEnrollment({ id: mailboxId, address: "hello@example.com", status: "provisioned" }, withPasskey ? passkeyOptions(rpId, useDouble) : null);
      const symbols = enrollment.recoveryKey.replace(/-/g, "");
      const confirmed = enrollment.confirmRecovery(enrollment.recoveryCheck.positions.map((p) => symbols[p - 1]).join(""));
      const request = enrollment.request();
      return { ok: true as const, request, recoveryKey: enrollment.recoveryKey, fingerprint: enrollment.fingerprint, passkey: enrollment.passkey, confirmed, wrapBytes: request.wraps.map((w) => fromBase64(w.wrapped).length) };
    } catch (e) {
      return { ok: false as const, error: errorOf(e), stack: e instanceof Error ? String(e.stack ?? "") : "", failedCalls: takeFailures() };
    }
  },
  async keyIdOfRequest(request: EnrollRequest) {
    return keyIdOf(fromBase64(request.publicKey));
  },
  async unlockPasskey(view: MailboxView, rpId: string, useDouble: boolean) {
    try {
      unlocked = await unlockWithPasskey(view, { rpId, ...(useDouble ? { credentials: double } : {}) });
      return { ok: true as const, keyId: unlocked.keyId, fingerprint: unlocked.fingerprint, locked: unlocked.locked };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  async unlockRecovery(view: MailboxView, recoveryKey: string) {
    try {
      unlocked = await unlockWithRecoveryKey(view, recoveryKey);
      return { ok: true as const, keyId: unlocked.keyId, fingerprint: unlocked.fingerprint };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  async openMessages(items: MessageItem[]): Promise<OpenedMessage[]> {
    return unlocked!.openMessages(items);
  },
  async openBody(item: MessageItem, sealedBase64: string) {
    const body = await unlocked!.openBody(item, fromBase64(sealedBase64));
    return { text: body.text, html: body.html, attachments: body.attachments.map((a) => ({ filename: a.filename, mimeType: a.mimeType, size: a.size, contentId: a.contentId, inline: a.inline })) };
  },
  async addPasskeyWithRecovery(rpId: string, useDouble: boolean, recoveryKey: string) {
    try {
      const wrap = await unlocked!.addPasskey(passkeyOptions(rpId, useDouble, "Second passkey"), await unlocked!.reauthenticate({ recoveryKey }));
      return { ok: true as const, wrap, wrapBytes: fromBase64(wrap.wrapped).length };
    } catch (e) {
      return { ok: false as const, error: errorOf(e) };
    }
  },
  lock() {
    void unlocked?.lock();
    return unlocked?.locked ?? null;
  },

  // ---- diagnostics: the crypto probe (test/browser/crypto-probe.ts) ----
  probe: {
    checks: () => PROBE_CHECKS,
    run: (rounds: number, only?: string[]) => runProbe(rounds, only),
    keyShapes: (draws: number) => keyShapes(draws),
    failedCalls: () => takeFailures(),
  },

  /** A2 (deriveFactorKey) in this engine, for factors the Node side derived with @hpke/core (devices.test.ts). Secrets and keys as base64url. */
  async factorPublicKeys(factors: { mailboxId: string; factorId: string; kind: "passkey-prf" | "recovery"; secret: string }[]) {
    const out: ({ ok: true; publicKey: string } | { ok: false; error: { name: string; message: string }; failedCalls: ReturnType<typeof takeFailures> })[] = [];
    for (const f of factors) {
      try {
        const key = await deriveFactorKey({ mailboxId: f.mailboxId, factorId: f.factorId, kind: f.kind, secret: fromBase64(f.secret) }); // pragma: allowlist secret (random test values the Node side made)
        out.push({ ok: true, publicKey: toBase64url(factorPublicKey(key)) });
      } catch (e) {
        out.push({ ok: false, error: errorOf(e), failedCalls: takeFailures() });
      }
    }
    return out;
  },

  // ---- kept devices (spec 002, contracts/device-v1.md Part C) ----
  device: {
    prompts: () => ({ ...prompts }),
    canKeep: () => canKeepDevices(indexedDbDeviceStore()),
    /** As Safari's private windows: IndexedDB refuses any value that holds a CryptoKey. */
    canKeepWhenStorageRefusesKeys: () =>
      canKeepWithPatch(() => {
        const put = IDBObjectStore.prototype.put;
        IDBObjectStore.prototype.put = function (this: IDBObjectStore, value: unknown, key?: IDBValidKey) {
          if (holdsKey(value)) throw new DOMException("a CryptoKey cannot be stored here", "DataCloneError");
          return put.call(this, value, key);
        };
        return () => {
          IDBObjectStore.prototype.put = put;
        };
      }),
    /** A browser with no IndexedDB at all. */
    canKeepWithoutIndexedDb: () =>
      canKeepWithPatch(() => {
        const descriptor = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
        Object.defineProperty(globalThis, "indexedDB", { value: undefined, configurable: true });
        return () => {
          if (descriptor) Object.defineProperty(globalThis, "indexedDB", descriptor);
          else delete (globalThis as { indexedDB?: unknown }).indexedDB;
        };
      }),
    async unlockRecovery(view: MailboxView, recoveryKey: string, signInId: string | null, keep: boolean) {
      try {
        deviceSession = await unlockWithRecoveryKey(view, recoveryKey, keep ? { store: indexedDbDeviceStore(), signInId } : { signInId });
        return { ok: true as const, keyIds: deviceSession.keyIds, device: deviceSession.device };
      } catch (e) {
        return { ok: false as const, error: errorOf(e) };
      }
    },
    sessionProof: (challenge: ChallengeView) => deviceSession!.sessionProof(challenge),
    answerFactor: (challenge: ChallengeView) => deviceSession!.freshFactor!.answer(challenge),
    async keep(label: string, lockAfter: LockAfter) {
      pendingKeep = await deviceSession!.keepThisDevice({ label, lockAfter }, deviceSession!.freshFactor!);
      return pendingKeep.request;
    },
    async commitKeep() {
      try {
        await pendingKeep!.commit();
        return { ok: true as const, device: deviceSession!.device };
      } catch (e) {
        return { ok: false as const, error: errorOf(e) };
      }
    },
    async resume(view: MailboxView, signInId: string | null) {
      try {
        const r = await resumeDevice(view, { store: indexedDbDeviceStore(), signInId });
        if (r.state === "unlocked") deviceSession = r.mailbox;
        return { ok: true as const, state: r.state, ...(r.state === "locked" ? { reason: r.reason, device: r.device } : {}), ...(r.state === "unlocked" ? { keyIds: r.mailbox.keyIds, device: r.mailbox.device } : {}) };
      } catch (e) {
        return { ok: false as const, error: errorOf(e) };
      }
    },
    openMessages: (items: MessageItem[]) => deviceSession!.openMessages(items),
    async lock() {
      return deviceSession!.lock();
    },
    /** What the dashboard does with the mail session: it rides in the send form (D29). */
    sendForm(token: string) {
      const form = encodeSendForm({ to: [{ name: "", address: "ana@example.com" }], cc: [], bcc: [], subject: "x", text: "x", inReplyTo: null, references: [], attachments: [] }, { idempotencyKey: "k-1", session: token });
      return JSON.parse(form.get("request") as string).session as string;
    },
    dumpIndexedDb,
  },
};

export type Harness = typeof harness;
export type { MessageHeader, SerializedBody };

(globalThis as unknown as { harness: Harness }).harness = harness;
document.getElementById("status")!.textContent = "ready";
