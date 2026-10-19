// D1g: a kept device in real browsers (contracts/device-v1.md Part C; spec 002 §9), on the page the
// other browser tests use: the dashboard's exact policy with Trusted Types ENFORCED. The fake Mail runs
// here in Node; the browser makes every key and every request, as the dashboard's inbox will.
//
// What this proves, per browser: the storage check (D31) is true where keys can be kept and false,
// never an exception, where storage refuses them; a kept device survives a reload (a new page in the
// same browser context) and opens the inbox with no prompt; what IndexedDB holds is exactly K5's
// fields, with non-extractable P-256 keys, no X25519 key and no token; and the spec's two open
// questions: a non-extractable P-256 key opens its seal (@hpke/core, A4), and a non-extractable X25519
// key derives bits with its own public key (A5, the binding key behind every tag check). And every
// factor key (A2) is the one @hpke/core derives in Node, those whose scalar starts with a zero byte
// included: the keys WebKit's libgcrypt backend refused (WebKit bug 307095, see webkit-probe.test.ts).
//
// WebKit runs only in CI's browsers job (its host libraries are missing here). Playwright's WebKit
// is not Safari: where its IndexedDB cannot keep a CryptoKey, the test checks that the fallback is
// the safe one (a shared computer that keeps nothing) instead.
import { Buffer } from "node:buffer";
import { DhkemX25519HkdfSha256 } from "@hpke/core";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { chromium, firefox, webkit, type Browser, type BrowserContext, type Page } from "playwright";
import { newId } from "@proprietor/mail-crypto";
import { KEPT_DEVICE_FIELDS } from "../../src/index";
import { enrolledMailbox, type Enrolled } from "../keyring-support";
import type { Harness } from "./harness";
import { startTestServer, type TestServer } from "./server";

declare global {
  // eslint-disable-next-line no-var
  var harness: Harness;
}

const BROWSERS = { chromium, firefox, webkit } as const;
type BrowserName = keyof typeof BROWSERS;
const chosen = (process.env.MAIL_CLIENT_BROWSERS ?? "chromium,firefox,webkit")
  .split(",")
  .map((s) => s.trim())
  .filter((s): s is BrowserName => s in BROWSERS);

type Dumped = Awaited<ReturnType<Harness["device"]["dumpIndexedDb"]>>;
type DescribedValue = Dumped["records"][number];

/** The record of one mailbox, among every record this browser context keeps (one per mailbox, K5). */
function recordOf(dumped: Dumped, mailboxId: string): Extract<DescribedValue, { kind: "object" }> {
  const found = dumped.records.filter((r) => r.kind === "object" && r.fields.mailboxId?.kind === "string" && r.fields.mailboxId.value === mailboxId);
  expect(found.length).toBe(1);
  return found[0] as Extract<DescribedValue, { kind: "object" }>;
}

/**
 * A2 from the contract's text, in Node: HKDF with raw Web Crypto, then @hpke/core's DeriveKeyPair, an
 * implementation the package does not use. With `zeroFirstByte`, a factor whose skF, clamped, starts
 * with a zero byte (1 random secret in 32): the input the GCrypt engine's PKCS #8 import refuses.
 */
async function nodeFactor(kind: "passkey-prf" | "recovery", zeroFirstByte: boolean) {
  const kem = new DhkemX25519HkdfSha256();
  const utf8 = (s: string) => new TextEncoder().encode(s);
  const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
  for (;;) {
    const mailboxId = newId("mbx");
    const factorId = newId("wrp");
    const secret = crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test value)
    const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const info = utf8(`proprietor-mail/v1/factor-key|${mailboxId}|${factorId}|${kind}`);
    const ikm = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(factorId), info }, base, 256); // pragma: allowlist secret (HKDF parameter names)
    const pair = await kem.deriveKeyPair(ikm);
    const skF = new Uint8Array(await kem.serializePrivateKey(pair.privateKey));
    if (((skF[0]! & 248) === 0) !== zeroFirstByte) continue;
    return { input: { mailboxId, factorId, kind, secret: b64url(secret) }, publicKey: b64url(new Uint8Array(await kem.serializePublicKey(pair.publicKey))) }; // pragma: allowlist secret (random test values made for the run)
  }
}

/** Every CryptoKey and every string anywhere in a described record. */
function walk(value: DescribedValue, keys: DescribedValue[] = [], strings: string[] = []): { keys: DescribedValue[]; strings: string[] } {
  if (value.kind === "CryptoKey") keys.push(value);
  else if (value.kind === "string") strings.push(value.value);
  else if (value.kind === "object") for (const v of Object.values(value.fields)) walk(v, keys, strings);
  return { keys, strings };
}

describe.each(chosen)("%s: a kept device under the dashboard's policy", (name) => {
  let server: TestServer;
  let browser: Browser;
  let context: BrowserContext;
  let canKeep = false;
  const pages: Page[] = [];

  async function openPage(): Promise<Page> {
    const page = await context.newPage();
    pages.push(page);
    await page.goto(server.origin + "/");
    await page.waitForFunction(() => document.getElementById("status")?.textContent === "ready", null, { timeout: 30_000 });
    return page;
  }

  /** F1 in `page`: the recovery key, a mail session, a factor proof, keepThisDevice, registerDevice at the fake, commit. */
  async function keepIn(page: Page, e: Enrolled, signInId: string) {
    const unlocked = await page.evaluate(([v, k, s]) => harness.device.unlockRecovery(v, k, s, true), [e.fake.mailbox(), e.recoveryKey, signInId] as const);
    if (!unlocked.ok) throw new Error(`${unlocked.error.name}: ${unlocked.error.message}`);
    const proof = await page.evaluate((c) => harness.device.sessionProof(c), await e.fake.challenge({ purpose: "session" }));
    const { session } = await e.fake.openSession(proof);
    const factorChallenge = await e.fake.challenge({ purpose: "factor", factorId: e.fake.wraps.find((w) => w.kind === "recovery")!.id });
    const factorProof = await page.evaluate((c) => harness.device.answerFactor(c), factorChallenge);
    const request = await page.evaluate(() => harness.device.keep("Test laptop", "sign-out"));
    await e.fake.registerDevice(request, { session, factorProof });
    const committed = await page.evaluate(() => harness.device.commitKeep());
    if (!committed.ok) throw new Error(`${committed.error.name}: ${committed.error.message}`);
    return { session, request };
  }

  beforeAll(async () => {
    server = await startTestServer();
    browser = await BROWSERS[name].launch({ headless: true });
    context = await browser.newContext();
  });

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  test("the page is under the policy, Trusted Types enforced where the browser has them", async () => {
    const page = await openPage();
    expect(await page.evaluate(() => harness.enforced())).toBe(await page.evaluate(() => harness.trustedTypesPresent()));
    if (name !== "webkit") expect(await page.evaluate(() => harness.enforced())).toBe(true);
  });

  test("the storage check (D31): true where this browser keeps non-extractable P-256 keys; false, never an exception, where storage refuses keys or there is no IndexedDB", async () => {
    const page = await openPage();
    canKeep = await page.evaluate(() => harness.device.canKeep());
    console.info(`${name}: canKeepDevices(indexedDbDeviceStore()) = ${canKeep}`);
    if (name !== "webkit") expect(canKeep).toBe(true); // Chromium and Firefox keep CryptoKeys in IndexedDB
    expect(await page.evaluate(() => harness.device.canKeepWhenStorageRefusesKeys())).toBe(false);
    expect(await page.evaluate(() => harness.device.canKeepWithoutIndexedDb())).toBe(false);
    // The probe leaves nothing behind.
    expect((await page.evaluate(() => harness.device.dumpIndexedDb())).records).toEqual([]);
  });

  test("A2 in this engine: every factor key is the one @hpke/core derives in Node, including the 1 in 32 whose clamped scalar starts with a zero byte (WebKit bug 307095 refuses that scalar in PKCS #8)", async () => {
    const factors: Awaited<ReturnType<typeof nodeFactor>>[] = [];
    for (const kind of ["passkey-prf", "recovery"] as const) {
      for (let i = 0; i < 4; i++) factors.push(await nodeFactor(kind, true));
      for (let i = 0; i < 2; i++) factors.push(await nodeFactor(kind, false));
    }
    const page = await openPage();
    const got = await page.evaluate((input) => harness.factorPublicKeys(input), factors.map((f) => f.input));
    expect(got).toEqual(factors.map((f) => ({ ok: true, publicKey: f.publicKey })));
  });

  test("F1, then a reload (a new page in the same context) opens the inbox with no prompt; IndexedDB holds exactly K5's fields, non-extractable P-256 keys, no X25519 key and no token", async () => {
    const e = await enrolledMailbox();
    const first = await openPage();
    if (!canKeep) {
      // D31 on an engine that cannot keep keys: the browser is a shared computer. It unlocks, keeps nothing.
      expect(name).toBe("webkit");
      const shared = await first.evaluate(([v, k]) => harness.device.unlockRecovery(v, k, null, false), [e.fake.mailbox(), e.recoveryKey] as const);
      expect(shared.ok).toBe(true);
      expect((await first.evaluate(() => harness.device.dumpIndexedDb())).records).toEqual([]);
      return;
    }
    const { session, request } = await keepIn(first, e, "signin-1");

    const reload = await openPage();
    const { item } = await e.fake.deliver();
    const resumed = await reload.evaluate(([v]) => harness.device.resume(v, "signin-1"), [e.fake.mailbox()] as const);
    if (!resumed.ok) throw new Error(`${resumed.error.name}: ${resumed.error.message}`);
    expect(resumed.state).toBe("unlocked");
    expect(resumed.device).toEqual({ id: request.device.id, label: "Test laptop", lockAfter: "sign-out", keepsUnlocked: true });
    const [opened] = await reload.evaluate((items) => harness.device.openMessages(items), [item]);
    expect(opened!.undecryptable).toBe(false);
    expect(opened!.header!.subject).toBe("Kitchen remodel quote");
    // A device session: the stored signing key signed the proof, and Mail checked it.
    const proof = await reload.evaluate((c) => harness.device.sessionProof(c), await e.fake.challenge({ purpose: "session" }));
    const second = await e.fake.openSession(proof);
    expect(second.device).toBe(request.device.id);
    // The token passes through the page the way the dashboard uses it, in the send form; it is never stored.
    expect(await reload.evaluate((t) => harness.device.sendForm(t), second.session)).toBe(second.session);
    expect(await reload.evaluate(() => harness.device.prompts())).toEqual({ get: 0, create: 0 });

    const dumped = await reload.evaluate(() => harness.device.dumpIndexedDb());
    if (dumped.databases !== null) expect(dumped.databases).toEqual(["proprietor-mail"]);
    // Nothing else anywhere in the database: every record is a kept device's, with exactly K5's fields.
    for (const r of dumped.records) {
      if (r.kind !== "object") throw new Error("not a record");
      expect(Object.keys(r.fields).sort()).toEqual([...KEPT_DEVICE_FIELDS].sort());
      expect(walk(r).keys.every((k) => k.kind === "CryptoKey" && k.algorithm.name !== "X25519" && !k.extractable)).toBe(true);
    }
    const record = recordOf(dumped, e.mailboxId);
    const { keys, strings } = walk(record);
    expect(keys.length).toBe(2);
    for (const key of keys) {
      if (key.kind !== "CryptoKey") throw new Error("not a key");
      expect(key.type).toBe("private");
      expect(key.extractable).toBe(false);
      expect(key.algorithm.namedCurve).toBe("P-256");
      expect(key.algorithm.name).not.toBe("X25519");
    }
    expect(keys.map((k) => (k.kind === "CryptoKey" ? [k.algorithm.name, k.usages] : null)).sort()).toEqual([
      ["ECDH", ["deriveBits"]],
      ["ECDSA", ["sign"]],
    ]);
    for (const token of [session, second.session]) {
      for (const r of dumped.records) expect(walk(r).strings.some((x) => x.includes(token))).toBe(false);
    }
    expect(strings).not.toContain(second.session);
    expect(record.fields.lastKeyId).toEqual({ kind: "string", value: e.fake.activeKey.keyId });
  });

  test("Lock now, then a reload asks for a factor: the unlock key is gone from IndexedDB, the device is still kept", async () => {
    if (!canKeep) return; // nothing is kept where keys cannot be (checked above)
    const e = await enrolledMailbox();
    const page = await openPage();
    const { session } = await keepIn(page, e, "signin-1");
    const { updateDevice } = await page.evaluate(() => harness.device.lock());
    await e.fake.updateDevice(updateDevice!, { session });
    const reload = await openPage();
    const resumed = await reload.evaluate(([v]) => harness.device.resume(v, "signin-1"), [e.fake.mailbox()] as const);
    expect(resumed).toMatchObject({ ok: true, state: "locked", reason: "locked", device: { keepsUnlocked: false } });
    const record = recordOf(await reload.evaluate(() => harness.device.dumpIndexedDb()), e.mailboxId);
    expect(record.fields.unlockKey).toEqual({ kind: "null", value: null });
    expect(record.fields.unlockPublic).toEqual({ kind: "null", value: null });
    expect(walk(record).keys.length).toBe(1);
    // A factor unlocks it again on the same device (F4), and the tags it made verify (K3, A5 in this engine).
    const again = await reload.evaluate(([v, k]) => harness.device.unlockRecovery(v, k, "signin-1", true), [e.fake.mailbox(), e.recoveryKey] as const);
    if (!again.ok) throw new Error(`${again.error.name}: ${again.error.message}`);
    expect(again.device).toMatchObject({ keepsUnlocked: false });
  });

  test("no policy violation on any page but the harness's own probes", async () => {
    for (const page of pages) {
      const violations = await page.evaluate(() => harness.violations());
      expect(violations.filter((v) => !(v.directive === "require-trusted-types-for" && v.sample.startsWith("Element innerHTML|<b>probe</b>")))).toEqual([]);
    }
  });
});
