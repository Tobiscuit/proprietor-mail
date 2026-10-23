// D1g: a kept device in real browsers (contracts/device-v1.md Part C; spec 002 §9), on the page the
// other browser tests use: the dashboard's exact policy with Trusted Types ENFORCED. The fake Mail runs
// here in Node; the browser makes every key and every request, as the dashboard's inbox will.
//
// What this proves, per browser: the storage check (D31) is true where keys can be kept and false,
// never an exception, where storage refuses them; a kept device survives a reload (a new page in the
// same browser context) and opens the inbox with no prompt; what IndexedDB holds is exactly K5's
// fields, with non-extractable P-256 keys, no X25519 key and no token; and the spec's two open
// questions: a non-extractable P-256 key opens its seal (@hpke/core, A4), and a non-extractable X25519
// key derives bits with its own public key (A5, the binding key behind every tag check).
//
// WebKit runs only in CI, on macOS (the browsers-macos job; Linux WebKit is not tested). Playwright's WebKit
// is not Safari: where its IndexedDB cannot keep a CryptoKey, the test checks that the fallback is
// the safe one (a shared computer that keeps nothing) instead.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { chromium, firefox, webkit, type Browser, type BrowserContext, type Page } from "playwright";
import { KEPT_DEVICE_FIELDS } from "../../src/index";
import { enrolledMailbox, rotateByHand, type Enrolled } from "../keyring-support";
import type { Harness } from "./harness";
import { startTestServer, type TestServer } from "./server";

declare global {
  // eslint-disable-next-line no-var
  var harness: Harness;
}

const contracts = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../contracts");
const deviceVectors = JSON.parse(readFileSync(resolve(contracts, "device-v1.vectors.json"), "utf8"));
const descriptorVectors = JSON.parse(readFileSync(resolve(contracts, "action-descriptor-v1.vectors.json"), "utf8"));

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

  /**
   * F1 in `page`: the recovery key; a mail session with a factor proof bound to it (D38); keepThisDevice,
   * registerDevice at the fake with a factor proof bound to that request (K4, K12); commit.
   */
  async function keepIn(page: Page, e: Enrolled, signInId: string) {
    const unlocked = await page.evaluate(([v, k, s]) => harness.device.unlockRecovery(v, k, s, true), [e.fake.mailbox(), e.recoveryKey, signInId] as const);
    if (!unlocked.ok) throw new Error(`${unlocked.error.name}: ${unlocked.error.message}`);
    const factorId = e.fake.wraps.find((w) => w.kind === "recovery")!.id;
    const sessionChallenge = await e.fake.challenge({ purpose: "session" });
    const sessionConfirmation = await page.evaluate((c) => harness.device.sessionConfirmation(c), sessionChallenge);
    const forSession = await page.evaluate(([c, conf]) => harness.device.answerFactor(c, conf), [await e.fake.challenge({ purpose: "factor", factorId, action: sessionConfirmation.action }), sessionConfirmation] as const);
    const proof = await page.evaluate(([c, f]) => harness.device.sessionProof(c, f), [sessionChallenge, forSession] as const);
    const { session } = await e.fake.openSession(proof);
    const { request, confirmation } = await page.evaluate(() => harness.device.keep("Test laptop", "sign-out"));
    const factorProof = await page.evaluate(([c, conf]) => harness.device.answerFactor(c, conf), [await e.fake.challenge({ purpose: "factor", factorId, action: confirmation.action }), confirmation] as const);
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

  test("round 3 in this engine: every device-v1 and action-descriptor-v1 vector (Ed25519 factor keys derived and signing here, A11 statements, the factor graph, descriptors)", async () => {
    const page = await openPage();
    const r = await page.evaluate(([d, a]) => harness.cryptoVectors(d, a), [deviceVectors, descriptorVectors] as const);
    console.info(`${name}: ${JSON.stringify(r)}`);
    expect(r).toEqual({
      derived: deviceVectors.factors.map(() => "ok"),
      signsHere: true,
      statements: { verified: 5, refusedChanges: 31, failures: 0 },
      graph: { trusted: true, device: true, outsider: false },
      descriptors: { valid: 8, invalidRefused: 33 },
      requestDigest: true,
    });
  });

  test("K10: another account on this browser profile resumes to nothing; the owner's record is not touched", async () => {
    if (!canKeep) return; // nothing is kept where keys cannot be (checked above)
    const e = await enrolledMailbox();
    const page = await openPage();
    await keepIn(page, e, "signin-1");
    const other = await page.evaluate(([v]) => harness.device.resume(v, "signin-other", "acc_other"), [e.fake.mailbox()] as const);
    expect(other).toMatchObject({ ok: true, state: "none" });
    const record = recordOf(await page.evaluate(() => harness.device.dumpIndexedDb()), e.mailboxId);
    expect(record.fields.accountId).toEqual({ kind: "string", value: "acc_owner" });
    expect(record.fields.unlockKey!.kind).toBe("CryptoKey");
    expect(await page.evaluate(([v]) => harness.device.resume(v, "signin-1"), [e.fake.mailbox()] as const)).toMatchObject({ ok: true, state: "unlocked" });
  });

  test("K11 across two pages: the slower page's lastKeyId write misses, it resumes again from the newer value, and IndexedDB never moves back", async () => {
    if (!canKeep) return;
    const e = await enrolledMailbox();
    const first = await openPage();
    await keepIn(first, e, "signin-1");
    const older = e.fake.mailbox();
    await rotateByHand(e.fake, e.recoveryKey);
    const newer = e.fake.mailbox();
    const k2 = e.fake.activeKey.keyId;
    const pageB = await openPage();
    const pageA = await openPage();
    // B reads its record (the first key) and walks its older view; its write waits.
    await pageB.evaluate(([v]) => harness.device.resumeGated(v, "signin-1"), [older] as const);
    await pageB.evaluate(() => harness.device.gatedAtSwap());
    // A, shown the newer view, moves the anchor forward.
    expect(await pageA.evaluate(([v]) => harness.device.resume(v, "signin-1"), [newer] as const)).toMatchObject({ ok: true, state: "unlocked" });
    // B's write misses (one readwrite transaction: read, compare, write); B resumes again and finds the newer key out of its view's reach.
    const b = await pageB.evaluate(() => harness.device.gatedRelease());
    expect(b).toMatchObject({ ok: false, error: { name: "MailboxChanged" } });
    const record = recordOf(await pageA.evaluate(() => harness.device.dumpIndexedDb()), e.mailboxId);
    expect(record.fields.lastKeyId).toEqual({ kind: "string", value: k2 });
  });

  test("no policy violation on any page but the harness's own probes", async () => {
    for (const page of pages) {
      const violations = await page.evaluate(() => harness.violations());
      expect(violations.filter((v) => !(v.directive === "require-trusted-types-for" && v.sample.startsWith("Element innerHTML|<b>probe</b>")))).toEqual([]);
    }
  });
});
