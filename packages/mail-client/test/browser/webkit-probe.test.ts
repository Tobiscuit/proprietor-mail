// A probe of the crypto primitives device-v1 and envelope v1 rely on, in the engine itself: each one
// over many fresh random inputs (test/browser/crypto-probe.ts), with its counts printed. It runs in
// WebKit always: every browser on an iPhone is WebKit, and Playwright's WebKit runs only in CI.
// MAIL_CLIENT_PROBE=1 runs it in the other engines too.
//
// The bar: mail-crypto's own operations (the "package" checks) never fail, in any engine. Web Crypto's
// own primitives (the "engine" checks) never fail either, except in WebKit with the signature of
// WebKit bug 307095 (libgcrypt drops a scalar's leading zero byte; see crypto-probe.ts), which is
// counted and printed, so the day Playwright's WebKit carries the fix shows up here as zeros.
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { chromium, firefox, webkit, type Browser, type Page } from "playwright";
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
  .filter((s): s is BrowserName => s in BROWSERS)
  .filter((s) => s === "webkit" || process.env.MAIL_CLIENT_PROBE === "1");
const ROUNDS = Number(process.env.MAIL_CLIENT_PROBE_ROUNDS ?? "300");

if (chosen.length === 0) {
  test.skip("the crypto probe runs in WebKit, or in every engine with MAIL_CLIENT_PROBE=1", () => undefined);
}

describe.each(chosen)("%s: the crypto probe", (name) => {
  let server: TestServer;
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    server = await startTestServer();
    browser = await BROWSERS[name].launch({ headless: true });
    page = await (await browser.newContext()).newPage();
    await page.goto(server.origin + "/");
    await page.waitForFunction(() => document.getElementById("status")?.textContent === "ready", null, { timeout: 30_000 });
  });

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  test(`every primitive, ${ROUNDS} fresh random inputs each: the package's operations never fail; the engine's fail only with WebKit bug 307095's signature, and only in WebKit`, { timeout: 900_000 }, async () => {
    const checks = await page.evaluate(() => harness.probe.checks());
    console.info(`${name} probe | ${checks.length} checks, ${ROUNDS} rounds each`);
    expect(checks.length).toBe(21); // a probe that runs nothing would pass
    const report: Record<string, Awaited<ReturnType<Harness["probe"]["run"]>>[string]> = {};
    for (const check of checks) {
      Object.assign(report, await page.evaluate(([n, c]) => harness.probe.run(n, [c]), [ROUNDS, check] as const));
    }
    for (const [check, line] of Object.entries(report)) {
      const bad = line.threw + line.wrongLength + line.mismatch + line.knownEngineBug;
      console.info(
        `${name} probe | ${line.layer} | ${check} | tries ${line.tries} | threw ${line.threw} | wrong length ${line.wrongLength} | mismatch ${line.mismatch} | known engine bug ${line.knownEngineBug}` +
          (bad ? ` | examples ${JSON.stringify(line.examples)}` : ""),
      );
    }
    const failing = Object.entries(report).filter(([, l]) => l.threw + l.wrongLength + l.mismatch > 0 || (l.knownEngineBug > 0 && (l.layer === "package" || name !== "webkit")));
    expect(failing.map(([check, l]) => `${check} (${l.layer}): ${l.threw} threw, ${l.wrongLength} wrong length, ${l.mismatch} mismatch, ${l.knownEngineBug} known engine bug`)).toEqual([]);
  });

  test("the private keys this engine's generateKey makes: how many start with a zero byte, and whether it clamps them", { timeout: 300_000 }, async () => {
    const shapes = await page.evaluate((n) => harness.probe.keyShapes(n), ROUNDS * 4);
    console.info(`${name} probe | generated X25519 private keys | ${JSON.stringify(shapes)}`);
    expect(shapes.draws).toBe(ROUNDS * 4);
  });
});
