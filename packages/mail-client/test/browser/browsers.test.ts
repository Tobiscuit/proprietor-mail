// The tests contracts/mail-client-v1.md requires ("Tests this contract requires"), in real browsers
// through Playwright, on a page served with the dashboard's exact policy and Trusted Types
// ENFORCED: the frame runs no script (including through markup DOMPurify has historically
// mishandled), remote images never load, nonce-stamped styles apply, cid: images render as data:
// URLs, the inherited frame-ancestors 'none' does not stop the frame, and the key ceremony runs
// through Chromium's virtual authenticator with PRF, or an injected double elsewhere.
//
// Opt-in (MAIL_CLIENT_BROWSER_TESTS=1): the Playwright browsers must be installed. The browsers to
// run come from MAIL_CLIENT_BROWSERS (default: chromium,firefox,webkit); a browser that cannot
// launch FAILS its tests, it never skips them.
import { Buffer } from "node:buffer";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { chromium, firefox, webkit, type Browser, type BrowserContext, type Frame, type Page } from "playwright";
import { newId, sealMessage } from "@proprietor/mail-crypto";
import type { MailboxView, MessageItem } from "../../src/index";
import { mailboxAfterEnroll, multipartRaw, PNG_1x1, sampleHeader, sampleRaw } from "../support";
import type { Harness, SerializedBody } from "./harness";
import { POLICY_NAME, startTestServer, type TestServer } from "./server";

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

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64");

/** The hostile message every render test uses. */
function hostileBody(remoteImageUrl: string): SerializedBody {
  return {
    text: null,
    html: [
      "<html><head>",
      '<meta http-equiv="refresh" content="0;url=http://evil.example/">',
      '<base href="http://evil.example/">',
      '<link rel="stylesheet" href="http://evil.example/x.css">',
      '<style>@import url("http://evil.example/i.css"); .x{color:green;background:url(http://evil.example/bg.png)} .y{color:blue}</style>',
      "<script>window.__ran=1</script>",
      "</head>",
      '<body onload="window.__ran=2">',
      '<p id="marker" class="x">Hello <a href="http://example.com/x">link</a> <a href="javascript:alert(1)">bad</a> <a href="mailto:a@example.com">mail</a> <a href="/relative">rel</a></p>',
      `<img id="remote" src="${remoteImageUrl}"> <img id="logo" src="cid:logo@example.com" alt="logo"> <img srcset="http://evil.example/a.png 1x" src="cid:nope">`,
      '<img id="svg" src="data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=">',
      '<table background="http://evil.example/t.png"><tr><td style="background:url(http://evil.example/td.png);color:red">cell</td></tr></table>',
      '<form action="http://evil.example/f"><input name="q"><button>go</button></form>',
      '<iframe src="http://evil.example/"></iframe><object data="x"></object>',
      '<div onclick="window.__ran=3" style="color:blue">div</div>',
      "<svg><script>window.__ran=4</script></svg>",
      "</body></html>",
    ].join("\n"),
    attachments: [{ filename: "logo.png", mimeType: "image/png", contentId: "logo@example.com", inline: true, contentBase64: b64(PNG_1x1) }],
  };
}

/** Markup DOMPurify has historically mishandled (mXSS), each carrying a handler that must not survive. */
const MXSS = [
  '<svg><p><style><img src=x onerror="window.__ran=1"></style></p></svg>',
  '<math><mtext><table><mglyph><style><img src=x onerror="window.__ran=1"></style></mglyph></table></mtext></math>',
  '<noscript><p title="</noscript><img src=x onerror=\'window.__ran=1\'>"></p></noscript>',
  '<form><math><mtext></form><form><mglyph><style></math><img src onerror="window.__ran=1"></style></mglyph></form></mtext></math></form>',
  '<a href="javascript:window.__ran=1">x</a><a href="&#106;avascript:window.__ran=1">y</a>',
  '<img src="x" onerror="window.__ran=1"><img src=x onError="window.__ran=1">',
  '<svg><animate onbegin="window.__ran=1" attributeName=x dur=1s>',
  '<details open ontoggle="window.__ran=1">',
  '<style>@import "http://evil.example/x.css"; body{background:url(javascript:1)}</style>',
  '<p style="width:expression(window.__ran=1)">x</p>',
  "<xmp><p onclick=1>x</p></xmp><template><script>window.__ran=1</script></template>",
];

describe.each(chosen)("%s under the dashboard's policy", (name) => {
  let server: TestServer;
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;
  let hasVirtualAuthenticator = false;

  beforeAll(async () => {
    server = await startTestServer();
    browser = await BROWSERS[name].launch({ headless: true });
    context = await browser.newContext();
    page = await context.newPage();
    if (name === "chromium") {
      const cdp = await context.newCDPSession(page);
      await cdp.send("WebAuthn.enable", { enableUI: false });
      await cdp.send("WebAuthn.addVirtualAuthenticator", {
        options: {
          protocol: "ctap2",
          ctap2Version: "ctap2_1",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          hasPrf: true,
          automaticPresenceSimulation: true,
        },
      });
      hasVirtualAuthenticator = true;
    }
    await page.goto(server.origin + "/");
    await page.waitForFunction(() => document.getElementById("status")?.textContent === "ready", null, { timeout: 30_000 });
  });

  afterAll(async () => {
    await browser?.close();
    await server?.close();
  });

  const readingPane = (): Frame => {
    const child = page.frames().find((f) => f.parentFrame() === page.mainFrame());
    if (!child) throw new Error("no reading pane frame");
    return child;
  };

  test("the page is under the policy: Trusted Types enforced wherever the browser has them, the harness script ran under the nonce", async () => {
    const present = await page.evaluate(() => harness.trustedTypesPresent());
    const enforced = await page.evaluate(() => harness.enforced());
    expect(enforced).toBe(present);
    if (name === "chromium") expect(enforced).toBe(true);
    expect(await page.evaluate(() => harness.nonceOfScript())).toBe(server.nonce);
  });

  test("pageNonce() is the page's own script nonce, never a server-rendered element's attribute", async () => {
    expect(await page.evaluate(() => harness.pageNonce())).toBe(server.nonce);
  });

  test("renderBody strips everything hostile and counts what it blocked; showInFrame puts it in the sandboxed frame", async () => {
    const result = await page.evaluate((body) => harness.render(body, "allow-popups allow-popups-to-escape-sandbox", null), hostileBody(`${server.origin}/remote.png`));
    if (!result.ok) throw new Error(`${result.error.name}: ${result.error.message}`);
    expect(result.remoteImagesBlocked).toBe(7); // @import, style url(), the remote img, the srcset, the SVG data: image, the table background, the td style url()
    expect(result.inlineImages).toBe(1);
    expect(result.referrerPolicy).toBe("no-referrer");
    if (await page.evaluate(() => harness.trustedTypesPresent())) expect(result.trustedType).toBe("[object TrustedHTML]");

    const html = result.html;
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/\son\w+\s*=/i);
    expect(html).not.toMatch(/<(?:form|input|button|iframe|object|link|meta http-equiv|base|svg)\b/i);
    expect(html).not.toMatch(/javascript:/i);
    expect(html).not.toContain("evil.example");
    expect(html).not.toContain("/remote.png");
    expect(html).not.toContain("srcset");
    expect(html).not.toContain("/relative");
    expect(html).toContain(`<a href="http://example.com/x" target="_blank" rel="noopener noreferrer">`);
    expect(html).toContain(`<a href="mailto:a@example.com" target="_blank" rel="noopener noreferrer">`);
    expect(html).toContain(`<img id="logo" src="data:image/png;base64,${b64(PNG_1x1)}" alt="logo">`);
    expect(html).toContain(`<style nonce="${server.nonce}">`);
    expect(html).toContain(".x{color:green;background:none}");
    expect(html).not.toMatch(/\sstyle=/i);
    expect(html).toContain(".pm-inline-1{background:none;color:red}");
    expect(html).toContain('<div class="pm-inline-2">div</div>');
    expect(html).not.toMatch(/<style(?![^>]*nonce=)/i);
    expect(html).toContain('<meta charset="utf-8">');
    expect(html).not.toContain("http-equiv");
  });

  test("inside the frame: no script ran, the nonce-stamped style applies, the cid: image rendered, nothing remote was fetched, and frame-ancestors 'none' did not stop it", async () => {
    const pane = readingPane();
    await pane.waitForLoadState("load");
    const inside = await pane.evaluate(async () => {
      const logo = document.getElementById("logo") as HTMLImageElement | null;
      if (logo && !logo.complete) await new Promise((r) => logo.addEventListener("load", r, { once: true }));
      return {
        scripts: document.scripts.length,
        ran: (window as unknown as { __ran?: number }).__ran ?? null,
        marker: document.getElementById("marker") !== null,
        markerColor: getComputedStyle(document.getElementById("marker")!).color,
        logoWidth: logo?.naturalWidth ?? -1,
        handlers: Array.from(document.querySelectorAll("*")).flatMap((el) => Array.from(el.attributes).map((a) => a.name)).filter((n) => n.startsWith("on")),
        origin: location.origin,
        remoteSrc: document.getElementById("remote")?.getAttribute("src") ?? null,
        divColor: getComputedStyle(document.querySelector("div.pm-inline-2")!).color,
        cellColor: getComputedStyle(document.querySelector("td")!).color,
        forms: document.forms.length,
      };
    });
    expect(inside.scripts).toBe(0);
    expect(inside.ran).toBeNull();
    expect(inside.marker).toBe(true);
    expect(inside.markerColor).toBe("rgb(0, 128, 0)");
    expect(inside.logoWidth).toBe(1);
    expect(inside.handlers).toEqual([]);
    expect(inside.origin).toBe("null");
    expect(inside.remoteSrc).toBeNull();
    // Inline style attributes survive as class rules in the nonce-stamped sheet (style-src-attr would refuse them).
    expect(inside.divColor).toBe("rgb(0, 0, 255)");
    expect(inside.cellColor).toBe("rgb(255, 0, 0)");
    expect(inside.forms).toBe(0);
    expect(server.remoteImageHits()).toBe(0);
  });

  test("markup DOMPurify has historically mishandled renders without any script or handler", async () => {
    for (const sample of MXSS) {
      const result = await page.evaluate((body) => harness.render(body, "allow-popups", null), { text: null, html: sample, attachments: [] } satisfies SerializedBody);
      if (!result.ok) throw new Error(`${sample}: ${result.error.name}: ${result.error.message}`);
      expect(result.html, sample).not.toMatch(/<script/i);
      expect(result.html, sample).not.toMatch(/\son\w+\s*=/i);
      expect(result.html, sample).not.toMatch(/javascript:|expression\(|@import/i);
      const pane = readingPane();
      await pane.waitForLoadState("load");
      const inside = await pane.evaluate(() => ({
        scripts: document.scripts.length,
        ran: (window as unknown as { __ran?: number }).__ran ?? null,
        handlers: Array.from(document.querySelectorAll("*")).flatMap((el) => Array.from(el.attributes).map((a) => a.name)).filter((n) => n.startsWith("on")),
      }));
      expect(inside, sample).toEqual({ scripts: 0, ran: null, handlers: [] });
    }
    expect(server.remoteImageHits()).toBe(0);
  });

  test("plain text is escaped and keeps its line breaks", async () => {
    const result = await page.evaluate((body) => harness.render(body, "allow-popups", null), { text: "line one\n<b>not bold</b> & more\n  indented", html: null, attachments: [] } satisfies SerializedBody);
    if (!result.ok) throw new Error(result.error.message);
    expect(result.html).toContain('<pre class="plain">line one\n&lt;b&gt;not bold&lt;/b&gt; &amp; more\n  indented</pre>');
    const pane = readingPane();
    await pane.waitForLoadState("load");
    expect(await pane.evaluate(() => ({ b: document.querySelector("b"), text: document.querySelector("pre")!.textContent }))).toEqual({ b: null, text: "line one\n<b>not bold</b> & more\n  indented" });
  });

  test("showInFrame refuses a frame without the allowed sandbox, a forged body and a disposed one; renderBody refuses a missing nonce", async () => {
    const body: SerializedBody = { text: "x", html: null, attachments: [] };
    for (const sandbox of [null, "allow-scripts", "allow-same-origin", "allow-forms", "allow-top-navigation", "allow-popups allow-scripts", "allow-top-navigation-by-user-activation", "allow-modals"]) {
      const result = await page.evaluate(([b, s]) => harness.render(b, s, null), [body, sandbox] as const);
      expect(result.ok, `sandbox=${JSON.stringify(sandbox)}`).toBe(false);
      if (!result.ok) expect(result.error.name).toBe("UnsafeFrame");
    }
    // An empty sandbox attribute is the strictest sandbox of all.
    for (const sandbox of ["", "allow-popups", "allow-popups allow-popups-to-escape-sandbox", "ALLOW-POPUPS"]) {
      const result = await page.evaluate(([b, s]) => harness.render(b, s, null), [body, sandbox] as const);
      expect(result.ok, sandbox).toBe(true);
    }
    const forged = await page.evaluate(() => harness.showForged("allow-popups"));
    expect(forged.ok).toBe(false);
    if (!forged.ok) expect(forged.error.name).toBe("TypeError");
    const disposed = await page.evaluate((b) => harness.showDisposed(b), body);
    expect(disposed.ok).toBe(false);
    for (const nonce of ["", "short", 'abc"onload="x', "nonce with spaces"]) {
      const result = await page.evaluate(([b, n]) => harness.renderOnly(b, n), [body, nonce] as const);
      expect(result.ok, `nonce=${JSON.stringify(nonce)}`).toBe(false);
      if (!result.ok) expect(result.error.name).toBe("TypeError");
    }
  });

  test("Trusted Types: a plain string cannot reach srcdoc where enforcement exists, and no policy but the package's was ever created", async () => {
    const enforced = await page.evaluate(() => harness.enforced());
    const control = await page.evaluate(() => harness.stringSrcdoc());
    expect(control.threw).toBe(enforced);
    const violations = await page.evaluate(() => harness.violations());
    expect(violations.filter((v) => v.directive === "trusted-types"), "no `dompurify` or other policy was attempted").toEqual([]);
    // DOMPurify parses the message into a detached document that inherits the page's policy, so the
    // message's own <style> elements and style attributes are reported as refused inline styles
    // there (they never render there anyway). Nothing else may be reported: no script, image,
    // frame or connection was attempted by the page.
    // The harness's two deliberate controls (an innerHTML probe, the plain-string srcdoc above) are
    // reported as refused sinks: that is enforcement working. The message's <base> is reported by
    // the detached parse too, before the sanitiser removes it.
    // Since Chromium 156 (Playwright 1.64) the detached parse also reports the message's inline event
    // handlers (script-src-attr); they never run there either. Each must come from a call site that
    // also reported the message's inline styles, i.e. the parse itself: a handler reported from
    // anywhere else (the page, the frame) still fails this test.
    const parseSites = new Set(violations.filter((v) => /^style-src(?:-elem|-attr)?$/.test(v.directive)).map((v) => v.site));
    const expected = (v: { directive: string; blocked: string; sample: string; site: string }) =>
      (/^style-src(?:-elem|-attr)?$/.test(v.directive) && v.blocked === "inline") ||
      (v.directive === "script-src-attr" && v.blocked === "inline" && parseSites.has(v.site)) ||
      (v.directive === "require-trusted-types-for" && /^(?:Element innerHTML\|<b>probe<\/b>|HTMLIFrameElement srcdoc\|<p>plain string<\/p>)/.test(v.sample)) ||
      v.directive === "base-uri";
    expect(violations.filter((v) => !expected(v))).toEqual([]);
    expect(POLICY_NAME).toBe("proprietor-mail#srcdoc");
  });

  describe("the key ceremony", () => {
    const mailboxId = newId("mbx");
    let view: MailboxView;
    let recoveryKey: string;
    let pub: { keyId: string; publicKey: Uint8Array };

    test("startEnrollment: a key pair, a passkey wrap from the PRF output and a recovery wrap, all made in this browser", async () => {
      const useDouble = !hasVirtualAuthenticator;
      const result = await page.evaluate(([id, host, d]) => harness.enroll(id, host, d, true), [mailboxId, server.host, useDouble] as const);
      if (!result.ok) throw new Error(`${result.error.name}: ${result.error.message}`);
      expect(result.passkey).toBe("prf");
      expect(result.confirmed).toBe(true);
      expect(result.wrapBytes).toEqual([77, 77]);
      expect(result.request.wraps.map((w) => w.kind)).toEqual(["passkey-prf", "recovery"]);
      expect(result.request.wraps[0]!.credentialId).toMatch(/^[A-Za-z0-9_-]{16,}$/);
      recoveryKey = result.recoveryKey;
      view = mailboxAfterEnroll(mailboxId, result.request);
      const keyId = await page.evaluate((r) => harness.keyIdOfRequest(r), result.request);
      expect(view.keys[0]!.keyId).toBe(keyId);
      pub = { keyId, publicKey: Buffer.from(result.request.publicKey, "base64url") };
    });

    test("unlockWithPasskey opens a message the Worker sealed to the enrolled key", async () => {
      const useDouble = !hasVirtualAuthenticator;
      const unlocked = await page.evaluate(([v, host, d]) => harness.unlockPasskey(v, host, d), [view, server.host, useDouble] as const);
      if (!unlocked.ok) throw new Error(`${unlocked.error.name}: ${unlocked.error.message}`);
      expect(unlocked.keyId).toBe(pub.keyId);
      const messageId = newId("msg");
      const sealed = await sealMessage(pub, { mailboxId, messageId }, sampleHeader, sampleRaw);
      const item: MessageItem = { id: messageId, folder: "inbox", direction: "in", receivedAt: "2026-10-04T10:00:00.000Z", size: sampleRaw.length, seen: false, flagged: false, keyId: sealed.keyId, keyEnvelope: sealed.keyEnvelope, header: sealed.header };
      const [opened] = await page.evaluate((items) => harness.openMessages(items), [item]);
      expect(opened!.undecryptable).toBe(false);
      expect(opened!.header).toStrictEqual(sampleHeader);

      const multipart = await sealMessage(pub, { mailboxId, messageId }, { ...sampleHeader, subject: "Plans" }, multipartRaw);
      const body = await page.evaluate(([i, s]) => harness.openBody(i, s), [{ ...item, keyEnvelope: multipart.keyEnvelope, header: multipart.header }, b64(multipart.body)] as const);
      expect(body.html).toContain("cid:logo@example.com");
      expect(body.attachments.map((a) => a.contentId)).toEqual(["logo@example.com", null]);
    });

    test("a second passkey needs a fresh unlock (K1): added with the recovery key, it then unlocks the mailbox", async () => {
      const useDouble = !hasVirtualAuthenticator;
      const added = await page.evaluate(([host, d, key]) => harness.addPasskeyWithRecovery(host, d, key), [server.host, useDouble, recoveryKey] as const);
      if (!added.ok) throw new Error(`${added.error.name}: ${added.error.message}`);
      expect(added.wrapBytes).toBe(77);
      const twoPasskeys: MailboxView = { ...view, wraps: [...view.wraps, { ...added.wrap, createdAt: "2026-10-04T11:00:00.000Z", createdBy: "acc_owner" }] };
      const unlocked = await page.evaluate(([v, host, d]) => harness.unlockPasskey(v, host, d), [twoPasskeys, server.host, useDouble] as const);
      expect(unlocked.ok).toBe(true);
    });

    test("unlockWithRecoveryKey, and KeySubstitutionDetected when the advertised key is not the one the wraps hold (G7)", async () => {
      const unlocked = await page.evaluate(([v, key]) => harness.unlockRecovery(v, key), [view, recoveryKey] as const);
      expect(unlocked.ok).toBe(true);
      const forged: MailboxView = { ...view, keys: [{ ...view.keys[0]!, publicKey: Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url") }] };
      const result = await page.evaluate(([v, key]) => harness.unlockRecovery(v, key), [forged, recoveryKey] as const);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error.name).toBe("KeySubstitutionDetected");
      const byPasskey = await page.evaluate(([v, host, d]) => harness.unlockPasskey(v, host, d), [forged, server.host, !hasVirtualAuthenticator] as const);
      expect(byPasskey.ok).toBe(false);
      if (!byPasskey.ok) expect(byPasskey.error.name).toBe("KeySubstitutionDetected");
      expect(await page.evaluate(() => harness.lock())).toBe(true);
    });
  });
});
