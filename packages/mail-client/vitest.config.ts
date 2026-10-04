import { configDefaults, defineConfig } from "vitest/config";

// Two kinds of test, one config.
//
// `test/*.test.ts` run in Node: Web Crypto is standard there, and WebAuthn is behind the
// `credentials` port, so the key ceremony, unlock, open, threads, search and the send form are
// all checked without a browser.
//
// `test/browser/*.test.ts` drive real browsers through Playwright (contracts/mail-client-v1.md,
// "Tests this contract requires"): a page served with the dashboard's exact policy, Trusted
// Types enforced, the one sandboxed frame, and Chromium's virtual authenticator with PRF. They
// need the Playwright browsers installed (`npx playwright install --with-deps`), so they run on
// request: `npm run test:browsers -w @proprietor/mail-client`, which sets
// MAIL_CLIENT_BROWSER_TESTS=1. CI's browser job always runs them; they never skip silently.
const browsers = process.env.MAIL_CLIENT_BROWSER_TESTS === "1";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    exclude: browsers ? configDefaults.exclude : [...configDefaults.exclude, "test/browser/**"],
    testTimeout: browsers ? 120_000 : 30_000,
    hookTimeout: 120_000,
  },
});
