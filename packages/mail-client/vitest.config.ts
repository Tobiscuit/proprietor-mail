import { defineConfig } from "vitest/config";

// The stub's API-surface test runs in Node. The real package's browser tests
// (contracts/mail-client-v1.md, "Tests this contract requires") are S6a's.
export default defineConfig({
  test: { environment: "node", include: ["test/**/*.test.ts"] },
});
