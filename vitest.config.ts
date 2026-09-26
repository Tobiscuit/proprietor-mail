import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { TEST_CAPABILITY_KEYS } from "./test/support/test-keys.ts";

// TWO PROJECTS, one `npm test` (the SEO engine's harness, adapted).
//
// `worker` runs inside workerd, not Node: a real D1 with the real migrations
// applied, real SQLite-backed Durable Objects, a real R2 simulation. What passes
// here is what the runtime does. Storage is isolated per test FILE, so tests in
// one file use fresh mailbox ids rather than relying on a clean slate.
//
// `packages` runs the two workspace packages' own tests in Node, where Web
// Crypto is standard. S1 and S3 own those tests; this project only collects
// them so that `npm test` at the root runs everything.
//
// `wrangler` and `miniflare` are returned together from cloudflareTest:
// returning only `miniflare` silently drops the wrangler config and the D1
// binding with it.
export default defineConfig({
  test: {
    projects: [
      {
        plugins: [
          cloudflareTest(async () => {
            const migrations = await readD1Migrations(path.join(import.meta.dirname, "migrations"));
            return {
              wrangler: { configPath: "./wrangler.jsonc" },
              miniflare: {
                bindings: {
                  // Test-only: the migrations to apply, and a fixed capability
                  // key (the one in contracts/capability-v1.vectors.json).
                  TEST_MIGRATIONS: migrations,
                  MAIL_CAPABILITY_KEYS: JSON.stringify(TEST_CAPABILITY_KEYS),
                  // No SES credentials: the SES adapter is built lazily, on the
                  // first real send, and every test injects a fake RawMailer.
                },
              },
            };
          }),
        ],
        test: {
          name: "worker",
          include: ["test/**/*.test.ts"],
          exclude: ["**/node_modules/**", "test/node/**"],
          setupFiles: ["./test/support/apply-migrations.ts"],
        },
      },
      {
        test: {
          name: "packages",
          environment: "node",
          include: ["packages/*/src/**/*.test.ts", "packages/*/test/**/*.test.ts", "test/node/**/*.test.ts"],
        },
      },
    ],
  },
});
