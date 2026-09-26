import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { TEST_CAPABILITY_KEYS } from "./test/support/test-keys.ts";

// THREE KINDS OF PROJECT, one `npm test` (the SEO engine's harness, adapted).
//
// `worker` runs inside workerd, not Node: a real D1 with the real migrations
// applied, real SQLite-backed Durable Objects, a real R2 simulation. What passes
// here is what the runtime does. Storage is isolated per test FILE, so tests in
// one file use fresh mailbox ids rather than relying on a clean slate.
//
// `packages/*` makes each workspace package its own project, run with the
// package's OWN vitest.config.ts when it has one (S1's excludes its vectors
// writer, for example), in Node, where Web Crypto is standard. S1 and S3 own
// those tests and configs; the root only runs them, so that `npm test` runs
// everything. `node` holds this slice's own Node-side checks (the scripts, the
// wrangler config).
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
      "packages/*",
      {
        test: {
          name: "node",
          environment: "node",
          include: ["test/node/**/*.test.ts"],
        },
      },
    ],
  },
});
