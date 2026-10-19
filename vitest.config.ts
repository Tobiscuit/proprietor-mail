import path from "node:path";
import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import { escapeGuard } from "./test/harness/escape-guard.ts";
import { TEST_CAPABILITY_KEYS } from "./test/support/test-keys.ts";

// THREE KINDS OF PROJECT, one `npm test`.
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
//
// `escapeGuard()` fails the run when workerd reports an exception that escaped
// an RPC hop (an uncaught throw, or an invocation cancelled as "hung") that no
// test declared (test/harness/escape-guard.ts, test/README.md). It adds its
// own reporter, so it runs whatever `--reporter` says. Do not set
// `dangerouslyIgnoreUnhandledErrors` either: vitest's own policy is the guard
// for the rejections it can see.
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
          escapeGuard(),
        ],
        test: {
          name: "worker",
          include: ["test/**/*.test.ts"],
          exclude: ["**/node_modules/**", "test/node/**"],
          setupFiles: ["./test/support/apply-migrations.ts"],
          // A shared CI runner, with every file's crypto running at once, is several times slower than a
          // laptop: M7's 101 sends take about 1 s here and came within a few milliseconds of vitest's default
          // 5 s there. A bound still, just not one that load can trip.
          testTimeout: 20_000,
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
