import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";
// Type-only, so it is erased at compile time and no Node-side pool code
// reaches workerd.
import type { D1Migration } from "@cloudflare/vitest-pool-workers";

// Every test file starts from a Directory built by the REAL migrations, not a
// hand-kept test schema: a migration that would fail in production fails here.
//
// TEST_MIGRATIONS is injected by vitest.config.ts and is deliberately absent
// from wrangler.jsonc, so it is not on `Env`; the cast lives here, at the one
// place it is read.
const testEnv = env as typeof env & { TEST_MIGRATIONS?: D1Migration[] };

if (testEnv.TEST_MIGRATIONS === undefined) {
  throw new Error(
    "TEST_MIGRATIONS is missing: vitest.config.ts must return both `wrangler` and `miniflare` from cloudflareTest().",
  );
}
await applyD1Migrations(env.DIRECTORY, testEnv.TEST_MIGRATIONS);
