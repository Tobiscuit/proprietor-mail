import { configDefaults, defineConfig } from "vitest/config";

// The vectors generator only runs on request: `npm run write-vectors`.
const writeVectors = process.env.WRITE_VECTORS === "1";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    exclude: writeVectors ? configDefaults.exclude : [...configDefaults.exclude, "test/vectors.write.test.ts"],
    testTimeout: 30_000,
  },
});
