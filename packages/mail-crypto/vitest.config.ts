import { configDefaults, defineConfig } from "vitest/config";

// The vectors generators only run on request: `npm run write-vectors` (envelope v1) and
// `npm run write-device-vectors` (device-v1).
const writeVectors = process.env.WRITE_VECTORS === "1";

export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    exclude: writeVectors ? configDefaults.exclude : [...configDefaults.exclude, "test/vectors.write.test.ts", "test/device-vectors.write.test.ts"],
    testTimeout: 30_000,
  },
});
