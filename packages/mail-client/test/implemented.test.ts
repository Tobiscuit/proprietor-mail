// IMPLEMENTED = true, and nothing left that throws NotImplemented (the stub's marker).
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { IMPLEMENTED } from "../src/index";

const srcDir = resolve(dirname(fileURLToPath(import.meta.url)), "../src");

test("IMPLEMENTED is true, so the screens stop showing 'coming soon'", () => {
  expect(IMPLEMENTED).toBe(true);
});

test("no source file still throws NotImplemented", () => {
  for (const name of readdirSync(srcDir)) {
    expect(readFileSync(join(srcDir, name), "utf8"), name).not.toMatch(/throw new NotImplemented/);
  }
});
