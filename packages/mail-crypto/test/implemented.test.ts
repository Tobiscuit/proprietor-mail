// S1g: IMPLEMENTED = true, and nothing left that throws NotImplemented.
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { ENVELOPE_VERSION, IMPLEMENTED } from "../src/index";

const srcDir = resolve(dirname(fileURLToPath(import.meta.url)), "../src");

test("IMPLEMENTED is true, so S2's end-to-end tests stop skipping", () => {
  expect(IMPLEMENTED).toBe(true);
  expect(ENVELOPE_VERSION).toBe(1);
});

test("no source file still throws NotImplemented", () => {
  for (const name of readdirSync(srcDir)) {
    expect(readFileSync(join(srcDir, name), "utf8"), name).not.toMatch(/throw new NotImplemented/);
  }
});
