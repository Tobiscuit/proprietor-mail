import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { IMPLEMENTED } from "../src/index";

/**
 * The package runs unchanged in a Worker and in Node: fetch, Web Crypto and
 * TextEncoder only. tsconfig.json already typechecks src/ with no Node types
 * ("types": []); this scan also catches what a cast or `any` would hide.
 */
const srcDir = new URL("../src/", import.meta.url);
const sources = readdirSync(srcDir)
  .filter((f) => f.endsWith(".ts"))
  .map((f) => [f, readFileSync(new URL(f, srcDir), "utf8")] as const);

describe("runtime portability", () => {
  it("has source files to check", () => {
    expect(sources.length).toBeGreaterThan(0);
  });

  it.each(sources)("%s uses no Node built-ins", (_file, code) => {
    const withoutComments = code.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
    expect(withoutComments).not.toMatch(/["']node:/);
    expect(withoutComments).not.toMatch(/\bBuffer\b/);
    expect(withoutComments).not.toMatch(/\bprocess\./);
    expect(withoutComments).not.toMatch(/\brequire\(/);
    expect(withoutComments).not.toMatch(/\bMath\.random\b/);
  });

  it("pins every dependency exactly", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as Record<string, Record<string, string>>;
    for (const deps of [pkg.dependencies ?? {}, pkg.devDependencies ?? {}]) {
      for (const [name, version] of Object.entries(deps)) expect(version, name).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });
});

describe("package state", () => {
  it("is implemented", () => {
    expect(IMPLEMENTED).toBe(true);
  });
});
