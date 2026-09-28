// S1r: scripts/sha256sums.mjs prints the SHA256SUMS that the release workflow
// attaches to a mail-crypto-v* release, and that the dashboard's vendoring
// script checks its copy of src/ against. The format is sha256sum's own:
// "<64 hex>  src/<path>" per file, paths relative to this package, sorted
// bytewise (as `LC_ALL=C sort` would), LF line endings, nothing else.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, test } from "vitest";

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(packageDir, "scripts", "sha256sums.mjs");
const scratch = mkdtempSync(join(tmpdir(), "mail-crypto-sha256sums-"));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

function run(dir?: string) {
  return spawnSync(process.execPath, dir === undefined ? [script] : [script, dir], { encoding: "utf8" });
}

function sums(dir?: string): string {
  const result = run(dir);
  expect(result.stderr).toBe("");
  expect(result.status).toBe(0);
  return result.stdout;
}

/** The lines as [hash, path] pairs, after checking the whole text's shape. */
function parse(text: string): Array<[string, string]> {
  expect(text).not.toContain("\r");
  expect(text.endsWith("\n")).toBe(true);
  return text
    .slice(0, -1)
    .split("\n")
    .map((line) => {
      const match = /^([0-9a-f]{64}) {2}(src\/.+)$/.exec(line);
      if (!match) throw new Error(`not a sha256sum line: ${JSON.stringify(line)}`);
      return [match[1]!, match[2]!];
    });
}

/** Computed without the script: a recursive readdir and node:crypto. */
function independentSums(dir: string): Map<string, string> {
  const expected = new Map<string, string>();
  for (const entry of readdirSync(join(dir, "src"), { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const file = join(entry.parentPath, entry.name);
    const path = relative(dir, file).split(sep).join("/");
    expected.set(path, createHash("sha256").update(readFileSync(file)).digest("hex"));
  }
  return expected;
}

const bytewise = (a: string, b: string) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));

const hasSha256sum = spawnSync("sha256sum", ["--version"]).status === 0;

/** `sha256sum --check --strict` run in `dir` on `text`; its exit status and output. */
function sha256sumCheck(dir: string, text: string) {
  const file = join(scratch, `SHA256SUMS-${Math.random().toString(36).slice(2)}`);
  writeFileSync(file, text);
  return spawnSync("sha256sum", ["--check", "--strict", file], { cwd: dir, encoding: "utf8" });
}

/** A throwaway package directory whose src/ holds `files` (path -> content). */
function fixture(files: Record<string, string>): string {
  const dir = mkdtempSync(join(scratch, "pkg-"));
  mkdirSync(join(dir, "src"));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, "src", path)), { recursive: true });
    writeFileSync(join(dir, "src", path), content);
  }
  return dir;
}

describe("SHA256SUMS of this package's src/", () => {
  let text = "";
  let lines: Array<[string, string]> = [];
  beforeAll(() => {
    text = sums();
    lines = parse(text);
  });

  test("hashes every file under src/, and nothing else", () => {
    const expected = independentSums(packageDir);
    expect(expected.size).toBeGreaterThan(0);
    expect(lines).toHaveLength(expected.size);
    expect(new Map(lines.map(([hash, path]) => [path, hash]))).toEqual(expected);
  });

  test("lists paths in bytewise order, each once", () => {
    const paths = lines.map(([, path]) => path);
    for (let i = 1; i < paths.length; i++) expect(bytewise(paths[i - 1]!, paths[i]!)).toBeLessThan(0);
  });

  test("is deterministic", () => {
    expect(sums()).toBe(text);
  });

  test.skipIf(!hasSha256sum)("is accepted by sha256sum --check --strict", () => {
    const check = sha256sumCheck(packageDir, text);
    expect(check.stderr).toBe("");
    expect(check.status).toBe(0);
    expect(check.stdout).toBe(lines.map(([, path]) => `${path}: OK\n`).join(""));
  });
});

describe("on a fixture tree", () => {
  // U+FF5E is EF BD 9E in UTF-8 and U+1D4B3 is F0 9D 92 B3, but in UTF-16 the
  // latter's surrogate (D835) sorts before FF5E: String#sort gets this wrong.
  const dir = fixture({
    "b.ts": "b",
    "B.ts": "B",
    "a-b.ts": "a-b",
    "a/z.ts": "a/z",
    "a/b/c.ts": "nested",
    "é.ts": "e acute",
    "～.ts": "fullwidth tilde",
    "\u{1D4B3}.ts": "mathematical script X",
    "empty.ts": "",
  });

  test("orders by UTF-8 bytes, not by UTF-16 code units", () => {
    const paths = parse(sums(dir)).map(([, path]) => path);
    expect(paths).toEqual([
      "src/B.ts",
      "src/a-b.ts",
      "src/a/b/c.ts",
      "src/a/z.ts",
      "src/b.ts",
      "src/empty.ts",
      "src/é.ts",
      "src/～.ts",
      "src/\u{1D4B3}.ts",
    ]);
    expect([...paths].sort()).not.toEqual(paths);
  });

  test("hashes match node:crypto, and sha256sum accepts them", () => {
    const text = sums(dir);
    expect(new Map(parse(text).map(([hash, path]) => [path, hash]))).toEqual(independentSums(dir));
    if (hasSha256sum) expect(sha256sumCheck(dir, text).status).toBe(0);
  });
});

describe("refuses what sha256sum's format cannot record faithfully", () => {
  test.each([
    ["an empty src/", () => fixture({})],
    ["a missing src/", () => mkdtempSync(join(scratch, "pkg-"))],
    ["a file name with a newline", () => fixture({ "bad\nname.ts": "x" })],
    ["a file name with a backslash", () => fixture({ "bad\\name.ts": "x" })],
    [
      "a symbolic link",
      () => {
        const dir = fixture({ "real.ts": "x" });
        symlinkSync("real.ts", join(dir, "src", "link.ts"));
        return dir;
      },
    ],
  ])("%s: exits 1, prints nothing to stdout", (_what, make) => {
    const result = run(make());
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toMatch(/^sha256sums: /);
  });
});
