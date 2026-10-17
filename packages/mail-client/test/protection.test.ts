// PROTECTION (contracts/mail-client-v1.md "The promise, as data", as amended by spec 002): the texts
// the dashboard shows are the specs', read from specs/001-inbox-module/spec.md and
// specs/002-device-sessions/spec.md, so no screen ever claims more than the specs.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { PROTECTION } from "../src/index";

const specs = resolve(dirname(fileURLToPath(import.meta.url)), "../../../specs");
const spec001 = readFileSync(resolve(specs, "001-inbox-module/spec.md"), "utf8");
const spec002 = readFileSync(resolve(specs, "002-device-sessions/spec.md"), "utf8");

/** The blockquote under a bold heading, joined with spaces. */
function blockquoteAfter(spec: string, heading: string): string {
  const start = spec.indexOf(heading);
  expect(start, heading).toBeGreaterThan(-1);
  const lines: string[] = [];
  for (const line of spec.slice(start + heading.length).split("\n").slice(1)) {
    if (!line.startsWith("> ")) break;
    lines.push(line.slice(2).trim());
  }
  return lines.join(" ");
}

/** The rows of the table under a heading, until the table ends. */
function tableAfter(spec: string, heading: string): string[][] {
  const start = spec.indexOf(heading);
  expect(start, heading).toBeGreaterThan(-1);
  const rows: string[][] = [];
  let inTable = false;
  for (const line of spec.slice(start).split("\n").slice(1)) {
    if (line.startsWith("|")) {
      inTable = true;
      rows.push(line.split("|").slice(1, -1).map((c) => c.trim()));
    } else if (inTable) break;
  }
  return rows.slice(2); // the header and the separator
}

const rows001 = tableAfter(spec001, "## 4. What the platform can see, even under Option A");
const rows002 = tableAfter(spec002, "What the platform can see (001 §4) gains these rows:");

describe("PROTECTION: spec 001", () => {
  test("optionA is the spec's Option A text, with {operator} filled in", () => {
    const text = blockquoteAfter(spec001, "**Option A — encrypted with your key (structural).**");
    expect(text).toContain("{operator}");
    expect(PROTECTION.optionA("{operator}")).toBe(text);
    expect(PROTECTION.optionA("Acme")).toBe(text.replaceAll("{operator}", "Acme"));
    expect(PROTECTION.optionA("Acme")).not.toContain("{operator}");
    // The sentence that only Decision 2's publication step may add is not there.
    expect(PROTECTION.optionA("Acme")).not.toContain("public record");
  });

  test("metadata starts with the spec's §4 table, row for row", () => {
    expect(rows001.length).toBeGreaterThanOrEqual(7);
    expect(PROTECTION.metadata.slice(0, rows001.length).map((m) => [m.what, m.where, m.why])).toEqual(rows001);
  });

  test("Option B's word never appears: the texts never say the operator can't read mail in transit", () => {
    expect(PROTECTION.optionA("Acme")).not.toMatch(/can't read your mail/);
    expect(PROTECTION.devices("Acme")).not.toMatch(/can't read your mail/);
  });
});

describe("PROTECTION: spec 002 §5, the promise amended", () => {
  test("devices is the spec's \"Devices you keep unlocked.\" text, with {operator} filled in", () => {
    const text = blockquoteAfter(spec002, "**Devices you keep unlocked.**");
    expect(text).toContain("{operator}");
    expect(text).toContain("A device you keep unlocked opens your mail without your security key");
    expect(PROTECTION.devices("{operator}")).toBe(text);
    expect(PROTECTION.devices("Acme")).toBe(text.replaceAll("{operator}", "Acme"));
    expect(PROTECTION.devices("Acme")).not.toContain("{operator}");
  });

  test("metadata goes on with the rows spec 002 §5 adds, row for row, and nothing else", () => {
    expect(rows002.length).toBe(3);
    expect(PROTECTION.metadata.slice(rows001.length).map((m) => [m.what, m.where, m.why])).toEqual(rows002);
    expect(PROTECTION.metadata.length).toBe(rows001.length + rows002.length);
  });

  test("R11, D33: spec 002's words never assume a phone, a face scan or a fingerprint", () => {
    // (Spec 001's own §4 row "So the phone can buzz" predates R11; it is compared with that spec as it is.)
    const words = [PROTECTION.devices("Acme"), ...PROTECTION.metadata.slice(rows001.length).map((m) => `${m.what} ${m.where} ${m.why}`)].join(" ");
    expect(words).not.toMatch(/\b(?:phone|Face ID|fingerprint)\b/i);
  });
});
