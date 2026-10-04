// PROTECTION (contracts/mail-client-v1.md "The promise, as data"): the texts the dashboard shows are
// the spec's, read from specs/001-inbox-module/spec.md, so no screen ever claims more than the spec.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { PROTECTION } from "../src/index";

const spec = readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), "../../../specs/001-inbox-module/spec.md"), "utf8");

/** The blockquote under a bold heading, joined with spaces. */
function blockquoteAfter(heading: string): string {
  const start = spec.indexOf(heading);
  expect(start, heading).toBeGreaterThan(-1);
  const lines: string[] = [];
  for (const line of spec.slice(start + heading.length).split("\n").slice(1)) {
    if (!line.startsWith("> ")) break;
    lines.push(line.slice(2).trim());
  }
  return lines.join(" ");
}

/** The rows of the table under a section heading, until a blank line. */
function tableAfter(heading: string): string[][] {
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

describe("PROTECTION", () => {
  test("optionA is the spec's Option A text, with {operator} filled in", () => {
    const text = blockquoteAfter("**Option A — encrypted with your key (structural).**");
    expect(text).toContain("{operator}");
    expect(PROTECTION.optionA("{operator}")).toBe(text);
    expect(PROTECTION.optionA("Acme")).toBe(text.replaceAll("{operator}", "Acme"));
    expect(PROTECTION.optionA("Acme")).not.toContain("{operator}");
    // The sentence that only Decision 2's publication step may add is not there.
    expect(PROTECTION.optionA("Acme")).not.toContain("public record");
  });

  test("metadata is the spec's §4 table, row for row", () => {
    const rows = tableAfter("## 4. What the platform can see, even under Option A");
    expect(rows.length).toBeGreaterThanOrEqual(7);
    expect(PROTECTION.metadata.map((m) => [m.what, m.where, m.why])).toEqual(rows);
  });

  test("Option B's word never appears: the texts never say the operator can't read mail in transit", () => {
    expect(PROTECTION.optionA("Acme")).not.toMatch(/can't read your mail/);
  });
});
