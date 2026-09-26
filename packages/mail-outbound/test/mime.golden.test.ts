import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildMime, type ComposedMessage } from "../src/index";
import { ALTERNATIVE, MIXED, TEXT_ONLY, goldenOptions } from "./fixtures";

/**
 * The golden files were written line by line, independently of this package
 * (only their base64 pieces were computed, with Python's base64 module), so a
 * byte-for-byte match checks the builder against a format fixed in advance,
 * not against its own earlier output. They are CRLF files: keep them binary.
 */
const golden = (name: string) =>
  new TextDecoder().decode(readFileSync(new URL(`./golden/${name}.eml`, import.meta.url)));

describe("buildMime: one golden file per MIME shape", () => {
  const cases: [string, ComposedMessage][] = [
    ["text-only", TEXT_ONLY],
    ["alternative", ALTERNATIVE],
    ["mixed", MIXED],
  ];

  it.each(cases)("%s.eml", (name, msg) => {
    const built = buildMime(msg, goldenOptions());
    expect(new TextDecoder().decode(built.raw)).toBe(golden(name));
    expect(built.messageId).toBe("000102030405060708090a0b0c0d0e0f@operator.example");
  });

  it("returns to + cc + bcc as the envelope, lower-cased and de-duplicated", () => {
    expect(buildMime(TEXT_ONLY, goldenOptions()).recipients).toEqual([
      "ana@example.com",
      "bo@example.org",
      "pat@example.net",
      "hidden-bcc@example.com",
    ]);
  });
});
