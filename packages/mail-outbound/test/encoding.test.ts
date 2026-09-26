import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";
import {
  base64,
  encodedWords,
  foldHeader,
  foldUnstructured,
  quotedPrintable,
  rfc2231Params,
  rfc5322Date,
} from "../src/encoding";

const lines = (s: string) => s.split("\r\n");

describe("base64", () => {
  // RFC 4648 §10 test vectors.
  it.each([
    ["", ""],
    ["f", "Zg=="],
    ["fo", "Zm8="],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg=="],
    ["fooba", "Zm9vYmE="],
    ["foobar", "Zm9vYmFy"],
  ])("RFC 4648 vector %j", (input, expected) => {
    expect(base64(new TextEncoder().encode(input))).toBe(expected);
  });

  it("matches Node's encoder on every byte value, unwrapped and wrapped at 76", () => {
    const bytes = new Uint8Array(1000).map((_, i) => (i * 7 + 3) & 0xff);
    const reference = Buffer.from(bytes).toString("base64");
    expect(base64(bytes)).toBe(reference);
    const wrapped = base64(bytes, 76);
    expect(wrapped.replace(/\r\n/g, "")).toBe(reference);
    const physical = lines(wrapped);
    expect(physical.slice(0, -1).every((l) => l.length === 76)).toBe(true);
    expect(physical.at(-1)!.length).toBeLessThanOrEqual(76);
  });
});

describe("quotedPrintable (RFC 2045 §6.7)", () => {
  it.each([
    ["", ""],
    ["abc", "abc"],
    ["a=b", "a=3Db"],
    ["é", "=C3=A9"],
    ["line \nnext", "line=20\r\nnext"],
    ["tab\t", "tab=09"],
    ["a\r\nb\rc\nd", "a\r\nb\r\nc\r\nd"],
    ["\u0000\u007f", "=00=7F"],
    ["ends with newline\n", "ends with newline\r\n"],
  ])("%j", (input, expected) => {
    expect(quotedPrintable(input)).toBe(expected);
  });

  it("soft-breaks long lines at 76 characters including the '='", () => {
    const out = quotedPrintable("x".repeat(200));
    for (const l of lines(out)) expect(l.length).toBeLessThanOrEqual(76);
    expect(out.replace(/=\r\n/g, "")).toBe("x".repeat(200));
  });

  it("never splits an =XX escape across a soft break", () => {
    const out = quotedPrintable("x".repeat(74) + "é");
    expect(lines(out)).toEqual(["x".repeat(74) + "=", "=C3=A9"]);
  });
});

describe("encodedWords (RFC 2047, B encoding)", () => {
  const decode = (word: string) => {
    const m = /^=\?UTF-8\?B\?([A-Za-z0-9+/=]*)\?=$/.exec(word);
    expect(m).not.toBeNull();
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(m![1]!, "base64"));
  };

  it("encodes a short name as one word", () => {
    expect(encodedWords("Ana Pérez")).toEqual(["=?UTF-8?B?QW5hIFDDqXJleg==?="]);
  });

  it("keeps every word within 64 characters and every word a whole number of characters", () => {
    const text = "😀".repeat(30) + " Pérez " + "中文".repeat(40);
    const words = encodedWords(text);
    expect(words.length).toBeGreaterThan(1);
    for (const w of words) expect(w.length).toBeLessThanOrEqual(64);
    // fatal decoding throws if a word ended in the middle of a UTF-8 sequence
    expect(words.map(decode).join("")).toBe(text);
  });
});

describe("foldHeader", () => {
  it("keeps short headers on one line and always puts the first token on the first line", () => {
    expect(foldHeader("To", ["a@example.com"])).toBe("To: a@example.com\r\n");
    const long = "x".repeat(100);
    expect(foldHeader("To", [long, "b"])).toBe(`To: ${long}\r\n b\r\n`);
  });

  it("folds between tokens so lines stay within 76 characters", () => {
    const tokens = Array.from({ length: 20 }, (_, i) => `<id${i}.abcdefgh@mail.example.com>`);
    const folded = foldHeader("References", tokens);
    expect(folded.endsWith("\r\n")).toBe(true);
    const physical = lines(folded.slice(0, -2));
    expect(physical.length).toBeGreaterThan(1);
    for (const l of physical) expect(l.length).toBeLessThanOrEqual(76);
    // unfolding (RFC 5322 §2.2.3: remove each CRLF that precedes WSP) gives the tokens back
    expect(folded.replace(/\r\n /g, " ")).toBe(`References: ${tokens.join(" ")}\r\n`);
  });
});

describe("foldUnstructured", () => {
  it("folds only before whitespace and unfolds to the exact value", () => {
    const value = "Your appointment on Monday,  28 September 2026 at 09:30 has been confirmed by our team";
    const folded = foldUnstructured("Subject", value);
    for (const l of lines(folded.slice(0, -2))) expect(l.length).toBeLessThanOrEqual(76);
    expect(folded.replace(/\r\n(?=[ \t])/g, "")).toBe(`Subject: ${value}\r\n`);
  });

  it("writes an empty value as a bare field name", () => {
    expect(foldUnstructured("Subject", "")).toBe("Subject:\r\n");
  });
});

describe("rfc2231Params", () => {
  it("quotes a short ASCII value", () => {
    expect(rfc2231Params("filename", "report.pdf")).toEqual(['filename="report.pdf"']);
  });

  it("percent-encodes non-ASCII values and splits them into numbered sections", () => {
    const params = rfc2231Params("filename", "Factura señor Pérez — septiembre 2026.pdf");
    expect(params).toEqual([
      "filename*0*=UTF-8''Factura%20se%C3%B1or%20P%C3%A9rez%20%E2%80%94%20septiem",
      "filename*1*=bre%202026.pdf",
    ]);
  });

  it("uses a single unnumbered section when it fits", () => {
    expect(rfc2231Params("filename", "résumé.pdf")).toEqual(["filename*=UTF-8''r%C3%A9sum%C3%A9.pdf"]);
  });

  it("encodes values that a quoted-string would have to escape", () => {
    expect(rfc2231Params("name", 'say "hi".txt')).toEqual(["name*=UTF-8''say%20%22hi%22.txt"]);
  });
});

describe("rfc5322Date", () => {
  it("formats UTC with a numeric zone", () => {
    expect(rfc5322Date(new Date("2026-09-26T15:04:05Z"))).toBe("Sat, 26 Sep 2026 15:04:05 +0000");
    expect(rfc5322Date(new Date("2026-01-01T00:00:00.999Z"))).toBe("Thu, 01 Jan 2026 00:00:00 +0000");
  });
});
