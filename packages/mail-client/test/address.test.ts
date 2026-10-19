// isAddress: the address rule of S6a (one "@", a non-empty local part, a domain with a dot inside it,
// none of whitespace, @, <, >, ", (, ), comma, ;, :, [, ], \), checked in linear time. The pattern it
// replaces backtracks polynomially (CodeQL js/polynomial-redos), and decodeSendForm runs on the
// server over strings a form supplies. The set it accepts is the old pattern's, exactly.
import { describe, expect, test } from "vitest";
import { isAddress, parseAddressList } from "../src/compose";

const OLD = /^[^\s@<>"(),;:[\]\\]+@[^\s@<>"(),;:[\]\\]+\.[^\s@<>"(),;:[\]\\]+$/;
const OLD_NAMED = /^(?:"((?:[^"\\]|\\.)*)"|([^<]*?))\s*<([^<>]*)>$/;

/** Test data, not keys: Math.random is the right tool (crypto randomness taken modulo is biased). */
function randomString(alphabet: string[], min: number, max: number): string {
  const n = min + Math.floor(Math.random() * (max - min + 1));
  return Array.from({ length: n }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
}

/** S6a's parseAddressList on one token, with its own two patterns. */
function oldParseToken(token: string) {
  const named = OLD_NAMED.exec(token);
  const name = named ? (named[1] !== undefined ? named[1].replace(/\\(.)/g, "$1") : named[2]!.trim()) : "";
  const address = named ? named[3]!.trim() : token;
  return OLD.test(address) ? { addresses: [{ name, address }], invalid: [] } : { addresses: [], invalid: [token] };
}

describe("isAddress", () => {
  test("accepts and refuses exactly what the old pattern did, on every string over a small alphabet, and on random longer ones", () => {
    const alphabet = ["a", ".", "@", "!", " ", "<", "é", " "];
    const strings: string[] = [""];
    let level = [""];
    for (let length = 1; length <= 6; length++) {
      level = level.flatMap((x) => alphabet.map((c) => x + c));
      for (const x of level) strings.push(x);
    }
    for (let i = 0; i < 5000; i++) {
      strings.push(randomString(alphabet, 7, 26));
    }
    for (const s of strings) expect(isAddress(s), JSON.stringify(s)).toBe(OLD.test(s));
  });

  test("ordinary addresses", () => {
    for (const ok of ["ana@example.com", "a.b+c@mail.example.org", "x@y.z", "user@sub.domain.example.com", "a@b..c", "a@b.c."]) expect(isAddress(ok), ok).toBe(true);
    for (const bad of ["", "ana", "@example.com", "ana@", "ana@example", "ana@.com", "ana@com.", "a@b@c.d", "a b@c.d", "<a@b.c>", "a@b.c,d@e.f"]) expect(isAddress(bad), bad).toBe(false);
  });

  test("linear: the input that made the old pattern backtrack is answered at once", () => {
    const hostile = "!@!" + "!.".repeat(50_000);
    const start = performance.now();
    expect(isAddress(hostile + " ")).toBe(false);
    expect(performance.now() - start).toBeLessThan(100);
  });

  test("parseAddressList reads every token as before, names included, where the old name pattern also backtracked", () => {
    const alphabet = ["a", " ", '"', "\\", "<", ">", "@", ".", "b"];
    const inputs: string[] = [];
    let level = [""];
    for (let length = 1; length <= 5; length++) {
      level = level.flatMap((s) => alphabet.map((c) => s + c));
      for (const x of level) inputs.push(x);
    }
    for (let i = 0; i < 20_000; i++) {
      inputs.push(randomString(alphabet, 6, 29));
    }
    for (const input of inputs) {
      const trimmed = input.trim();
      if (trimmed.length === 0) continue;
      expect(parseAddressList(input), JSON.stringify(input)).toEqual(oldParseToken(trimmed));
    }
    const start = performance.now();
    parseAddressList("a" + " ".repeat(20_000) + "x");
    expect(performance.now() - start).toBeLessThan(100);
  });
});
