// Round 3, contracts/device-v1.md A10 and contracts/action-descriptor-v1.md "Format": RFC 8785
// (JSON Canonicalization Scheme) for the values action descriptors and requests hold: plain objects,
// arrays, strings, safe integers and null. Anything else is refused, lone surrogates included
// (RFC 8785 §3.2.2.2: a compliant implementation terminates with an error on one).
import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { canonicalJson, requestDigest } from "../src/index";

const sha256b64u = (text: string) => createHash("sha256").update(Buffer.from(text, "utf8")).digest("base64url");

describe("RFC 8785 for descriptors and requests", () => {
  test("RFC 8785 §3.2.3's sorting sample: member names sorted by UTF-16 code units", () => {
    const sample = {
      "€": "Euro Sign",
      "\r": "Carriage Return",
      "דּ": "Hebrew Letter Dalet With Dagesh",
      "1": "One",
      "😀": "Emoji: Grinning Face",
      "\u0080": "Control",
      "ö": "Latin Small Letter O With Diaeresis",
    };
    expect(canonicalJson(sample)).toBe(
      '{"\\r":"Carriage Return","1":"One","\u0080":"Control","ö":"Latin Small Letter O With Diaeresis",' +
        '"€":"Euro Sign","😀":"Emoji: Grinning Face","דּ":"Hebrew Letter Dalet With Dagesh"}',
    );
  });

  test("members are sorted by name, never by the engine's property order (integer-like names come first in JavaScript)", () => {
    expect(canonicalJson({ a: 3, "9": 2, "10": 1 })).toBe('{"10":1,"9":2,"a":3}');
  });

  test("objects are sorted at every depth; arrays keep their order", () => {
    expect(canonicalJson({ b: [{ z: 1, y: [2, 1] }, "x", null], a: {} })).toBe('{"a":{},"b":[{"y":[2,1],"z":1},"x",null]}');
    expect(canonicalJson([])).toBe("[]");
    expect(canonicalJson(Object.assign(Object.create(null) as object, { k: "v" }))).toBe('{"k":"v"}');
  });

  test("strings: only the control characters, the quote and the backslash are escaped (RFC 8785 §3.2.2.2)", () => {
    const input = "\u0000\b\t\n\u000b\f\r\u001f\"\\/\u007f\u0085\u2028\u2029é🚚";
    expect(canonicalJson(input)).toBe('"\\u0000\\b\\t\\n\\u000b\\f\\r\\u001f\\"\\\\/\u007f\u0085\u2028\u2029é🚚"');
  });

  test("numbers: safe integers as ECMAScript writes them; -0 is 0", () => {
    expect(canonicalJson([0, 1, -1, 1792627200, Number.MAX_SAFE_INTEGER, -Number.MAX_SAFE_INTEGER, -0])).toBe(
      "[0,1,-1,1792627200,9007199254740991,-9007199254740991,0]",
    );
  });

  test.each([
    ["a fraction", 0.5],
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["an integer beyond 2^53 - 1", 2 ** 53],
    ["1e21", 1e21],
    ["true", true],
    ["false", false],
    ["undefined", undefined],
    ["a bigint", 1n],
    ["a symbol", Symbol("s")],
    ["a function", () => 1],
    ["a Date", new Date(0)],
    ["bytes", new Uint8Array(1)],
    ["a Map", new Map()],
    ["a class instance", new (class Thing {})()],
    ["a lone high surrogate", "a\ud800b"],
    ["a lone low surrogate", "a\udc00b"],
    ["a reversed surrogate pair", "\ude00\ud83d"],
  ])("refuses %s, at the top and nested in an object and an array", (_, value) => {
    expect(() => canonicalJson(value)).toThrow(TypeError);
    expect(() => canonicalJson({ ok: "x", nested: value })).toThrow(TypeError);
    expect(() => canonicalJson(["x", value])).toThrow(TypeError);
  });

  test("refuses a member name with a lone surrogate, an array with a hole, and a cycle", () => {
    expect(() => canonicalJson({ "\ud800": "x" })).toThrow(TypeError);
    expect(() => canonicalJson([1, , 3])).toThrow(TypeError); // eslint-disable-line no-sparse-arrays
    const cycle: Record<string, unknown> = { a: "x" };
    cycle.self = cycle;
    expect(() => canonicalJson(cycle)).toThrow(TypeError);
    const loop: unknown[] = [];
    loop.push(loop);
    expect(() => canonicalJson(loop)).toThrow(TypeError);
  });

  test("the same value reached twice without a cycle is serialized twice", () => {
    const shared = { k: "v" };
    expect(canonicalJson({ a: shared, b: [shared] })).toBe('{"a":{"k":"v"},"b":[{"k":"v"}]}');
  });
});

describe("A10 requestDigest: base64url SHA-256 of the request's RFC 8785 bytes", () => {
  test("the digest of the request's canonical UTF-8, whatever order its members were written in", async () => {
    const a = { rotation: { from: "k1", tags: [], seals: [] }, deviceIds: ["dev_b", "dev_a"] };
    const b = { deviceIds: ["dev_b", "dev_a"], rotation: { seals: [], tags: [], from: "k1" } };
    const canonical = '{"deviceIds":["dev_b","dev_a"],"rotation":{"from":"k1","seals":[],"tags":[]}}';
    expect(canonicalJson(a)).toBe(canonical);
    expect(await requestDigest(a)).toBe(sha256b64u(canonical));
    expect(await requestDigest(b)).toBe(sha256b64u(canonical));
    expect(await requestDigest(a)).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test("labels outside ASCII are hashed as their UTF-8", async () => {
    const request = { device: { id: "dev_x", label: "Büro 🚚" }, seal: null };
    expect(await requestDigest(request)).toBe(sha256b64u('{"device":{"id":"dev_x","label":"Büro 🚚"},"seal":null}'));
  });

  test("an array order is part of the request", async () => {
    expect(await requestDigest({ deviceIds: ["a", "b"] })).not.toBe(await requestDigest({ deviceIds: ["b", "a"] }));
  });

  test("A10: a request holds only strings, null, arrays and objects; a number anywhere is refused", async () => {
    await expect(requestDigest({ n: 1 })).rejects.toBeInstanceOf(TypeError);
    await expect(requestDigest({ list: [{ deep: 0 }] })).rejects.toBeInstanceOf(TypeError);
  });

  test("a request is an object: an array, a string or null at the top is refused", async () => {
    for (const value of [[], "x", null]) await expect(requestDigest(value as never)).rejects.toBeInstanceOf(TypeError);
  });
});
