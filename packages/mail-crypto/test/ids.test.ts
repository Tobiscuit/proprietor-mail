// S1a: newId, keyIdOf, fingerprint (contracts/envelope-v1.md "Identifiers", "The mailbox key pair").
import { describe, expect, test } from "vitest";
import { fingerprint, keyIdOf, newId, type IdPrefix } from "../src/index";
import { crockfordToBytes, hex, sha256 } from "./reference";

describe("S1a newId", () => {
  test.each(["mbx", "msg", "drf", "wrp", "dev", "chl"] as const)(
    "newId(%s) is <prefix>_<26 lowercase Crockford base32 characters of 16 bytes>",
    (prefix) => {
      const id = newId(prefix);
      const [p, suffix, ...rest] = id.split("_");
      expect(p).toBe(prefix);
      expect(rest).toEqual([]);
      expect(suffix).toMatch(/^[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
      // 26 symbols carry 130 bits; the number they spell must fit in 16 bytes.
      expect(crockfordToBytes(suffix!, 16)).not.toBeNull();
    },
  );

  test("newId draws fresh randomness every call", () => {
    const ids = new Set(Array.from({ length: 2000 }, () => newId("msg")));
    expect(ids.size).toBe(2000);
  });

  test("newId uses the whole 128 bits (every first symbol 0-7 appears, none above)", () => {
    const firsts = new Set(Array.from({ length: 2000 }, () => newId("drf").slice(4, 5)));
    expect([...firsts].sort().join("")).toBe("01234567");
  });

  test("newId refuses a prefix the contract does not define", () => {
    expect(() => newId("usr" as IdPrefix)).toThrow(TypeError);
  });
});

describe("S1a keyIdOf", () => {
  test("keyId = lowercase hex of the first 16 bytes of SHA-256(public key)", async () => {
    const pk = crypto.getRandomValues(new Uint8Array(32));
    const expected = hex((await sha256(pk)).slice(0, 16));
    expect(await keyIdOf(pk)).toBe(expected);
  });

  test("known answer: SHA-256 of 32 zero bytes", async () => {
    expect(await keyIdOf(new Uint8Array(32))).toBe("66687aadf862bd776c8fc18b8e9f8e20");
  });

  test("keyIdOf refuses a public key that is not 32 bytes", async () => {
    await expect(keyIdOf(new Uint8Array(31))).rejects.toThrow(TypeError);
    await expect(keyIdOf(new Uint8Array(33))).rejects.toThrow(TypeError);
  });
});

describe("S1a fingerprint", () => {
  test("fingerprint = keyId in groups of four", () => {
    expect(fingerprint("3f9a07c1d2e3f4a5b6c7d8e9fa0b1c2d")).toBe("3f9a 07c1 d2e3 f4a5 b6c7 d8e9 fa0b 1c2d");
  });

  test("fingerprint refuses anything that is not a keyId", () => {
    expect(() => fingerprint("3F9A07C1D2E3F4A5B6C7D8E9FA0B1C2D")).toThrow(TypeError);
    expect(() => fingerprint("3f9a")).toThrow(TypeError);
    expect(() => fingerprint("3f9a07c1d2e3f4a5b6c7d8e9fa0b1c2g")).toThrow(TypeError);
  });
});
