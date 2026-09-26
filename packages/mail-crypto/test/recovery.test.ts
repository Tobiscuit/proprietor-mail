// S1e: newRecoveryKey, parseRecoveryKey (contracts/envelope-v1.md "The recovery key as people see it").
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  generateMailboxKey,
  newId,
  newRecoveryKey,
  parseRecoveryKey,
  RecoveryKeyTypo,
  unwrapPrivateKey,
  wrapPrivateKey,
} from "../src/index";
import { sha256 as sha256Sync } from "../src/sha256";
import { crockfordToBytes, hex, sha256 } from "./reference";

const DISPLAY = /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}$/;

/** The contract's parsing rules, read independently: upper-case, drop spaces and hyphens, I/L→1, O→0. */
function normalize(display: string): string {
  return display.replace(/[\s-]/g, "").toUpperCase().replace(/[IL]/g, "1").replace(/O/g, "0");
}

describe("S1e synchronous SHA-256 (for the checksum; Web Crypto has no synchronous digest)", () => {
  test("matches Web Crypto for every length from 0 to 300 bytes", async () => {
    for (let n = 0; n <= 300; n++) {
      const data = crypto.getRandomValues(new Uint8Array(n));
      expect(hex(sha256Sync(data))).toBe(hex(await sha256(data)));
    }
  });

  test('known answer: SHA-256("abc") (FIPS 180-4)', () => {
    expect(hex(sha256Sync(new TextEncoder().encode("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("S1e recovery key display", () => {
  test("55 upper-case Crockford symbols of secret || SHA-256(secret)[0..2], in 11 groups of 5", async () => {
    const { secret, display } = newRecoveryKey();
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
    expect(display).toMatch(DISPLAY);
    const bytes = crockfordToBytes(display.replaceAll("-", ""), 34);
    expect(bytes).not.toBeNull();
    expect(hex(bytes!)).toBe(hex(secret) + hex((await sha256(new Uint8Array(secret))).subarray(0, 2)));
  });

  test("every call makes a new secret", () => {
    const a = newRecoveryKey();
    const b = newRecoveryKey();
    expect(hex(a.secret)).not.toBe(hex(b.secret));
    expect(a.display).not.toBe(b.display);
  });

  test("display round-trips", () => {
    for (let i = 0; i < 500; i++) {
      const { secret, display } = newRecoveryKey();
      expect(hex(parseRecoveryKey(display))).toBe(hex(secret));
    }
  });

  test("lower case, spaces, missing or extra separators and I/L/O are accepted", () => {
    let key = newRecoveryKey();
    while (!key.display.includes("1") || !key.display.includes("0")) key = newRecoveryKey();
    const { secret, display } = key;
    const variants = [
      display.toLowerCase(),
      display.replaceAll("-", " "),
      display.replaceAll("-", ""),
      ` ${display.replaceAll("-", "  ")}\n`,
      display.replaceAll("-", "").replace(/(.{4})/g, "$1-"),
      display.replaceAll("1", "I"),
      display.replaceAll("1", "l"),
      display.replaceAll("1", "L"),
      display.replaceAll("1", "i"),
      display.replaceAll("0", "O"),
      display.replaceAll("0", "o"),
    ];
    for (const v of variants) expect(hex(parseRecoveryKey(v))).toBe(hex(secret));
  });

  test("every single-character substitution is a RecoveryKeyTypo, or a different secret whose wrap fails", async () => {
    const mailboxId = newId("mbx");
    const { privateKey } = await generateMailboxKey();
    const { secret, display } = newRecoveryKey();
    const wrap = await wrapPrivateKey(privateKey, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
    const candidates = [..."0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz- ._!#*é"];
    let typos = 0;
    let aliases = 0;
    let collisions = 0;
    for (let i = 0; i < display.length; i++) {
      for (const c of candidates) {
        if (c === display[i]) continue;
        const changed = display.slice(0, i) + c + display.slice(i + 1);
        if (normalize(changed) === normalize(display)) {
          aliases++; // lower case, I/L for 1, O for 0, space for hyphen: the same key
          expect(hex(parseRecoveryKey(changed))).toBe(hex(secret));
          continue;
        }
        let parsed: Uint8Array;
        try {
          parsed = parseRecoveryKey(changed);
        } catch (e) {
          expect(e).toBeInstanceOf(RecoveryKeyTypo);
          typos++;
          continue;
        }
        collisions++; // the 16-bit checksum matched by chance: must not be the same secret, and must not unwrap
        expect(hex(parsed)).not.toBe(hex(secret));
        await expect(unwrapPrivateKey(wrap, { mailboxId, secret: parsed })).rejects.toBeInstanceOf(DecryptionFailed); // pragma: allowlist secret (a test variable)
      }
    }
    expect(typos + aliases + collisions).toBe(display.length * candidates.length - display.length);
    expect(aliases).toBeGreaterThan(0);
    expect(typos).toBeGreaterThan(4000);
  });

  test("a checksum mismatch, a wrong length, a U, a set leading pad bit, or non-ASCII is a RecoveryKeyTypo", () => {
    const { display } = newRecoveryKey();
    const flat = display.replaceAll("-", "");
    // Last symbol carries only checksum bits: any other value is a checksum mismatch.
    const last = flat.at(-1)!;
    const otherLast = last === "0" ? "1" : "0";
    const bad = [
      flat.slice(0, -1) + otherLast,
      flat.slice(0, -1),
      flat + "0",
      flat.slice(0, 10) + "U" + flat.slice(11),
      "Z" + flat.slice(1), // first symbol above 3 sets one of the 3 leading pad bits
      flat.slice(0, 10) + "ı" + flat.slice(11), // dotless i: not an accepted alias
      "",
    ];
    for (const b of bad) expect(() => parseRecoveryKey(b)).toThrow(RecoveryKeyTypo);
  });

  test("a recovery wrap opens with the secret parsed back from its display", async () => {
    const mailboxId = newId("mbx");
    const { publicKey, privateKey } = await generateMailboxKey();
    const { secret, display } = newRecoveryKey();
    const wrap = await wrapPrivateKey(privateKey, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
    const typed = display.toLowerCase().replaceAll("-", " ");
    const unlocked = await unwrapPrivateKey(wrap, { mailboxId, secret: parseRecoveryKey(typed) }); // pragma: allowlist secret (a function call)
    expect(unlocked.keyId).toBe(publicKey.keyId);
  });
});
