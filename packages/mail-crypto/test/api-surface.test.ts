// The API that contracts/envelope-v1.md promises, by the names src/index.ts
// first declared as stubs. It holds for the stub and for S1's implementation
// alike, so this package always has a test: without one, `vitest run` finds no
// test files and exits 1. S1 may add exports; removing one of these breaks the
// contract, and this test.
import { describe, expect, test } from "vitest";
import * as api from "../src/index";

const functions = [
  // both sides
  "newId",
  "keyIdOf",
  "fingerprint",
  // the Worker
  "sealMessage",
  // the browser
  "generateMailboxKey",
  "openHeader",
  "openBody",
  "sealDraft",
  "openDraft",
  "publicKeyMatches",
  "prfInput",
  "wrapPrivateKey",
  "unwrapPrivateKey",
  "newRecoveryKey",
  "parseRecoveryKey",
  // contracts/device-v1.md Part A, the browser's half (slice D1)
  "deriveFactorKey",
  "factorPublicKey",
  "generateSigningKey",
  "generateUnlockKey",
  "isDeviceSigningKey",
  "isDeviceUnlockKey",
  "signDeviceProof",
  "sealKey",
  "openKeySeal",
  "bindingKey",
  "bindingTag",
  "verifyBindingTag",
  "openChallenge",
] as const;

const errors = ["NotImplemented", "DecryptionFailed", "RecoveryKeyTypo"] as const;

describe("@proprietor/mail-crypto exports the contract's API", () => {
  test.each(functions)("%s is an exported function", (name) => {
    expect(typeof api[name]).toBe("function");
  });

  test.each(errors)("%s is an exported Error subclass", (name) => {
    expect(api[name].prototype).toBeInstanceOf(Error);
  });

  test("the device-v1 lengths: key seals of 142 and 109 bytes, challenges of 80", () => {
    expect(api.KEY_SEAL_BYTES).toEqual({ device: 142, factor: 109, successor: 109 });
    expect(api.CHALLENGE_BYTES).toBe(80);
  });

  test("IMPLEMENTED is a boolean and ENVELOPE_VERSION is 1", () => {
    expect(typeof api.IMPLEMENTED).toBe("boolean");
    expect(api.ENVELOPE_VERSION).toBe(1);
  });
});
