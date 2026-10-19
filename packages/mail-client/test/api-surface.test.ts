// The API contracts/mail-client-v1.md promises, by name. It holds for the stub
// and for S6a's implementation alike; removing one of these breaks the
// contract and this test. S6a may add exports.
import { describe, expect, test } from "vitest";
import * as api from "../src/index";

const functions = [
  "passkeySupport",
  "startEnrollment",
  "unlockWithPasskey",
  "unlockWithRecoveryKey",
  "pageNonce",
  "renderBody",
  "showInFrame",
  "threadsOf",
  "searchMessages",
  "replyTo",
  "forwardOf",
  "parseAddressList",
  "encodeSendForm",
  "decodeSendForm",
  // spec 002, kept devices (slice D1)
  "canKeepDevices",
  "indexedDbDeviceStore",
  "memoryDeviceStore",
  "resumeDevice",
] as const;

const errors = [
  "MailClientError",
  "NotImplemented",
  "UnsupportedBrowser",
  "PrfUnavailable",
  "PasskeyCancelled",
  "NoMatchingWrap",
  "KeySubstitutionDetected",
  "RecoveryKeyTypo",
  "WrongRecoveryKey",
  "MailboxLocked",
  "UndecryptableBody",
  // spec 002 (slice D1)
  "DeviceRemoved",
  "StorageUnavailable",
  "FactorExpired",
  "MailboxChanged",
  "StaleFactor",
  "NoRecoveryFactor",
  "InvalidDeviceLabel",
  "InvalidChallenge",
  // D1's round 2 (contracts/device-v1.md Part C as amended on 2026-10-19)
  "FlaggedRecipient",
] as const;

describe("@proprietor/mail-client exports the contract's API", () => {
  test.each(functions)("%s is an exported function", (name) => {
    expect(typeof api[name]).toBe("function");
  });

  test.each(errors)("%s is an Error subclass whose name is stable", (name) => {
    const E = api[name];
    expect(E.prototype).toBeInstanceOf(Error);
    expect(new E("x").name).toBe(name);
  });

  test("PROTECTION and IMPLEMENTED exist", () => {
    expect(typeof api.PROTECTION.optionA).toBe("function");
    expect(typeof api.PROTECTION.devices).toBe("function");
    expect(typeof api.IMPLEMENTED).toBe("boolean");
  });

  test("the spec 002 constants: K5's fields, the lock settings, the FreshFactor's 2 minutes, the one database", () => {
    expect(api.KEPT_DEVICE_FIELDS.length).toBe(11);
    expect(api.LOCK_AFTER_MS).toEqual({ "right-away": 0, "15-minutes": 900_000, "1-hour": 3_600_000, "sign-out": Infinity });
    expect(api.FRESH_FACTOR_MS).toBe(120_000);
    expect(api.DEVICE_DATABASE).toEqual({ name: "proprietor-mail", version: 1, store: "kept-devices" });
  });
});
