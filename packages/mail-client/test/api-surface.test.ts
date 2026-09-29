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
    expect(typeof api.IMPLEMENTED).toBe("boolean");
  });
});
