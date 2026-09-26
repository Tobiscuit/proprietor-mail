// The API that specs/001-inbox-module/plan.md promises, by the names
// src/index.ts first declared as stubs. It holds for the stub and for S3's
// implementation alike, so this package always has a test: without one,
// `vitest run` finds no test files and exits 1. S3 may add exports; removing
// one of these breaks the plan, and this test.
import { describe, expect, test } from "vitest";
import * as api from "../src/index";

const functions = ["buildMime", "sesRawMailer"] as const;

const errors = ["NotImplemented", "InvalidMessage", "SendRejected"] as const;

describe("@platform-mail/outbound exports the plan's API", () => {
  test.each(functions)("%s is an exported function", (name) => {
    expect(typeof api[name]).toBe("function");
  });

  test.each(errors)("%s is an exported Error subclass", (name) => {
    expect(api[name].prototype).toBeInstanceOf(Error);
  });

  test("IMPLEMENTED is a boolean and LIMITS holds both numbers", () => {
    expect(typeof api.IMPLEMENTED).toBe("boolean");
    expect(api.LIMITS).toMatchObject({ maxRecipients: expect.any(Number), maxRawBytes: expect.any(Number) });
  });
});
