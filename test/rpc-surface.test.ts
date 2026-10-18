import { describe, expect, it } from "vitest";
import { MailAdmin } from "../src/admin";

// What an entrypoint serves over Workers RPC is every function on its
// prototype, TypeScript `private` methods included; only `#private` ones are
// not served. MailService's surface is checked against SESSION_NEEDS
// (test/device-sessions.test.ts); MailAdmin's is fixed here.

/** The public methods a WorkerEntrypoint class serves over RPC: the functions on its own prototype. */
function rpcMethods(cls: { prototype: object }): string[] {
  return Object.getOwnPropertyNames(cls.prototype).filter((n) => n !== "constructor" && typeof Object.getOwnPropertyDescriptor(cls.prototype, n)?.value === "function");
}

describe("MailAdmin's RPC surface (plan.md §4, tasks.md S2i)", () => {
  it("serves suspend, resume and setDelivery, and nothing else", () => {
    expect(rpcMethods(MailAdmin).sort()).toEqual(["resume", "setDelivery", "suspend"]);
  });
});
