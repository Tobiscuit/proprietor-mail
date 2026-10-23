import { describe, expect, it } from "vitest";
import { MailAdmin } from "../src/admin";
import { MailService } from "../src/service";

// What an entrypoint serves over Workers RPC is every function on its
// prototype, TypeScript `private` methods included; only `#private` ones are
// not served. A helper that takes a callback and hands it the Mailbox would,
// if served, let a caller skip the public methods' checks.

/** The methods a WorkerEntrypoint class serves over RPC: the functions on its own prototype. */
function rpcMethods(cls: { prototype: object }): string[] {
  return Object.getOwnPropertyNames(cls.prototype).filter((n) => n !== "constructor" && typeof Object.getOwnPropertyDescriptor(cls.prototype, n)?.value === "function");
}

describe("what the Mail Worker serves over RPC", () => {
  it("MailService: the contract's methods (contracts/mail-service-v1.md and device-v1.md Part B), and no helper", () => {
    expect(rpcMethods(MailService).sort()).toEqual(
      [
        "addWrap",
        "audit",
        "body",
        "challenge",
        "deleteDraft",
        "drafts",
        "enroll",
        "list",
        "mailbox",
        "mailboxes",
        "openSession",
        "purge",
        "registerDevice",
        "removeDevices",
        "removeWrap",
        "revokeDevices",
        "saveDraft",
        "send",
        "setPolicy",
        "unread",
        "update",
        "updateDevice",
        "upgrade",
      ],
    );
  });

  it("MailAdmin: suspend, resume and setDelivery, and nothing else", () => {
    expect(rpcMethods(MailAdmin).sort()).toEqual(["resume", "setDelivery", "suspend"]);
  });
});
