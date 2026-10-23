// R2-2 and round 3, contracts/device-v1.md Part C K8: a rotation proves itself before it is sent.
// removeDevices opens its successor seal with the new key (it must give back the old key), the new key's
// seal for the factor just used with that factor's key (it must give back the new key), and verifies its
// transition with that factor's signing key (round 3), and answers the request only when all three hold:
// a rotation whose seals do not open would leave mail that arrives after it readable only in the page
// that made it, and one whose transition does not verify would be refused by every other browser (K2″).
//
// The seams: mail-crypto's sealKey and signStatement are wrapped for this file only (vi.mock), so a test
// can corrupt the seal made for one recipient, or the transition's signature, as a broken engine or a
// bug would, before removeDevices checks them.
import { describe, expect, test, vi } from "vitest";
import { memoryDeviceStore, RotationUnproven, unlockWithRecoveryKey } from "../src/index";
import { openSession, OWNER, proofFor } from "./flows";
import { enrolledMailbox, type Enrolled } from "./keyring-support";

const corrupt = vi.hoisted(() => ({ to: null as null | { kind: "successor" } | { kind: "factor"; factorId: string } | { kind: "transition" } }));

vi.mock("@proprietor/mail-crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@proprietor/mail-crypto")>();
  const flipLast = (b64: string) => {
    const bytes = Buffer.from(b64, "base64url");
    bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
    return bytes.toString("base64url");
  };
  return {
    ...actual,
    sealKey: async (...args: Parameters<typeof actual.sealKey>) => {
      const sealed = await actual.sealKey(...args);
      const to = args[2];
      const target = corrupt.to;
      if (target === null || target.kind === "transition" || target.kind !== to.kind || (to.kind === "factor" && target.kind === "factor" && to.factorId !== target.factorId)) return sealed;
      return flipLast(sealed); // one bit of the AES-GCM tag, the seal's last byte
    },
    signStatement: async (...args: Parameters<typeof actual.signStatement>) => {
      const signature = await actual.signStatement(...args);
      return corrupt.to?.kind === "transition" && args[1].kind === "transition" ? flipLast(signature) : signature;
    },
  };
});

async function keepBrowser(e: Enrolled, label: string) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId: OWNER, signInId: "s" });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return { unlocked, session, deviceId: pending.request.device.id };
}

describe("K8: removeDevices proves its own seals and transition before it answers the request", () => {
  test("an honest rotation proves itself and is sent", async () => {
    corrupt.to = null;
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const pending = await a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff);
    await e.fake.removeDevices(pending.request, { session: a.session, factorProof: await proofFor(e.fake, ff, pending) });
    await pending.commit();
  });

  test("a successor seal that does not open with the new key: RotationUnproven, and no request", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const keyId = a.unlocked.keyId;
    corrupt.to = { kind: "successor" };
    try {
      await expect(a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff)).rejects.toBeInstanceOf(RotationUnproven);
    } finally {
      corrupt.to = null;
    }
    // Nothing changed here, and the FreshFactor still works: the honest rotation goes through next.
    expect(a.unlocked.keyId).toBe(keyId);
    const pending = await a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff);
    await e.fake.removeDevices(pending.request, { session: a.session, factorProof: await proofFor(e.fake, ff, pending) });
  });

  test("the new key's seal for the factor just used, when it does not open with that factor's key: RotationUnproven", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    corrupt.to = { kind: "factor", factorId: ff.factorId };
    try {
      await expect(a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff)).rejects.toBeInstanceOf(RotationUnproven);
      expect(new RotationUnproven().name).toBe("RotationUnproven");
    } finally {
      corrupt.to = null;
    }
  });

  test("round 3: a transition whose signature does not verify with the factor's signing key: RotationUnproven", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    corrupt.to = { kind: "transition" };
    try {
      await expect(a.unlocked.removeDevices(e.fake.mailbox(), [b.deviceId], ff)).rejects.toBeInstanceOf(RotationUnproven);
    } finally {
      corrupt.to = null;
    }
    expect(e.fake.devices.map((d) => d.id).sort()).toEqual([a.deviceId, b.deviceId].sort());
  });
});
