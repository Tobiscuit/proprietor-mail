// R2-2, contracts/device-v1.md Part C K8 (new on 2026-10-19): a rotation proves itself before it is
// sent. removeDevice opens its successor seal with the new key (it must give back the old key) and the
// new key's seal for the factor just used with that factor's key (it must give back the new key), and
// answers the request only when both do: a rotation whose seals do not open would leave mail that
// arrives after it readable only in the page that made it.
//
// The seam: mail-crypto's sealKey is wrapped for this file only (vi.mock), so a test can corrupt the
// seal it makes for one recipient, as a broken engine or a bug would, before removeDevice checks it.
import { describe, expect, test, vi } from "vitest";
import {
  memoryDeviceStore,
  RotationUnproven,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type FreshFactor,
  type UnlockedMailbox,
} from "../src/index";
import type { FakeMail } from "./fake-mail";
import { enrolledMailbox, type Enrolled } from "./keyring-support";

const corrupt = vi.hoisted(() => ({ to: null as null | { kind: "successor" } | { kind: "factor"; factorId: string } }));

vi.mock("@proprietor/mail-crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@proprietor/mail-crypto")>();
  return {
    ...actual,
    sealKey: async (...args: Parameters<typeof actual.sealKey>) => {
      const sealed = await actual.sealKey(...args);
      const to = args[2];
      const target = corrupt.to;
      if (target === null || target.kind !== to.kind || (to.kind === "factor" && target.kind === "factor" && to.factorId !== target.factorId)) return sealed;
      // One bit of the AES-GCM tag, the seal's last byte.
      const bytes = Buffer.from(sealed, "base64url");
      bytes[bytes.length - 1] = bytes[bytes.length - 1]! ^ 1;
      return bytes.toString("base64url");
    },
  };
});

async function openSession(fake: FakeMail, unlocked: UnlockedMailbox) {
  return (await fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })))).session;
}
async function proofOf(fake: FakeMail, ff: FreshFactor) {
  return ff.answer(await fake.challenge({ purpose: "factor", factorId: ff.factorId }));
}
async function keepBrowser(e: Enrolled, label: string) {
  const store = memoryDeviceStore();
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, signInId: "s" });
  const session = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofOf(e.fake, ff) });
  await pending.commit();
  return { unlocked, session, deviceId: pending.request.device.id };
}

describe("K8: removeDevice opens its own seals before it answers the request", () => {
  test("an honest rotation proves itself and is sent", async () => {
    corrupt.to = null;
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    const pending = await a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff);
    await e.fake.removeDevice(pending.request, { session: a.session, factorProof: await proofOf(e.fake, ff) });
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
      await expect(a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff)).rejects.toBeInstanceOf(RotationUnproven);
    } finally {
      corrupt.to = null;
    }
    // Nothing changed here, and the FreshFactor still works: the honest rotation goes through next.
    expect(a.unlocked.keyId).toBe(keyId);
    const pending = await a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff);
    await e.fake.removeDevice(pending.request, { session: a.session, factorProof: await proofOf(e.fake, ff) });
  });

  test("the new key's seal for the factor just used, when it does not open with that factor's key: RotationUnproven", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    const ff = await a.unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    corrupt.to = { kind: "factor", factorId: ff.factorId };
    try {
      await expect(a.unlocked.removeDevice(e.fake.mailbox(), b.deviceId, ff)).rejects.toBeInstanceOf(RotationUnproven);
      expect(new RotationUnproven().name).toBe("RotationUnproven");
    } finally {
      corrupt.to = null;
    }
  });

  test("a factor that receives no seal of the new key cannot prove the rotation: RotationUnproven", async () => {
    const e = await enrolledMailbox();
    const a = await keepBrowser(e, "Office laptop");
    const b = await keepBrowser(e, "Lost phone");
    // The passkey listed with no factor key (an anomaly once sessions are required): the rotation seals nothing to it.
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!;
    Object.assign(passkey, { factorKey: null, tag: null, tagKeyId: null });
    const byPasskey = await unlockWithPasskey(e.fake.mailbox(), { rpId: "example.com", credentials: e.credentials as never });
    await expect(byPasskey.removeDevice(e.fake.mailbox(), b.deviceId, byPasskey.freshFactor!)).rejects.toBeInstanceOf(RotationUnproven);
    expect(a.deviceId).not.toBe(b.deviceId);
  });
});
