import { sealChallenge, verifyDeviceProof } from "@proprietor/mail-crypto";
import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { Proofs } from "../src/ports";
import { challenge, factorProof, keepDevice, openChallenge, openSession, rotationFor, signProof, type TestDevice, type Upgraded, upgradedMailbox } from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { capFor, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// openSession awaits the device's signature check (contracts/device-v1.md
// B6, A7). Other calls can reach the Mailbox during that await, so what was
// checked before it is checked again after it. Here a removal runs inside
// that await: the device itself is removed, or another device is and the key
// rotates. Either way no session may be written.

const mail = () => exports.MailService;

const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };
const DEVICE_REVOKED = { name: "DeviceRevoked", message: "this device is not in the mailbox" };

const sha256 = async (b64u: string) => base64urlFromBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", bytesFromBase64url(b64u))));
const tick = () => new Promise((resolve) => setTimeout(resolve, 2));

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 1000 && !condition(); i++) await tick();
  if (!condition()) throw new Error(`timed out waiting for ${what}`);
}

/**
 * The real proofs, except that verifyDeviceProof, once called, waits until
 * the test opens the gate. It waits on a timer rather than on a bare
 * promise, so the Mailbox's request always has something to wait for and
 * workerd never takes it for hung.
 */
function gatedProofs(): { proofs: Proofs; gate: { entered: boolean; open: boolean } } {
  const gate = { entered: false, open: false };
  return {
    gate,
    proofs: {
      sealChallenge,
      async verifyDeviceProof(signingKey, ids, signature) {
        gate.entered = true;
        while (!gate.open) await tick();
        return verifyDeviceProof(signingKey, ids, signature);
      },
    },
  };
}

/** A phone and a laptop kept, and a plain session (R5) to remove either from. */
async function twoDevices(): Promise<{ u: Upgraded; phone: TestDevice; laptop: TestDevice; remover: string }> {
  const u = await upgradedMailbox();
  const phone = await keepDevice(u);
  const laptop = await keepDevice(u, { session: (await openSession(u.mb, u.mailboxKey)).session });
  const remover = (await openSession(u.mb, u.mailboxKey)).session;
  return { u, phone, laptop, remover };
}

/** The phone starts to open its session; the answer and the signature are both right. Its signature check waits at the gate. */
async function phoneOpensBehindTheGate(u: Upgraded, phone: TestDevice) {
  const c = await challenge(u.mb, { purpose: "session" });
  const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
  const signature = await signProof(u.mb.id, phone, c);
  const { proofs, gate } = gatedProofs();
  u.mb.ports.proofs = proofs;
  const pending = mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: { id: phone.id, signature } });
  await until(() => gate.entered, "the signature check");
  return { c, gate, pending };
}

async function removeDuringTheCheck(u: Upgraded, deviceId: string, remover: string) {
  const { rotation } = await rotationFor(u.mb, deviceId);
  return valueOf(await mail().removeDevice(await capFor(u.mb), { deviceId, rotation }, { session: remover, factorProof: await factorProof(u.mb, u.recovery) }));
}

describe("openSession checks the device and the key again after it awaits the signature check (B6)", () => {
  it("(a) the device is removed meanwhile: DeviceRevoked, and no session is written", async () => {
    const { u, phone, remover } = await twoDevices();
    const { gate, pending } = await phoneOpensBehindTheGate(u, phone);
    await removeDuringTheCheck(u, phone.id, remover);
    gate.open = true;
    expect(refusalOf(await pending)).toEqual(DEVICE_REVOKED);
    // The only session left is the remover's: the rotation ended the others, and the phone got none.
    expect(await sql(u.mb, "SELECT token_hash, device_id FROM mail_sessions")).toEqual([{ token_hash: await sha256(remover), device_id: null }]);
  });

  it("(b) another device is removed meanwhile, so the key rotated: ProofRejected, and no session is written", async () => {
    const { u, phone, laptop, remover } = await twoDevices();
    const { c, gate, pending } = await phoneOpensBehindTheGate(u, phone);
    await removeDuringTheCheck(u, laptop.id, remover);
    gate.open = true;
    expect(refusalOf(await pending)).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT token_hash, device_id FROM mail_sessions")).toEqual([{ token_hash: await sha256(remover), device_id: null }]);
    expect((await sql<{ detail: string }>(u.mb, "SELECT detail FROM audit WHERE action = 'proof-rejected' ORDER BY id DESC LIMIT 1")).map((r) => JSON.parse(r.detail))).toEqual([
      { challenge: c.id, purpose: "session", reason: "key" },
    ]);
    // The phone is still kept, and opens a session under the new key once it has it (F2).
    expect((await sql<{ id: string }>(u.mb, "SELECT id FROM devices")).map((d) => d.id)).toContain(phone.id);
  });
});

describe("a rotation deletes the old key's session challenges (B7)", () => {
  it("leaves none of them, used or not, and keeps the factor challenges", async () => {
    const { u, laptop, remover } = await twoDevices();
    const oldKey = u.mb.key!.keyId;
    await challenge(u.mb, { purpose: "session" });
    const used = await challenge(u.mb, { purpose: "session" });
    valueOf(await mail().openSession(await capFor(u.mb), { challengeId: used.id, answer: await openChallenge(u.mb.id, used, u.mailboxKey) }));
    const factor = await challenge(u.mb, { purpose: "factor", factorId: u.passkey.id });
    expect((await sql<{ n: number }>(u.mb, "SELECT COUNT(*) AS n FROM challenges WHERE purpose = 'session' AND target_id = ?", oldKey))[0]!.n).toBeGreaterThanOrEqual(2);
    await removeDuringTheCheck(u, laptop.id, remover);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM challenges WHERE purpose = 'session' AND target_id = ?", oldKey)).toEqual([{ n: 0 }]);
    expect((await sql<{ id: string }>(u.mb, "SELECT id FROM challenges WHERE purpose = 'factor'")).map((r) => r.id)).toContain(factor.id);
  });
});
