import { sealChallenge, verifyDeviceProof, verifyStatement } from "@proprietor/mail-crypto";
import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { Proofs } from "../src/ports";
import {
  challenge,
  emailConfirmation,
  factorProof,
  keepDevice,
  newDevice,
  openChallenge,
  plainSession,
  registerAction,
  registerRequest,
  removeDevicesAction,
  rotationFor,
  signProof,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes } from "./support/capability-tokens";
import { capFor, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Take first: whatever Mail spends once or counts against a cap is taken
// before it is compared, in one statement or one synchronous step, never
// across an await (sessions.ts, devices.ts). Here the calls really run at the
// same time: the Mailbox's awaits (sealing a challenge, verifying a
// signature) are held open on a timer until every call has either reached
// them or been answered, so a check made before an await and a spend made
// after it would let more than one call through, and these tests would see it.

const mail = () => exports.MailService;

const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };

const tick = () => new Promise((resolve) => setTimeout(resolve, 2));

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function until(condition: () => boolean, what: string): Promise<void> {
  for (let i = 0; i < 2000 && !condition(); i++) await tick();
  if (!condition()) throw new Error(`timed out waiting for ${what}`);
}

/** The real proofs, each one's await held at a gate (on a timer, so workerd never takes a request for hung), counting who reached it. */
function gatedProofs(): { proofs: Proofs; gate: { open: boolean; sealed: number; verifiedDevice: number; verifiedStatement: number } } {
  const gate = { open: false, sealed: 0, verifiedDevice: 0, verifiedStatement: 0 };
  const held = async () => {
    while (!gate.open) await tick();
  };
  return {
    gate,
    proofs: {
      async sealChallenge(target, ids) {
        gate.sealed++;
        await held();
        return sealChallenge(target, ids);
      },
      async verifyDeviceProof(signingKey, ids, signature) {
        gate.verifiedDevice++;
        await held();
        return verifyDeviceProof(signingKey, ids, signature);
      },
      async verifyStatement(publicKey, statement, signature) {
        gate.verifiedStatement++;
        await held();
        return verifyStatement(publicKey, statement, signature);
      },
    },
  };
}

type Answer = Parameters<typeof refusalOf>[0];

/** Starts every call at once; resolves with the answers, and counts how many were answered while the gate was shut. */
function race(calls: (() => PromiseLike<unknown>)[]): { all: Promise<Answer[]>; settled: () => number } {
  let settled = 0;
  const all = Promise.all(
    calls.map(async (call) => {
      const answer = (await call()) as Answer;
      settled++;
      return answer;
    }),
  );
  return { all, settled: () => settled };
}

const okCount = (answers: { ok: boolean }[]) => answers.filter((a) => a.ok).length;

describe("the 20-live-challenge cap is taken before a challenge is sealed (M16)", () => {
  it("twenty-five challenges asked at once: twenty are issued and sealed, five are RateLimited and seal nothing", async () => {
    const u = await upgradedMailbox();
    const { proofs, gate } = gatedProofs();
    u.mb.ports.proofs = proofs;
    const cap = await capFor(u.mb);
    const r = race(Array.from({ length: 25 }, () => () => mail().challenge(cap, { purpose: "session" })));
    await until(() => gate.sealed + r.settled() === 25, "every call to seal or be answered");
    expect([gate.sealed, r.settled()]).toEqual([20, 5]);
    gate.open = true;
    const answers = await r.all;
    expect(okCount(answers)).toBe(20);
    expect(answers.filter((a) => !a.ok).map((a) => refusalOf(a).name)).toEqual(Array(5).fill("RateLimited"));
    expect(gate.sealed).toBe(20);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM challenges WHERE used_at IS NULL AND answer_hash IS NOT NULL")).toEqual([{ n: 20 }]);
  });
});

describe("a challenge is spent before its answer is compared (M16)", () => {
  it("five wrong answers at once to five challenges spend exactly those five, each audited once", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const made = await Promise.all(Array.from({ length: 5 }, () => challenge(u.mb, { purpose: "session" })));
    const cap = await capFor(u.mb);
    const wrong = () => base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)));
    const calls = await Promise.all(made.map(async (c) => ({ id: c.id, device: { id: device.id, signature: await signProof(u.mb.id, device, c) } })));
    const answers = await Promise.all(calls.map((c) => mail().openSession(cap, { challengeId: c.id, answer: wrong(), device: c.device })));
    expect(answers.map((a) => refusalOf(a))).toEqual(Array(5).fill(PROOF_REJECTED));
    const ids = made.map((c) => c.id);
    expect((await sql<{ id: string }>(u.mb, `SELECT id FROM challenges WHERE used_at IS NOT NULL AND id IN (${ids.map(() => "?").join(",")})`, ...ids)).map((r) => r.id).sort()).toEqual([...ids].sort());
    const audited = (await sql<{ detail: string }>(u.mb, "SELECT detail FROM audit WHERE action = 'proof-rejected'")).map((r) => JSON.parse(r.detail) as { challenge: string; reason: string });
    expect(audited.map((d) => d.challenge).sort()).toEqual([...ids].sort());
    expect(new Set(audited.map((d) => d.reason))).toEqual(new Set(["answer"]));
  });

  it("one challenge presented five times at once is compared once: only the first reaches the signature check, the rest are refused as used", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const c = await challenge(u.mb, { purpose: "session" });
    const request = { challengeId: c.id, answer: await openChallenge(u.mb.id, c, u.mailboxKey), device: { id: device.id, signature: await signProof(u.mb.id, device, c) } };
    const { proofs, gate } = gatedProofs();
    u.mb.ports.proofs = proofs;
    const cap = await capFor(u.mb);
    const r = race(Array.from({ length: 5 }, () => () => mail().openSession(cap, request)));
    await until(() => gate.verifiedDevice + r.settled() === 5, "every call to be compared or answered");
    expect([gate.verifiedDevice, r.settled()]).toEqual([1, 4]);
    gate.open = true;
    const answers = await r.all;
    expect(okCount(answers)).toBe(1);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions WHERE device_id = ?", device.id)).toEqual([{ n: 2 }]);
  });
});

describe("a factor proof is spent once, however many calls carry it at once (M17′)", () => {
  it("two removeDevices with one proof at once: exactly one rotation, the other ProofRejected; only one reaches the transition check", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const remover = await plainSession(u);
    const request = { deviceIds: [device.id], rotation: (await rotationFor(u.mb, device.id, u.recovery)).rotation };
    const proof = await factorProof(u.mb, u.recovery, removeDevicesAction(request));
    const { proofs, gate } = gatedProofs();
    u.mb.ports.proofs = proofs;
    const cap = await capFor(u.mb);
    const r = race([0, 1].map(() => () => mail().removeDevices(cap, request, { session: remover, factorProof: proof })));
    await until(() => gate.verifiedStatement + r.settled() === 2, "both calls to be checked or answered");
    expect([gate.verifiedStatement, r.settled()]).toEqual([1, 1]);
    gate.open = true;
    const answers = await r.all;
    expect(okCount(answers)).toBe(1);
    expect(refusalOf(answers.find((a) => !a.ok)!)).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM keys")).toEqual([{ n: 2 }]);
  });

  it("two registerDevice with one proof at once: one device is kept, the other call is ProofRejected", async () => {
    const u = await upgradedMailbox();
    const request = await registerRequest(u, await newDevice(), u.recovery);
    const proof = await factorProof(u.mb, u.recovery, registerAction(request));
    const second = await plainSession(u);
    const { proofs, gate } = gatedProofs();
    u.mb.ports.proofs = proofs;
    const cap = await capFor(u.mb);
    const r = race([u.session, second].map((session) => () => mail().registerDevice(cap, request, { session, factorProof: proof })));
    // The one that spent the proof verifies two statements (its admission, then its unlock key); the other is refused before any.
    await until(() => gate.verifiedStatement >= 1 && r.settled() === 1, "one call to be checked and the other answered");
    gate.open = true;
    const answers = await r.all;
    expect(okCount(answers)).toBe(1);
    expect(refusalOf(answers.find((a) => !a.ok)!)).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM devices")).toEqual([{ n: 1 }]);
  });
});

describe("an email code's challenge is spent once (B7a)", () => {
  it("two revokeDevices with one attestation at once: exactly one is applied, the other is ProofRejected", async () => {
    const u = await upgradedMailbox();
    const phone = await keepDevice(u);
    const laptop = await keepDevice(u, { session: await plainSession(u) });
    const { attestation } = await emailConfirmation(u.mb, [phone.id]);
    const cap = await capFor(u.mb, { confirmation: attestation });
    const answers = await Promise.all([0, 1, 2].map(() => mail().revokeDevices(cap, { deviceIds: [phone.id] })));
    expect(okCount(answers)).toBe(1);
    expect(answers.filter((a) => !a.ok).map((a) => refusalOf(a))).toEqual([PROOF_REJECTED, PROOF_REJECTED]);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM audit WHERE action = 'device-revoked'")).toEqual([{ n: 1 }]);
    const v = valueOf(await mail().mailbox(await capFor(u.mb)));
    expect([v.devices.map((d) => d.id), v.rotationDue?.devices]).toEqual([[laptop.id], [phone.id]]);
  });
});
