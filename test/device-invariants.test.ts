import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import {
  type Action,
  activeKeyId,
  actionInput,
  challenge,
  fakeSeal,
  fakeTag,
  keepDevice,
  mailboxKeyPair,
  newDevice,
  openChallenge,
  openSessionAction,
  emailCode,
  plainSession,
  registerAction,
  registerRequest,
  removeDevicesAction,
  rotationFor,
  signProof,
  signUnlockKey,
  type TestFactor,
  type Upgraded,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { type CapturedConsole, captureConsole } from "./support/console";
import { incomingEmail, sampleMessage } from "./support/email";
import { testId } from "./support/ids";
import { capFor, mint, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";
import { byteString, captureDiagnostics, directoryHaystacks, type Haystack, mailboxHaystacks, r2Haystacks, search } from "./support/scan";

// Spec 002's share of the invariants that hold across every flow: M1 (no
// token or answer at rest or in a log), B9's audit rows (ids, kinds,
// counts and labels only), the daily housekeeping of challenges and
// sessions, and answers as values from every new method.

const mail = () => exports.MailService;
const MINUTE = 60 * 1000;
const utf8 = (s: string) => new TextEncoder().encode(s);

let captured: CapturedConsole;
let diagnostics: ReturnType<typeof captureDiagnostics>;
beforeEach(() => {
  captured = captureConsole();
  diagnostics = captureDiagnostics();
});
afterEach(() => {
  diagnostics.stop();
  captured.restore();
});

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function everything(mb: TestMailbox): Promise<Haystack[]> {
  return [
    ...(await mailboxHaystacks(mb.stub)),
    ...(await directoryHaystacks()),
    ...(await r2Haystacks()),
    ...captured.lines.map((text, i) => ({ where: `console line ${i}`, text: byteString(utf8(text)) })),
    ...diagnostics.messages,
  ];
}

/** Records every bearer secret the flow handles: session tokens and challenge answers. (A challenge's nonce is not one: it is sent for the device to sign.) */
class Bearers {
  readonly values: Record<string, Uint8Array> = {};
  private n = 0;
  add(kind: "session" | "answer", b64u: string): string {
    this.values[`${kind} ${++this.n}`] = bytesFromBase64url(b64u);
    return b64u;
  }
}

/**
 * F5, F1, F2, F3/F4, F8, F6 and a send, end to end through MailService, with
 * every session token and challenge answer recorded on the way.
 */
async function everyFlow(bearers: Bearers): Promise<{ u: Upgraded; submitted: Record<string, Uint8Array> }> {
  const u = await upgradedMailbox();
  const submitted: Record<string, Uint8Array> = {};
  const proveWith = async (factor: TestFactor, action: Action) => {
    const c = await challenge(u.mb, { purpose: "factor", factorId: factor.id, action: await actionInput(action) });
    return { challengeId: c.id, answer: bearers.add("answer", await openChallenge(u.mb.id, c, factor.pair)) };
  };
  const sessionFor = async (key: CryptoKeyPair, device?: Awaited<ReturnType<typeof newDevice>>) => {
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = bearers.add("answer", await openChallenge(u.mb.id, c, key));
    // D38: a device's signature, or a factor proof bound to this session challenge.
    const second = device === undefined ? { factorProof: await proveWith(u.passkey, openSessionAction(c.id)) } : { device: { id: device.id, signature: await signProof(u.mb.id, device, c) } };
    return bearers.add("session", valueOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, ...second })).session);
  };
  bearers.add("session", u.session);

  // F1: keep a device.
  const device = await newDevice({ label: "Office laptop" });
  const request = await registerRequest(u, device, u.recovery);
  submitted.deviceSeal = bytesFromBase64url(request.seal!);
  submitted.signingKey = device.signingKey; // pragma: allowlist secret (a public P-256 point)
  submitted.unlockKey = device.unlockKey!;
  valueOf(await mail().registerDevice(await capFor(u.mb), request, { session: u.session, factorProof: await proveWith(u.recovery, registerAction(request)) }));
  // F2: the device opens its own session; F3: it locks; F4: it unlocks again.
  const deviceSession = await sessionFor(u.mailboxKey, device);
  valueOf(await mail().updateDevice(await capFor(u.mb), { unlockKey: null, unlockSignature: null, tag: fakeTag(), tagKeyId: u.mb.key!.keyId, seal: null }, { session: deviceSession }));
  const deviceSession2 = await sessionFor(u.mailboxKey, device);
  valueOf(
    await mail().updateDevice(
      await capFor(u.mb),
      {
        unlockKey: base64urlFromBytes(device.unlockKey!),
        unlockSignature: await signUnlockKey(u.mb.id, device, device.unlockKey!),
        tag: fakeTag(),
        tagKeyId: u.mb.key!.keyId,
        seal: fakeSeal(142),
      },
      { session: deviceSession2 },
    ),
  );
  // Mail in and out, read with a session.
  await worker.email!(incomingEmail(sampleMessage({ to: u.mb.address }), { to: u.mb.address }).message, env, createExecutionContext());
  valueOf(await mail().send(await capFor(u.mb), { idempotencyKey: "m1-devices", to: [{ address: "ana@example.com" }], subject: "s", text: "t", session: deviceSession2 }));
  valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: deviceSession2 }));
  // A wrong answer, so a refused proof is in the audit too.
  const refused = await challenge(u.mb, { purpose: "session" });
  const wrong = bearers.add("answer", base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32))));
  expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: refused.id, answer: wrong, device: { id: device.id, signature: await signProof(u.mb.id, device, refused) } })).name).toBe("ProofRejected");
  // F6: a plain session (R5) removes the device; the key rotates.
  const remover = await sessionFor(u.mailboxKey);
  const { next, rotation } = await rotationFor(u.mb, device.id, u.passkey);
  submitted.successorSeal = bytesFromBase64url(rotation.successorSeal);
  submitted.newPublicKey = next.publicKey;
  const removal = { deviceIds: [device.id], rotation };
  valueOf(await mail().removeDevices(await capFor(u.mb), removal, { session: remover, factorProof: await proveWith(u.passkey, removeDevicesAction(removal)) }));
  // Under the new key: a session, and the audit read.
  const after = await sessionFor(await mailboxKeyPair(next));
  valueOf(await mail().audit(await capFor(u.mb), {}, { session: after }));
  return { u, submitted };
}

describe("M1, extended (domain-model §3): no session token or challenge answer is at rest or in a log", () => {
  it("after every flow, none is in any table, object, log or diagnostics channel, in any form; only their hashes are", async () => {
    const bearers = new Bearers();
    const { u } = await everyFlow(bearers);
    expect(Object.keys(bearers.values).filter((k) => k.startsWith("session")).length).toBeGreaterThanOrEqual(5);
    expect(Object.keys(bearers.values).filter((k) => k.startsWith("answer")).length).toBeGreaterThanOrEqual(7);
    const haystacks = await everything(u.mb);
    expect(haystacks.some((h) => h.where === "mailbox sqlite challenges")).toBe(true);
    expect(haystacks.some((h) => h.where === "mailbox sqlite mail_sessions")).toBe(true);
    expect(haystacks.some((h) => h.where.startsWith("console"))).toBe(true);
    expect(search(haystacks, bearers.values)).toEqual([]);
    // The scan does see these tables: the hash of the last session is there.
    const last = Object.entries(bearers.values).filter(([k]) => k.startsWith("session")).at(-1)![1];
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", last));
    expect(search(haystacks, { digest })).toContainEqual({ target: "digest", form: "base64url@0", where: "mailbox sqlite mail_sessions" });
  });
});

describe("audit rows (B9): ids, kinds, counts and labels; never a token, an answer, a seal or a key", () => {
  it("records each change by its action, and no detail holds a secret, a seal or a key", async () => {
    const bearers = new Bearers();
    const { u, submitted } = await everyFlow(bearers);
    const rows = await sql<{ action: string; detail: string }>(u.mb, "SELECT action, detail FROM audit ORDER BY id");
    const actions = rows.map((r) => r.action);
    for (const action of ["mailbox-upgraded", "device-registered", "device-unlock-key", "proof-rejected", "device-removed", "key-rotated"]) {
      expect(actions, action).toContain(action);
    }
    const haystacks = rows.map((r, i) => ({ where: `audit ${i} ${r.action}`, text: byteString(utf8(r.detail)) }));
    expect(search(haystacks, { ...bearers.values, ...submitted })).toEqual([]);
    for (const r of rows) {
      for (const value of Object.values(JSON.parse(r.detail) as Record<string, unknown>)) {
        expect(["string", "number", "boolean"].includes(typeof value) || value === null, `${r.action}: ${JSON.stringify(value)}`).toBe(true);
      }
    }
  });
});

describe("the daily housekeeping deletes expired challenges and sessions (B9)", () => {
  it("deletes each once it has expired, keeps the live ones, and answers as before", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const used = await challenge(u.mb, { purpose: "session" });
    valueOf(await mail().openSession(await capFor(u.mb), { challengeId: used.id, answer: await openChallenge(u.mb.id, used, u.mailboxKey), device: { id: device.id, signature: await signProof(u.mb.id, device, used) } }));
    await challenge(u.mb, { purpose: "factor", factorId: u.recovery.id, action: await actionInput(openSessionAction(used.id)) });
    const email = await challenge(u.mb, { purpose: "email", action: { kind: "revoke-device", deviceIds: [device.id] } });
    u.mb.ports.clock.advance(2 * MINUTE - 1);
    const young = await challenge(u.mb, { purpose: "session" });
    const youngSession = valueOf(
      await mail().openSession(await capFor(u.mb), { challengeId: young.id, answer: await openChallenge(u.mb.id, young, u.mailboxKey), device: { id: device.id, signature: await signProof(u.mb.id, device, young) } }),
    ).session;
    const youngest = await challenge(u.mb, { purpose: "session" });
    u.mb.ports.clock.advance(1);
    // At 2 minutes every challenge from before has expired but the email one (10 minutes, B6); the youngest and the young one's have not.
    expect(await u.mb.stub.dailyHousekeeping()).toEqual({ trash: 0, sends: 0, audit: 0, suppression: 0 });
    const left = await sql<{ id: string }>(u.mb, "SELECT id FROM challenges");
    expect(left.map((c) => c.id).sort()).toEqual([email.id, young.id, youngest.id].sort());
    const lines = () => captured.lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.event === "housekeeping");
    // The first session's, the upgrade's key challenge, the registration's factor challenge, `used`, and the factor challenge.
    expect(lines().at(-1)).toMatchObject({ challenges: 5, sessions: 0 });

    // Sessions: the upgrade's (now the device's), the registration's and `used`'s live 60 minutes; a millisecond before, all four are kept.
    u.mb.ports.clock.advance(58 * MINUTE - 1);
    await u.mb.stub.dailyHousekeeping();
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual([{ n: 3 }]);
    expect(lines().at(-1)).toMatchObject({ challenges: 3, sessions: 0 });
    u.mb.ports.clock.advance(1);
    await u.mb.stub.dailyHousekeeping();
    expect(lines().at(-1)).toMatchObject({ challenges: 0, sessions: 2 });
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual([{ n: 1 }]);
    valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: youngSession }));
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM challenges")).toEqual([{ n: 0 }]);
  });
});

describe("answers are values from every new method (contracts/mail-service-v1.md)", () => {
  function newMethods(cap: string): [string, () => Promise<unknown>][] {
    return [
      ["challenge", () => mail().challenge(cap, { purpose: "session" })],
      ["openSession", () => mail().openSession(cap, {})],
      ["upgrade", () => mail().upgrade(cap, {}, {})],
      ["registerDevice", () => mail().registerDevice(cap, {}, {})],
      ["updateDevice", () => mail().updateDevice(cap, {}, {})],
      ["removeDevices", () => mail().removeDevices(cap, {}, {})],
      ["revokeDevices", () => mail().revokeDevices(cap, {})],
    ];
  }

  it("refuses a bad capability, one with no mailbox, and a closed mailbox, as values", async () => {
    for (const [method, call] of newMethods("not-a-token")) {
      expect([method, await call()]).toEqual([method, { ok: false, error: { name: "CapabilityRejected", message: "capability rejected: invalid", reason: "invalid" } }]);
    }
    const open = await provisionMailbox();
    for (const [method, call] of newMethods(await mint({ business: open.businessId }))) {
      expect([method, await call()]).toEqual([method, { ok: false, error: { name: "InvalidRequest", message: "invalid request: the capability names no mailbox" } }]);
    }
    const closed = await provisionMailbox({ status: "closed" });
    for (const [method, call] of newMethods(await capFor(closed))) {
      expect([method, await call()]).toEqual([method, { ok: false, error: { name: "NotFound", message: "not found" } }]);
    }
  });

  it("logs one line per call with the method, the jti and the outcome, and never a token", async () => {
    const u = await upgradedMailbox();
    const session = await plainSession(u);
    await mail().list(await capFor(u.mb, { jti: "trace-jti-session" }), { folder: "inbox" }, { session });
    await mail().list(await capFor(u.mb, { jti: "trace-jti-no-session" }), { folder: "inbox" });
    const lines = captured.lines.filter((l) => l.includes('"mail-service"')).map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.filter((l) => String(l.jti).startsWith("trace-jti"))).toEqual([
      { event: "mail-service", method: "list", jti: "trace-jti-session", outcome: "accepted", mailbox: u.mb.id, result: "ok" },
      { event: "mail-service", method: "list", jti: "trace-jti-no-session", outcome: "accepted", mailbox: u.mb.id, result: "SessionRequired" },
    ]);
    expect(captured.lines.some((l) => l.includes(session))).toBe(false);
  });

  it("refuses a request that sends a private key or a token under any other name to a new method", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u); // the upgrade's session becomes this device's, for updateDevice
    const keyId = u.mb.key!.keyId;
    const leaky = await registerRequest(u, await newDevice(), u.recovery, { privateKey: "x" });
    const leakyProof = await (async () => {
      const c = await challenge(u.mb, { purpose: "factor", factorId: u.recovery.id, action: await actionInput(registerAction(leaky)) });
      return { challengeId: c.id, answer: await openChallenge(u.mb.id, c, u.recovery.pair) };
    })();
    for (const [method, answer] of [
      ["registerDevice", await mail().registerDevice(await capFor(u.mb), leaky, { session: u.session, factorProof: leakyProof })],
      ["updateDevice", await mail().updateDevice(await capFor(u.mb), { unlockKey: null, unlockSignature: null, tag: fakeTag(), tagKeyId: keyId, seal: null, privateKey: "x" }, { session: u.session })],
      ["revokeDevices", await mail().revokeDevices(await emailCode(u, [device.id]), { deviceIds: [device.id], privateKey: "x" })],
      ["challenge", await mail().challenge(await capFor(u.mb), { purpose: "session", answer: "x" })],
      ["openSession", await mail().openSession(await capFor(u.mb), { challengeId: testId("wrp").replace("wrp", "chl"), answer: base64urlFromBytes(new Uint8Array(32)), session: "x" })],
    ] as const) {
      expect([method, refusalOf(answer).name]).toEqual([method, "InvalidRequest"]);
    }
    expect(await activeKeyId(u.mb)).toBe(keyId);
  });
});
