import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import {
  activeKeyId,
  type ChallengeView,
  challenge,
  deviceInput,
  factorProof,
  fakeSeal,
  fakeTag,
  keepDevice,
  mailboxKeyPair,
  newDevice,
  openChallenge,
  openSession,
  rotationFor,
  signProof,
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
// token, answer or nonce at rest or in a log), B9's audit rows (ids, kinds,
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

/** Records every bearer secret the flow handles: session tokens, challenge answers, and the nonces of the challenges. */
class Bearers {
  readonly values: Record<string, Uint8Array> = {};
  private n = 0;
  add(kind: "session" | "answer" | "nonce", b64u: string): string {
    this.values[`${kind} ${++this.n}`] = bytesFromBase64url(b64u);
    return b64u;
  }
  challenge(c: ChallengeView): ChallengeView {
    this.add("nonce", c.nonce);
    return c;
  }
}

/**
 * F5, F1, F2, F3/F4, F8, F6 and a send, end to end through MailService, with
 * every token, answer and nonce recorded on the way.
 */
async function everyFlow(bearers: Bearers): Promise<{ u: Upgraded; submitted: Record<string, Uint8Array> }> {
  const u = await upgradedMailbox();
  const submitted: Record<string, Uint8Array> = {};
  const proveWith = async (factor: Upgraded["recovery"]) => {
    const c = bearers.challenge(await challenge(u.mb, { purpose: "factor", factorId: factor.id }));
    return { challengeId: c.id, answer: bearers.add("answer", await openChallenge(u.mb.id, c, factor.pair)) };
  };
  const sessionFor = async (key: CryptoKeyPair, device?: Awaited<ReturnType<typeof newDevice>>) => {
    const c = bearers.challenge(await challenge(u.mb, { purpose: "session" }));
    const answer = bearers.add("answer", await openChallenge(u.mb.id, c, key));
    const signed = device === undefined ? {} : { device: { id: device.id, signature: await signProof(u.mb.id, device, c) } };
    return bearers.add("session", valueOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, ...signed })).session);
  };
  bearers.add("session", u.session);

  // F1: keep a device.
  const device = await newDevice({ label: "Office laptop" });
  const input = deviceInput(device, u.mb.key!.keyId);
  const seal = fakeSeal(142);
  submitted.deviceSeal = bytesFromBase64url(seal);
  submitted.signingKey = device.signingKey; // pragma: allowlist secret (a public P-256 point)
  submitted.unlockKey = device.unlockKey!;
  valueOf(await mail().registerDevice(await capFor(u.mb), { device: input, seal }, { session: u.session, factorProof: await proveWith(u.recovery) }));
  // F2: the device opens its own session; F3: it locks; F4: it unlocks again.
  const deviceSession = await sessionFor(u.mailboxKey, device);
  valueOf(await mail().updateDevice(await capFor(u.mb), { unlockKey: null, tag: fakeTag(), tagKeyId: u.mb.key!.keyId, seal: null }, { session: deviceSession }));
  const deviceSession2 = await sessionFor(u.mailboxKey, device);
  valueOf(
    await mail().updateDevice(
      await capFor(u.mb),
      { unlockKey: base64urlFromBytes(device.unlockKey!), tag: fakeTag(), tagKeyId: u.mb.key!.keyId, seal: fakeSeal(142) },
      { session: deviceSession2 },
    ),
  );
  // Mail in and out, read with a session.
  await worker.email!(incomingEmail(sampleMessage({ to: u.mb.address }), { to: u.mb.address }).message, env, createExecutionContext());
  valueOf(await mail().send(await capFor(u.mb), { idempotencyKey: "m1-devices", to: [{ address: "ana@example.com" }], subject: "s", text: "t", session: deviceSession2 }));
  valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: deviceSession2 }));
  // A wrong answer, so a refused proof is in the audit too.
  const refused = bearers.challenge(await challenge(u.mb, { purpose: "session" }));
  const wrong = bearers.add("answer", base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32))));
  refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: refused.id, answer: wrong }));
  // F6: a plain session (R5) removes the device; the key rotates.
  const remover = await sessionFor(u.mailboxKey);
  const { next, rotation } = await rotationFor(u.mb, device.id);
  submitted.successorSeal = bytesFromBase64url(rotation.successorSeal);
  submitted.newPublicKey = next.publicKey;
  valueOf(await mail().removeDevice(await capFor(u.mb), { deviceId: device.id, rotation }, { session: remover, factorProof: await proveWith(u.passkey) }));
  // Under the new key: a session, and the audit read.
  const after = await sessionFor(await mailboxKeyPair(next));
  valueOf(await mail().audit(await capFor(u.mb), {}, { session: after }));
  return { u, submitted };
}

describe("M1, extended (domain-model §3): no session token, challenge answer or nonce is at rest or in a log", () => {
  it("after every flow, none is in any table, object, log or diagnostics channel, in any form; only their hashes are", async () => {
    const bearers = new Bearers();
    const { u } = await everyFlow(bearers);
    expect(Object.keys(bearers.values).filter((k) => k.startsWith("session")).length).toBeGreaterThanOrEqual(5);
    expect(Object.keys(bearers.values).filter((k) => k.startsWith("answer")).length).toBeGreaterThanOrEqual(7);
    expect(Object.keys(bearers.values).filter((k) => k.startsWith("nonce")).length).toBeGreaterThanOrEqual(7);
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
    const used = await challenge(u.mb, { purpose: "session" });
    valueOf(await mail().openSession(await capFor(u.mb), { challengeId: used.id, answer: await openChallenge(u.mb.id, used, u.mailboxKey) }));
    await challenge(u.mb, { purpose: "factor", factorId: u.recovery.id });
    u.mb.ports.clock.advance(2 * MINUTE - 1);
    const young = await challenge(u.mb, { purpose: "session" });
    const youngSession = (await openSession(u.mb, u.mailboxKey)).session;
    u.mb.ports.clock.advance(1);
    // At 2 minutes the upgrade's challenge, `used` and the factor challenge have expired; the young one and its session's have not.
    expect(await u.mb.stub.dailyHousekeeping()).toEqual({ trash: 0, sends: 0, audit: 0, suppression: 0 });
    const left = await sql<{ id: string }>(u.mb, "SELECT id FROM challenges");
    expect(left.map((c) => c.id)).not.toContain(used.id);
    expect(left).toHaveLength(2);
    expect(left.map((c) => c.id)).toContain(young.id);
    const lines = () => captured.lines.map((l) => JSON.parse(l) as Record<string, unknown>).filter((l) => l.event === "housekeeping");
    expect(lines().at(-1)).toMatchObject({ challenges: 3, sessions: 0 });

    // Sessions: the two opened at the start live 60 minutes; a millisecond before, all three are kept.
    u.mb.ports.clock.advance(58 * MINUTE - 1);
    await u.mb.stub.dailyHousekeeping();
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual([{ n: 3 }]);
    expect(lines().at(-1)).toMatchObject({ challenges: 2, sessions: 0 });
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
      ["removeDevice", () => mail().removeDevice(cap, {}, {})],
      ["setFactorKey", () => mail().setFactorKey(cap, {}, {})],
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
    const { session } = await openSession(u.mb, u.mailboxKey);
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
    await keepDevice(u); // the upgrade's session becomes this device's, for updateDevice
    const keyId = u.mb.key!.keyId;
    for (const [method, answer] of [
      ["registerDevice", await mail().registerDevice(await capFor(u.mb), { device: deviceInput(await newDevice(), keyId, { privateKey: "x" }), seal: fakeSeal(142) }, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) })],
      ["updateDevice", await mail().updateDevice(await capFor(u.mb), { unlockKey: null, tag: fakeTag(), tagKeyId: keyId, seal: null, privateKey: "x" }, { session: u.session })],
      ["challenge", await mail().challenge(await capFor(u.mb), { purpose: "session", answer: "x" })],
      ["openSession", await mail().openSession(await capFor(u.mb), { challengeId: testId("wrp").replace("wrp", "chl"), answer: base64urlFromBytes(new Uint8Array(32)), session: "x" })],
    ] as const) {
      expect([method, refusalOf(answer).name]).toEqual([method, "InvalidRequest"]);
    }
    expect(await activeKeyId(u.mb)).toBe(keyId);
  });
});
