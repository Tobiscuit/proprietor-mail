import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import {
  challenge,
  factorInput,
  factorProof,
  fakeSeal,
  fakeTag,
  keepDevice,
  legacyMailbox,
  mailboxKeyPair,
  newDevice,
  newFactorKey,
  openChallenge,
  openSession,
  rotationFor,
  signProof,
  type TestDevice,
  type Upgraded,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { incomingEmail, sampleMessage } from "./support/email";
import { testId } from "./support/ids";
import { capFor, newKeyPair, recoveryWrap, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// contracts/device-v1.md B7 (removeDevice), domain-model M18, M19 and M5′,
// plan.md F6: removing a device rotates the mailbox key in one transaction.

const mail = () => exports.MailService;

const SESSION_REQUIRED = { name: "SessionRequired", message: "a live mail session is required" };
const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };
const DEVICE_REVOKED = { name: "DeviceRevoked", message: "this device is not in the mailbox" };

const sha256 = async (b64u: string) => base64urlFromBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", bytesFromBase64url(b64u))));
const view = async (mb: TestMailbox) => valueOf(await mail().mailbox(await capFor(mb)));
const byRecipient = <T extends { to: { kind: string; id: string } }>(xs: T[]) => [...xs].sort((a, b) => `${a.to.kind}:${a.to.id}`.localeCompare(`${b.to.kind}:${b.to.id}`));

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function arrive(mb: TestMailbox): Promise<void> {
  const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  mb.ports.clock.advance(1000);
}

/** Everything a removal may change, for "nothing changed". */
async function keyRingState(mb: TestMailbox) {
  return {
    view: await view(mb),
    sessions: await sql(mb, "SELECT token_hash, device_id FROM mail_sessions ORDER BY token_hash"),
    keys: await sql(mb, "SELECT * FROM keys ORDER BY created_at"),
    seals: await sql(mb, "SELECT * FROM key_seals ORDER BY to_kind, to_id"),
  };
}

/**
 * An upgraded mailbox with three kept devices: a phone (the upgrade's session
 * became its session), a laptop, and a front-desk browser that keeps nothing;
 * each with a session of its own, and a plain session to remove from (R5:
 * a browser unlocked with the recovery key alone).
 */
async function threeDevices() {
  const u = await upgradedMailbox();
  const phone = await keepDevice(u);
  const laptop = await keepDevice(u, { session: (await openSession(u.mb, u.mailboxKey)).session });
  const desk = await keepDevice(u, { device: await newDevice({ label: "Front desk", keepsNothing: true }), session: (await openSession(u.mb, u.mailboxKey)).session });
  const laptopSession = (await openSession(u.mb, u.mailboxKey, { device: laptop })).session;
  const remover = (await openSession(u.mb, u.mailboxKey)).session;
  return { u, phone, laptop, desk, laptopSession, remover };
}

async function remove(u: Upgraded, deviceId: string, rotation: unknown, session: string) {
  return mail().removeDevice(await capFor(u.mb), { deviceId, rotation }, { session, factorProof: await factorProof(u.mb, u.recovery) });
}

describe("removeDevice: the device goes and the key rotates, in one transaction (B7, M18)", () => {
  it("leaves exactly M18's state: device, seals and sessions gone, the new key active, the old one retired with its successor seal, new seals and tags", async () => {
    const { u, phone, laptop, desk, laptopSession, remover } = await threeDevices();
    const before = await view(u.mb);
    const old = before.keys[0]!;
    const { next, rotation } = await rotationFor(u.mb, phone.id);
    u.mb.ports.clock.advance(60 * 1000);
    const at = u.mb.ports.clock.now().toISOString();

    expect(await remove(u, phone.id, rotation, remover)).toEqual({ ok: true, value: { keyId: next.keyId } });

    const after = await view(u.mb);
    expect(after.devices.map((d) => d.id).sort()).toEqual([laptop.id, desk.id].sort());
    expect(after.keys).toEqual([
      { ...old, retiredAt: at, successor: { keyId: next.keyId, sealed: rotation.successorSeal } },
      { keyId: next.keyId, publicKey: base64urlFromBytes(next.publicKey), createdAt: at, createdBy: "acc_owner", retiredAt: null, successor: null },
    ]);
    // Exactly the rotation's seals, every one of the new key (M19): the laptop and both factors; not the desk (it keeps nothing), never the phone.
    expect(byRecipient(after.seals)).toEqual(byRecipient(rotation.seals.map((s) => ({ keyId: next.keyId, ...s }))));
    expect(after.seals.map((s) => s.to.id).sort()).toEqual([laptop.id, u.recovery.id, u.passkey.id].sort());
    // Every remaining device and keyed factor is tagged under the new key.
    for (const t of rotation.tags) {
      const holder = t.to.kind === "device" ? after.devices.find((d) => d.id === t.to.id) : after.wraps.find((w) => w.id === t.to.id);
      expect([t.to.id, holder?.tag, holder?.tagKeyId]).toEqual([t.to.id, t.tag, next.keyId]);
    }
    expect(rotation.tags.map((t) => t.to.id).sort()).toEqual([laptop.id, desk.id, u.recovery.id, u.passkey.id].sort());
    // Every other session ended, the phone's with it; the remover's stays.
    expect(await sql(u.mb, "SELECT token_hash, device_id FROM mail_sessions")).toEqual([{ token_hash: await sha256(remover), device_id: null }]);
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: laptopSession }))).toEqual(SESSION_REQUIRED);
    valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: remover }));

    const audit = await sql<{ action: string; detail: string }>(u.mb, "SELECT action, detail FROM audit WHERE action IN ('device-removed', 'key-rotated') ORDER BY id");
    expect(audit.map((a) => [a.action, JSON.parse(a.detail)])).toEqual([
      ["device-removed", { device: phone.id, label: phone.label, sessions: 1 }],
      ["key-rotated", { from: old.keyId, to: next.keyId, seals: 3, sessions: 3 }],
    ]);
  });

  it("seals the next arrival to the new key, and earlier mail keeps the key it was sealed to", async () => {
    const { u, phone, remover } = await threeDevices();
    await arrive(u.mb);
    const { next, rotation } = await rotationFor(u.mb, phone.id);
    valueOf(await remove(u, phone.id, rotation, remover));
    await arrive(u.mb);
    expect(u.mb.ports.sealer.sealed.map((s) => s.pub.keyId)).toEqual([u.mb.key!.keyId, next.keyId]);
    const items = valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: remover })).items;
    expect(items.map((m) => m.keyId)).toEqual([next.keyId, u.mb.key!.keyId]);
  });

  it("refuses the removed device from then on, and a session challenge made before the rotation opens nothing", async () => {
    const { u, phone, remover } = await threeDevices();
    const early = await challenge(u.mb, { purpose: "session" });
    const earlyAnswer = await openChallenge(u.mb.id, early, u.mailboxKey);
    const { next, rotation } = await rotationFor(u.mb, phone.id);
    valueOf(await remove(u, phone.id, rotation, remover));
    // The phone's session ended with it.
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: u.session }))).toEqual(SESSION_REQUIRED);
    // A key proof of the old key, made before the rotation, opens no session after it.
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: early.id, answer: earlyAnswer }))).toEqual(PROOF_REJECTED);
    // New challenges are sealed to the new key, which the phone never got.
    const fresh = await challenge(u.mb, { purpose: "session" });
    expect(fresh.keyId).toBe(next.keyId);
    await expect(openChallenge(u.mb.id, fresh, u.mailboxKey)).rejects.toThrow();
    // Even holding the new key, the phone is not a device of the mailbox any more.
    const newKey = await mailboxKeyPair(next);
    const c = await challenge(u.mb, { purpose: "session" });
    expect(
      refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer: await openChallenge(u.mb.id, c, newKey), device: { id: phone.id, signature: await signProof(u.mb.id, phone, c) } })),
    ).toEqual(DEVICE_REVOKED);
    valueOf(await mail().openSession(await capFor(u.mb), { challengeId: fresh.id, answer: await openChallenge(u.mb.id, fresh, newKey) }));
  });

  it("works from the removed device's own session (Remove this device), which ends with it", async () => {
    const { u, phone } = await threeDevices();
    const { rotation } = await rotationFor(u.mb, phone.id);
    valueOf(await remove(u, phone.id, rotation, u.session));
    expect((await view(u.mb)).devices.map((d) => d.id)).not.toContain(phone.id);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual([{ n: 0 }]);
  });

  it("refuses, and changes nothing, a rotation that misses or adds a recipient, names one twice, is stale, reuses a key, or has a seal of the wrong length", async () => {
    const { u, phone, laptop, desk, remover } = await threeDevices();
    const { rotation } = await rotationFor(u.mb, phone.id);
    const without = (kind: string, id: string) => rotation.seals.filter((s) => !(s.to.kind === kind && s.to.id === id));
    const cases: [string, unknown, string?][] = [
      ["a device seal missing", { ...rotation, seals: without("device", laptop.id) }],
      ["a factor seal missing", { ...rotation, seals: without("factor", u.passkey.id) }],
      ["a tag missing", { ...rotation, tags: rotation.tags.filter((t) => t.to.id !== desk.id) }],
      ["a seal to the removed device", { ...rotation, seals: [...rotation.seals, { to: { kind: "device", id: phone.id }, sealed: fakeSeal(142) }] }],
      ["a seal to a device that keeps nothing", { ...rotation, seals: [...rotation.seals, { to: { kind: "device", id: desk.id }, sealed: fakeSeal(142) }] }],
      ["a seal to an unknown factor", { ...rotation, seals: [...rotation.seals, { to: { kind: "factor", id: testId("wrp") }, sealed: fakeSeal(109) }] }],
      ["a seal named twice", { ...rotation, seals: [...rotation.seals, rotation.seals[0]] }],
      ["a tag for the removed device", { ...rotation, tags: [...rotation.tags, { to: { kind: "device", id: phone.id }, tag: fakeTag() }] }],
      ["a tag named twice", { ...rotation, tags: [...rotation.tags, rotation.tags[0]] }],
      ["a stale from", { ...rotation, from: (await newKeyPair()).keyId }],
      ["a key the mailbox already had", { ...rotation, publicKey: base64urlFromBytes(u.mb.key!.publicKey) }],
      ["a low-order new key", { ...rotation, publicKey: base64urlFromBytes(new Uint8Array(32)) }],
      ["a short successor seal", { ...rotation, successorSeal: fakeSeal(109).slice(0, -2) }],
      ["a device seal of 109 bytes", { ...rotation, seals: rotation.seals.map((s) => (s.to.kind === "device" ? { ...s, sealed: fakeSeal(109) } : s)) }],
      ["a factor seal of 142 bytes", { ...rotation, seals: rotation.seals.map((s) => (s.to.kind === "factor" ? { ...s, sealed: fakeSeal(142) } : s)) }],
      ["a seal to a kind there is none of", { ...rotation, seals: [...rotation.seals, { to: { kind: "successor", id: testId("wrp") }, sealed: fakeSeal(109) }] }],
      ["an unexpected field", { ...rotation, privateKey: "x" }],
    ];
    const before = await keyRingState(u.mb);
    for (const [name, bad] of cases) {
      expect([name, refusalOf(await remove(u, phone.id, bad, remover)).name]).toEqual([name, "InvalidRequest"]);
    }
    expect([" an unknown device", refusalOf(await remove(u, (await newDevice()).id, rotation, remover)).name]).toEqual([" an unknown device", "InvalidRequest"]);
    expect(await keyRingState(u.mb)).toEqual(before);
    // The same request, untouched, still works: nothing above changed what it is checked against.
    valueOf(await remove(u, phone.id, rotation, remover));
  });

  it("refuses a second removal made from the same view: another browser rotated first (G38)", async () => {
    const { u, phone, laptop, remover } = await threeDevices();
    const first = await rotationFor(u.mb, phone.id);
    const second = await rotationFor(u.mb, laptop.id);
    valueOf(await remove(u, phone.id, first.rotation, remover));
    expect(refusalOf(await remove(u, laptop.id, second.rotation, remover))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: the rotation is from a key that is not active",
    });
  });

  it("M19: after two rotations each retired key has its successor seal, and every seal is of the active key", async () => {
    const { u, phone, laptop, remover } = await threeDevices();
    const first = await rotationFor(u.mb, phone.id);
    valueOf(await remove(u, phone.id, first.rotation, remover));
    const second = await rotationFor(u.mb, laptop.id);
    valueOf(await remove(u, laptop.id, second.rotation, remover));
    const keys = await sql<{ key_id: string; retired_at: string | null; successor_key_id: string | null }>(u.mb, "SELECT key_id, retired_at, successor_key_id FROM keys ORDER BY created_at");
    expect(keys.map((k) => [k.key_id, k.retired_at === null, k.successor_key_id])).toEqual([
      [u.mb.key!.keyId, false, first.next.keyId],
      [first.next.keyId, false, second.next.keyId],
      [second.next.keyId, true, null],
    ]);
    expect(await sql(u.mb, "SELECT DISTINCT key_id FROM key_seals")).toEqual([{ key_id: second.next.keyId }]);
  });

  it("is refused while sessions are optional, and is the owner's", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const { session } = await openSession(mb, mailboxKey);
    expect(refusalOf(await mail().removeDevice(await capFor(mb), { deviceId: testId("wrp").replace("wrp", "dev"), rotation: {} }, { session }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: sessions are not on for this mailbox: upgrade first",
    });
    expect(refusalOf(await mail().removeDevice(await capFor(mb, { role: "editor" }), {}, { session }))).toEqual({ name: "Forbidden", message: "forbidden" });
  });
});

describe("M5′ through rotations: the active key stays reachable by a recovery factor", () => {
  /** A legacy mailbox with a second recovery wrap, upgraded naming the first only: the second has no factor key. */
  async function twoRecoveries() {
    const { mb, mailboxKey, recoveryId, passkeyId } = await legacyMailbox();
    const spare = recoveryWrap(mb.key!.keyId, { label: "Spare sheet" });
    valueOf(await mail().addWrap(await capFor(mb), spare));
    const recovery = await newFactorKey(recoveryId, "recovery");
    const passkey = await newFactorKey(passkeyId, "passkey-prf");
    const { session } = await openSession(mb, mailboxKey);
    valueOf(await mail().upgrade(await capFor(mb), { factors: [factorInput(recovery, mb.key!.keyId), factorInput(passkey, mb.key!.keyId)] }, { session }));
    const u: Upgraded = { mb, mailboxKey, session, recovery, passkey };
    return { u, spare };
  }

  it("refuses a rotation that would reach no recovery factor", async () => {
    const { u } = await twoRecoveries();
    const device = await keepDevice(u);
    // The keyed recovery key goes: the spare, unkeyed, still reaches the active key through its own wrap (M5′).
    valueOf(await mail().removeWrap(await capFor(u.mb), u.recovery.id, { session: u.session, factorProof: await factorProof(u.mb, u.passkey) }));
    const { session: remover } = await openSession(u.mb, u.mailboxKey);
    const { rotation } = await rotationFor(u.mb, device.id);
    const answer = await mail().removeDevice(await capFor(u.mb), { deviceId: device.id, rotation }, { session: remover, factorProof: await factorProof(u.mb, u.passkey) });
    expect(refusalOf(answer)).toEqual({ name: "InvalidRequest", message: "invalid request: the new key must reach a recovery factor (M5′)" });
    expect((await view(u.mb)).devices.map((d) => d.id)).toEqual([device.id]);
  });

  it("after a rotation, removeWrap counts only recovery factors that reach the new key", async () => {
    const { u, spare } = await twoRecoveries();
    const device = await keepDevice(u);
    const { session: remover } = await openSession(u.mb, u.mailboxKey);
    const { rotation } = await rotationFor(u.mb, device.id);
    valueOf(await mail().removeDevice(await capFor(u.mb), { deviceId: device.id, rotation }, { session: remover, factorProof: await factorProof(u.mb, u.recovery) }));
    // The spare's wrap is of the retired key and it has no factor key: it does not reach the new one.
    expect(refusalOf(await mail().removeWrap(await capFor(u.mb), u.recovery.id, { session: remover, factorProof: await factorProof(u.mb, u.passkey) }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: the last recovery factor that reaches the active key cannot be removed",
    });
    valueOf(await mail().removeWrap(await capFor(u.mb), spare.id, { session: remover, factorProof: await factorProof(u.mb, u.recovery) }));
  });
});

describe("setFactorKey after a rotation (B7, F9)", () => {
  it("needs a seal of the active key for a factor whose wrap is of a retired key, and stores it with the factor's seals", async () => {
    const u = await upgradedMailbox({ passkeyLeftOut: true });
    const device: TestDevice = await keepDevice(u);
    const { session: remover } = await openSession(u.mb, u.mailboxKey);
    const { next, rotation } = await rotationFor(u.mb, device.id);
    valueOf(await mail().removeDevice(await capFor(u.mb), { deviceId: device.id, rotation }, { session: remover, factorProof: await factorProof(u.mb, u.recovery) }));
    const request = { factorId: u.passkey.id, factorKey: base64urlFromBytes(u.passkey.publicKey), tag: fakeTag(), tagKeyId: next.keyId, seal: null as string | null };
    expect(refusalOf(await mail().setFactorKey(await capFor(u.mb), request, { session: remover, factorProof: await factorProof(u.mb, u.recovery) })).name).toBe("InvalidRequest");
    const seal = fakeSeal(109);
    valueOf(await mail().setFactorKey(await capFor(u.mb), { ...request, seal }, { session: remover, factorProof: await factorProof(u.mb, u.recovery) }));
    expect((await view(u.mb)).seals).toContainEqual({ keyId: next.keyId, to: { kind: "factor", id: u.passkey.id }, sealed: seal });
    expect((await sql<{ detail: string }>(u.mb, "SELECT detail FROM audit WHERE action = 'factor-key-set'")).map((r) => JSON.parse(r.detail))).toEqual([
      { factor: u.passkey.id, kind: "passkey-prf", seal: true, via: u.recovery.id },
    ]);
  });
});
