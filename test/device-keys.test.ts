import { newId } from "@proprietor/mail-crypto";
import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  activeKeyId,
  challenge,
  deviceInput,
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
  type Proof,
  rotationFor,
  signProof,
  type TestFactor,
  type Upgraded,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { testId } from "./support/ids";
import { capFor, newKeyPair, passkeyWrap, provisionMailbox, recoveryWrap, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// contracts/device-v1.md B3, B5, B6, B7: factor proofs (M17), kept devices
// (M15, M21), factor keys, and wraps once sessions are required (M5′).

const mail = () => exports.MailService;
const MINUTE = 60 * 1000;

const SESSION_REQUIRED = { name: "SessionRequired", message: "a live mail session is required" };
const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };
const DEVICE_REVOKED = { name: "DeviceRevoked", message: "this device is not in the mailbox" };

const random = (n: number) => base64urlFromBytes(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (b64u: string) => base64urlFromBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", bytesFromBase64url(b64u))));
const now = (mb: TestMailbox) => mb.ports.clock.now().toISOString();

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function audits(mb: TestMailbox, action: string) {
  return (await sql<{ actor: string; detail: string }>(mb, "SELECT actor, detail FROM audit WHERE action = ? ORDER BY id", action)).map((r) => ({
    actor: r.actor,
    detail: JSON.parse(r.detail) as Record<string, unknown>,
  }));
}

const view = async (mb: TestMailbox) => valueOf(await mail().mailbox(await capFor(mb)));

/** A wrap a browser adds once sessions are required (B7): of the active key, with its factor key and a tag under it. */
async function keyedWrap(kind: "passkey-prf" | "recovery", keyId: string, over: Record<string, unknown> = {}) {
  const wrap = kind === "recovery" ? recoveryWrap(keyId, { label: "Printed sheet" }) : passkeyWrap(keyId, { label: "Second security key" });
  const factor = await newFactorKey(wrap.id, kind);
  return { factor, wrap: { ...wrap, factorKey: base64urlFromBytes(factor.publicKey), tag: fakeTag(), tagKeyId: keyId, ...over } };
}

/** A device session (F2): the key proof and the device's signature. */
const deviceSession = async (u: Upgraded, device: Awaited<ReturnType<typeof newDevice>>) =>
  (await openSession(u.mb, u.mailboxKey, { device })).session;

describe("factor proofs (B3, B6, M17)", () => {
  it("a factor challenge is sealed to that factor's key, which alone opens it", async () => {
    const u = await upgradedMailbox();
    const c = await challenge(u.mb, { purpose: "factor", factorId: u.passkey.id });
    expect(c).toMatchObject({ purpose: "factor", keyId: null, factorId: u.passkey.id });
    expect(bytesFromBase64url(await openChallenge(u.mb.id, c, u.passkey.pair))).toHaveLength(32);
    await expect(openChallenge(u.mb.id, c, u.mailboxKey)).rejects.toThrow();
    await expect(openChallenge(u.mb.id, c, u.recovery.pair)).rejects.toThrow();
  });

  /** Each method that needs a factor proof, as a call that succeeds with a good one. */
  async function factorCalls(u: Upgraded): Promise<[string, (proof?: Proof) => Promise<Parameters<typeof refusalOf>[0]>][]> {
    const keyId = u.mb.key!.keyId;
    const device = await newDevice();
    const added = await keyedWrap("passkey-prf", keyId);
    const left = await newFactorKey(u.passkey.id, "passkey-prf");
    // A plain session for the removal: the upgrade's own becomes the kept device's, and ends with it.
    const remover = (await openSession(u.mb, u.mailboxKey)).session;
    return [
      ["registerDevice", async (proof) => mail().registerDevice(await capFor(u.mb), { device: deviceInput(device, keyId), seal: fakeSeal(142) }, { session: u.session, factorProof: proof })],
      ["addWrap", async (proof) => mail().addWrap(await capFor(u.mb), added.wrap, { session: u.session, factorProof: proof })],
      [
        "setFactorKey",
        async (proof) =>
          mail().setFactorKey(
            await capFor(u.mb),
            { factorId: u.passkey.id, factorKey: base64urlFromBytes(left.publicKey), tag: fakeTag(), tagKeyId: keyId, seal: null },
            { session: u.session, factorProof: proof },
          ),
      ],
      ["removeWrap", async (proof) => mail().removeWrap(await capFor(u.mb), added.wrap.id, { session: u.session, factorProof: proof })],
      // Last: it rotates the key. The device is the one registerDevice kept above; the rotation is made from the view of the moment.
      [
        "removeDevice",
        async (proof) =>
          mail().removeDevice(await capFor(u.mb), { deviceId: device.id, rotation: (await rotationFor(u.mb, device.id)).rotation }, { session: remover, factorProof: proof }),
      ],
    ];
  }

  it("each method that needs one refuses without a factor proof, with a wrong, used or session one, and changes nothing; with a good one it works", async () => {
    // The passkey is left out of the upgrade, so setFactorKey has a factor to key; the recovery key proves.
    const u = await upgradedMailbox({ passkeyLeftOut: true });
    for (const [method, call] of await factorCalls(u)) {
      const before = await view(u.mb);
      expect([method, refusalOf(await call())]).toEqual([method, PROOF_REJECTED]);
      const wrong = await factorProof(u.mb, u.recovery);
      expect([method, refusalOf(await call({ ...wrong, answer: random(32) }))]).toEqual([method, PROOF_REJECTED]);
      expect([method, refusalOf(await call(wrong))]).toEqual([method, PROOF_REJECTED]);
      const sessionChallenge = await challenge(u.mb, { purpose: "session" });
      const asProof = { challengeId: sessionChallenge.id, answer: await openChallenge(u.mb.id, sessionChallenge, u.mailboxKey) };
      expect([method, refusalOf(await call(asProof))]).toEqual([method, PROOF_REJECTED]);
      expect(await view(u.mb)).toEqual(before);
      const good = await factorProof(u.mb, u.recovery);
      expect([method, (await call(good)).ok]).toEqual([method, true]);
      expect([method, refusalOf(await call(good))]).toEqual([method, PROOF_REJECTED]);
    }
    // Per method: the wrong answer, its reuse, the session challenge, and the good proof's reuse. A missing proof is not a proof, and is not audited.
    const reasons = (await audits(u.mb, "proof-rejected")).map((a) => a.detail.reason);
    expect(reasons).toEqual(Array.from({ length: 5 }, () => ["answer", "used", "purpose", "used"]).flat());
  });

  it("audits the replay of a spent factor proof once: five tries, one proof-rejected row", async () => {
    const u = await upgradedMailbox();
    const proof = await factorProof(u.mb, u.recovery);
    const add = async () => mail().addWrap(await capFor(u.mb), (await keyedWrap("passkey-prf", u.mb.key!.keyId)).wrap, { session: u.session, factorProof: proof });
    valueOf(await add());
    for (let i = 0; i < 5; i++) expect(refusalOf(await add())).toEqual(PROOF_REJECTED);
    expect((await audits(u.mb, "proof-rejected")).filter((a) => a.detail.challenge === proof.challengeId).map((a) => a.detail.reason)).toEqual(["used"]);
  });

  it("is spent by the call that carries it, whatever the call then answers", async () => {
    const u = await upgradedMailbox();
    const proof = await factorProof(u.mb, u.recovery);
    const device = await newDevice();
    const keyId = u.mb.key!.keyId;
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), { device: deviceInput(device, keyId, { label: "" }), seal: fakeSeal(142) }, { session: u.session, factorProof: proof })).name).toBe("InvalidRequest");
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), { device: deviceInput(device, keyId), seal: fakeSeal(142) }, { session: u.session, factorProof: proof }))).toEqual(PROOF_REJECTED);
  });

  it("refuses a proof for a factor removed since its challenge was made", async () => {
    const u = await upgradedMailbox();
    const fromPasskey = await factorProof(u.mb, u.passkey);
    valueOf(await mail().removeWrap(await capFor(u.mb), u.passkey.id, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) }));
    const device = await newDevice();
    expect(
      refusalOf(await mail().registerDevice(await capFor(u.mb), { device: deviceInput(device, u.mb.key!.keyId), seal: fakeSeal(142) }, { session: u.session, factorProof: fromPasskey })),
    ).toEqual(PROOF_REJECTED);
    expect((await audits(u.mb, "proof-rejected")).at(-1)!.detail).toEqual({ challenge: fromPasskey.challengeId, purpose: "factor", reason: "factor" });
  });

  it("refuses another account's proof, which stays its account's, and an expired one", async () => {
    const u = await upgradedMailbox();
    const theirs = await factorProof(u.mb, u.recovery, { sub: "acc_other" });
    const call = async (proof: Proof) =>
      mail().addWrap(await capFor(u.mb), (await keyedWrap("passkey-prf", u.mb.key!.keyId)).wrap, { session: u.session, factorProof: proof });
    expect(refusalOf(await call(theirs))).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", theirs.challengeId)).toEqual([{ used_at: null }]);
    expect(refusalOf(await call({ challengeId: newId("chl"), answer: random(32) }))).toEqual(PROOF_REJECTED);
    const late = await factorProof(u.mb, u.recovery);
    u.mb.ports.clock.advance(2 * MINUTE);
    expect(refusalOf(await call(late))).toEqual(PROOF_REJECTED);
    // Another account's challenge and one that does not exist spend nothing, and are not audited; the expired one is.
    expect((await audits(u.mb, "proof-rejected")).map((a) => a.detail.reason)).toEqual(["expired"]);
  });

  it("refuses a factor proof sent to a method that takes none", async () => {
    const u = await upgradedMailbox();
    const proof = await factorProof(u.mb, u.recovery);
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: u.session, factorProof: proof }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: this call takes no factor proof",
    });
  });
});

describe("registerDevice (B7, F1)", () => {
  it("keeps the device with a seal of the active key; the caller's session becomes the device's; audited device-registered", async () => {
    const u = await upgradedMailbox();
    const device = await newDevice({ label: "Office laptop" });
    const keyId = u.mb.key!.keyId;
    const input = deviceInput(device, keyId);
    const seal = fakeSeal(142);
    const answer = valueOf(await mail().registerDevice(await capFor(u.mb), { device: input, seal }, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) }));
    const at = now(u.mb);
    expect(answer).toEqual({
      id: device.id,
      label: "Office laptop",
      signingKey: input.signingKey, // pragma: allowlist secret (a public P-256 point)
      unlockKey: input.unlockKey,
      tag: input.tag,
      tagKeyId: keyId,
      createdAt: at,
      createdBy: "acc_owner",
      lastSeenAt: at,
    });
    const v = await view(u.mb);
    expect(v.devices).toEqual([answer]);
    expect(v.seals).toEqual([{ keyId, to: { kind: "device", id: device.id }, sealed: seal }]);
    expect(await sql(u.mb, "SELECT device_id FROM mail_sessions WHERE token_hash = ?", await sha256(u.session))).toEqual([{ device_id: device.id }]);
    expect(await audits(u.mb, "device-registered")).toEqual([
      { actor: "acc_owner", detail: { device: device.id, label: "Office laptop", unlockKey: true, factor: u.recovery.id } },
    ]);
  });

  it("keeps a device that keeps nothing (lock after: right away) with no unlock key and no seal", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u, { device: await newDevice({ keepsNothing: true }) });
    const v = await view(u.mb);
    expect(v.devices.map((d) => [d.id, d.unlockKey])).toEqual([[device.id, null]]);
    expect(v.seals).toEqual([]);
  });

  it("takes a seal exactly when there is an unlock key, of 142 bytes", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const keeps = await newDevice();
    const keepsNothing = await newDevice({ keepsNothing: true });
    for (const request of [
      { device: deviceInput(keeps, keyId), seal: null },
      { device: deviceInput(keeps, keyId) },
      { device: deviceInput(keeps, keyId), seal: fakeSeal(109) },
      { device: deviceInput(keeps, keyId), seal: random(143) },
      { device: deviceInput(keepsNothing, keyId), seal: fakeSeal(142) },
    ]) {
      expect(refusalOf(await mail().registerDevice(await capFor(u.mb), request, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) })).name).toBe("InvalidRequest");
    }
    expect((await view(u.mb)).devices).toEqual([]);
  });

  it("refuses public keys that are not uncompressed P-256 points on the curve", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const device = await newDevice();
    const offCurve = device.signingKey.slice();
    offCurve[64] = offCurve[64]! ^ 1;
    const compressed = Uint8Array.of(2 | (device.signingKey[64]! & 1), ...device.signingKey.slice(1, 33));
    const wrongLead = Uint8Array.of(5, ...device.signingKey.slice(1));
    for (const over of [
      { signingKey: base64urlFromBytes(offCurve) }, // pragma: allowlist secret (a test fixture: a malformed public P-256 point)
      { unlockKey: base64urlFromBytes(offCurve) },
      { signingKey: base64urlFromBytes(compressed) }, // pragma: allowlist secret (a test fixture: a malformed public P-256 point)
      { signingKey: base64urlFromBytes(wrongLead) }, // pragma: allowlist secret (a test fixture: a malformed public P-256 point)
      { unlockKey: random(65) },
      { signingKey: null },
    ]) {
      const answer = await mail().registerDevice(await capFor(u.mb), { device: deviceInput(device, keyId, over), seal: fakeSeal(142) }, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) });
      expect([Object.keys(over)[0], refusalOf(answer).name]).toEqual([Object.keys(over)[0], "InvalidRequest"]);
    }
  });

  it("takes a label of 1 to 40 characters on one line, in any script", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    for (const label of ["", "x".repeat(41), "Office\nlaptop", "Office laptop", "Office\u0000", "\uD800 broken"]) {
      const device = await newDevice({ label });
      expect([label, refusalOf(await mail().registerDevice(await capFor(u.mb), { device: deviceInput(device, keyId), seal: fakeSeal(142) }, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) })).name]).toEqual([label, "InvalidRequest"]);
    }
    const forty = "鍵".repeat(20) + "🔑".repeat(20);
    expect([...forty]).toHaveLength(40);
    await keepDevice(u, { device: await newDevice({ label: forty }) });
    expect((await view(u.mb)).devices.map((d) => d.label)).toEqual([forty]);
  });

  it("refuses a tag that is not 32 bytes or not under the active key, an id in use, and a 21st device", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const device = await newDevice();
    const register = async (input: Record<string, unknown>) =>
      mail().registerDevice(await capFor(u.mb), { device: input, seal: fakeSeal(142) }, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) });
    expect(refusalOf(await register(deviceInput(device, keyId, { tag: random(31) }))).name).toBe("InvalidRequest");
    expect(refusalOf(await register(deviceInput(device, (await newKeyPair()).keyId)))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: a tag must be made under the active key",
    });
    await keepDevice(u, { device });
    expect(refusalOf(await register(deviceInput(device, keyId)))).toEqual({ name: "InvalidRequest", message: "invalid request: that device id is in use" });
    for (let i = 1; i < 20; i++) await keepDevice(u);
    expect((await view(u.mb)).devices).toHaveLength(20);
    expect(refusalOf(await register(deviceInput(await newDevice(), keyId)))).toEqual({ name: "InvalidRequest", message: "invalid request: a mailbox keeps at most 20 devices" });
  });

  it("is refused while sessions are optional (upgrade first), and is the owner's", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const { session } = await openSession(mb, mailboxKey);
    expect(refusalOf(await mail().registerDevice(await capFor(mb), { device: deviceInput(await newDevice(), mb.key!.keyId), seal: fakeSeal(142) }, { session }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: sessions are not on for this mailbox: upgrade first",
    });
    expect(refusalOf(await mail().registerDevice(await capFor(mb, { role: "editor" }), {}, { session }))).toEqual({ name: "Forbidden", message: "forbidden" });
  });
});

describe("device sessions (B6, M15, M21)", () => {
  it("a kept device opens its own session with its signature, and its lastSeenAt moves", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    u.mb.ports.clock.advance(5 * MINUTE);
    const opened = await openSession(u.mb, u.mailboxKey, { device });
    expect(opened.device).toBe(device.id);
    expect(await sql(u.mb, "SELECT device_id FROM mail_sessions WHERE token_hash = ?", await sha256(opened.session))).toEqual([{ device_id: device.id }]);
    expect((await view(u.mb)).devices[0]!.lastSeenAt).toBe(now(u.mb));
  });

  it("refuses a signature over another nonce (audited) and one by another key, and either spends the challenge", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
    const otherNonce = await signProof(u.mb.id, device, { ...c, nonce: random(32) });
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: { id: device.id, signature: otherNonce } }))).toEqual(PROOF_REJECTED);
    expect((await audits(u.mb, "proof-rejected")).at(-1)!.detail).toEqual({ challenge: c.id, purpose: "session", reason: "signature" });
    expect(
      refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: { id: device.id, signature: await signProof(u.mb.id, device, c) } })),
    ).toEqual(PROOF_REJECTED);
    const c2 = await challenge(u.mb, { purpose: "session" });
    const stranger = await newDevice();
    const byStranger = await signProof(u.mb.id, device, c2, stranger.signing);
    expect(
      refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c2.id, answer: await openChallenge(u.mb.id, c2, u.mailboxKey), device: { id: device.id, signature: byStranger } })),
    ).toEqual(PROOF_REJECTED);
  });

  it("answers DeviceRevoked for an unknown device and for another account's device (M21, G42)", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const unknown = await newDevice();
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: { id: unknown.id, signature: await signProof(u.mb.id, unknown, c) } }))).toEqual(DEVICE_REVOKED);
    // Another person of the business, holding the key, presenting the owner's device with a good signature.
    const theirs = await challenge(u.mb, { purpose: "session" }, { sub: "acc_other" });
    const signed = { id: device.id, signature: await signProof(u.mb.id, device, theirs) };
    expect(
      refusalOf(await mail().openSession(await capFor(u.mb, { sub: "acc_other" }), { challengeId: theirs.id, answer: await openChallenge(u.mb.id, theirs, u.mailboxKey), device: signed })),
    ).toEqual(DEVICE_REVOKED);
  });

  it("deletes a session whose device is gone and answers DeviceRevoked (B2); then the token is simply unknown", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const session = await deviceSession(u, device);
    await sql(u.mb, "DELETE FROM devices WHERE id = ?", device.id);
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session }))).toEqual(DEVICE_REVOKED);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions WHERE token_hash = ?", await sha256(session))).toEqual([{ n: 0 }]);
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session }))).toEqual(SESSION_REQUIRED);
  });
});

describe("updateDevice (B7, F3, F4)", () => {
  it("locks the device: its unlock key and seals are cleared and its tag replaced, audited device-unlock-key cleared", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const session = await deviceSession(u, device);
    const keyId = u.mb.key!.keyId;
    const tag = fakeTag();
    const answer = valueOf(await mail().updateDevice(await capFor(u.mb), { unlockKey: null, tag, tagKeyId: keyId, seal: null }, { session }));
    expect(answer).toMatchObject({ id: device.id, unlockKey: null, tag, tagKeyId: keyId });
    expect((await view(u.mb)).seals).toEqual([]);
    expect((await audits(u.mb, "device-unlock-key")).at(-1)).toEqual({ actor: "acc_owner", detail: { device: device.id, unlockKey: "cleared" } });
  });

  it("unlocks it again: a new unlock key, tag and seal, and none of its earlier seals", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const session = await deviceSession(u, device);
    const keyId = u.mb.key!.keyId;
    const fresh = await newDevice();
    const unlockKey = base64urlFromBytes(fresh.unlockKey!);
    const seal = fakeSeal(142);
    const answer = valueOf(await mail().updateDevice(await capFor(u.mb), { unlockKey, tag: fakeTag(), tagKeyId: keyId, seal }, { session }));
    expect(answer.unlockKey).toBe(unlockKey);
    expect((await view(u.mb)).seals).toEqual([{ keyId, to: { kind: "device", id: device.id }, sealed: seal }]);
    expect((await audits(u.mb, "device-unlock-key")).at(-1)!.detail).toEqual({ device: device.id, unlockKey: "set" });
  });

  it("is only for that device's own session", async () => {
    const u = await upgradedMailbox();
    await keepDevice(u);
    const keyId = u.mb.key!.keyId;
    const { session: plain } = await openSession(u.mb, u.mailboxKey);
    const request = { unlockKey: null, tag: fakeTag(), tagKeyId: keyId, seal: null };
    expect(refusalOf(await mail().updateDevice(await capFor(u.mb), request, { session: plain }))).toEqual(SESSION_REQUIRED);
    expect(refusalOf(await mail().updateDevice(await capFor(u.mb), request))).toEqual(SESSION_REQUIRED);
  });

  it("refuses an unlock key off the curve, a seal of the wrong length or without an unlock key, one missing, and a tag under another key", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const session = await deviceSession(u, device);
    const keyId = u.mb.key!.keyId;
    const point = base64urlFromBytes((await newDevice()).unlockKey!);
    const offCurve = bytesFromBase64url(point);
    offCurve[64] = offCurve[64]! ^ 1;
    for (const request of [
      { unlockKey: base64urlFromBytes(offCurve), tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: point, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(109) },
      { unlockKey: point, tag: fakeTag(), tagKeyId: keyId, seal: null },
      { unlockKey: null, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: point, tag: fakeTag(), tagKeyId: keyId },
      { unlockKey: point, tag: fakeTag(), tagKeyId: (await newKeyPair()).keyId, seal: fakeSeal(142) },
      { unlockKey: point, tag: random(16), tagKeyId: keyId, seal: fakeSeal(142) },
    ]) {
      expect(refusalOf(await mail().updateDevice(await capFor(u.mb), request, { session })).name).toBe("InvalidRequest");
    }
    expect((await view(u.mb)).devices[0]!.unlockKey).toBe(base64urlFromBytes(device.unlockKey!));
  });
});

describe("setFactorKey (B7, F9)", () => {
  it("gives a factor without one its key, proved by another factor, with no seal while its wrap is of the active key; audited factor-key-set", async () => {
    const u = await upgradedMailbox({ passkeyLeftOut: true });
    const keyId = u.mb.key!.keyId;
    const tag = fakeTag();
    const request = { factorId: u.passkey.id, factorKey: base64urlFromBytes(u.passkey.publicKey), tag, tagKeyId: keyId, seal: null };
    expect(await mail().setFactorKey(await capFor(u.mb), request, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) })).toEqual({ ok: true, value: null });
    expect((await view(u.mb)).wraps.find((w) => w.id === u.passkey.id)).toMatchObject({ factorKey: request.factorKey, tag, tagKeyId: keyId });
    expect(await audits(u.mb, "factor-key-set")).toEqual([{ actor: "acc_owner", detail: { factor: u.passkey.id, kind: "passkey-prf", seal: false, via: u.recovery.id } }]);
    // From now on the passkey proves for itself.
    await factorProof(u.mb, u.passkey);
  });

  it("refuses a proof from the factor being keyed, a factor that has a key, and an unknown factor", async () => {
    const u = await upgradedMailbox({ passkeyLeftOut: true });
    const keyId = u.mb.key!.keyId;
    const other = await newFactorKey(testId("wrp"), "recovery");
    const set = async (factorId: string, factor: TestFactor) =>
      mail().setFactorKey(
        await capFor(u.mb),
        { factorId, factorKey: base64urlFromBytes(other.publicKey), tag: fakeTag(), tagKeyId: keyId, seal: null },
        { session: u.session, factorProof: await factorProof(u.mb, factor) },
      );
    expect(refusalOf(await set(u.recovery.id, u.recovery))).toEqual({ name: "InvalidRequest", message: "invalid request: the factor proof must come from another factor" });
    // A second recovery key, keyed, to prove with.
    const second = await keyedWrap("recovery", keyId);
    valueOf(await mail().addWrap(await capFor(u.mb), second.wrap, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) }));
    expect(refusalOf(await set(u.recovery.id, second.factor))).toEqual({ name: "InvalidRequest", message: "invalid request: that factor already has a factor key" });
    expect(refusalOf(await set(testId("wrp"), u.recovery))).toEqual({ name: "InvalidRequest", message: "invalid request: no such factor" });
  });

  it("refuses an unusable factor key, a tag not under the active key, and a seal while the wrap is of the active key", async () => {
    const u = await upgradedMailbox({ passkeyLeftOut: true });
    const keyId = u.mb.key!.keyId;
    const good = { factorId: u.passkey.id, factorKey: base64urlFromBytes(u.passkey.publicKey), tag: fakeTag(), tagKeyId: keyId, seal: null };
    for (const over of [
      { factorKey: base64urlFromBytes(new Uint8Array(32)) },
      { factorKey: random(33) },
      { tagKeyId: (await newKeyPair()).keyId },
      { seal: fakeSeal(109) },
      { seal: undefined },
    ]) {
      const answer = await mail().setFactorKey(await capFor(u.mb), { ...good, ...over }, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) });
      expect([Object.keys(over)[0], refusalOf(answer).name]).toEqual([Object.keys(over)[0], "InvalidRequest"]);
    }
    expect((await view(u.mb)).wraps.find((w) => w.id === u.passkey.id)!.factorKey).toBeNull();
  });

  it("is refused while sessions are optional", async () => {
    const { mb, mailboxKey, passkeyId } = await legacyMailbox();
    const { session } = await openSession(mb, mailboxKey);
    const passkey = await newFactorKey(passkeyId, "passkey-prf");
    const request = { factorId: passkeyId, factorKey: base64urlFromBytes(passkey.publicKey), tag: fakeTag(), tagKeyId: mb.key!.keyId, seal: null };
    expect(refusalOf(await mail().setFactorKey(await capFor(mb), request, { session }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: sessions are not on for this mailbox: upgrade first",
    });
  });
});

describe("addWrap and removeWrap once sessions are required (B7, M5′, R8)", () => {
  it("addWrap takes a wrap of the active key with its factor key and a tag under that key, and the new factor proves at once (R8)", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const added = await keyedWrap("passkey-prf", keyId);
    valueOf(await mail().addWrap(await capFor(u.mb), added.wrap, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) }));
    expect((await view(u.mb)).wraps.find((w) => w.id === added.wrap.id)).toMatchObject({
      keyId,
      kind: "passkey-prf",
      factorKey: added.wrap.factorKey,
      tag: added.wrap.tag,
      tagKeyId: keyId,
    });
    expect((await audits(u.mb, "wrap-added")).at(-1)!.detail).toEqual({ wrap: added.wrap.id, kind: "passkey-prf" });
    await factorProof(u.mb, added.factor);
  });

  it("addWrap refuses a wrap without a factor key or tag, with a tag under another key, of another key, or with an unusable factor key", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const other = (await newKeyPair()).keyId;
    for (const over of [
      { factorKey: undefined },
      { tag: undefined },
      { tagKeyId: undefined },
      { tagKeyId: other },
      { keyId: other, tagKeyId: other },
      { factorKey: base64urlFromBytes(new Uint8Array(32)) },
      { label: "a\uD800" },
    ]) {
      const { wrap } = await keyedWrap("passkey-prf", keyId, over);
      const answer = await mail().addWrap(await capFor(u.mb), JSON.parse(JSON.stringify(wrap)), { session: u.session, factorProof: await factorProof(u.mb, u.recovery) });
      expect([JSON.stringify(over), refusalOf(answer).name]).toEqual([JSON.stringify(over), "InvalidRequest"]);
    }
    expect((await view(u.mb)).wraps).toHaveLength(2);
  });

  it("removeWrap removes a factor, and refuses the last recovery factor that reaches the active key (M5′)", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const remove = async (id: string, by: TestFactor) => mail().removeWrap(await capFor(u.mb), id, { session: u.session, factorProof: await factorProof(u.mb, by) });
    expect(refusalOf(await remove(u.recovery.id, u.passkey))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: the last recovery factor that reaches the active key cannot be removed",
    });
    const second = await keyedWrap("recovery", keyId);
    valueOf(await mail().addWrap(await capFor(u.mb), second.wrap, { session: u.session, factorProof: await factorProof(u.mb, u.recovery) }));
    valueOf(await remove(u.recovery.id, u.recovery));
    valueOf(await remove(u.passkey.id, second.factor));
    expect((await view(u.mb)).wraps.map((w) => w.id)).toEqual([second.wrap.id]);
    expect(refusalOf(await remove(second.wrap.id, second.factor)).name).toBe("InvalidRequest");
    expect((await audits(u.mb, "wrap-removed")).map((a) => a.detail.wrap)).toEqual([u.recovery.id, u.passkey.id]);
  });
});

describe("enroll with factor keys and a device (B5, F12)", () => {
  async function enrolment(mb: TestMailbox, opts: { device?: boolean } = {}) {
    const key = await newKeyPair();
    const recovery = await keyedWrap("recovery", key.keyId);
    const passkey = await keyedWrap("passkey-prf", key.keyId);
    const device = await newDevice({ label: "Front desk" });
    const seal = fakeSeal(142);
    const request = {
      publicKey: base64urlFromBytes(key.publicKey),
      wraps: [recovery.wrap, passkey.wrap],
      ...(opts.device === false ? {} : { device: { device: deviceInput(device, key.keyId), seal } }),
    };
    return { key, recovery, passkey, device, seal, request };
  }

  it("starts sessions required when every wrap carries a factor key, and keeps the enrolling device with its seal", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mb);
    expect(await mail().enroll(await capFor(mb), e.request)).toEqual({ ok: true, value: { keyId: e.key.keyId } });
    const v = await view(mb);
    expect(v.status).toBe("active");
    expect(v.sessions).toBe("required");
    expect(v.wraps.map((w) => [w.id, w.factorKey, w.tagKeyId])).toEqual(
      expect.arrayContaining([
        [e.recovery.wrap.id, e.recovery.wrap.factorKey, e.key.keyId],
        [e.passkey.wrap.id, e.passkey.wrap.factorKey, e.key.keyId],
      ]),
    );
    expect(v.devices).toEqual([expect.objectContaining({ id: e.device.id, label: "Front desk", tagKeyId: e.key.keyId, createdBy: "acc_owner", lastSeenAt: null })]);
    expect(v.seals).toEqual([{ keyId: e.key.keyId, to: { kind: "device", id: e.device.id }, sealed: e.seal }]);
    // F12's last step: the enrolling browser opens its device session.
    const { device } = await openSession(mb, await mailboxKeyPair(e.key), { device: e.device });
    expect(device).toBe(e.device.id);
  });

  it("refuses wraps that mix factor keys and none, a device without factor keys, and a device that is not under the new key", async () => {
    const mixed = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mixed);
    const plain = { ...e.request, wraps: [e.recovery.wrap, passkeyWrap(e.key.keyId)] };
    expect(refusalOf(await mail().enroll(await capFor(mixed), plain))).toEqual({ name: "InvalidRequest", message: "invalid request: either every wrap carries a factor key or none does" });
    const noKeys = { publicKey: e.request.publicKey, wraps: [recoveryWrap(e.key.keyId)], device: e.request.device };
    expect(refusalOf(await mail().enroll(await capFor(mixed), noKeys))).toEqual({ name: "InvalidRequest", message: "invalid request: a device needs factor keys" });
    const otherKey = (await newKeyPair()).keyId;
    const staleDevice = { ...e.request, device: { device: deviceInput(e.device, otherKey), seal: e.seal } };
    expect(refusalOf(await mail().enroll(await capFor(mixed), staleDevice)).name).toBe("InvalidRequest");
    const staleWrapTag = { ...e.request, wraps: [{ ...e.recovery.wrap, tagKeyId: otherKey }, e.passkey.wrap] };
    expect(refusalOf(await mail().enroll(await capFor(mixed), staleWrapTag)).name).toBe("InvalidRequest");
    const noSeal = { ...e.request, device: { device: deviceInput(e.device, e.key.keyId), seal: null } };
    expect(refusalOf(await mail().enroll(await capFor(mixed), noSeal)).name).toBe("InvalidRequest");
    const v = await view(mixed);
    expect([v.status, v.sessions, v.keys, v.devices]).toEqual(["provisioned", "optional", [], []]);
  });

  it("an enrolment with factor keys and no device is fine, and M5 still wants a recovery wrap", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mb, { device: false });
    expect(refusalOf(await mail().enroll(await capFor(mb), { ...e.request, wraps: [e.passkey.wrap] }))).toEqual({ name: "InvalidRequest", message: "invalid request: a recovery wrap is required" });
    valueOf(await mail().enroll(await capFor(mb), e.request));
    expect((await view(mb)).sessions).toBe("required");
  });
});
