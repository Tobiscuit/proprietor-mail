import { newId } from "@proprietor/mail-crypto";
import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  type Action,
  activeKeyId,
  addFactorAction,
  admitDevice,
  challenge,
  cycleAdmissions,
  deviceInput,
  factorOf,
  factorProof,
  fakeSeal,
  fakeTag,
  keepDevice,
  keyedWrap,
  legacyMailbox,
  mailboxKeyPair,
  newDevice,
  newUnlockKey,
  openChallenge,
  openSession,
  plainSession,
  type Proof,
  registerAction,
  registerRequest,
  removeDevicesAction,
  removeFactorAction,
  rotationFor,
  signProof,
  signUnlockKey,
  type TestFactor,
  type Upgraded,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { testId } from "./support/ids";
import { capFor, newKeyPair, passkeyWrap, provisionMailbox, recoveryWrap, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// contracts/device-v1.md B3, B5, B6, B7: factor proofs (M17′), kept devices
// (M15′, M21′), factor keys, and wraps once sessions are required (M5′, M24),
// as round 3 amends them: every factor proof bound to its call's request,
// and every admission and unlock key signed (M25).

const mail = () => exports.MailService;
const MINUTE = 60 * 1000;

const SESSION_REQUIRED = { name: "SessionRequired", message: "a live mail session is required" };
const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };
const DEVICE_REVOKED = { name: "DeviceRevoked", message: "this device is not in the mailbox" };
const FORBIDDEN = { name: "Forbidden", message: "forbidden" };

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

/** registerDevice with `factor`'s proof bound to exactly this request. */
async function register(u: Upgraded, request: { device: Record<string, unknown>; seal: unknown }, factor: TestFactor = u.recovery, session = u.session) {
  const proof = await factorProof(u.mb, factor, registerAction(request as never));
  return mail().registerDevice(await capFor(u.mb), request, { session, factorProof: proof });
}

/** addWrap with `factor`'s proof bound to exactly this wrap. */
async function addWrap(u: Upgraded, wrap: Record<string, unknown>, factor: TestFactor = u.recovery, session = u.session) {
  return mail().addWrap(await capFor(u.mb), wrap, { session, factorProof: await factorProof(u.mb, factor, addFactorAction(wrap)) });
}

/** removeWrap with `factor`'s proof bound to exactly this wrap id. */
async function removeWrap(u: Upgraded, wrapId: string, factor: TestFactor, session = u.session) {
  return mail().removeWrap(await capFor(u.mb), wrapId, { session, factorProof: await factorProof(u.mb, factor, removeFactorAction(wrapId)) });
}

/** A device session (F2): the key proof and the device's signature. */
const deviceSession = async (u: Upgraded, device: Awaited<ReturnType<typeof newDevice>>) =>
  (await openSession(u.mb, u.mailboxKey, { device })).session;

describe("factor proofs (B3, B6, M17′)", () => {
  it("a factor challenge is sealed to that factor's key, which alone opens it, with its action's digest", async () => {
    const u = await upgradedMailbox();
    const c = await challenge(u.mb, { purpose: "factor", factorId: u.passkey.id, action: { kind: "remove-factor", request: random(32) } });
    expect(c).toMatchObject({ purpose: "factor", keyId: null, factorId: u.passkey.id, descriptor: expect.any(String) });
    expect(bytesFromBase64url(await openChallenge(u.mb.id, c, u.passkey.pair))).toHaveLength(32);
    await expect(openChallenge(u.mb.id, c, u.mailboxKey)).rejects.toThrow();
    await expect(openChallenge(u.mb.id, c, u.recovery.pair)).rejects.toThrow();
    // A6: the aad ends with the descriptor's digest; another digest opens nothing.
    await expect(openChallenge(u.mb.id, c, u.passkey.pair, random(32))).rejects.toThrow();
  });

  /** Each method that needs a factor proof, as a request and the call that sends it with a proof; each succeeds with a good one. */
  async function factorCalls(u: Upgraded): Promise<[string, Action, (proof?: Proof) => Promise<Parameters<typeof refusalOf>[0]>][]> {
    const device = await newDevice();
    const added = await keyedWrap(u.mb, "passkey-prf", u.mb.key!.keyId, u.recovery);
    const registration = await registerRequest(u, device, u.recovery);
    // A plain session for the removal: the upgrade's own becomes the kept device's, and ends with it.
    const remover = await plainSession(u);
    const removal = { deviceIds: [device.id], rotation: (await rotationFor(u.mb, device.id, u.recovery)).rotation };
    return [
      ["registerDevice", registerAction(registration), async (proof) => mail().registerDevice(await capFor(u.mb), registration, { session: u.session, factorProof: proof })],
      ["addWrap", addFactorAction(added.wrap), async (proof) => mail().addWrap(await capFor(u.mb), added.wrap, { session: u.session, factorProof: proof })],
      ["removeWrap", removeFactorAction(added.wrap.id), async (proof) => mail().removeWrap(await capFor(u.mb), added.wrap.id, { session: u.session, factorProof: proof })],
      // Last: it rotates the key. The device is the one registerDevice kept above; the rotation was made from the view after it.
      ["removeDevices", removeDevicesAction(removal), async (proof) => mail().removeDevices(await capFor(u.mb), removal, { session: remover, factorProof: proof })],
    ];
  }

  it("each method that needs one refuses without a factor proof, with a wrong, used or session one, and changes nothing; with a good one it works", async () => {
    const u = await upgradedMailbox();
    // removeDevices' rotation was made before registerDevice kept the device it removes: it names the same remaining recipients either way.
    for (const [method, bound, run] of await factorCalls(u)) {
      const before = await view(u.mb);
      expect([method, refusalOf(await run())]).toEqual([method, PROOF_REJECTED]);
      const wrong = await factorProof(u.mb, u.recovery, bound);
      expect([method, refusalOf(await run({ ...wrong, answer: random(32) }))]).toEqual([method, PROOF_REJECTED]);
      expect([method, refusalOf(await run(wrong))]).toEqual([method, PROOF_REJECTED]);
      const sessionChallenge = await challenge(u.mb, { purpose: "session" });
      const asProof = { challengeId: sessionChallenge.id, answer: await openChallenge(u.mb.id, sessionChallenge, u.mailboxKey) };
      expect([method, refusalOf(await run(asProof))]).toEqual([method, PROOF_REJECTED]);
      expect(await view(u.mb)).toEqual(before);
      const good = await factorProof(u.mb, u.recovery, bound);
      expect([method, (await run(good)).ok]).toEqual([method, true]);
      expect([method, refusalOf(await run(good))]).toEqual([method, PROOF_REJECTED]);
    }
    // Per method: the wrong answer, its reuse, the session challenge, and the good proof's reuse. A missing proof is not a proof, and is not audited.
    const reasons = (await audits(u.mb, "proof-rejected")).map((a) => a.detail.reason);
    expect(reasons).toEqual(Array.from({ length: 4 }, () => ["answer", "used", "purpose", "used"]).flat());
  });

  it("audits the replay of a spent factor proof once: five tries, one proof-rejected row", async () => {
    const u = await upgradedMailbox();
    const { wrap } = await keyedWrap(u.mb, "passkey-prf", u.mb.key!.keyId, u.recovery);
    const proof = await factorProof(u.mb, u.recovery, addFactorAction(wrap));
    const add = async () => mail().addWrap(await capFor(u.mb), wrap, { session: u.session, factorProof: proof });
    valueOf(await add());
    for (let i = 0; i < 5; i++) expect(refusalOf(await add())).toEqual(PROOF_REJECTED);
    expect((await audits(u.mb, "proof-rejected")).filter((a) => a.detail.challenge === proof.challengeId).map((a) => a.detail.reason)).toEqual(["used"]);
  });

  it("is spent by the call that carries it, whatever the call then answers", async () => {
    const u = await upgradedMailbox();
    const device = await newDevice();
    const bad = await registerRequest(u, device, u.recovery, { tag: random(31) });
    const proof = await factorProof(u.mb, u.recovery, registerAction(bad));
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), bad, { session: u.session, factorProof: proof })).name).toBe("InvalidRequest");
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), bad, { session: u.session, factorProof: proof }))).toEqual(PROOF_REJECTED);
  });

  it("refuses a proof for a factor removed since its challenge was made (M24: never accepted again)", async () => {
    const u = await upgradedMailbox();
    const device = await newDevice();
    const request = await registerRequest(u, device, u.passkey);
    const fromPasskey = await factorProof(u.mb, u.passkey, registerAction(request));
    valueOf(await removeWrap(u, u.passkey.id, u.recovery));
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), request, { session: u.session, factorProof: fromPasskey }))).toEqual(PROOF_REJECTED);
    expect((await audits(u.mb, "proof-rejected")).at(-1)!.detail).toEqual({ challenge: fromPasskey.challengeId, purpose: "factor", reason: "factor" });
    // And no new challenge is issued to it.
    expect(refusalOf(await mail().challenge(await capFor(u.mb), { purpose: "factor", factorId: u.passkey.id, action: { kind: "remove-factor", request: random(32) } }))).toEqual({
      name: "NotFound",
      message: "not found",
    });
  });

  it("refuses another account's proof, which stays its account's, and an expired one", async () => {
    const u = await upgradedMailbox();
    const { wrap } = await keyedWrap(u.mb, "passkey-prf", u.mb.key!.keyId, u.recovery);
    const theirs = await factorProof(u.mb, u.recovery, addFactorAction(wrap), { sub: "acc_other" });
    const call = async (proof: Proof) => mail().addWrap(await capFor(u.mb), wrap, { session: u.session, factorProof: proof });
    expect(refusalOf(await call(theirs))).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", theirs.challengeId)).toEqual([{ used_at: null }]);
    expect(refusalOf(await call({ challengeId: newId("chl"), answer: random(32) }))).toEqual(PROOF_REJECTED);
    const late = await factorProof(u.mb, u.recovery, addFactorAction(wrap));
    u.mb.ports.clock.advance(2 * MINUTE);
    expect(refusalOf(await call(late))).toEqual(PROOF_REJECTED);
    // Another account's challenge and one that does not exist spend nothing, and are not audited; the expired one is.
    expect((await audits(u.mb, "proof-rejected")).map((a) => a.detail.reason)).toEqual(["expired"]);
  });

  it("refuses a factor proof sent to a method that takes none, and a key proof to any method but upgrade", async () => {
    const u = await upgradedMailbox();
    const { wrap } = await keyedWrap(u.mb, "passkey-prf", u.mb.key!.keyId, u.recovery);
    const proof = await factorProof(u.mb, u.recovery, addFactorAction(wrap));
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: u.session, factorProof: proof }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: this call takes no factor proof",
    });
    expect(refusalOf(await mail().addWrap(await capFor(u.mb), wrap, { session: u.session, factorProof: proof, keyProof: proof }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: this call takes no key proof",
    });
    // Neither refusal spent the proof.
    valueOf(await mail().addWrap(await capFor(u.mb), wrap, { session: u.session, factorProof: proof }));
  });
});

describe("registerDevice (B7, F1)", () => {
  it("keeps the device with a seal of the active key; the caller's session becomes the device's; audited device-registered", async () => {
    const u = await upgradedMailbox();
    const device = await newDevice({ label: "Office laptop" });
    const keyId = u.mb.key!.keyId;
    const request = await registerRequest(u, device, u.recovery);
    const answer = valueOf(await register(u, request));
    const at = now(u.mb);
    expect(answer).toEqual({
      id: device.id,
      label: "Office laptop",
      signingKey: request.device.signingKey, // pragma: allowlist secret (a public P-256 point)
      unlockKey: request.device.unlockKey,
      unlockSignature: request.device.unlockSignature,
      admission: request.device.admission,
      tag: request.device.tag,
      tagKeyId: keyId,
      createdAt: at,
      createdBy: "acc_owner",
      lastSeenAt: at,
    });
    const v = await view(u.mb);
    expect(v.devices).toEqual([answer]);
    expect(v.seals).toEqual([{ keyId, to: { kind: "device", id: device.id }, sealed: request.seal }]);
    expect(await sql(u.mb, "SELECT device_id FROM mail_sessions WHERE token_hash = ?", await sha256(u.session))).toEqual([{ device_id: device.id }]);
    expect(await audits(u.mb, "device-registered")).toEqual([
      { actor: "acc_owner", detail: { device: device.id, label: "Office laptop", unlockKey: true, factor: u.recovery.id } },
    ]);
  });

  it("keeps a device that keeps nothing (lock after: right away) with no unlock key, no unlock signature and no seal", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u, { device: await newDevice({ keepsNothing: true }) });
    const v = await view(u.mb);
    expect(v.devices.map((d) => [d.id, d.unlockKey, d.unlockSignature])).toEqual([[device.id, null, null]]);
    expect(v.seals).toEqual([]);
  });

  it("takes a seal exactly when there is an unlock key, of 142 bytes", async () => {
    const u = await upgradedMailbox();
    const keeps = await newDevice();
    const keepsNothing = await newDevice({ keepsNothing: true });
    const keepsInput = (await registerRequest(u, keeps, u.recovery)).device;
    const nothingInput = (await registerRequest(u, keepsNothing, u.recovery)).device;
    for (const request of [
      { device: keepsInput, seal: null },
      { device: keepsInput, seal: fakeSeal(109) },
      { device: keepsInput, seal: random(143) },
      { device: nothingInput, seal: fakeSeal(142) },
    ]) {
      expect(refusalOf(await register(u, request)).name).toBe("InvalidRequest");
    }
    expect((await view(u.mb)).devices).toEqual([]);
  });

  it("refuses public keys that are not uncompressed P-256 points on the curve", async () => {
    const u = await upgradedMailbox();
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
      const answer = await register(u, await registerRequest(u, device, u.recovery, over));
      expect([Object.keys(over)[0], refusalOf(answer).name]).toEqual([Object.keys(over)[0], "InvalidRequest"]);
    }
  });

  it("takes a label of 1 to 40 characters on one line, in any script; none of U+0000-U+001F, U+007F-U+009F, U+2028, U+2029 (action-descriptor-v1)", async () => {
    const u = await upgradedMailbox();
    // Such a device cannot be described (Mail issues no challenge naming it), so no proof can confirm it either.
    const sendable = await registerRequest(u, await newDevice(), u.recovery);
    for (const label of ["", "x".repeat(41), "Office\nlaptop", "Office\u0000", "\uD800 broken", "Office\u007f", "Office\u0085", "Office\u009f", "Office\u2028", "Office\u2029"]) {
      const device = await newDevice({ label });
      // Labels go into the expectations escaped: a lone surrogate cannot cross the test pool's WebSocket.
      const named = JSON.stringify(label);
      const action = { kind: "register-device", device: { id: device.id, label }, request: random(32) };
      expect([named, refusalOf(await mail().challenge(await capFor(u.mb), { purpose: "factor", factorId: u.recovery.id, action })).name]).toEqual([named, "InvalidRequest"]);
      const request = await registerRequest(u, device, u.recovery);
      const elsewhere = await factorProof(u.mb, u.recovery, registerAction(sendable));
      // A lone surrogate is not even serializable as A10 says, so that request is InvalidRequest; any other names a device no proof was for.
      const expected = label.includes("\uD800") ? "InvalidRequest" : "ProofRejected";
      expect([named, refusalOf(await mail().registerDevice(await capFor(u.mb), request, { session: u.session, factorProof: elsewhere })).name]).toEqual([named, expected]);
    }
    expect((await view(u.mb)).devices).toEqual([]);
    const forty = "鍵".repeat(20) + "🔑".repeat(20);
    expect([...forty]).toHaveLength(40);
    await keepDevice(u, { device: await newDevice({ label: forty }) });
    expect((await view(u.mb)).devices.map((d) => d.label)).toEqual([forty]);
  });

  it("refuses a tag that is not 32 bytes or not under the active key, an id in use, and a 21st device", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const device = await newDevice();
    expect(refusalOf(await register(u, await registerRequest(u, device, u.recovery, { tag: random(31) }))).name).toBe("InvalidRequest");
    expect(refusalOf(await register(u, await registerRequest(u, device, u.recovery, { tagKeyId: (await newKeyPair()).keyId })))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: a tag must be made under the active key",
    });
    await keepDevice(u, { device });
    expect(refusalOf(await register(u, await registerRequest(u, device, u.recovery)))).toEqual({ name: "InvalidRequest", message: "invalid request: that device id is in use" });
    // Eighteen more, written directly (the test is about the limit, and 18 full registrations are slow on a
    // shared runner); then the 20th through the API, which still works, and the 21st, which does not.
    const admission = await admitDevice(u.mb.id, device, u.recovery);
    await runInDurableObject(u.mb.stub, (_i, state) => {
      for (let i = 0; i < 18; i++) {
        state.storage.sql.exec(
          "INSERT INTO devices (id, account_id, label, signing_key, unlock_key, unlock_sig, admission_by, admission_sig, tag, tag_key_id, created_at, created_by) VALUES (?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?)",
          newId("dev"),
          "acc_owner",
          `Kept ${i + 2}`,
          device.signingKey,
          admission.by,
          admission.signature,
          fakeTag(),
          keyId,
          now(u.mb),
          "acc_owner",
        );
      }
    });
    await keepDevice(u);
    expect((await view(u.mb)).devices).toHaveLength(20);
    expect(refusalOf(await register(u, await registerRequest(u, await newDevice(), u.recovery)))).toEqual({ name: "InvalidRequest", message: "invalid request: a mailbox keeps at most 20 devices" });
  });

  it("round 3, M25: the admission is by the factor whose proof the call spends, and both it and the unlock key's signature verify", async () => {
    const u = await upgradedMailbox();
    const device = await newDevice();
    const stranger = await newDevice();
    const cases: [string, Record<string, unknown>][] = [
      ["admitted by another factor than the proof's", { admission: await admitDevice(u.mb.id, device, u.passkey) }],
      ["an admission over another device", { admission: await admitDevice(u.mb.id, stranger, u.recovery) }],
      ["an admission whose signature is not one", { admission: { by: u.recovery.id, signature: random(64) } }],
      ["an unlock key signed by another device", { unlockSignature: await signUnlockKey(u.mb.id, stranger, device.unlockKey!) }],
      ["an unlock key with no signature", { unlockSignature: null }],
      ["a signature with no unlock key", { unlockKey: null }],
      ["an unlock signature of the wrong length", { unlockSignature: random(63) }],
    ];
    for (const [name, over] of cases) {
      const request = await registerRequest(u, device, u.recovery, over);
      expect([name, refusalOf(await register(u, request, u.recovery)).name]).toEqual([name, "InvalidRequest"]);
    }
    expect((await view(u.mb)).devices).toEqual([]);
    // The same device, admitted by the passkey whose proof it spends, is kept.
    await keepDevice(u, { device, factor: u.passkey });
    expect((await view(u.mb)).devices.map((d) => [d.id, d.admission.by])).toEqual([[device.id, u.passkey.id]]);
  });

  it("is refused while sessions are optional (upgrade first), and is the owner's", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const { session } = await openSession(mb, mailboxKey);
    expect(refusalOf(await mail().registerDevice(await capFor(mb), { device: {}, seal: null }, { session }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: sessions are not on for this mailbox: upgrade first",
    });
    expect(refusalOf(await mail().registerDevice(await capFor(mb, { role: "editor" }), {}, { session }))).toEqual(FORBIDDEN);
  });
});

describe("device sessions (B6, M15′, M21′)", () => {
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

  it("answers DeviceRevoked for an unknown device, and Forbidden for another account's device, which spends and writes nothing (M21′, D37)", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const unknown = await newDevice();
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: { id: unknown.id, signature: await signProof(u.mb.id, unknown, c) } }))).toEqual(DEVICE_REVOKED);
    // Another person of the business, holding the key, presenting the owner's device with a good signature.
    const theirs = await challenge(u.mb, { purpose: "session" }, { sub: "acc_other" });
    const signed = { id: device.id, signature: await signProof(u.mb.id, device, theirs) };
    const before = { audit: await sql(u.mb, "SELECT COUNT(*) AS n FROM audit"), sessions: await sql(u.mb, "SELECT * FROM mail_sessions ORDER BY token_hash"), devices: await sql(u.mb, "SELECT * FROM devices") };
    expect(
      refusalOf(await mail().openSession(await capFor(u.mb, { sub: "acc_other" }), { challengeId: theirs.id, answer: await openChallenge(u.mb.id, theirs, u.mailboxKey), device: signed })),
    ).toEqual(FORBIDDEN);
    expect({ audit: await sql(u.mb, "SELECT COUNT(*) AS n FROM audit"), sessions: await sql(u.mb, "SELECT * FROM mail_sessions ORDER BY token_hash"), devices: await sql(u.mb, "SELECT * FROM devices") }).toEqual(before);
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", theirs.id)).toEqual([{ used_at: null }]);
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
  it("locks the device: its unlock key, its signature and its seals are cleared and its tag replaced, audited device-unlock-key cleared", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const session = await deviceSession(u, device);
    const keyId = u.mb.key!.keyId;
    const tag = fakeTag();
    const answer = valueOf(await mail().updateDevice(await capFor(u.mb), { unlockKey: null, unlockSignature: null, tag, tagKeyId: keyId, seal: null }, { session }));
    expect(answer).toMatchObject({ id: device.id, unlockKey: null, unlockSignature: null, tag, tagKeyId: keyId });
    expect((await view(u.mb)).seals).toEqual([]);
    expect((await audits(u.mb, "device-unlock-key")).at(-1)).toEqual({ actor: "acc_owner", detail: { device: device.id, unlockKey: "cleared" } });
  });

  it("unlocks it again: a new unlock key signed by the device, a tag and a seal, and none of its earlier seals", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const session = await deviceSession(u, device);
    const keyId = u.mb.key!.keyId;
    const fresh = await newUnlockKey();
    const unlockKey = base64urlFromBytes(fresh);
    const unlockSignature = await signUnlockKey(u.mb.id, device, fresh);
    const seal = fakeSeal(142);
    const answer = valueOf(await mail().updateDevice(await capFor(u.mb), { unlockKey, unlockSignature, tag: fakeTag(), tagKeyId: keyId, seal }, { session }));
    expect([answer.unlockKey, answer.unlockSignature]).toEqual([unlockKey, unlockSignature]);
    expect((await view(u.mb)).seals).toEqual([{ keyId, to: { kind: "device", id: device.id }, sealed: seal }]);
    expect((await audits(u.mb, "device-unlock-key")).at(-1)!.detail).toEqual({ device: device.id, unlockKey: "set" });
  });

  it("is only for that device's own session", async () => {
    const u = await upgradedMailbox();
    await keepDevice(u);
    const keyId = u.mb.key!.keyId;
    const plain = await plainSession(u);
    const request = { unlockKey: null, unlockSignature: null, tag: fakeTag(), tagKeyId: keyId, seal: null };
    expect(refusalOf(await mail().updateDevice(await capFor(u.mb), request, { session: plain }))).toEqual(SESSION_REQUIRED);
    expect(refusalOf(await mail().updateDevice(await capFor(u.mb), request))).toEqual(SESSION_REQUIRED);
  });

  it("refuses an unlock key off the curve or not signed by the device, a seal of the wrong length or without an unlock key, one missing, and a tag under another key", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const stranger = await newDevice();
    const session = await deviceSession(u, device);
    const keyId = u.mb.key!.keyId;
    const fresh = await newUnlockKey();
    const point = base64urlFromBytes(fresh);
    const signed = await signUnlockKey(u.mb.id, device, fresh);
    const offCurve = fresh.slice();
    offCurve[64] = offCurve[64]! ^ 1;
    for (const request of [
      { unlockKey: base64urlFromBytes(offCurve), unlockSignature: signed, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: point, unlockSignature: signed, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(109) },
      { unlockKey: point, unlockSignature: signed, tag: fakeTag(), tagKeyId: keyId, seal: null },
      { unlockKey: null, unlockSignature: null, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: point, unlockSignature: signed, tag: fakeTag(), tagKeyId: keyId },
      { unlockKey: point, unlockSignature: signed, tag: fakeTag(), tagKeyId: (await newKeyPair()).keyId, seal: fakeSeal(142) },
      { unlockKey: point, unlockSignature: signed, tag: random(16), tagKeyId: keyId, seal: fakeSeal(142) },
      // Round 3 (A11, M25): the device's own signature over its unlock key, exactly when there is one.
      { unlockKey: point, unlockSignature: null, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: point, unlockSignature: await signUnlockKey(u.mb.id, stranger, fresh), tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: point, unlockSignature: await signUnlockKey(u.mb.id, device, device.unlockKey!), tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
      { unlockKey: null, unlockSignature: signed, tag: fakeTag(), tagKeyId: keyId, seal: null },
      { unlockKey: point, tag: fakeTag(), tagKeyId: keyId, seal: fakeSeal(142) },
    ]) {
      expect([JSON.stringify(Object.keys(request)), refusalOf(await mail().updateDevice(await capFor(u.mb), request, { session })).name]).toEqual([JSON.stringify(Object.keys(request)), "InvalidRequest"]);
    }
    expect((await view(u.mb)).devices[0]!.unlockKey).toBe(base64urlFromBytes(device.unlockKey!));
  });
});

describe("addWrap and removeWrap once sessions are required (B7, M5′, M24, R8)", () => {
  it("addWrap takes a wrap of the active key with its keys, its admission and a tag under that key, and the new factor proves at once (R8)", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const added = await keyedWrap(u.mb, "passkey-prf", keyId, u.recovery);
    valueOf(await addWrap(u, added.wrap));
    expect((await view(u.mb)).wraps.find((w) => w.id === added.wrap.id)).toMatchObject({
      keyId,
      kind: "passkey-prf",
      factorKey: added.wrap.factorKey,
      signingKey: added.wrap.signingKey, // pragma: allowlist secret (a public Ed25519 key)
      admission: added.wrap.admission,
      tag: added.wrap.tag,
      tagKeyId: keyId,
    });
    expect((await audits(u.mb, "wrap-added")).at(-1)!.detail).toEqual({ wrap: added.wrap.id, kind: "passkey-prf" });
    await factorProof(u.mb, added.factor, removeFactorAction(added.wrap.id));
  });

  it("addWrap refuses a wrap without a factor key, signing key, admission or tag, with a tag under another key, of another key, or with an unusable key", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const other = (await newKeyPair()).keyId;
    for (const over of [
      { factorKey: undefined },
      { signingKey: undefined },
      { admission: undefined },
      { tag: undefined },
      { tagKeyId: undefined },
      { tagKeyId: other },
      { keyId: other, tagKeyId: other },
      { factorKey: base64urlFromBytes(new Uint8Array(32)) },
      { signingKey: random(31) }, // pragma: allowlist secret (a test fixture: a malformed public key)
      { label: "a\uD800" },
    ]) {
      const { wrap } = await keyedWrap(u.mb, "passkey-prf", keyId, u.recovery, over);
      const plain = JSON.parse(JSON.stringify(wrap)) as Record<string, unknown>;
      let answer;
      try {
        answer = await addWrap(u, plain);
      } catch {
        // A lone surrogate does not serialize as A10 says, so no descriptor can name the request: send it with a proof for something else.
        answer = await mail().addWrap(await capFor(u.mb), plain, { session: u.session, factorProof: await factorProof(u.mb, u.recovery, removeFactorAction(wrap.id)) });
      }
      expect([JSON.stringify(over), refusalOf(answer).name]).toEqual([JSON.stringify(over), "InvalidRequest"]);
    }
    expect((await view(u.mb)).wraps).toHaveLength(2);
  });

  it("round 3, M25: addWrap's admission is by the factor whose proof the call spends, and by the new factor itself, and both verify", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const byPasskey = await keyedWrap(u.mb, "recovery", keyId, u.passkey);
    expect(refusalOf(await addWrap(u, byPasskey.wrap, u.recovery))).toEqual({ name: "InvalidRequest", message: "invalid request: a factor is admitted by the factor whose proof the call spends" });
    const unsigned = await keyedWrap(u.mb, "recovery", keyId, u.recovery);
    const forged = { ...unsigned.wrap, admission: { ...unsigned.wrap.admission, selfSignature: unsigned.wrap.admission.signature } };
    expect(refusalOf(await addWrap(u, forged, u.recovery)).name).toBe("InvalidRequest");
    const relabelled = { ...unsigned.wrap, label: "Another sheet" };
    expect(refusalOf(await addWrap(u, relabelled, u.recovery)).name).toBe("InvalidRequest");
    expect((await view(u.mb)).wraps).toHaveLength(2);
    valueOf(await addWrap(u, byPasskey.wrap, u.passkey));
  });

  it("removeWrap removes a factor, keeps its record in removedFactors (M24), and refuses the last recovery factor that reaches the active key (M5′)", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    expect(refusalOf(await removeWrap(u, u.recovery.id, u.passkey))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: the last recovery factor that reaches the active key cannot be removed",
    });
    const second = await keyedWrap(u.mb, "recovery", keyId, u.recovery);
    valueOf(await addWrap(u, second.wrap));
    const listed = (await view(u.mb)).wraps.find((w) => w.id === u.recovery.id)!;
    u.mb.ports.clock.advance(1000);
    valueOf(await removeWrap(u, u.recovery.id, u.recovery));
    const removedAt = now(u.mb);
    valueOf(await removeWrap(u, u.passkey.id, second.factor));
    const v = await view(u.mb);
    expect(v.wraps.map((w) => w.id)).toEqual([second.wrap.id]);
    expect(v.removedFactors[0]).toEqual({
      id: u.recovery.id,
      kind: "recovery",
      credentialId: null,
      label: listed.label,
      factorKey: listed.factorKey,
      signingKey: listed.signingKey, // pragma: allowlist secret (a public Ed25519 key)
      admission: listed.admission,
      removedAt,
    });
    expect(v.removedFactors.map((f) => f.id)).toEqual([u.recovery.id, u.passkey.id]);
    expect(refusalOf(await removeWrap(u, second.wrap.id, second.factor)).name).toBe("InvalidRequest");
    expect((await audits(u.mb, "wrap-removed")).map((a) => a.detail.wrap)).toEqual([u.recovery.id, u.passkey.id]);
    // A removed factor's id is never a new wrap's.
    const reused = await keyedWrap(u.mb, "passkey-prf", keyId, second.factor, {}, { id: u.passkey.id });
    expect(refusalOf(await addWrap(u, reused.wrap, second.factor))).toEqual({ name: "InvalidRequest", message: "invalid request: that wrap id exists" });
  });
});

describe("enroll with factor keys and a device (B5, F12)", () => {
  async function enrolment(mb: TestMailbox, opts: { device?: boolean } = {}) {
    const key = await newKeyPair();
    const recoveryPlain = recoveryWrap(key.keyId, { label: "Recovery key" });
    const passkeyPlain = passkeyWrap(key.keyId, { label: "Phone" });
    const recoveryFactor = await factorOf(recoveryPlain);
    const passkeyFactor = await factorOf(passkeyPlain);
    const admissions = await cycleAdmissions(mb.id, [recoveryFactor, passkeyFactor]);
    const keyed = (plain: typeof recoveryPlain, factor: TestFactor) => ({
      ...plain,
      factorKey: base64urlFromBytes(factor.publicKey),
      signingKey: base64urlFromBytes(factor.signingKey), // pragma: allowlist secret (a public Ed25519 key)
      admission: admissions.get(factor.id)!,
      tag: fakeTag(),
      tagKeyId: key.keyId,
    });
    const recovery = { factor: recoveryFactor, wrap: keyed(recoveryPlain, recoveryFactor) };
    const passkey = { factor: passkeyFactor, wrap: keyed(passkeyPlain, passkeyFactor) };
    const device = await newDevice({ label: "Front desk" });
    const seal = fakeSeal(142);
    const deviceRequest = { device: await deviceInput(mb.id, device, key.keyId, passkeyFactor), seal };
    const request = {
      publicKey: base64urlFromBytes(key.publicKey),
      wraps: [recovery.wrap, passkey.wrap],
      ...(opts.device === false ? {} : { device: deviceRequest }),
    };
    return { key, recovery, passkey, device, seal, deviceRequest, request };
  }

  it("starts sessions required when every wrap carries its keys and admission, and keeps the enrolling device with its seal", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mb);
    expect(await mail().enroll(await capFor(mb), e.request)).toEqual({ ok: true, value: { keyId: e.key.keyId } });
    const v = await view(mb);
    expect(v.status).toBe("active");
    expect(v.sessions).toBe("required");
    expect(v.wraps.map((w) => [w.id, w.factorKey, w.signingKey, w.admission, w.tagKeyId])).toEqual(
      expect.arrayContaining([
        [e.recovery.wrap.id, e.recovery.wrap.factorKey, e.recovery.wrap.signingKey, e.recovery.wrap.admission, e.key.keyId],
        [e.passkey.wrap.id, e.passkey.wrap.factorKey, e.passkey.wrap.signingKey, e.passkey.wrap.admission, e.key.keyId],
      ]),
    );
    expect(v.devices).toEqual([
      expect.objectContaining({ id: e.device.id, label: "Front desk", tagKeyId: e.key.keyId, createdBy: "acc_owner", lastSeenAt: null, admission: e.deviceRequest.device.admission }),
    ]);
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
    const staleDevice = { ...e.request, device: { device: { ...e.deviceRequest.device, tagKeyId: otherKey }, seal: e.seal } };
    expect(refusalOf(await mail().enroll(await capFor(mixed), staleDevice)).name).toBe("InvalidRequest");
    const staleWrapTag = { ...e.request, wraps: [{ ...e.recovery.wrap, tagKeyId: otherKey }, e.passkey.wrap] };
    expect(refusalOf(await mail().enroll(await capFor(mixed), staleWrapTag)).name).toBe("InvalidRequest");
    const noSeal = { ...e.request, device: { device: e.deviceRequest.device, seal: null } };
    expect(refusalOf(await mail().enroll(await capFor(mixed), noSeal)).name).toBe("InvalidRequest");
    const v = await view(mixed);
    expect([v.status, v.sessions, v.keys, v.devices]).toEqual(["provisioned", "optional", [], []]);
  });

  it("round 3, M25: refuses admissions outside A11's cycle or that do not verify, and a device its factors did not admit", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mb);
    const swapped = { ...e.request, wraps: [{ ...e.recovery.wrap, admission: e.passkey.wrap.admission }, { ...e.passkey.wrap, admission: e.recovery.wrap.admission }] };
    const unsigned = { ...e.request, wraps: [{ ...e.recovery.wrap, admission: { ...e.recovery.wrap.admission, signature: random(64) } }, e.passkey.wrap] };
    const relabelled = { ...e.request, wraps: [{ ...e.recovery.wrap, label: "Another sheet" }, e.passkey.wrap] };
    const stranger = await factorOf(recoveryWrap(e.key.keyId));
    const strangersDevice = { ...e.request, device: { device: await deviceInput(mb.id, e.device, e.key.keyId, stranger), seal: e.seal } };
    const unsignedUnlock = { ...e.request, device: { device: { ...e.deviceRequest.device, unlockSignature: random(64) }, seal: e.seal } };
    for (const [name, request] of [
      ["admissions swapped", swapped],
      ["an admission that is not a signature", unsigned],
      ["a label the admission was not made for", relabelled],
      ["a device admitted by a factor that is not enrolling", strangersDevice],
      ["a device whose unlock key it did not sign", unsignedUnlock],
    ] as const) {
      expect([name, refusalOf(await mail().enroll(await capFor(mb), request)).name]).toEqual([name, "InvalidRequest"]);
    }
    const v = await view(mb);
    expect([v.status, v.sessions, v.keys, v.devices]).toEqual(["provisioned", "optional", [], []]);
    valueOf(await mail().enroll(await capFor(mb), e.request));
  });

  it("an enrolment with factor keys and no device is fine, and M5 still wants a recovery wrap", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mb, { device: false });
    expect(refusalOf(await mail().enroll(await capFor(mb), { ...e.request, wraps: [e.passkey.wrap] }))).toEqual({ name: "InvalidRequest", message: "invalid request: a recovery wrap is required" });
    valueOf(await mail().enroll(await capFor(mb), e.request));
    expect((await view(mb)).sessions).toBe("required");
  });

  it("a single factor at enrollment admits itself (A11)", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const e = await enrolment(mb, { device: false });
    const alone = await cycleAdmissions(mb.id, [e.recovery.factor]);
    valueOf(await mail().enroll(await capFor(mb), { ...e.request, wraps: [{ ...e.recovery.wrap, admission: alone.get(e.recovery.factor.id)! }] }));
    expect((await view(mb)).wraps.map((w) => w.admission!.by)).toEqual([e.recovery.factor.id]);
  });
});
