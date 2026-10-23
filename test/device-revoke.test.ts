import { newId } from "@proprietor/mail-crypto";
import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import committedVectors from "../contracts/action-descriptor-v1.vectors.json?raw";
import {
  actionInput,
  challenge,
  emailCode,
  emailConfirmation,
  factorProof,
  keepDevice,
  keyedWrap,
  legacyMailbox,
  newDevice,
  openChallenge,
  openSession,
  plainSession,
  registerRequest,
  removeDevices,
  removeDevicesAction,
  rotationFor,
  signProof,
  type TestAttestation,
  type Upgraded,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes } from "./support/capability-tokens";
import { capFor, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Round 3 of spec 002 (D35): an email code, which the dashboard checks and
// attests in the capability's `confirmation` claim (capability-v1), revokes
// devices and does nothing else (contracts/device-v1.md B7a, domain-model
// M22): the devices, their seals and their sessions go, a rotation is due,
// and no key, seal, tag or factor is written. The next factor holder
// finishes the rotation with removeDevices (F14, M23).

const mail = () => exports.MailService;
const MINUTE = 60 * 1000;

interface DescriptorVectors {
  valid: { name: string; object: unknown; utf8: string; sha256: string }[];
  attestations: {
    sub: string;
    now: number;
    descriptor: string;
    accepted: { name: string; attestation: TestAttestation }[];
    refused: { name: string; attestation: Record<string, unknown>; why: string }[];
  };
}
const vectors = JSON.parse(committedVectors) as DescriptorVectors;

const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };
const SESSION_REQUIRED = { name: "SessionRequired", message: "a live mail session is required" };
const DEVICE_REVOKED = { name: "DeviceRevoked", message: "this device is not in the mailbox" };
const INVALID_CAPABILITY = { name: "CapabilityRejected", message: "capability rejected: invalid", reason: "invalid" };

const view = async (mb: TestMailbox) => valueOf(await mail().mailbox(await capFor(mb)));

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function audits(mb: TestMailbox, action: string) {
  return (await sql<{ actor: string; detail: string }>(mb, "SELECT actor, detail FROM audit WHERE action = ? ORDER BY id", action)).map((r) => ({
    actor: r.actor,
    detail: JSON.parse(r.detail) as Record<string, unknown>,
  }));
}

/** Everything a revocation may not write (M22): the key ring's keys, wraps (factors, tags) and the other devices' rows. */
async function keyRing(mb: TestMailbox) {
  return {
    keys: await sql(mb, "SELECT * FROM keys ORDER BY key_id"),
    wraps: await sql(mb, "SELECT * FROM key_wraps ORDER BY id"),
    removedFactors: await sql(mb, "SELECT * FROM removed_factors ORDER BY id"),
  };
}

/** A mailbox with three kept devices (a phone, a laptop, a front-desk browser that keeps nothing), each with a session. */
async function threeDevices() {
  const u = await upgradedMailbox();
  const phone = await keepDevice(u, { device: await newDevice({ label: "Phone" }) });
  const laptop = await keepDevice(u, { device: await newDevice({ label: "Laptop" }), session: await plainSession(u) });
  const desk = await keepDevice(u, { device: await newDevice({ label: "Front desk", keepsNothing: true }), session: await plainSession(u) });
  const sessions = {
    phone: u.session,
    laptop: (await openSession(u.mb, u.mailboxKey, { device: laptop })).session,
    desk: (await openSession(u.mb, u.mailboxKey, { device: desk })).session,
  };
  return { u, phone, laptop, desk, sessions };
}

describe("revokeDevices (B7a, M22): an email code revokes, and nothing else", () => {
  it("deletes the devices, their seals and their sessions, makes a rotation due, writes no key, seal, tag or factor, and audits the code's id", async () => {
    const { u, phone, laptop, desk, sessions } = await threeDevices();
    const before = { ring: await keyRing(u.mb), desk: await sql(u.mb, "SELECT * FROM devices WHERE id = ?", desk.id), seals: await sql(u.mb, "SELECT * FROM key_seals WHERE to_kind = 'factor' ORDER BY to_id") };
    const { attestation } = await emailConfirmation(u.mb, [phone.id, laptop.id]);
    u.mb.ports.clock.advance(30 * 1000);
    const since = u.mb.ports.clock.now().toISOString();
    // No session, no auth: the capability's attestation stands for the confirmation.
    const answer = valueOf(await mail().revokeDevices(await capFor(u.mb, { confirmation: attestation }), { deviceIds: [laptop.id, phone.id] }));
    expect(answer).toEqual({ revoked: [laptop.id, phone.id].sort() });

    const v = await view(u.mb);
    expect(v.devices.map((d) => d.id)).toEqual([desk.id]);
    expect(v.seals.filter((s) => s.to.kind === "device")).toEqual([]);
    expect(v.rotationDue).toEqual({ since, by: "acc_owner", devices: [laptop.id, phone.id].sort() });
    expect({ ring: await keyRing(u.mb), desk: await sql(u.mb, "SELECT * FROM devices WHERE id = ?", desk.id), seals: await sql(u.mb, "SELECT * FROM key_seals WHERE to_kind = 'factor' ORDER BY to_id") }).toEqual(before);
    // Their sessions are gone; the desk's stays.
    for (const s of [sessions.phone, sessions.laptop]) expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: s }))).toEqual(SESSION_REQUIRED);
    valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: sessions.desk }));
    // The phone's one session (the upgrade's, which keeping it made its own); the laptop's two (the one it was kept in, and its own).
    const ended = new Map([[phone.id, 1], [laptop.id, 2]]);
    expect(await audits(u.mb, "device-revoked")).toEqual(
      [laptop, phone]
        .sort((a, b) => (a.id < b.id ? -1 : 1))
        .map((d) => ({ actor: "acc_owner", detail: { device: d.id, label: d.label, sessions: ended.get(d.id), method: "email-code", codeId: attestation.codeId } })),
    );
    expect(await audits(u.mb, "rotation-due")).toEqual([{ actor: "acc_owner", detail: { devices: [laptop.id, phone.id].sort().join(","), since } }]);
  });

  it("a revoked device is refused at once: its signature names no device, and a key proof alone opens no session (B7a, D38)", async () => {
    const { u, phone } = await threeDevices();
    valueOf(await mail().revokeDevices(await emailCode(u, [phone.id]), { deviceIds: [phone.id] }));
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: { id: phone.id, signature: await signProof(u.mb.id, phone, c) } }))).toEqual(DEVICE_REVOKED);
    const c2 = await challenge(u.mb, { purpose: "session" });
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c2.id, answer: await openChallenge(u.mb.id, c2, u.mailboxKey) })).name).toBe("InvalidRequest");
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions WHERE device_id = ?", phone.id)).toEqual([{ n: 0 }]);
  });

  it("a second revocation while one is due keeps its start, names the last account, and adds its devices", async () => {
    const { u, phone, laptop } = await threeDevices();
    const since = u.mb.ports.clock.now().toISOString();
    valueOf(await mail().revokeDevices(await emailCode(u, [phone.id]), { deviceIds: [phone.id] }));
    u.mb.ports.clock.advance(MINUTE);
    valueOf(await mail().revokeDevices(await emailCode(u, [laptop.id], { sub: "acc_other" }), { deviceIds: [laptop.id] }));
    expect((await view(u.mb)).rotationDue).toEqual({ since, by: "acc_other", devices: [phone.id, laptop.id] });
  });

  it("is spent by the first call that presents it, whatever its outcome: a second call with the same attestation is ProofRejected", async () => {
    const { u, phone, laptop } = await threeDevices();
    const { attestation } = await emailConfirmation(u.mb, [phone.id]);
    const cap = await capFor(u.mb, { confirmation: attestation });
    // The first call names another device than the descriptor did: refused, and the challenge is spent.
    expect(refusalOf(await mail().revokeDevices(cap, { deviceIds: [laptop.id] }))).toEqual(PROOF_REJECTED);
    expect(refusalOf(await mail().revokeDevices(cap, { deviceIds: [phone.id] }))).toEqual(PROOF_REJECTED);
    expect((await view(u.mb)).devices).toHaveLength(3);
    const reasons = (await audits(u.mb, "proof-rejected")).map((a) => a.detail);
    expect(reasons.map((d) => [d.purpose, d.reason])).toEqual([
      ["email", "devices"],
      ["email", "used"],
    ]);
  });

  it("refuses an email challenge that expired (10 minutes), another account's, and none at all, writing nothing for the last two", async () => {
    const { u, phone } = await threeDevices();
    const late = await emailConfirmation(u.mb, [phone.id]);
    u.mb.ports.clock.advance(10 * MINUTE);
    const lateAttestation = { ...late.attestation, at: Math.floor(u.mb.ports.clock.now().getTime() / 1000) };
    expect(refusalOf(await mail().revokeDevices(await capFor(u.mb, { confirmation: lateAttestation }), { deviceIds: [phone.id] }))).toEqual(PROOF_REJECTED);
    const auditRows = await sql(u.mb, "SELECT COUNT(*) AS n FROM audit");
    // Another account asked for it: the attestation names a challenge that is not this account's.
    const theirs = await emailConfirmation(u.mb, [phone.id], { sub: "acc_other" });
    expect(refusalOf(await mail().revokeDevices(await capFor(u.mb, { confirmation: { ...theirs.attestation, accountId: "acc_owner" } }), { deviceIds: [phone.id] }))).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", theirs.challenge.id)).toEqual([{ used_at: null }]);
    expect(refusalOf(await mail().revokeDevices(await capFor(u.mb), { deviceIds: [phone.id] }))).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM audit")).toEqual(auditRows);
    expect((await view(u.mb)).devices.map((d) => d.id)).toContain(phone.id);
  });

  it("refuses a digest of a factor or key challenge: only an email challenge's descriptor is confirmed by a code", async () => {
    const { u, phone } = await threeDevices();
    const remover = await plainSession(u);
    const removal = { deviceIds: [phone.id], rotation: (await rotationFor(u.mb, phone.id, u.recovery)).rotation };
    const factor = await challenge(u.mb, { purpose: "factor", factorId: u.recovery.id, action: await actionInput(removeDevicesAction(removal)) });
    const { attestation } = await emailConfirmation(u.mb, [phone.id]);
    const forFactor = { ...attestation, actionKind: "remove-devices", actionDigest: (await sql<{ action_digest: string }>(u.mb, "SELECT action_digest FROM challenges WHERE id = ?", factor.id))[0]!.action_digest };
    expect(refusalOf(await mail().revokeDevices(await capFor(u.mb, { confirmation: forFactor }), { deviceIds: [phone.id] }))).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", factor.id)).toEqual([{ used_at: null }]);
    expect((await view(u.mb)).devices.map((d) => d.id)).toContain(phone.id);
    // And the factor challenge still confirms its own removal.
    valueOf(await mail().removeDevices(await capFor(u.mb), removal, { session: remover, factorProof: { challengeId: factor.id, answer: await openChallenge(u.mb.id, factor, u.recovery.pair) } }));
  });

  it("is the owner's, needs sessions on, takes no session, and refuses a malformed request after spending the attestation", async () => {
    const { u, phone } = await threeDevices();
    expect(refusalOf(await mail().revokeDevices(await capFor(u.mb, { role: "editor", confirmation: (await emailConfirmation(u.mb, [phone.id])).attestation }), { deviceIds: [phone.id] }))).toEqual({
      name: "Forbidden",
      message: "forbidden",
    });
    for (const request of [{ deviceIds: phone.id }, { deviceIds: [] }, { deviceIds: [phone.id], extra: "x" }, { deviceIds: [phone.id, phone.id] }, null]) {
      const { attestation } = await emailConfirmation(u.mb, [phone.id]);
      const cap = await capFor(u.mb, { confirmation: attestation });
      expect([JSON.stringify(request), refusalOf(await mail().revokeDevices(cap, request)).name]).toEqual([JSON.stringify(request), "InvalidRequest"]);
      // That call spent it.
      expect(refusalOf(await mail().revokeDevices(cap, { deviceIds: [phone.id] }))).toEqual(PROOF_REJECTED);
    }
    expect((await view(u.mb)).devices.map((d) => d.id)).toContain(phone.id);
    const optional = await legacyMailbox();
    expect(refusalOf(await mail().revokeDevices(await capFor(optional.mb), { deviceIds: [newId("dev")] }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: sessions are not on for this mailbox: upgrade first",
    });
  });
});

describe("capability-v1's confirmation claim: read strictly, by revokeDevices only", () => {
  it("a malformed claim is CapabilityRejected (invalid) on revokeDevices, and nothing is spent", async () => {
    const { u, phone } = await threeDevices();
    const { challenge: c, attestation } = await emailConfirmation(u.mb, [phone.id]);
    const malformed: unknown[] = [
      "email-code",
      [attestation],
      { ...attestation, extra: true },
      (({ codeId: _c, ...rest }) => rest)(attestation),
      { ...attestation, at: "1792627350" },
      { ...attestation, at: 1.5 },
      { ...attestation, at: -1 },
      { ...attestation, actionDigest: attestation.actionDigest.slice(1) },
      { ...attestation, actionDigest: `${attestation.actionDigest.slice(0, 42)}+` },
      { ...attestation, codeId: "x".repeat(65) },
      { ...attestation, codeId: "a code" },
      { ...attestation, method: "" },
      { ...attestation, accountId: 7 },
      null,
    ];
    for (const confirmation of malformed) {
      expect([JSON.stringify(confirmation)?.slice(0, 50), refusalOf(await mail().revokeDevices(await capFor(u.mb, { confirmation }), { deviceIds: [phone.id] }))]).toEqual([
        JSON.stringify(confirmation)?.slice(0, 50),
        INVALID_CAPABILITY,
      ]);
    }
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", c.id)).toEqual([{ used_at: null }]);
    valueOf(await mail().revokeDevices(await capFor(u.mb, { confirmation: attestation }), { deviceIds: [phone.id] }));
  });

  it("every other method ignores the claim, malformed or not", async () => {
    const { u } = await threeDevices();
    const session = await plainSession(u);
    const cap = await capFor(u.mb, { confirmation: { anything: "at all" } });
    valueOf(await mail().mailbox(cap));
    valueOf(await mail().list(cap, { folder: "inbox" }, { session }));
    valueOf(await mail().challenge(cap, { purpose: "session" }));
  });
});

describe("M22: an email attestation never opens any other method", () => {
  it("not removeDevices, registerDevice, addWrap, removeWrap, openSession, upgrade or a session method: each answers as if there were none, and the attestation stays unspent", async () => {
    const { u, phone } = await threeDevices();
    const { challenge: email, attestation } = await emailConfirmation(u.mb, [phone.id]);
    const cap = await capFor(u.mb, { confirmation: attestation });
    const session = await plainSession(u);
    const before = { view: await view(u.mb), ring: await keyRing(u.mb) };

    const removal = { deviceIds: [phone.id], rotation: (await rotationFor(u.mb, phone.id, u.recovery)).rotation };
    expect(refusalOf(await mail().removeDevices(cap, removal, { session }))).toEqual(PROOF_REJECTED);
    const registration = await registerRequest(u, await newDevice(), u.recovery);
    expect(refusalOf(await mail().registerDevice(cap, registration, { session }))).toEqual(PROOF_REJECTED);
    const { wrap } = await keyedWrap(u.mb, "passkey-prf", u.mb.key!.keyId, u.recovery);
    expect(refusalOf(await mail().addWrap(cap, wrap, { session }))).toEqual(PROOF_REJECTED);
    expect(refusalOf(await mail().removeWrap(cap, u.passkey.id, { session }))).toEqual(PROOF_REJECTED);
    expect(refusalOf(await mail().upgrade(cap, { factors: [] }, { session }))).toEqual(PROOF_REJECTED);
    expect(refusalOf(await mail().list(cap, { folder: "inbox" }))).toEqual(SESSION_REQUIRED);
    const c = await challenge(u.mb, { purpose: "session" });
    expect(refusalOf(await mail().openSession(cap, { challengeId: c.id, answer: await openChallenge(u.mb.id, c, u.mailboxKey) })).name).toBe("InvalidRequest");
    // The email challenge itself is no factor proof (its purpose), and is spent by that try, as any challenge presented as a proof is.
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", email.id)).toEqual([{ used_at: null }]);
    expect({ view: await view(u.mb), ring: await keyRing(u.mb) }).toEqual(before);
    // The attestation was never read: it still revokes, once.
    valueOf(await mail().revokeDevices(cap, { deviceIds: [phone.id] }));
  });

  it("an email challenge presented as a factor proof is refused for its purpose", async () => {
    const { u, phone } = await threeDevices();
    const session = await plainSession(u);
    const { challenge: email } = await emailConfirmation(u.mb, [phone.id]);
    const removal = { deviceIds: [phone.id], rotation: (await rotationFor(u.mb, phone.id, u.recovery)).rotation };
    const asProof = { challengeId: email.id, answer: base64urlFromBytes(new Uint8Array(32)) };
    expect(refusalOf(await mail().removeDevices(await capFor(u.mb), removal, { session, factorProof: asProof }))).toEqual(PROOF_REJECTED);
    expect((await audits(u.mb, "proof-rejected")).at(-1)!.detail).toEqual({ challenge: email.id, purpose: "email", reason: "purpose" });
    expect((await view(u.mb)).devices.map((d) => d.id)).toContain(phone.id);
  });
});

describe("F14, M23: the due rotation is finished by removeDevices with a factor, and only so", () => {
  it("removeDevices with no devices finishes it: a new key, the transition signed, every other session ended, no rotation due", async () => {
    const { u, phone, laptop, desk } = await threeDevices();
    valueOf(await mail().revokeDevices(await emailCode(u, [phone.id]), { deviceIds: [phone.id] }));
    const finisher = await plainSession(u);
    const { next, rotation } = await rotationFor(u.mb, [], u.passkey);
    expect(valueOf(await removeDevices(u, { deviceIds: [], rotation }, finisher, u.passkey))).toEqual({ keyId: next.keyId });
    const v = await view(u.mb);
    expect(v.rotationDue).toBeNull();
    expect(v.devices.map((d) => d.id).sort()).toEqual([laptop.id, desk.id].sort());
    expect(v.keys.find((k) => k.retiredAt !== null)!.successor).toMatchObject({ keyId: next.keyId, signedBy: u.passkey.id });
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual([{ n: 1 }]);
    expect((await audits(u.mb, "key-rotated")).at(-1)!.detail).toMatchObject({ to: next.keyId, factor: u.passkey.id, due: true });
  });

  it("removeDevices with no devices is refused when no rotation is due", async () => {
    const { u } = await threeDevices();
    const session = await plainSession(u);
    const { rotation } = await rotationFor(u.mb, [], u.recovery);
    expect(refusalOf(await removeDevices(u, { deviceIds: [], rotation }, session, u.recovery))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: removeDevices names no device only to finish a rotation that is due",
    });
  });

  it("a removal with devices also clears a due rotation (removing every flagged device is one step, D40)", async () => {
    const { u, phone, laptop } = await threeDevices();
    valueOf(await mail().revokeDevices(await emailCode(u, [phone.id]), { deviceIds: [phone.id] }));
    const session = await plainSession(u);
    const { rotation } = await rotationFor(u.mb, [laptop.id], u.recovery);
    valueOf(await removeDevices(u, { deviceIds: [laptop.id], rotation }, session, u.recovery));
    expect((await view(u.mb)).rotationDue).toBeNull();
  });
});

describe("the attestation cases of action-descriptor-v1's vectors are Mail's checks", () => {
  /** The vectors' mailbox, kept device ("Laptop") and pending email challenge, at the vectors' clock, for their `sub`. */
  async function vectorMailbox(): Promise<{ u: Upgraded; deviceId: string; reset: () => Promise<string> }> {
    const valid = vectors.valid.find((v) => v.name === vectors.attestations.descriptor)!;
    const object = valid.object as { mailboxId: string; targets: { deviceId: string; label: string }[]; issuedAt: number; nonce: string };
    const u = await upgradedMailbox({ id: object.mailboxId });
    const target = object.targets[0]!;
    const device = { ...(await newDevice({ label: target.label })), id: target.deviceId };
    await keepDevice(u, { device });
    u.mb.ports.clock.current = new Date(vectors.attestations.now * 1000);
    const reset = async () => {
      const id = newId("chl");
      await sql(u.mb, "DELETE FROM challenges");
      await sql(
        u.mb,
        "INSERT INTO challenges (id, purpose, target_id, answer_hash, nonce, account_id, kind, descriptor, action_digest, created_at, expires_at) VALUES (?, 'email', '', NULL, ?, ?, 'revoke-device', ?, ?, ?, ?)",
        id,
        object.nonce,
        vectors.attestations.sub,
        base64urlFromBytes(new TextEncoder().encode(valid.utf8)),
        valid.sha256,
        new Date(object.issuedAt * 1000).toISOString(),
        new Date((object.issuedAt + 600) * 1000).toISOString(),
      );
      return id;
    };
    return { u, deviceId: target.deviceId, reset };
  }

  it("refuses each refused case (nine), and changes nothing; then accepts the accepted one", async () => {
    const { u, deviceId, reset } = await vectorMailbox();
    const pendingDigest = vectors.valid.find((v) => v.name === vectors.attestations.descriptor)!.sha256;
    const call = async (attestation: unknown) =>
      mail().revokeDevices(await capFor(u.mb, { sub: vectors.attestations.sub, confirmation: attestation }), { deviceIds: [deviceId] });
    expect(vectors.attestations.refused).toHaveLength(9);
    for (const refused of vectors.attestations.refused) {
      const challengeId = await reset();
      const a = refused.attestation as Partial<TestAttestation> & Record<string, unknown>;
      const shapeOnly = Object.keys(a).length !== 6 || typeof a.at !== "number";
      const answer = refusalOf(await call(a));
      // A claim that is not an attestation's shape is the capability's fault; any other rule is the confirmation's.
      expect([refused.name, answer]).toEqual([refused.name, shapeOnly ? INVALID_CAPABILITY : PROOF_REJECTED]);
      const spent = (await sql<{ used_at: string | null }>(u.mb, "SELECT used_at FROM challenges WHERE id = ?", challengeId))[0]!.used_at !== null;
      // Spent exactly when it reached Mail naming the pending challenge's digest (B7a: whatever the outcome).
      expect([refused.name, spent]).toEqual([refused.name, !shapeOnly && a.actionDigest === pendingDigest]);
      expect([refused.name, (await view(u.mb)).devices.map((d) => d.id), (await view(u.mb)).rotationDue]).toEqual([refused.name, [deviceId], null]);
    }
    expect(vectors.attestations.accepted).toHaveLength(1);
    await reset();
    expect(valueOf(await call(vectors.attestations.accepted[0]!.attestation))).toEqual({ revoked: [deviceId] });
    const v = await view(u.mb);
    expect([v.devices, v.rotationDue]).toEqual([[], { since: u.mb.ports.clock.now().toISOString(), by: vectors.attestations.sub, devices: [deviceId] }]);
    expect((await audits(u.mb, "device-revoked")).at(-1)!.detail).toMatchObject({ device: deviceId, method: "email-code", codeId: "code_example_1" });
  });
});
