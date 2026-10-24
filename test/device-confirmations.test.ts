import { newId } from "@proprietor/mail-crypto";
import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  actionInput,
  addFactorAction,
  challenge,
  descriptorDigest,
  descriptorOf,
  factorProof,
  keepDevice,
  keyedWrap,
  keyProof,
  legacyMailbox,
  newDevice,
  openChallenge,
  openSession,
  openSessionAction,
  plainSession,
  registerAction,
  registerRequest,
  removeDevicesAction,
  removeFactorAction,
  requestDigestOf,
  rotationFor,
  signProof,
  upgradeRequest,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { capFor, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Round 3 of spec 002 (D36, D38, D37): action descriptors issued with
// challenges (contracts/device-v1.md A10, B6; action-descriptor-v1), every
// factor and key proof checked against its own call's request (M17′), a
// session that needs more than a key proof (M15′), and another account's
// device (M21′).

const mail = () => exports.MailService;
const MINUTE = 60 * 1000;

const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };
const FORBIDDEN = { name: "Forbidden", message: "forbidden" };

const random = (n: number) => base64urlFromBytes(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (b64u: string) => base64urlFromBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", bytesFromBase64url(b64u))));
const at = (mb: TestMailbox, ms = 0) => new Date(mb.ports.clock.now().getTime() + ms).toISOString();
const view = async (mb: TestMailbox) => valueOf(await mail().mailbox(await capFor(mb)));

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function rejections(mb: TestMailbox, challengeId: string): Promise<unknown[]> {
  return (await sql<{ detail: string }>(mb, "SELECT detail FROM audit WHERE action = 'proof-rejected' ORDER BY id"))
    .map((r) => JSON.parse(r.detail) as Record<string, unknown>)
    .filter((d) => d.challenge === challengeId)
    .map((d) => d.reason);
}

/** RFC 8785 of a descriptor (it holds numbers too: version and issuedAt), written here from the RFC. */
function jcs(value: unknown): string {
  if (typeof value === "number") return JSON.stringify(value);
  if (value === null || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((k) => `${JSON.stringify(k)}:${jcs(record[k])}`).join(",")}}`;
}

describe("challenge issues an action descriptor (A10, B6, action-descriptor-v1)", () => {
  it("for every purpose but session: Mail's kind, mailbox, targets with Mail's labels, nonce, time and request, in RFC 8785; stored with its digest", async () => {
    const u = await upgradedMailbox();
    const laptop = await keepDevice(u, { device: await newDevice({ label: "Büro \"laptop\" \\ 1" }) });
    const phone = await keepDevice(u, { device: await newDevice({ label: "Phone" }), session: await plainSession(u) });
    const request = random(32);
    const issuedAt = Math.floor(u.mb.ports.clock.now().getTime() / 1000);
    const cases = [
      { purpose: "factor", factorId: u.recovery.id, action: { kind: "remove-devices", deviceIds: [phone.id, laptop.id], request } },
      { purpose: "factor", factorId: u.passkey.id, action: { kind: "open-session", request } },
      { purpose: "key", action: { kind: "upgrade", request } },
      { purpose: "email", action: { kind: "revoke-device", deviceIds: [laptop.id] } },
    ] as const;
    for (const input of cases) {
      const c = await challenge(u.mb, input as unknown as Record<string, unknown>);
      const bytes = bytesFromBase64url(c.descriptor!);
      const d = descriptorOf(c);
      // The bytes are exactly the canonical form of what they hold.
      expect(new TextDecoder().decode(bytes)).toBe(jcs(d));
      const targets =
        input.action.kind === "remove-devices"
          ? [laptop, phone].sort((a, b) => (a.id < b.id ? -1 : 1)).map((x) => ({ deviceId: x.id, label: x.label }))
          : input.action.kind === "revoke-device"
            ? [{ deviceId: laptop.id, label: laptop.label }]
            : [];
      expect(d).toEqual({
        version: 1,
        kind: input.action.kind,
        mailboxId: u.mb.id,
        targets,
        nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
        issuedAt,
        ...(input.action.kind === "revoke-device" ? {} : { request }),
      });
      expect(await sql(u.mb, "SELECT purpose, kind, descriptor, action_digest FROM challenges WHERE id = ?", c.id)).toEqual([
        { purpose: input.purpose, kind: input.action.kind, descriptor: c.descriptor, action_digest: await descriptorDigest(c) },
      ]);
    }
    const session = await challenge(u.mb, { purpose: "session" });
    expect([session.descriptor, (await sql(u.mb, "SELECT kind, descriptor, action_digest FROM challenges WHERE id = ?", session.id))[0]]).toEqual([
      null,
      { kind: null, descriptor: null, action_digest: null },
    ]);
  });

  it("an email challenge is not sealed, has no answer, names no key or factor, and lives 10 minutes; a key challenge names the active key", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const email = await challenge(u.mb, { purpose: "email", action: { kind: "revoke-device", deviceIds: [device.id] } });
    expect(email).toMatchObject({ purpose: "email", keyId: null, factorId: null, sealed: null, expiresAt: at(u.mb, 10 * MINUTE) });
    expect(await sql(u.mb, "SELECT answer_hash FROM challenges WHERE id = ?", email.id)).toEqual([{ answer_hash: null }]);
    const key = await challenge(u.mb, { purpose: "key", action: { kind: "upgrade", request: random(32) } });
    expect(key).toMatchObject({ purpose: "key", keyId: u.mb.key!.keyId, factorId: null, expiresAt: at(u.mb, 2 * MINUTE) });
    expect(bytesFromBase64url(await openChallenge(u.mb.id, key, u.mailboxKey))).toHaveLength(32);
    // A6: a key challenge opens with the mailbox key and its digest only; the session form of its aad opens nothing.
    await expect(openChallenge(u.mb.id, { ...key, purpose: "session" }, u.mailboxKey)).rejects.toThrow();
  });

  it("refuses an action whose kind is not its purpose's, a device Mail does not hold, and anything outside the contract (InvalidRequest), and stores nothing", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const digest = random(32);
    const twentyOne = Array.from({ length: 21 }, () => newId("dev"));
    const cases: [string, Record<string, unknown>][] = [
      ["revoke-device by a factor", { purpose: "factor", factorId: u.recovery.id, action: { kind: "revoke-device", deviceIds: [device.id] } }],
      ["upgrade by a factor", { purpose: "factor", factorId: u.recovery.id, action: { kind: "upgrade", request: digest } }],
      ["open-session by the key", { purpose: "key", action: { kind: "open-session", request: digest } }],
      ["remove-devices by an email code", { purpose: "email", action: { kind: "remove-devices", deviceIds: [device.id], request: digest } }],
      ["register-device by an email code", { purpose: "email", action: { kind: "register-device", device: { id: newId("dev"), label: "x" }, request: digest } }],
      ["an unknown kind", { purpose: "factor", factorId: u.recovery.id, action: { kind: "revoke-everything", request: digest } }],
      ["no action", { purpose: "email" }],
      ["a session challenge with an action", { purpose: "session", action: { kind: "open-session", request: digest } }],
      ["a device Mail does not hold (email)", { purpose: "email", action: { kind: "revoke-device", deviceIds: [newId("dev")] } }],
      ["a device Mail does not hold (factor)", { purpose: "factor", factorId: u.recovery.id, action: { kind: "remove-devices", deviceIds: [newId("dev")], request: digest } }],
      ["no device to revoke", { purpose: "email", action: { kind: "revoke-device", deviceIds: [] } }],
      ["twenty-one devices", { purpose: "email", action: { kind: "revoke-device", deviceIds: twentyOne } }],
      ["a device twice", { purpose: "email", action: { kind: "revoke-device", deviceIds: [device.id, device.id] } }],
      ["a request that is not a digest", { purpose: "factor", factorId: u.recovery.id, action: { kind: "open-session", request: "short" } }],
      ["an action with an extra member", { purpose: "factor", factorId: u.recovery.id, action: { kind: "open-session", request: digest, extra: "x" } }],
      ["revoke-device with a request", { purpose: "email", action: { kind: "revoke-device", deviceIds: [device.id], request: digest } }],
      ["a key challenge naming a factor", { purpose: "key", factorId: u.recovery.id, action: { kind: "upgrade", request: digest } }],
      ["a label outside the rule", { purpose: "factor", factorId: u.recovery.id, action: { kind: "register-device", device: { id: newId("dev"), label: "a\u0085b" }, request: digest } }],
    ];
    const before = await sql(u.mb, "SELECT COUNT(*) AS n FROM challenges");
    for (const [name, request] of cases) {
      expect([name, refusalOf(await mail().challenge(await capFor(u.mb), request)).name]).toEqual([name, "InvalidRequest"]);
    }
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM challenges")).toEqual(before);
  });

  it("B3: purposes email and key, and any action, need the owner; a session challenge needs openRoles only", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    await sql(u.mb, `UPDATE policy SET open_roles = '["owner","editor"]'`);
    const editor = { role: "editor" as const };
    valueOf(await mail().challenge(await capFor(u.mb, editor), { purpose: "session" }));
    for (const request of [
      { purpose: "email", action: { kind: "revoke-device", deviceIds: [device.id] } },
      { purpose: "key", action: { kind: "upgrade", request: random(32) } },
      { purpose: "factor", factorId: u.recovery.id, action: { kind: "open-session", request: random(32) } },
    ]) {
      expect([request.purpose, refusalOf(await mail().challenge(await capFor(u.mb, editor), request))]).toEqual([request.purpose, FORBIDDEN]);
    }
  });
});

describe("M17′: a proof confirms the call it was issued for, and no other (D36)", () => {
  it("a factor proof answered for one descriptor is refused on another call (another wrap, another kind, another device, another session challenge), and is spent", async () => {
    const u = await upgradedMailbox();
    const keyId = u.mb.key!.keyId;
    const spare = await keyedWrap(u.mb, "recovery", keyId, u.recovery);
    valueOf(await mail().addWrap(await capFor(u.mb), spare.wrap, { session: u.session, factorProof: await factorProof(u.mb, u.recovery, addFactorAction(spare.wrap)) }));

    // Removing the passkey was confirmed; the relay removes the spare recovery key with it.
    const forPasskey = await factorProof(u.mb, u.recovery, removeFactorAction(u.passkey.id));
    expect(refusalOf(await mail().removeWrap(await capFor(u.mb), spare.wrap.id, { session: u.session, factorProof: forPasskey }))).toEqual(PROOF_REJECTED);
    // Spent by that call: the call it was for is refused now too.
    expect(refusalOf(await mail().removeWrap(await capFor(u.mb), u.passkey.id, { session: u.session, factorProof: forPasskey }))).toEqual(PROOF_REJECTED);
    expect(await rejections(u.mb, forPasskey.challengeId)).toEqual(["action", "used"]);

    // A remove-factor proof on an addWrap (another kind).
    const another = await keyedWrap(u.mb, "passkey-prf", keyId, u.recovery);
    const wrongKind = await factorProof(u.mb, u.recovery, removeFactorAction(another.wrap.id));
    expect(refusalOf(await mail().addWrap(await capFor(u.mb), another.wrap, { session: u.session, factorProof: wrongKind }))).toEqual(PROOF_REJECTED);

    // A registration confirmed for one device, used for another (its own admission, signature and label all genuine).
    const mine = await registerRequest(u, await newDevice({ label: "Mine" }), u.recovery);
    const theirs = await registerRequest(u, await newDevice({ label: "Mine" }), u.recovery);
    const forMine = await factorProof(u.mb, u.recovery, registerAction(mine));
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), theirs, { session: u.session, factorProof: forMine }))).toEqual(PROOF_REJECTED);
    // The same device, but another seal (only the request's digest tells these apart).
    const resealed = { ...mine, seal: (await registerRequest(u, await newDevice(), u.recovery)).seal };
    const forMineAgain = await factorProof(u.mb, u.recovery, registerAction(mine));
    expect(refusalOf(await mail().registerDevice(await capFor(u.mb), resealed, { session: u.session, factorProof: forMineAgain }))).toEqual(PROOF_REJECTED);

    // An open-session proof bound to one session challenge, used with another.
    const c1 = await challenge(u.mb, { purpose: "session" });
    const c2 = await challenge(u.mb, { purpose: "session" });
    const forC1 = await factorProof(u.mb, u.passkey, openSessionAction(c1.id));
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c2.id, answer: await openChallenge(u.mb.id, c2, u.mailboxKey), factorProof: forC1 }))).toEqual(PROOF_REJECTED);
    expect(await rejections(u.mb, forC1.challengeId)).toEqual(["action"]);

    const v = await view(u.mb);
    expect(v.wraps.map((w) => w.id).sort()).toEqual([u.recovery.id, u.passkey.id, spare.wrap.id].sort());
    expect(v.devices).toEqual([]);
  });

  it("a relay's rotation with the owner's proof and session but its own key is refused, and changes nothing", async () => {
    const u = await upgradedMailbox();
    const lost = await keepDevice(u);
    const owner = await plainSession(u);
    // The owner's browser builds its removal and asks for its proof.
    const theOwners = { deviceIds: [lost.id], rotation: (await rotationFor(u.mb, lost.id, u.recovery)).rotation };
    const proof = await factorProof(u.mb, u.recovery, removeDevicesAction(theOwners));
    // The relay keeps the owner's transition and seals but rotates to a key of its own.
    const relays = await rotationFor(u.mb, lost.id, u.recovery);
    const swapped = { deviceIds: [lost.id], rotation: { ...theOwners.rotation, publicKey: relays.rotation.publicKey, successorSeal: relays.rotation.successorSeal } };
    const before = { view: await view(u.mb), keys: await sql(u.mb, "SELECT * FROM keys"), seals: await sql(u.mb, "SELECT * FROM key_seals") };
    expect(refusalOf(await mail().removeDevices(await capFor(u.mb), swapped, { session: owner, factorProof: proof }))).toEqual(PROOF_REJECTED);
    // Its own whole rotation (with a transition it could not have signed) fares no better.
    expect(refusalOf(await mail().removeDevices(await capFor(u.mb), { deviceIds: [lost.id], rotation: relays.rotation }, { session: owner, factorProof: proof }))).toEqual(PROOF_REJECTED);
    expect({ view: await view(u.mb), keys: await sql(u.mb, "SELECT * FROM keys"), seals: await sql(u.mb, "SELECT * FROM key_seals") }).toEqual(before);
    expect(await rejections(u.mb, proof.challengeId)).toEqual(["action", "used"]);
    // The owner, with a fresh proof for its own request, rotates.
    valueOf(await mail().removeDevices(await capFor(u.mb), theOwners, { session: owner, factorProof: await factorProof(u.mb, u.recovery, removeDevicesAction(theOwners)) }));
  });

  it("a proof for the same devices with another rotation is refused: the descriptor names the request's digest, not only its devices", async () => {
    const u = await upgradedMailbox();
    const lost = await keepDevice(u);
    const owner = await plainSession(u);
    const first = { deviceIds: [lost.id], rotation: (await rotationFor(u.mb, lost.id, u.recovery)).rotation };
    const second = { deviceIds: [lost.id], rotation: { ...first.rotation, seals: first.rotation.seals.map((s) => ({ ...s, sealed: (s.sealed.length === 190 ? random(142) : random(109)) })) } };
    const proof = await factorProof(u.mb, u.recovery, removeDevicesAction(first));
    expect(refusalOf(await mail().removeDevices(await capFor(u.mb), second, { session: owner, factorProof: proof }))).toEqual(PROOF_REJECTED);
    expect((await view(u.mb)).devices.map((d) => d.id)).toEqual([lost.id]);
  });

  it("a request A10 cannot serialize (a number, here) is InvalidRequest, and the proof is spent", async () => {
    const u = await upgradedMailbox();
    const proof = await factorProof(u.mb, u.recovery, removeFactorAction(u.passkey.id));
    expect(refusalOf(await mail().removeWrap(await capFor(u.mb), 7 as unknown as string, { session: u.session, factorProof: proof }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: the request holds a value A10 does not serialize",
    });
    expect(refusalOf(await mail().removeWrap(await capFor(u.mb), u.passkey.id, { session: u.session, factorProof: proof }))).toEqual(PROOF_REJECTED);
  });

  it("the upgrade's key proof confirms only that upgrade request (B5)", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey } = legacy;
    const { session } = await openSession(mb, mailboxKey);
    const owners = await upgradeRequest(mb, [await legacy.recovery(), await legacy.passkey()], mb.key!.keyId);
    const relays = await upgradeRequest(mb, [await legacy.recovery(), await legacy.passkey()], mb.key!.keyId);
    const proof = await keyProof(mb, mailboxKey, owners);
    expect(refusalOf(await mail().upgrade(await capFor(mb), relays, { session, keyProof: proof }))).toEqual(PROOF_REJECTED);
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM key_wraps WHERE factor_key IS NOT NULL")).toEqual([{ n: 0 }]);
  });
});

describe("M15′: while sessions are required, a key proof alone opens no session (D38)", () => {
  it("a session with a key proof alone is refused, and so is one with both a device and a factor proof; nothing is spent or written", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
    const sessions = await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions");
    const d38 = { name: "InvalidRequest", message: "invalid request: while sessions are required, a session needs a kept device's signature or a factor proof, exactly one (D38)" };
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer }))).toEqual(d38);
    const both = { device: { id: device.id, signature: await signProof(u.mb.id, device, c) }, factorProof: await factorProof(u.mb, u.recovery, openSessionAction(c.id)) };
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, ...both }))).toEqual(d38);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual(sessions);
    expect(await sql(u.mb, "SELECT used_at FROM challenges WHERE id = ?", c.id)).toEqual([{ used_at: null }]);
    // The same challenge then opens with a device's signature.
    valueOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, device: both.device }));
  });

  it("opens with a factor proof of kind open-session for this session challenge (F11): no device, both challenges spent", async () => {
    const u = await upgradedMailbox();
    const c = await challenge(u.mb, { purpose: "session" });
    const proof = await factorProof(u.mb, u.passkey, openSessionAction(c.id));
    const opened = valueOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer: await openChallenge(u.mb.id, c, u.mailboxKey), factorProof: proof }));
    expect(opened).toEqual({ session: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), expiresAt: at(u.mb, 60 * MINUTE), device: null });
    expect(await sql(u.mb, "SELECT token_hash, device_id FROM mail_sessions WHERE token_hash = ?", await sha256(opened.session))).toEqual([{ token_hash: await sha256(opened.session), device_id: null }]);
    expect((await sql<{ id: string; used: number }>(u.mb, "SELECT id, used_at IS NOT NULL AS used FROM challenges WHERE id IN (?, ?) ORDER BY id", c.id, proof.challengeId)).map((r) => r.used)).toEqual([1, 1]);
  });

  it("a wrong factor answer, or a wrong key answer, spends both challenges and opens nothing", async () => {
    const u = await upgradedMailbox();
    const c = await challenge(u.mb, { purpose: "session" });
    const answer = await openChallenge(u.mb.id, c, u.mailboxKey);
    const proof = await factorProof(u.mb, u.passkey, openSessionAction(c.id));
    const sessions = await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions");
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, factorProof: { ...proof, answer: random(32) } }))).toEqual(PROOF_REJECTED);
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer, factorProof: proof }))).toEqual(PROOF_REJECTED);
    const c2 = await challenge(u.mb, { purpose: "session" });
    const proof2 = await factorProof(u.mb, u.passkey, openSessionAction(c2.id));
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c2.id, answer: random(32), factorProof: proof2 }))).toEqual(PROOF_REJECTED);
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c2.id, answer: await openChallenge(u.mb.id, c2, u.mailboxKey), factorProof: proof2 }))).toEqual(PROOF_REJECTED);
    expect(await sql(u.mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual(sessions);
    expect([await rejections(u.mb, proof.challengeId), await rejections(u.mb, c2.id)]).toEqual([["answer"], ["answer", "used"]]);
  });

  it("a removed factor's proof opens no session (M24)", async () => {
    const u = await upgradedMailbox();
    const c = await challenge(u.mb, { purpose: "session" });
    const proof = await factorProof(u.mb, u.passkey, openSessionAction(c.id));
    valueOf(await mail().removeWrap(await capFor(u.mb), u.passkey.id, { session: u.session, factorProof: await factorProof(u.mb, u.recovery, removeFactorAction(u.passkey.id)) }));
    expect(refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: c.id, answer: await openChallenge(u.mb.id, c, u.mailboxKey), factorProof: proof }))).toEqual(PROOF_REJECTED);
    expect(await rejections(u.mb, proof.challengeId)).toEqual(["factor"]);
  });

  it("while sessions are optional a key proof alone still opens one, and a factor proof is refused", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    valueOf(await mail().openSession(await capFor(mb), await (async () => {
      const c = await challenge(mb, { purpose: "session" });
      return { challengeId: c.id, answer: await openChallenge(mb.id, c, mailboxKey) };
    })()));
    const c = await challenge(mb, { purpose: "session" });
    expect(refusalOf(await mail().openSession(await capFor(mb), { challengeId: c.id, answer: await openChallenge(mb.id, c, mailboxKey), factorProof: { challengeId: newId("chl"), answer: random(32) } }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: a factor proof opens no session while sessions are optional",
    });
  });
});

describe("M21′: a device works only for the account that kept it (D37, G42)", () => {
  it("another account's device is Forbidden, never DeviceRevoked: its record, its sessions and the challenge are untouched, and it still opens for its own account", async () => {
    const u = await upgradedMailbox();
    const device = await keepDevice(u);
    const ownersSession = (await openSession(u.mb, u.mailboxKey, { device })).session;
    const theirs = await challenge(u.mb, { purpose: "session" }, { sub: "acc_other" });
    const state = async () => ({
      devices: await sql(u.mb, "SELECT * FROM devices"),
      sessions: await sql(u.mb, "SELECT * FROM mail_sessions ORDER BY token_hash"),
      seals: await sql(u.mb, "SELECT * FROM key_seals"),
      audit: await sql(u.mb, "SELECT COUNT(*) AS n FROM audit"),
      challenge: await sql(u.mb, "SELECT used_at, refused_at FROM challenges WHERE id = ?", theirs.id),
    });
    const before = await state();
    for (let i = 0; i < 3; i++) {
      const answer = await mail().openSession(await capFor(u.mb, { sub: "acc_other" }), {
        challengeId: theirs.id,
        answer: await openChallenge(u.mb.id, theirs, u.mailboxKey),
        device: { id: device.id, signature: await signProof(u.mb.id, device, theirs) },
      });
      expect(refusalOf(answer)).toEqual(FORBIDDEN);
    }
    expect(await state()).toEqual(before);
    valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session: ownersSession }));
    await openSession(u.mb, u.mailboxKey, { device });
    // A device of its own, kept by the other account (an owner too), opens for that account only.
    const theirDevice = await keepDevice(u, { sub: "acc_other", session: await plainSession(u, u.recovery, { sub: "acc_other" }) });
    expect((await view(u.mb)).devices.find((d) => d.id === theirDevice.id)!.createdBy).toBe("acc_other");
    const mine = await challenge(u.mb, { purpose: "session" });
    expect(
      refusalOf(await mail().openSession(await capFor(u.mb), { challengeId: mine.id, answer: await openChallenge(u.mb.id, mine, u.mailboxKey), device: { id: theirDevice.id, signature: await signProof(u.mb.id, theirDevice, mine) } })),
    ).toEqual(FORBIDDEN);
  });
});

describe("the descriptor's request digest is A10's: RFC 8785 of the request as the call sends it", () => {
  it("Mail recomputes the same digest the browser does, member order notwithstanding", async () => {
    const u = await upgradedMailbox();
    const device = await newDevice();
    const request = await registerRequest(u, device, u.recovery);
    // The same request with its members in another order is the same request (RFC 8785 sorts them).
    const reordered = { seal: request.seal, device: Object.fromEntries(Object.entries(request.device).reverse()) as typeof request.device };
    expect(await requestDigestOf(reordered)).toBe(await requestDigestOf(request));
    const proof = await factorProof(u.mb, u.recovery, registerAction(request));
    valueOf(await mail().registerDevice(await capFor(u.mb), reordered, { session: u.session, factorProof: proof }));
    expect((await actionInput(registerAction(reordered))).request).toBe((await actionInput(registerAction(request))).request);
  });
});
