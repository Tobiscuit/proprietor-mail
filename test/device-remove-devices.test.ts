import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  emailCode,
  factorProof,
  keepDevice,
  newDevice,
  openSession,
  plainSession,
  removeDevices,
  removeDevicesAction,
  rotationFor,
  signTransition,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes } from "./support/capability-tokens";
import { capFor, newKeyPair, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Round 3 of spec 002: removeDevices (contracts/device-v1.md B7, replacing
// removeDevice; domain-model M18′, M23, M25; D39, D40). Several devices go
// in one rotation, and the rotation's transition is signed by the factor
// whose proof the call spends, and by no other.

const mail = () => exports.MailService;

const view = async (mb: TestMailbox) => valueOf(await mail().mailbox(await capFor(mb)));

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function state(mb: TestMailbox) {
  return {
    view: await view(mb),
    keys: await sql(mb, "SELECT * FROM keys ORDER BY created_at"),
    seals: await sql(mb, "SELECT * FROM key_seals ORDER BY to_kind, to_id"),
    sessions: await sql(mb, "SELECT token_hash, device_id FROM mail_sessions ORDER BY token_hash"),
  };
}

async function fourDevices() {
  const u = await upgradedMailbox();
  const phone = await keepDevice(u, { device: await newDevice({ label: "Phone" }) });
  const laptop = await keepDevice(u, { device: await newDevice({ label: "Laptop" }), session: await plainSession(u) });
  const tablet = await keepDevice(u, { device: await newDevice({ label: "Tablet" }), session: await plainSession(u) });
  const desk = await keepDevice(u, { device: await newDevice({ label: "Front desk", keepsNothing: true }), session: await plainSession(u) });
  const tabletSession = (await openSession(u.mb, u.mailboxKey, { device: tablet })).session;
  const remover = await plainSession(u);
  return { u, phone, laptop, tablet, desk, tabletSession, remover };
}

describe("removeDevices: several devices, one rotation (M18′, D40)", () => {
  it("removes two devices with their seals and sessions in one transaction; the others are sealed and tagged under the new key", async () => {
    const { u, phone, laptop, tablet, desk, remover } = await fourDevices();
    const old = u.mb.key!.keyId;
    const { next, rotation } = await rotationFor(u.mb, [phone.id, laptop.id], u.passkey);
    expect(valueOf(await removeDevices(u, { deviceIds: [laptop.id, phone.id], rotation }, remover, u.passkey))).toEqual({ keyId: next.keyId });
    const v = await view(u.mb);
    expect(v.devices.map((d) => d.id).sort()).toEqual([tablet.id, desk.id].sort());
    expect(v.seals.map((s) => `${s.keyId}:${s.to.kind}:${s.to.id}`).sort()).toEqual(
      [`${next.keyId}:device:${tablet.id}`, `${next.keyId}:factor:${u.recovery.id}`, `${next.keyId}:factor:${u.passkey.id}`].sort(),
    );
    expect(v.keys.map((k) => [k.keyId, k.retiredAt === null, k.successor?.keyId ?? null, k.successor?.signedBy ?? null])).toEqual([
      [old, false, next.keyId, u.passkey.id],
      [next.keyId, true, null, null],
    ]);
    expect(await sql(u.mb, "SELECT device_id FROM mail_sessions")).toEqual([{ device_id: null }]);
    const audit = await sql<{ action: string; detail: string }>(u.mb, "SELECT action, detail FROM audit WHERE action IN ('device-removed', 'key-rotated') ORDER BY id");
    expect(audit.map((a) => a.action)).toEqual(["device-removed", "device-removed", "key-rotated"]);
    expect(audit.slice(0, 2).map((a) => (JSON.parse(a.detail) as { device: string }).device).sort()).toEqual([laptop.id, phone.id].sort());
    // The other sessions that ended: the tablet's two and the desk's one (the removed devices' went with them; the remover's stays).
    expect(JSON.parse(audit[2]!.detail)).toEqual({ from: old, to: next.keyId, seals: 3, sessions: 3, factor: u.passkey.id, due: false });
  });

  it("names 0 to 20 distinct devices of the mailbox; a device that went meanwhile (revoked by an email code) stops everything", async () => {
    const { u, phone, laptop, remover } = await fourDevices();
    const request = { deviceIds: [phone.id, laptop.id], rotation: (await rotationFor(u.mb, [phone.id, laptop.id], u.recovery)).rotation };
    const proof = await factorProof(u.mb, u.recovery, removeDevicesAction(request));
    valueOf(await mail().revokeDevices(await emailCode(u, [laptop.id]), { deviceIds: [laptop.id] }));
    const before = await state(u.mb);
    expect(refusalOf(await mail().removeDevices(await capFor(u.mb), request, { session: remover, factorProof: proof }))).toEqual({ name: "InvalidRequest", message: "invalid request: no such device" });
    expect(await state(u.mb)).toEqual(before);
  });
});

describe("the transition is the proof's factor's (M23, M25, D39)", () => {
  it("refuses a rotation whose transition is unsigned, signed by another factor, or over another step, and changes nothing", async () => {
    const { u, phone, remover } = await fourDevices();
    const { next, rotation } = await rotationFor(u.mb, phone.id, u.recovery);
    const other = await newKeyPair();
    const cases: [string, unknown][] = [
      ["a signature that is not one", { signedBy: u.recovery.id, signature: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(64))) }],
      ["signed and named by the passkey, while the recovery key's proof is spent", await signTransition(u.mb.id, u.passkey, rotation.from, next)],
      [
        "named for the recovery key, signed by the passkey",
        { signedBy: u.recovery.id, signature: (await signTransition(u.mb.id, { ...u.passkey, id: u.recovery.id }, rotation.from, next)).signature },
      ],
      ["the recovery key's, over another new key", await signTransition(u.mb.id, u.recovery, rotation.from, other)],
      ["the recovery key's, from another key", await signTransition(u.mb.id, u.recovery, other.keyId, next)],
    ];
    const before = await state(u.mb);
    for (const [name, transition] of cases) {
      const answer = await removeDevices(u, { deviceIds: [phone.id], rotation: { ...rotation, transition } }, remover, u.recovery);
      expect([name, refusalOf(answer).name]).toEqual([name, "InvalidRequest"]);
    }
    expect(await state(u.mb)).toEqual(before);
    // Signed by the passkey, it goes through with the passkey's proof.
    valueOf(await removeDevices(u, { deviceIds: [phone.id], rotation: { ...rotation, transition: cases[1]![1] } }, remover, u.passkey));
    expect((await view(u.mb)).keys.find((k) => k.keyId === rotation.from)!.successor).toMatchObject({ keyId: next.keyId, signedBy: u.passkey.id });
  });
});
