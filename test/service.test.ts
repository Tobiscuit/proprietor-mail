import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import { base64urlFromBytes } from "./support/capability-tokens";
import { type CapturedConsole, captureConsole } from "./support/console";
import { incomingEmail, sampleMessage } from "./support/email";
import { testId } from "./support/ids";
import {
  capFor,
  directoryRow,
  mint,
  newKeyPair,
  nowSeconds,
  passkeyWrap,
  provisionMailbox,
  recoveryWrap,
  type TestMailbox,
} from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

const a_tag = () => crypto.randomUUID().slice(0, 8);

const mail = () => exports.MailService;

const NOT_FOUND = { ok: false, error: { name: "NotFound", message: "not found" } };

async function arrive(mb: TestMailbox, n = 1): Promise<void> {
  for (let i = 0; i < n; i++) {
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    await worker.email!(email.message, env, createExecutionContext());
    mb.ports.clock.advance(1000);
  }
}

/** Every MailService method, called with the given capability and a harmless argument. */
function everyMethod(cap: string): [string, () => Promise<unknown>][] {
  return [
    ["mailboxes", () => mail().mailboxes(cap)],
    ["mailbox", () => mail().mailbox(cap)],
    ["enroll", () => mail().enroll(cap, {})],
    ["addWrap", () => mail().addWrap(cap, {})],
    ["removeWrap", () => mail().removeWrap(cap, testId("wrp"))],
    ["list", () => mail().list(cap, { folder: "inbox" })],
    ["body", () => mail().body(cap, testId("msg"))],
    ["update", () => mail().update(cap, testId("msg"), { seen: true })],
    ["purge", () => mail().purge(cap, testId("msg"))],
    ["drafts", () => mail().drafts(cap)],
    ["saveDraft", () => mail().saveDraft(cap, {})],
    ["deleteDraft", () => mail().deleteDraft(cap, testId("drf"))],
    ["send", () => mail().send(cap, {})],
    ["unread", () => mail().unread(cap)],
    ["setPolicy", () => mail().setPolicy(cap, {})],
    ["audit", () => mail().audit(cap, {})],
  ];
}

let captured: CapturedConsole;
let logs: string[] = [];
beforeEach(() => {
  captured = captureConsole();
  logs = captured.lines;
});
afterEach(() => captured.restore());

describe("answers are values (contracts/mail-service-v1.md)", () => {
  it("answers a refused capability with a value from every method, never a rejection", async () => {
    for (const [method, call] of everyMethod("not-a-token")) {
      const answer = await call();
      expect([method, answer]).toEqual([
        method,
        { ok: false, error: { name: "CapabilityRejected", message: "capability rejected: invalid", reason: "invalid" } },
      ]);
    }
  });

  it("answers an unexpected failure as InternalError, and alerts the operator with the jti", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    mb.ports.sealer.keyIdOf = async () => {
      throw new TypeError("a bug nobody expected");
    };
    const key = await newKeyPair();
    const answer = await mail().enroll(await capFor(mb, { jti: "trace-jti-internal" }), {
      publicKey: base64urlFromBytes(key.publicKey),
      wraps: [recoveryWrap(key.keyId)],
    });
    expect(answer).toEqual({ ok: false, error: { name: "InternalError", message: "internal error" } });
    const alert = logs.map((l) => JSON.parse(l) as Record<string, unknown>).find((l) => l.event === "operator-alert");
    expect(alert).toEqual({ event: "operator-alert", kind: "mail-service-internal-error", method: "enroll", jti: "trace-jti-internal", mailbox: mb.id, error: null });
    // The Mailbox names what failed in its own line; nothing from the error's message reaches a log.
    expect(logs.some((l) => l.includes('"mailbox-error"') && l.includes('"TypeError"'))).toBe(true);
    expect(logs.some((l) => l.includes("a bug nobody expected"))).toBe(false);
    expect((await directoryRow(mb.id))?.status).toBe("provisioned");
  });
});

describe("capability checks on every call (contracts/capability-v1.md)", () => {
  it("refuses an expired token as CapabilityRejected{expired}", async () => {
    const mb = await provisionMailbox();
    const cap = await mint({ business: mb.businessId, mbx: mb.id, iat: nowSeconds() - 120 });
    expect(refusalOf(await mail().list(cap, { folder: "inbox" }))).toEqual({
      name: "CapabilityRejected",
      message: "capability rejected: expired",
      reason: "expired",
    });
  });

  it("logs the jti, the method and the outcome of every call, and nothing else", async () => {
    const mb = await provisionMailbox();
    await mail().unread(await capFor(mb, { jti: "trace-jti-accepted" }));
    const expired = await mint({ business: mb.businessId, mbx: mb.id, iat: nowSeconds() - 120, jti: "trace-jti-expired" });
    await mail().unread(expired);
    await mail().unread(await capFor(mb, { role: "editor", jti: "trace-jti-forbidden" }));
    const lines = logs.filter((l) => l.includes('"mail-service"')).map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toEqual([
      { event: "mail-service", method: "unread", jti: "trace-jti-accepted", outcome: "accepted", mailbox: mb.id, result: "ok" },
      { event: "mail-service", method: "unread", jti: "trace-jti-expired", outcome: "rejected", reason: "expired" },
      { event: "mail-service", method: "unread", jti: "trace-jti-forbidden", outcome: "accepted", mailbox: mb.id, result: "Forbidden" },
    ]);
  });

  it("asks for a mailbox in the capability for every mailbox method", async () => {
    const mb = await provisionMailbox();
    const noMailbox = await mint({ business: mb.businessId });
    for (const [method, call] of everyMethod(noMailbox).filter(([m]) => m !== "mailboxes")) {
      expect([method, await call()]).toEqual([
        method,
        { ok: false, error: { name: "InvalidRequest", message: "invalid request: the capability names no mailbox" } },
      ]);
    }
  });
});

describe("M4: a mailbox belongs to one business for life", () => {
  it("answers a capability for business A naming business B's mailbox exactly as it answers a missing mailbox", async () => {
    const a = await provisionMailbox();
    const b = await provisionMailbox();
    const crossBusiness = await mail().list(await mint({ business: a.businessId, mbx: b.id }), { folder: "inbox" });
    const missing = await mail().list(await mint({ business: a.businessId, mbx: testId("mbx") }), { folder: "inbox" });
    expect(crossBusiness).toEqual(NOT_FOUND);
    expect(crossBusiness).toStrictEqual(missing);
    // And B's own mailbox never learned anything: nothing was touched.
    expect((await directoryRow(b.id))?.business_id).toBe(b.businessId);
  });

  it("answers the same NotFound when the Mailbox itself refuses a Directory row that changed business", async () => {
    const mb = await provisionMailbox();
    await env.DIRECTORY.prepare("UPDATE mailboxes SET business_id = 'biz_moved' WHERE id = ?").bind(mb.id).run();
    // The Directory now says biz_moved, and the capability agrees; the Mailbox remembers its first business.
    const moved = await mail().list(await mint({ business: "biz_moved", mbx: mb.id }), { folder: "inbox" });
    const missing = await mail().list(await mint({ business: "biz_moved", mbx: testId("mbx") }), { folder: "inbox" });
    expect(moved).toEqual(NOT_FOUND);
    expect(moved).toStrictEqual(missing);
  });

  it("answers NotFound for a closed mailbox, for every method", async () => {
    const mb = await provisionMailbox({ status: "closed" });
    for (const [method, call] of everyMethod(await capFor(mb)).filter(([m]) => m !== "mailboxes")) {
      expect([method, await call()]).toEqual([method, NOT_FOUND]);
    }
  });

  it("lists only the capability's own business's mailboxes, to any member role, each with its addresses (primary first)", async () => {
    const a = await provisionMailbox({ status: "provisioned", addresses: [`team.${a_tag()}@mail.test`] });
    await provisionMailbox();
    const list = await mail().mailboxes(await mint({ business: a.businessId, role: "editor" }));
    expect(list).toEqual({ ok: true, value: [{ id: a.id, address: a.address, addresses: a.addresses, status: "provisioned" }] });
    expect(a.addresses).toHaveLength(2);
    expect(a.addresses[0]).toBe(a.address);
  });
});

describe("roles (D9: only owners open a mailbox by default)", () => {
  it("refuses an editor as Forbidden for reading, sending, keys and policy", async () => {
    const mb = await provisionMailbox();
    const cap = await capFor(mb, { role: "editor" });
    for (const call of [
      () => mail().mailbox(cap),
      () => mail().list(cap, { folder: "inbox" }),
      () => mail().unread(cap),
      () => mail().setPolicy(cap, { displayName: "X" }),
      () => mail().audit(cap, {}),
      () => mail().send(cap, { idempotencyKey: "k1", to: [{ address: "a@b.test" }], subject: "s", text: "t" }),
    ]) {
      expect(await call()).toEqual({ ok: false, error: { name: "Forbidden", message: "forbidden" } });
    }
  });
});

describe("mailbox() and enrolment (M5, M10)", () => {
  it("shows a provisioned mailbox with no keys, and the delivery mode and forward target (M10)", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect(view).toMatchObject({ id: mb.id, address: mb.address, addresses: [mb.address], status: "provisioned", displayName: "", keys: [], wraps: [] });
    expect(view.policy).toMatchObject({ delivery: "store", forwardTo: null, assistant: "off" });
  });

  it("enrols a key with a recovery wrap and activates the mailbox", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const key = await newKeyPair();
    const wraps = [recoveryWrap(key.keyId), passkeyWrap(key.keyId)];
    const result = await mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(key.publicKey), wraps });
    expect(result).toEqual({ ok: true, value: { keyId: key.keyId } });
    expect(await directoryRow(mb.id)).toMatchObject({ status: "active" });
    expect((await directoryRow(mb.id))?.activated_at).toEqual(expect.any(String));
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect(view.status).toBe("active");
    expect(view.keys).toEqual([
      expect.objectContaining({ keyId: key.keyId, publicKey: base64urlFromBytes(key.publicKey), createdBy: "acc_owner", retiredAt: null }),
    ]);
    expect(view.wraps.map((w) => [w.id, w.kind, w.wrapped])).toEqual(
      expect.arrayContaining(wraps.map((w) => [w.id, w.kind, w.wrapped])),
    );
  });

  it("M5: refuses enrolment without a recovery wrap, and the mailbox stays provisioned", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const key = await newKeyPair();
    const answer = await mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(key.publicKey), wraps: [passkeyWrap(key.keyId)] });
    expect(answer).toEqual({ ok: false, error: { name: "InvalidRequest", message: "invalid request: a recovery wrap is required" } });
    expect((await directoryRow(mb.id))?.status).toBe("provisioned");
    expect(valueOf(await mail().mailbox(await capFor(mb))).keys).toEqual([]);
  });

  it("recomputes the keyId: a wrap naming another key is refused", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const key = await newKeyPair();
    const other = await newKeyPair();
    const answer = await mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(key.publicKey), wraps: [recoveryWrap(other.keyId)] });
    expect(refusalOf(answer)).toMatchObject({ name: "InvalidRequest" });
    expect((await directoryRow(mb.id))?.status).toBe("provisioned");
  });

  it("enrols only a provisioned mailbox, and only an owner", async () => {
    const mb = await provisionMailbox();
    const key = await newKeyPair();
    const request = { publicKey: base64urlFromBytes(key.publicKey), wraps: [recoveryWrap(key.keyId)] };
    expect(refusalOf(await mail().enroll(await capFor(mb), request))).toMatchObject({ name: "InvalidRequest" });
    const fresh = await provisionMailbox({ status: "provisioned" });
    expect(refusalOf(await mail().enroll(await capFor(fresh, { role: "editor" }), request))).toMatchObject({ name: "Forbidden" });
    expect((await directoryRow(fresh.id))?.status).toBe("provisioned");
  });

  it("M5: the last recovery wrap cannot be removed; another can", async () => {
    const mb = await provisionMailbox();
    const cap = await capFor(mb);
    const [only] = valueOf(await mail().mailbox(cap)).wraps;
    expect(refusalOf(await mail().removeWrap(await capFor(mb), only!.id))).toMatchObject({ name: "InvalidRequest" });

    const second = recoveryWrap(mb.key!.keyId, { label: "Printed sheet" });
    expect(await mail().addWrap(await capFor(mb), second)).toEqual({ ok: true, value: null });
    expect(await mail().removeWrap(await capFor(mb), only!.id)).toEqual({ ok: true, value: null });
    expect(valueOf(await mail().mailbox(await capFor(mb))).wraps.map((w) => w.id)).toEqual([second.id]);
    expect(refusalOf(await mail().removeWrap(await capFor(mb), second.id))).toMatchObject({ name: "InvalidRequest" });
  });

  it("adds a passkey wrap for the mailbox's key only, and audits key changes", async () => {
    const mb = await provisionMailbox();
    const other = await newKeyPair();
    expect(refusalOf(await mail().addWrap(await capFor(mb), passkeyWrap(other.keyId)))).toMatchObject({ name: "InvalidRequest" });
    const phone = passkeyWrap(mb.key!.keyId);
    valueOf(await mail().addWrap(await capFor(mb), phone));
    valueOf(await mail().removeWrap(await capFor(mb), phone.id));
    const actions = valueOf(await mail().audit(await capFor(mb), {})).map((a) => a.action);
    expect(actions.slice(0, 3)).toEqual(["wrap-removed", "wrap-added", "key-enrolled"]);
  });
});

describe("reading", () => {
  it("lists a folder newest first, in pages, with only sealed fields", async () => {
    const mb = await provisionMailbox();
    await arrive(mb, 3);
    const cap = await capFor(mb);
    const first = valueOf(await mail().list(cap, { folder: "inbox", limit: 2 }));
    expect(first.items).toHaveLength(2);
    expect(first.next).toEqual(expect.any(String));
    const second = valueOf(await mail().list(await capFor(mb), { folder: "inbox", limit: 2, before: first.next! }));
    expect(second.items).toHaveLength(1);
    expect(second.next).toBeNull();
    const all = [...first.items, ...second.items];
    expect(all.map((m) => m.receivedAt)).toEqual([...all.map((m) => m.receivedAt)].sort().reverse());
    expect(Object.keys(all[0]!).sort()).toEqual(
      ["direction", "flagged", "folder", "header", "id", "keyEnvelope", "keyId", "receivedAt", "seen", "size"],
    );
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "inbox", limit: 101 }))).toMatchObject({ name: "InvalidRequest" });
    expect(refusalOf(await mail().list(await capFor(mb), { folder: "nope" }))).toMatchObject({ name: "InvalidRequest" });
  });

  it("streams the sealed body from R2, byte for byte, as the value of an ok answer", async () => {
    const mb = await provisionMailbox();
    await arrive(mb);
    const [item] = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    const answer = await mail().body(await capFor(mb), item!.id);
    expect(answer.ok).toBe(true);
    const stream = valueOf(answer);
    expect(stream).toBeInstanceOf(ReadableStream);
    const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
    const stored = await env.MAIL.get(`mbx/${mb.id}/msg/${item!.id}`);
    expect(bytes).toEqual(new Uint8Array(await stored!.arrayBuffer()));
    expect(new TextDecoder().decode(bytes.slice(0, 4))).toBe("PMB1");
  });

  it("answers NotFound for a message that does not exist, and for one whose R2 object is gone", async () => {
    const mb = await provisionMailbox();
    await arrive(mb);
    const [item] = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    expect(await mail().body(await capFor(mb), testId("msg"))).toEqual(NOT_FOUND);
    await env.MAIL.delete(`mbx/${mb.id}/msg/${item!.id}`);
    expect(await mail().body(await capFor(mb), item!.id)).toEqual(NOT_FOUND);
  });

  it("marks, flags and moves; Trash stamps the time; nothing moves into Drafts", async () => {
    const mb = await provisionMailbox();
    await arrive(mb, 2);
    const [a, b] = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    expect(valueOf(await mail().update(await capFor(mb), a!.id, { seen: true, flagged: true }))).toMatchObject({ seen: true, flagged: true, folder: "inbox" });
    expect(await mail().unread(await capFor(mb))).toEqual({ ok: true, value: { inbox: 1 } });
    valueOf(await mail().update(await capFor(mb), b!.id, { folder: "trash" }));
    const trashedAt = await runInDurableObject(mb.stub, (_i, state) =>
      state.storage.sql.exec("SELECT trashed_at FROM messages WHERE id = ?", b!.id).one().trashed_at,
    );
    expect(trashedAt).toBe(mb.ports.clock.now().toISOString());
    valueOf(await mail().update(await capFor(mb), b!.id, { folder: "inbox" }));
    expect(
      await runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec("SELECT trashed_at FROM messages WHERE id = ?", b!.id).one().trashed_at),
    ).toBeNull();
    expect(refusalOf(await mail().update(await capFor(mb), b!.id, { folder: "drafts" }))).toMatchObject({ name: "InvalidRequest" });
  });

  it("counts as unread only what the owner can open: a message sealed to a key the mailbox never held is listed, never counted", async () => {
    const mb = await provisionMailbox();
    await arrive(mb);
    const seal = mb.ports.sealer.seal.bind(mb.ports.sealer);
    // Sealed to a key this mailbox never held: no device can open it, so it can never be marked seen.
    const stranger = await newKeyPair();
    mb.ports.sealer.seal = async (pub, ids, header, raw) => ({ ...(await seal(pub, ids, header, raw)), keyId: stranger.keyId });
    await arrive(mb);
    // Sealed to a retired key of the mailbox: old mail stays readable (domain-model, KeyRing), so it counts.
    const retired = await newKeyPair();
    await runInDurableObject(mb.stub, (_i, state) =>
      state.storage.sql.exec(
        "INSERT INTO keys (key_id, public_key, created_at, created_by, retired_at) VALUES (?, ?, ?, ?, ?)",
        retired.keyId,
        retired.publicKey,
        "2026-09-01T00:00:00.000Z",
        "acc_owner",
        "2026-09-02T00:00:00.000Z",
      ),
    );
    mb.ports.sealer.seal = async (pub, ids, header, raw) => ({ ...(await seal(pub, ids, header, raw)), keyId: retired.keyId });
    await arrive(mb);

    // All three rows stay listed, each with its keyId, so the owner sees that something arrived.
    const items = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    expect(items.map((m) => m.keyId).sort()).toEqual([mb.key!.keyId, retired.keyId, stranger.keyId].sort());
    expect(await mail().unread(await capFor(mb))).toEqual({ ok: true, value: { inbox: 2 } });
    // The count sent to the dashboard on each arrival follows the same rule.
    expect(mb.ports.signal.events.map((e) => e.unread)).toEqual([1, 1, 2]);
  });

  it("purges a message (owner): the row and the R2 object", async () => {
    const mb = await provisionMailbox();
    await arrive(mb);
    const [item] = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    expect(await mail().purge(await capFor(mb), item!.id)).toEqual({ ok: true, value: null });
    expect(valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items).toEqual([]);
    expect(await env.MAIL.head(`mbx/${mb.id}/msg/${item!.id}`)).toBeNull();
  });
});

describe("drafts: sealed in the browser", () => {
  it("saves, lists and deletes a sealed draft, for a known key only", async () => {
    const mb = await provisionMailbox();
    const draft = {
      id: testId("drf"),
      keyId: mb.key!.keyId,
      keyEnvelope: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(80))),
      sealed: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(200))),
    };
    expect(await mail().saveDraft(await capFor(mb), draft)).toEqual({ ok: true, value: { id: draft.id, updatedAt: mb.ports.clock.now().toISOString() } });
    expect(await mail().drafts(await capFor(mb))).toEqual({ ok: true, value: [{ ...draft, updatedAt: mb.ports.clock.now().toISOString() }] });
    expect(refusalOf(await mail().saveDraft(await capFor(mb), { ...draft, keyId: "0".repeat(32) }))).toMatchObject({ name: "InvalidRequest" });
    expect(refusalOf(await mail().saveDraft(await capFor(mb), { ...draft, keyEnvelope: "AAAA" }))).toMatchObject({ name: "InvalidRequest" });
    expect(await mail().deleteDraft(await capFor(mb), draft.id)).toEqual({ ok: true, value: null });
    expect(valueOf(await mail().drafts(await capFor(mb)))).toEqual([]);
    expect(await mail().deleteDraft(await capFor(mb), draft.id)).toEqual(NOT_FOUND);
  });
});

describe("policy and audit", () => {
  it("refuses to turn the assistant on (D1): AssistantUnavailable", async () => {
    const mb = await provisionMailbox();
    expect(await mail().setPolicy(await capFor(mb), { assistant: "on" })).toEqual({
      ok: false,
      error: { name: "AssistantUnavailable", message: "the assistant is not available (spec decision D1)" },
    });
    expect(valueOf(await mail().mailbox(await capFor(mb))).policy.assistant).toBe("off");
  });

  it("sets the display name, and audits the change without its value", async () => {
    const mb = await provisionMailbox();
    const policy = valueOf(await mail().setPolicy(await capFor(mb), { displayName: "Example", assistant: "off" }));
    expect(policy).toMatchObject({ displayName: "Example", assistant: "off" });
    const [latest] = valueOf(await mail().audit(await capFor(mb), {}));
    expect(latest).toMatchObject({ actor: "acc_owner", action: "policy-changed", detail: { fields: "displayName,assistant" } });
    expect(refusalOf(await mail().setPolicy(await capFor(mb), { displayName: "a\r\nBcc: x@y.test" }))).toMatchObject({ name: "InvalidRequest" });
  });
});
