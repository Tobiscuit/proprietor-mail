import { runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import { createExecutionContext } from "cloudflare:test";
import { type CapturedConsole, captureConsole } from "./support/console";
import { incomingEmail, sampleMessage } from "./support/email";
import { base64urlFromBytes } from "./support/capability-tokens";
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
  rejectionOf,
  type TestMailbox,
} from "./support/mailbox";

const mail = () => exports.MailService;

async function arrive(mb: TestMailbox, n = 1): Promise<void> {
  for (let i = 0; i < n; i++) {
    const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
    await worker.email!(email.message, env, createExecutionContext());
    mb.ports.clock.advance(1000);
  }
}

let captured: CapturedConsole;
let logs: string[] = [];
beforeEach(() => {
  captured = captureConsole();
  logs = captured.lines;
});
afterEach(() => captured.restore());

describe("capability checks on every call (contracts/capability-v1.md)", () => {
  it("refuses a bad token as CapabilityRejected{invalid}, the name and reason crossing RPC", async () => {
    const mb = await provisionMailbox();
    const err = await rejectionOf(mail().list("not-a-token", { folder: "inbox" }));
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("CapabilityRejected");
    expect(err.reason).toBe("invalid");
    void mb;
  });

  it("refuses an expired token as CapabilityRejected{expired}", async () => {
    const mb = await provisionMailbox();
    const cap = await mint({ tenant: mb.tenantId, mbx: mb.id, iat: nowSeconds() - 120 });
    expect(await rejectionOf(mail().list(cap, { folder: "inbox" }))).toMatchObject({ name: "CapabilityRejected", reason: "expired" });
  });

  it("logs the jti, the method and the outcome of every call, and nothing else", async () => {
    const mb = await provisionMailbox();
    await mail().unread(await capFor(mb, { jti: "trace-jti-accepted" }));
    const expired = await mint({ tenant: mb.tenantId, mbx: mb.id, iat: nowSeconds() - 120, jti: "trace-jti-expired" });
    await rejectionOf(mail().unread(expired));
    const lines = logs.filter((l) => l.includes('"mail-service"')).map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines).toContainEqual({ event: "mail-service", method: "unread", jti: "trace-jti-accepted", outcome: "accepted", mailbox: mb.id, result: "ok" });
    expect(lines).toContainEqual({ event: "mail-service", method: "unread", jti: "trace-jti-expired", outcome: "rejected", reason: "expired" });
  });

  it("asks for a mailbox in the capability for every mailbox method", async () => {
    const mb = await provisionMailbox();
    const noMailbox = await mint({ tenant: mb.tenantId });
    expect(await rejectionOf(mail().list(noMailbox, { folder: "inbox" }))).toMatchObject({ name: "InvalidRequest" });
  });
});

describe("M4: a mailbox belongs to one tenant for life", () => {
  it("answers a capability for tenant A naming tenant B's mailbox exactly as it answers a missing mailbox", async () => {
    const a = await provisionMailbox();
    const b = await provisionMailbox();
    const crossTenant = await mint({ tenant: a.tenantId, mbx: b.id });
    const missing = await mint({ tenant: a.tenantId, mbx: testId("mbx") });
    const e1 = await rejectionOf(mail().list(crossTenant, { folder: "inbox" }));
    const e2 = await rejectionOf(mail().list(missing, { folder: "inbox" }));
    expect(e1.name).toBe("NotFound");
    expect({ name: e1.name, message: e1.message, keys: Object.keys(e1).sort() }).toEqual({
      name: e2.name,
      message: e2.message,
      keys: Object.keys(e2).sort(),
    });
    // And B's own mailbox never learned anything: nothing was touched.
    expect((await directoryRow(b.id))?.tenant_id).toBe(b.tenantId);
  });

  it("answers NotFound for a closed mailbox, for every method", async () => {
    const mb = await provisionMailbox({ status: "closed" });
    const cap = await capFor(mb);
    for (const call of [
      () => mail().mailbox(cap),
      () => mail().list(cap, { folder: "inbox" }),
      () => mail().unread(cap),
      () => mail().drafts(cap),
      () => mail().audit(cap, {}),
    ]) {
      expect(await rejectionOf(call())).toMatchObject({ name: "NotFound" });
    }
  });

  it("lists only the capability's own tenant's mailboxes, to any member role", async () => {
    const a = await provisionMailbox({ status: "provisioned" });
    await provisionMailbox();
    const list = await mail().mailboxes(await mint({ tenant: a.tenantId, role: "editor" }));
    expect(list).toEqual([{ id: a.id, address: a.address, status: "provisioned" }]);
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
      expect(await rejectionOf(call())).toMatchObject({ name: "Forbidden" });
    }
  });
});

describe("mailbox() and enrolment (M5, M10)", () => {
  it("shows a provisioned mailbox with no keys, and the delivery mode and forward target (M10)", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const view = await mail().mailbox(await capFor(mb));
    expect(view).toMatchObject({ id: mb.id, address: mb.address, status: "provisioned", displayName: "", keys: [], wraps: [] });
    expect(view.policy).toMatchObject({ delivery: "store", forwardTo: null, assistant: "off" });
  });

  it("enrols a key with a recovery wrap and activates the mailbox", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const key = await newKeyPair();
    const wraps = [recoveryWrap(key.keyId), passkeyWrap(key.keyId)];
    const result = await mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(key.publicKey), wraps });
    expect(result).toEqual({ keyId: key.keyId });
    expect(await directoryRow(mb.id)).toMatchObject({ status: "active" });
    expect((await directoryRow(mb.id))?.activated_at).toEqual(expect.any(String));
    const view = await mail().mailbox(await capFor(mb));
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
    const err = await rejectionOf(
      mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(key.publicKey), wraps: [passkeyWrap(key.keyId)] }),
    );
    expect(err).toMatchObject({ name: "InvalidRequest" });
    expect((await directoryRow(mb.id))?.status).toBe("provisioned");
    expect((await mail().mailbox(await capFor(mb))).keys).toEqual([]);
  });

  it("recomputes the keyId: a wrap naming another key is refused", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const key = await newKeyPair();
    const other = await newKeyPair();
    const err = await rejectionOf(
      mail().enroll(await capFor(mb), { publicKey: base64urlFromBytes(key.publicKey), wraps: [recoveryWrap(other.keyId)] }),
    );
    expect(err).toMatchObject({ name: "InvalidRequest" });
  });

  it("enrols only a provisioned mailbox, and only an owner", async () => {
    const mb = await provisionMailbox();
    const key = await newKeyPair();
    const request = { publicKey: base64urlFromBytes(key.publicKey), wraps: [recoveryWrap(key.keyId)] };
    expect(await rejectionOf(mail().enroll(await capFor(mb), request))).toMatchObject({ name: "InvalidRequest" });
    const fresh = await provisionMailbox({ status: "provisioned" });
    expect(await rejectionOf(mail().enroll(await capFor(fresh, { role: "editor" }), request))).toMatchObject({ name: "Forbidden" });
  });

  it("M5: the last recovery wrap cannot be removed; another can", async () => {
    const mb = await provisionMailbox();
    const cap = await capFor(mb);
    const [only] = (await mail().mailbox(cap)).wraps;
    expect(await rejectionOf(mail().removeWrap(await capFor(mb), only!.id))).toMatchObject({ name: "InvalidRequest" });

    const second = recoveryWrap(mb.key!.keyId, { label: "Printed sheet" });
    await mail().addWrap(await capFor(mb), second);
    await mail().removeWrap(await capFor(mb), only!.id);
    expect((await mail().mailbox(await capFor(mb))).wraps.map((w) => w.id)).toEqual([second.id]);
    expect(await rejectionOf(mail().removeWrap(await capFor(mb), second.id))).toMatchObject({ name: "InvalidRequest" });
  });

  it("adds a passkey wrap for the mailbox's key only, and audits key changes", async () => {
    const mb = await provisionMailbox();
    const other = await newKeyPair();
    expect(await rejectionOf(mail().addWrap(await capFor(mb), passkeyWrap(other.keyId)))).toMatchObject({ name: "InvalidRequest" });
    const phone = passkeyWrap(mb.key!.keyId);
    await mail().addWrap(await capFor(mb), phone);
    await mail().removeWrap(await capFor(mb), phone.id);
    const actions = (await mail().audit(await capFor(mb), {})).map((a) => a.action);
    expect(actions.slice(0, 3)).toEqual(["wrap-removed", "wrap-added", "key-enrolled"]);
  });
});

describe("reading", () => {
  it("lists a folder newest first, in pages, with only sealed fields", async () => {
    const mb = await provisionMailbox();
    await arrive(mb, 3);
    const cap = await capFor(mb);
    const first = await mail().list(cap, { folder: "inbox", limit: 2 });
    expect(first.items).toHaveLength(2);
    expect(first.next).toEqual(expect.any(String));
    const second = await mail().list(await capFor(mb), { folder: "inbox", limit: 2, before: first.next! });
    expect(second.items).toHaveLength(1);
    expect(second.next).toBeNull();
    const all = [...first.items, ...second.items];
    expect(all.map((m) => m.receivedAt)).toEqual([...all.map((m) => m.receivedAt)].sort().reverse());
    expect(Object.keys(all[0]!).sort()).toEqual(
      ["direction", "flagged", "folder", "header", "id", "keyEnvelope", "keyId", "receivedAt", "seen", "size"],
    );
    expect(await rejectionOf(mail().list(await capFor(mb), { folder: "inbox", limit: 101 }))).toMatchObject({ name: "InvalidRequest" });
    expect(await rejectionOf(mail().list(await capFor(mb), { folder: "nope" }))).toMatchObject({ name: "InvalidRequest" });
  });

  it("streams the sealed body from R2, byte for byte", async () => {
    const mb = await provisionMailbox();
    await arrive(mb);
    const [item] = (await mail().list(await capFor(mb), { folder: "inbox" })).items;
    const stream = await mail().body(await capFor(mb), item!.id);
    const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
    const stored = await env.MAIL.get(`mbx/${mb.id}/msg/${item!.id}`);
    expect(bytes).toEqual(new Uint8Array(await stored!.arrayBuffer()));
    expect(new TextDecoder().decode(bytes.slice(0, 4))).toBe("PMB1");
    expect(await rejectionOf(mail().body(await capFor(mb), testId("msg")))).toMatchObject({ name: "NotFound" });
  });

  it("marks, flags and moves; Trash stamps the time; nothing moves into Drafts", async () => {
    const mb = await provisionMailbox();
    await arrive(mb, 2);
    const [a, b] = (await mail().list(await capFor(mb), { folder: "inbox" })).items;
    expect(await mail().update(await capFor(mb), a!.id, { seen: true, flagged: true })).toMatchObject({ seen: true, flagged: true, folder: "inbox" });
    expect(await mail().unread(await capFor(mb))).toEqual({ inbox: 1 });
    await mail().update(await capFor(mb), b!.id, { folder: "trash" });
    const trashedAt = await runInDurableObject(mb.stub, (_i, state) =>
      state.storage.sql.exec("SELECT trashed_at FROM messages WHERE id = ?", b!.id).one().trashed_at,
    );
    expect(trashedAt).toBe(mb.ports.clock.now().toISOString());
    await mail().update(await capFor(mb), b!.id, { folder: "inbox" });
    expect(
      await runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec("SELECT trashed_at FROM messages WHERE id = ?", b!.id).one().trashed_at),
    ).toBeNull();
    expect(await rejectionOf(mail().update(await capFor(mb), b!.id, { folder: "drafts" }))).toMatchObject({ name: "InvalidRequest" });
  });

  it("purges a message (owner): the row and the R2 object", async () => {
    const mb = await provisionMailbox();
    await arrive(mb);
    const [item] = (await mail().list(await capFor(mb), { folder: "inbox" })).items;
    await mail().purge(await capFor(mb), item!.id);
    expect((await mail().list(await capFor(mb), { folder: "inbox" })).items).toEqual([]);
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
    await mail().saveDraft(await capFor(mb), draft);
    expect(await mail().drafts(await capFor(mb))).toEqual([{ ...draft, updatedAt: mb.ports.clock.now().toISOString() }]);
    expect(await rejectionOf(mail().saveDraft(await capFor(mb), { ...draft, keyId: "0".repeat(32) }))).toMatchObject({ name: "InvalidRequest" });
    expect(await rejectionOf(mail().saveDraft(await capFor(mb), { ...draft, keyEnvelope: "AAAA" }))).toMatchObject({ name: "InvalidRequest" });
    await mail().deleteDraft(await capFor(mb), draft.id);
    expect(await mail().drafts(await capFor(mb))).toEqual([]);
    expect(await rejectionOf(mail().deleteDraft(await capFor(mb), draft.id))).toMatchObject({ name: "NotFound" });
  });
});

describe("policy and audit", () => {
  it("refuses to turn the assistant on (D1): AssistantUnavailable", async () => {
    const mb = await provisionMailbox();
    expect(await rejectionOf(mail().setPolicy(await capFor(mb), { assistant: "on" }))).toMatchObject({ name: "AssistantUnavailable" });
    expect((await mail().mailbox(await capFor(mb))).policy.assistant).toBe("off");
  });

  it("sets the display name, and audits the change without its value", async () => {
    const mb = await provisionMailbox();
    const policy = await mail().setPolicy(await capFor(mb), { displayName: "Operator", assistant: "off" });
    expect(policy).toMatchObject({ displayName: "Operator", assistant: "off" });
    const [latest] = await mail().audit(await capFor(mb), {});
    expect(latest).toMatchObject({ actor: "acc_owner", action: "policy-changed", detail: { fields: "displayName,assistant" } });
    expect(await rejectionOf(mail().setPolicy(await capFor(mb), { displayName: "a\r\nBcc: x@y.test" }))).toMatchObject({ name: "InvalidRequest" });
  });
});
