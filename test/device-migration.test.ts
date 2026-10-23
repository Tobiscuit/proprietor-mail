import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { base64urlFromBytes } from "./support/capability-tokens";
import { incomingEmail, sampleMessage } from "./support/email";
import { testId } from "./support/ids";
import { migrateFromBeforeDevices } from "./support/legacy";
import { capFor, passkeyWrap, provisionMailbox, recoveryWrap, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// Spec 002, plan.md §2: the Mailbox migration 0003_devices, on a mailbox that
// existed before it. The whole existing suite is the other half of this
// proof: every one of its mailboxes runs 0003 in its constructor and starts
// with sessions "optional", and none of those tests changed.

const mail = () => exports.MailService;

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function arrive(mb: TestMailbox): Promise<void> {
  const email = incomingEmail(sampleMessage({ to: mb.address }), { to: mb.address });
  await worker.email!(email.message, env, createExecutionContext());
  mb.ports.clock.advance(1000);
}

/** A mailbox with something in every table 001 writes: two wraps, mail in, mail out, a draft, the audit. */
async function lived(): Promise<TestMailbox> {
  const mb = await provisionMailbox();
  valueOf(await mail().addWrap(await capFor(mb), passkeyWrap(mb.key!.keyId)));
  await arrive(mb);
  await arrive(mb);
  valueOf(await mail().send(await capFor(mb), { idempotencyKey: "before-0003", to: [{ address: "ana@example.com" }], subject: "s", text: "t" }));
  valueOf(
    await mail().saveDraft(await capFor(mb), {
      id: testId("drf"),
      keyId: mb.key!.keyId,
      keyEnvelope: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(80))),
      sealed: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(120))),
    }),
  );
  return mb;
}

describe("0003_devices on a mailbox created before it (plan.md §2)", () => {
  it("leaves every row the mailbox held exactly as it was, and records 0003 once", async () => {
    const mb = await lived();
    const report = await migrateFromBeforeDevices(mb.stub);
    expect(report.applied).toEqual(["0001_mailbox", "0002_suppression", "0003_devices"]);
    // Something of each kind was there to keep.
    for (const table of ["identity", "policy", "keys", "key_wraps", "messages", "drafts", "sends", "audit"]) {
      expect(report.before[table]!.length, table).toBeGreaterThan(0);
    }
    expect(report.before.key_wraps).toHaveLength(2);
    expect(report.before.messages).toHaveLength(3);
    expect(report.after).toEqual(report.before);
  });

  it("starts sessions as optional and every new column empty, and adds the new tables empty", async () => {
    const mb = await lived();
    await migrateFromBeforeDevices(mb.stub);
    expect(await sql(mb, "SELECT sessions FROM policy")).toEqual([{ sessions: "optional" }]);
    expect(await sql(mb, "SELECT successor_key_id, successor_seal, successor_signed_by, successor_sig FROM keys")).toEqual([
      { successor_key_id: null, successor_seal: null, successor_signed_by: null, successor_sig: null },
    ]);
    const empty = { factor_key: null, signing_key: null, admission_by: null, admission_sig: null, admission_self_sig: null, tag: null, tag_key_id: null };
    expect(await sql(mb, "SELECT factor_key, signing_key, admission_by, admission_sig, admission_self_sig, tag, tag_key_id FROM key_wraps")).toEqual([empty, empty]);
    for (const table of ["devices", "key_seals", "challenges", "mail_sessions", "removed_factors", "rotation_due"]) {
      expect(await sql(mb, `SELECT COUNT(*) AS n FROM ${table}`), table).toEqual([{ n: 0 }]);
    }
  });

  it("then behaves exactly as before: no session asked for reading, sending, drafts, keys or policy", async () => {
    const mb = await lived();
    await migrateFromBeforeDevices(mb.stub);
    const items = valueOf(await mail().list(await capFor(mb), { folder: "inbox" })).items;
    expect(items).toHaveLength(2);
    const body = valueOf(await mail().body(await capFor(mb), items[0]!.id));
    expect(new TextDecoder().decode((await new Response(body).arrayBuffer()).slice(0, 4))).toBe("PMB1");
    valueOf(await mail().update(await capFor(mb), items[0]!.id, { seen: true }));
    expect(valueOf(await mail().unread(await capFor(mb)))).toEqual({ inbox: 1 });
    expect(valueOf(await mail().drafts(await capFor(mb)))).toHaveLength(1);
    valueOf(await mail().send(await capFor(mb), { idempotencyKey: "after-0003", to: [{ address: "ana@example.com" }], subject: "s", text: "t" }));
    valueOf(await mail().setPolicy(await capFor(mb), { displayName: "Example" }));
    const second = recoveryWrap(mb.key!.keyId, { label: "Printed sheet" });
    valueOf(await mail().addWrap(await capFor(mb), second));
    valueOf(await mail().removeWrap(await capFor(mb), second.id));
    expect(valueOf(await mail().audit(await capFor(mb), {})).map((a) => a.action).slice(0, 3)).toEqual(["wrap-removed", "wrap-added", "policy-changed"]);
    // M5 as before: the last recovery wrap stays.
    const [recovery] = valueOf(await mail().mailbox(await capFor(mb))).wraps.filter((w) => w.kind === "recovery");
    expect(refusalOf(await mail().removeWrap(await capFor(mb), recovery!.id))).toMatchObject({ name: "InvalidRequest" });
  });

  it("shows the view's new fields (device-v1 B4), empty, beside the earlier ones", async () => {
    const mb = await lived();
    await migrateFromBeforeDevices(mb.stub);
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect(view.sessions).toBe("optional");
    expect(view.devices).toEqual([]);
    expect(view.seals).toEqual([]);
    expect(view.removedFactors).toEqual([]);
    expect(view.rotationDue).toBeNull();
    expect(view.keys).toEqual([
      {
        keyId: mb.key!.keyId,
        publicKey: base64urlFromBytes(mb.key!.publicKey),
        createdAt: expect.any(String),
        createdBy: "acc_owner",
        retiredAt: null,
        successor: null,
      },
    ]);
    expect(view.wraps).toHaveLength(2);
    for (const w of view.wraps) {
      expect(Object.keys(w).sort()).toEqual(
        ["admission", "createdAt", "createdBy", "credentialId", "factorKey", "id", "keyId", "kind", "label", "signingKey", "tag", "tagKeyId", "wrapped"].sort(),
      );
      expect([w.factorKey, w.signingKey, w.admission, w.tag, w.tagKeyId]).toEqual([null, null, null, null, null]);
    }
    expect(Object.keys(view).sort()).toEqual(
      ["addresses", "address", "devices", "displayName", "id", "keys", "policy", "removedFactors", "rotationDue", "seals", "sessions", "status", "wraps"].sort(),
    );
  });
});

describe("the schema 0003 adds is plan.md §2's, with round 3's additions (§10.1)", () => {
  interface Column {
    name: string;
    type: string;
    notnull: number;
    dflt_value: string | null;
    pk: number;
  }
  const columns = async (mb: TestMailbox, table: string) =>
    (await sql<Column & { cid: number }>(mb, `PRAGMA table_info("${table}")`)).map(({ name, type, notnull, dflt_value, pk }) => ({ name, type, notnull, dflt_value, pk }));
  const col = (name: string, type: string, notnull = 0, pk = 0, dflt_value: string | null = null): Column => ({ name, type, notnull, dflt_value, pk });

  it("adds the columns to policy, keys and key_wraps", async () => {
    const mb = await provisionMailbox();
    expect((await columns(mb, "policy")).at(-1)).toEqual(col("sessions", "TEXT", 1, 0, "'optional'"));
    expect((await columns(mb, "keys")).slice(-4)).toEqual([col("successor_key_id", "TEXT"), col("successor_seal", "TEXT"), col("successor_signed_by", "TEXT"), col("successor_sig", "TEXT")]);
    expect((await columns(mb, "key_wraps")).slice(-7)).toEqual([
      col("factor_key", "BLOB"),
      col("signing_key", "BLOB"),
      col("admission_by", "TEXT"),
      col("admission_sig", "TEXT"),
      col("admission_self_sig", "TEXT"),
      col("tag", "TEXT"),
      col("tag_key_id", "TEXT"),
    ]);
  });

  it("creates devices, key_seals, challenges, mail_sessions, removed_factors and rotation_due with their keys and indexes", async () => {
    const mb = await provisionMailbox();
    expect(await columns(mb, "devices")).toEqual([
      col("id", "TEXT", 0, 1),
      col("account_id", "TEXT", 1),
      col("label", "TEXT", 1),
      col("signing_key", "BLOB", 1),
      col("unlock_key", "BLOB"),
      col("unlock_sig", "TEXT"),
      col("admission_by", "TEXT", 1),
      col("admission_sig", "TEXT", 1),
      col("tag", "TEXT", 1),
      col("tag_key_id", "TEXT", 1),
      col("created_at", "TEXT", 1),
      col("created_by", "TEXT", 1),
      col("last_seen_at", "TEXT"),
    ]);
    expect(await columns(mb, "key_seals")).toEqual([
      col("key_id", "TEXT", 1, 1),
      col("to_kind", "TEXT", 1, 2),
      col("to_id", "TEXT", 1, 3),
      col("sealed", "TEXT", 1),
      col("created_at", "TEXT", 1),
      col("created_by", "TEXT", 1),
    ]);
    expect(await columns(mb, "challenges")).toEqual([
      col("id", "TEXT", 0, 1),
      col("purpose", "TEXT", 1),
      col("target_id", "TEXT", 1),
      col("answer_hash", "TEXT"),
      col("nonce", "TEXT", 1),
      col("account_id", "TEXT", 1),
      col("kind", "TEXT"),
      col("descriptor", "TEXT"),
      col("action_digest", "TEXT"),
      col("created_at", "TEXT", 1),
      col("expires_at", "TEXT", 1),
      col("used_at", "TEXT"),
      col("refused_at", "TEXT"),
    ]);
    expect(await columns(mb, "mail_sessions")).toEqual([
      col("token_hash", "TEXT", 0, 1),
      col("account_id", "TEXT", 1),
      col("device_id", "TEXT"),
      col("created_at", "TEXT", 1),
      col("expires_at", "TEXT", 1),
    ]);
    expect(await columns(mb, "removed_factors")).toEqual([
      col("id", "TEXT", 0, 1),
      col("kind", "TEXT", 1),
      col("credential_id", "TEXT"),
      col("label", "TEXT", 1),
      col("factor_key", "BLOB", 1),
      col("signing_key", "BLOB", 1),
      col("admission_by", "TEXT", 1),
      col("admission_sig", "TEXT", 1),
      col("admission_self_sig", "TEXT", 1),
      col("created_at", "TEXT", 1),
      col("created_by", "TEXT", 1),
      col("removed_at", "TEXT", 1),
      col("removed_by", "TEXT", 1),
    ]);
    expect(await columns(mb, "rotation_due")).toEqual([col("one", "INTEGER", 0, 1), col("since", "TEXT", 1), col("by_account", "TEXT", 1), col("devices", "TEXT", 1)]);
    const indexes = (await sql<{ name: string }>(mb, "SELECT name FROM sqlite_master WHERE type = 'index' AND name NOT LIKE 'sqlite_%'")).map((i) => i.name);
    expect(indexes).toEqual(expect.arrayContaining(["challenges_by_expiry", "challenges_by_digest", "mail_sessions_by_device", "mail_sessions_by_expiry"]));
  });

  it("enforces its CHECKs and its reference to keys in the database itself", async () => {
    const mb = await provisionMailbox();
    const keyId = mb.key!.keyId;
    await expect(sql(mb, "UPDATE policy SET sessions = 'off'")).rejects.toThrow(/CHECK constraint failed/);
    await expect(
      sql(mb, "INSERT INTO key_seals (key_id, to_kind, to_id, sealed, created_at, created_by) VALUES (?, 'successor', 'x', 's', 't', 'b')", keyId),
    ).rejects.toThrow(/CHECK constraint failed/);
    await expect(
      sql(mb, "INSERT INTO key_seals (key_id, to_kind, to_id, sealed, created_at, created_by) VALUES (?, 'device', 'x', 's', 't', 'b')", "0".repeat(32)),
    ).rejects.toThrow(/FOREIGN KEY constraint failed/);
    await expect(
      sql(mb, "INSERT INTO challenges (id, purpose, target_id, answer_hash, nonce, account_id, created_at, expires_at) VALUES ('c', 'device', 't', 'h', 'n', 'a', 't', 't')"),
    ).rejects.toThrow(/CHECK constraint failed/);
    // Round 3: an email challenge has no answer; a session challenge has no descriptor; every other has one.
    const challengeRow = (purpose: string, answer: string | null, kind: string | null, descriptor: string | null) =>
      sql(mb, "INSERT INTO challenges (id, purpose, target_id, answer_hash, nonce, account_id, kind, descriptor, created_at, expires_at) VALUES (?, ?, 't', ?, 'n', 'a', ?, ?, 't', 't')", crypto.randomUUID(), purpose, answer, kind, descriptor);
    await expect(challengeRow("email", "h", "revoke-device", "d")).rejects.toThrow(/CHECK constraint failed/);
    await expect(challengeRow("session", "h", "open-session", "d")).rejects.toThrow(/CHECK constraint failed/);
    await expect(challengeRow("factor", "h", null, null)).rejects.toThrow(/CHECK constraint failed/);
    await expect(challengeRow("key", "h", "upgrade", null)).rejects.toThrow(/CHECK constraint failed/);
    await challengeRow("email", null, "revoke-device", "d");
    await challengeRow("key", "h", "upgrade", "d");
    // A device's unlock signature is there exactly when its unlock key is; rotation_due has one row at most.
    const deviceRow = (unlockKey: Uint8Array | null, unlockSig: string | null) =>
      sql(
        mb,
        "INSERT INTO devices (id, account_id, label, signing_key, unlock_key, unlock_sig, admission_by, admission_sig, tag, tag_key_id, created_at, created_by) VALUES (?, 'a', 'l', x'04', ?, ?, 'w', 's', 't', 'k', 't', 'b')",
        crypto.randomUUID(),
        unlockKey,
        unlockSig,
      );
    await expect(deviceRow(new Uint8Array(65), null)).rejects.toThrow(/CHECK constraint failed/);
    await expect(deviceRow(null, "s")).rejects.toThrow(/CHECK constraint failed/);
    await expect(sql(mb, "INSERT INTO rotation_due (one, since, by_account, devices) VALUES (2, 't', 'a', '[]')")).rejects.toThrow(/CHECK constraint failed/);
    expect(await sql(mb, "SELECT sessions FROM policy")).toEqual([{ sessions: "optional" }]);
  });
});
