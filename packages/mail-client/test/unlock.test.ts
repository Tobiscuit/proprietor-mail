// Unlocking and the unlocked mailbox (contracts/mail-client-v1.md "Unlocking", "Reading", "Drafts").
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";
import { newId, sealDraft, type Draft } from "@proprietor/mail-crypto";
import {
  KeySubstitutionDetected,
  MailboxLocked,
  NoActiveKey,
  NoMatchingWrap,
  PasskeyCancelled,
  PrfUnavailable,
  RecoveryKeyTypo,
  UndecryptableBody,
  WrongRecoveryKey,
  startEnrollment,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  type DraftRecord,
  type EnrollRequest,
  type MailboxView,
} from "../src/index";
import { CredentialsDouble, b64url, fromB64url, mailboxAfterEnroll, multipartRaw, passkeyOptions, publicKeyOf, sampleHeader, sealedItem } from "./support";

const mailboxId = "mbx_0000000000000000000000unlk";
const provisioned = { id: mailboxId, address: "hello@example.com", status: "provisioned" as const };

let credentials: CredentialsDouble; // pragma: allowlist secret (a variable or type name, not a value)
let request: EnrollRequest;
let recoveryKey: string;
let view: MailboxView;
let pub: { keyId: string; publicKey: Uint8Array };

beforeAll(async () => {
  credentials = new CredentialsDouble();
  const enrollment = await startEnrollment(provisioned, passkeyOptions(credentials));
  const symbols = enrollment.recoveryKey.replace(/-/g, "");
  enrollment.confirmRecovery(enrollment.recoveryCheck.positions.map((p) => symbols[p - 1]).join(""));
  request = enrollment.request();
  recoveryKey = enrollment.recoveryKey;
  enrollment.discard();
  view = mailboxAfterEnroll(mailboxId, request);
  pub = await publicKeyOf(request);
});

afterEach(() => {
  vi.useRealTimers();
  credentials.options = {};
});

describe("unlockWithPasskey", () => {
  test("one get() with rpId, the passkey wraps' credential ids and a PRF input per credential; the credential used selects the wrap", async () => {
    const unlocked = await unlockWithPasskey(view, { rpId: "example.com", credentials });
    expect(unlocked.mailboxId).toBe(mailboxId);
    expect(unlocked.keyId).toBe(pub.keyId);
    expect(unlocked.locked).toBe(false);
    const got = credentials.got.at(-1)!;
    expect(got.rpId).toBe("example.com");
    expect(got.userVerification).toBe("required");
    const passkeyWraps = view.wraps.filter((w) => w.kind === "passkey-prf");
    expect(got.allowCredentials!.map((c) => b64url(c.id as ArrayBuffer))).toEqual(passkeyWraps.map((w) => w.credentialId));
    expect(got.allowCredentials!.every((c) => c.type === "public-key")).toBe(true);
    expect(Object.keys(got.extensions!.prf!.evalByCredential!)).toEqual(passkeyWraps.map((w) => w.credentialId));
    const { item } = await sealedItem(pub, mailboxId, newId("msg"));
    expect((await unlocked.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
  });

  test("a mailbox without a passkey wrap for its active key: NoMatchingWrap before any prompt", async () => {
    const recoveryOnly = { ...view, wraps: view.wraps.filter((w) => w.kind === "recovery") };
    const before = credentials.got.length;
    await expect(unlockWithPasskey(recoveryOnly, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(NoMatchingWrap);
    expect(credentials.got.length).toBe(before);
  });

  test("a credential the mailbox does not know: NoMatchingWrap", async () => {
    credentials.options = { strangerInGet: true };
    await expect(unlockWithPasskey(view, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(NoMatchingWrap);
  });

  test("a dismissed prompt: PasskeyCancelled; no PRF output: PrfUnavailable", async () => {
    credentials.options = { cancel: true };
    await expect(unlockWithPasskey(view, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(PasskeyCancelled);
    credentials.options = { prf: false };
    await expect(unlockWithPasskey(view, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(PrfUnavailable);
  });

  test("no active key: NoActiveKey", async () => {
    const retired = { ...view, keys: view.keys.map((k) => ({ ...k, retiredAt: "2026-10-04T00:00:00.000Z" })) };
    await expect(unlockWithPasskey(retired, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(NoActiveKey);
  });
});

describe("unlockWithRecoveryKey", () => {
  test("a typo is RecoveryKeyTypo (this package's), a wrong key is WrongRecoveryKey, the right one unlocks", async () => {
    const typo = recoveryKey.slice(0, 7) + (recoveryKey[7] === "7" ? "8" : "7") + recoveryKey.slice(8);
    await expect(unlockWithRecoveryKey(view, typo)).rejects.toBeInstanceOf(RecoveryKeyTypo);
    const other = await startEnrollment(provisioned, null);
    await expect(unlockWithRecoveryKey(view, other.recoveryKey)).rejects.toBeInstanceOf(WrongRecoveryKey);
    other.discard();
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey.toLowerCase().replace(/-/g, " "));
    expect(unlocked.keyId).toBe(pub.keyId);
  });
});

describe("the advertised public key is checked at every unlock (G7, K2)", () => {
  test("a substituted public key with the same keyId: KeySubstitutionDetected, on both paths", async () => {
    const forged = { ...view, keys: [{ ...view.keys[0]!, publicKey: b64url(crypto.getRandomValues(new Uint8Array(32))) }] };
    await expect(unlockWithRecoveryKey(forged, recoveryKey)).rejects.toBeInstanceOf(KeySubstitutionDetected);
    await expect(unlockWithPasskey(forged, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("a substituted key with its own keyId: no wrap opens to it, so NoMatchingWrap / WrongRecoveryKey", async () => {
    const other = await startEnrollment(provisioned, null);
    const symbols = other.recoveryKey.replace(/-/g, "");
    other.confirmRecovery(other.recoveryCheck.positions.map((p) => symbols[p - 1]).join(""));
    const otherKey = other.request();
    const forged = { ...view, keys: [{ ...view.keys[0]!, keyId: otherKey.wraps[0]!.keyId, publicKey: otherKey.publicKey }] };
    await expect(unlockWithRecoveryKey(forged, recoveryKey)).rejects.toBeInstanceOf(WrongRecoveryKey);
    await expect(unlockWithPasskey(forged, { rpId: "example.com", credentials })).rejects.toBeInstanceOf(NoMatchingWrap);
  });
});

describe("the unlocked mailbox", () => {
  test("locks itself after idleLockMs without touch(), tells listeners, and then refuses everything", async () => {
    vi.useFakeTimers();
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey, { idleLockMs: 60_000 });
    const locks: number[] = [];
    const off = unlocked.onLock(() => locks.push(1));
    vi.advanceTimersByTime(50_000);
    unlocked.touch();
    vi.advanceTimersByTime(50_000);
    expect(unlocked.locked).toBe(false);
    vi.advanceTimersByTime(10_001);
    expect(unlocked.locked).toBe(true);
    expect(locks).toEqual([1]);
    const { item } = await sealedItem(pub, mailboxId, newId("msg"));
    await expect(unlocked.openMessages([item])).rejects.toBeInstanceOf(MailboxLocked);
    await expect(unlocked.openBody(item, new Uint8Array(1))).rejects.toBeInstanceOf(MailboxLocked);
    await expect(unlocked.sealDraft(null, { to: [], cc: [], bcc: [], subject: "", text: "", inReplyTo: null, references: [] })).rejects.toBeInstanceOf(MailboxLocked);
    await expect(unlocked.openDrafts([])).rejects.toBeInstanceOf(MailboxLocked);
    await expect(unlocked.addPasskey(passkeyOptions(credentials), { recoveryKey })).rejects.toBeInstanceOf(MailboxLocked);
    await expect(unlocked.replaceRecoveryKey({ recoveryKey })).rejects.toBeInstanceOf(MailboxLocked);
    expect(() => unlocked.touch()).toThrow(MailboxLocked);
    unlocked.lock(); // idempotent
    expect(locks).toEqual([1]);
    off();
  });

  test("lock() is immediate and the default idle lock is 15 minutes", async () => {
    vi.useFakeTimers();
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey);
    vi.advanceTimersByTime(15 * 60_000 - 1);
    expect(unlocked.locked).toBe(false);
    vi.advanceTimersByTime(2);
    expect(unlocked.locked).toBe(true);
    const again = await unlockWithRecoveryKey(view, recoveryKey);
    again.lock();
    expect(again.locked).toBe(true);
  });

  test("openMessages: an item that fails to decrypt is undecryptable with a null header, and never fails the batch", async () => {
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey);
    const good = await sealedItem(pub, mailboxId, newId("msg"));
    const moved = await sealedItem(pub, mailboxId, newId("msg"));
    moved.item.id = newId("msg"); // the server moved the header to another message id
    const garbage = { ...good.item, id: newId("msg"), header: "AQ" };
    const opened = await unlocked.openMessages([good.item, moved.item, garbage]);
    expect(opened.map((m) => m.undecryptable)).toEqual([false, true, true]);
    expect(opened[0]!.header).toStrictEqual(sampleHeader);
    expect(opened[1]!.header).toBeNull();
    expect(opened[1]).toMatchObject({ id: moved.item.id, folder: "inbox", seen: false, flagged: false, size: moved.item.size, receivedAt: moved.item.receivedAt });
    expect(await unlocked.openMessages([])).toEqual([]);
  });

  test("openBody: the raw bytes, text, html and attachments with content ids; a bad body is UndecryptableBody", async () => {
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey);
    const { item, body } = await sealedItem(pub, mailboxId, newId("msg"), { ...sampleHeader, subject: "Plans" }, multipartRaw);
    const mail = await unlocked.openBody(item, body);
    expect(mail.raw).toEqual(multipartRaw);
    expect(mail.html).toContain('<img src="cid:logo@example.com">');
    expect(mail.text).toBeNull(); // no text/plain part: the screens quote the snippet instead (replyTo does)
    expect(mail.attachments.map((a) => [a.filename, a.mimeType, a.contentId, a.inline, a.size])).toEqual([
      ["logo.png", "image/png", "logo@example.com", true, 70],
      ["plan.pdf", "application/pdf", null, false, 22],
    ]);
    expect(mail.attachments[1]!.content).toBeInstanceOf(Uint8Array);
    expect(new TextDecoder().decode(mail.attachments[1]!.content.subarray(0, 5))).toBe("%PDF-");

    const plain = await sealedItem(pub, mailboxId, newId("msg"));
    const plainMail = await unlocked.openBody(plain.item, plain.body);
    expect(plainMail.text).toContain("Hi — we'd like a quote for the kitchen.");
    expect(plainMail.html).toBeNull();
    expect(plainMail.attachments).toEqual([]);

    await expect(unlocked.openBody(item, body.subarray(0, body.length - 1))).rejects.toBeInstanceOf(UndecryptableBody);
    await expect(unlocked.openBody({ ...item, id: newId("msg") }, body)).rejects.toBeInstanceOf(UndecryptableBody);
  });

  test("sealDraft / openDrafts round-trip through envelope v1 draft blocks; a moved draft is undecryptable", async () => {
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey);
    const input = { to: [{ name: "Ana", address: "ana@example.com" }], cc: [], bcc: [], subject: "Re: quote", text: "Soon.", inReplyTo: "abc@example.com", references: ["abc@example.com"] };
    const saved = await unlocked.sealDraft(null, input);
    expect(saved.id).toMatch(/^drf_[0-9a-hjkmnp-tv-z]{26}$/);
    expect(saved.keyId).toBe(pub.keyId);
    const again = await unlocked.sealDraft(saved.id, { ...input, text: "Soon!" });
    expect(again.id).toBe(saved.id);
    expect(again.sealed).not.toBe(saved.sealed);

    const records: DraftRecord[] = [
      { id: saved.id, keyId: saved.keyId, keyEnvelope: saved.keyEnvelope, sealed: saved.sealed, updatedAt: "2026-10-04T10:00:00.000Z" },
      { id: newId("drf"), keyId: again.keyId, keyEnvelope: again.keyEnvelope, sealed: again.sealed, updatedAt: "2026-10-04T10:01:00.000Z" },
    ];
    const opened = await unlocked.openDrafts(records);
    expect(opened[0]!.undecryptable).toBe(false);
    expect(opened[0]!.draft).toMatchObject({ v: 1, ...input });
    expect(opened[0]!.draft!.updatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(opened[0]!.updatedAt).toBe("2026-10-04T10:00:00.000Z");
    expect(opened[1]).toEqual({ id: records[1]!.id, updatedAt: records[1]!.updatedAt, draft: null, undecryptable: true });

    // A draft the Worker sealed (it never does, but the block format is the same) opens too.
    const draft: Draft = { v: 1, ...input, updatedAt: "2026-10-04T09:00:00.000Z" };
    const draftId = newId("drf");
    const sealed = await sealDraft(pub, { mailboxId, draftId }, draft);
    const [fromServer] = await unlocked.openDrafts([{ id: draftId, ...sealed, updatedAt: draft.updatedAt }]);
    expect(fromServer!.draft).toStrictEqual(draft);
  });

  test("addPasskey needs a fresh unlock (K1): with the recovery key, or with a passkey prompt", async () => {
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey);
    const wrongKey = (await startEnrollment(provisioned, null)).recoveryKey;
    await expect(unlocked.addPasskey(passkeyOptions(credentials, { label: "Phone" }), { recoveryKey: wrongKey })).rejects.toBeInstanceOf(WrongRecoveryKey);

    const byRecovery = await unlocked.addPasskey(passkeyOptions(credentials, { label: "Phone" }), { recoveryKey });
    expect(byRecovery).toMatchObject({ kind: "passkey-prf", keyId: pub.keyId, label: "Phone", credentialId: credentials.lastCredentialId() }); // pragma: allowlist secret (a variable or type name, not a value)
    expect(byRecovery.id).toMatch(/^wrp_/);
    expect(fromB64url(byRecovery.wrapped).length).toBe(77);

    const withTwo = { ...view, wraps: [...view.wraps, { ...byRecovery, createdAt: "2026-10-04T11:00:00.000Z", createdBy: "acc_owner" }] };
    credentials.options = { pick: 1 };
    const viaPhone = await unlockWithPasskey(withTwo, { rpId: "example.com", credentials });
    expect(viaPhone.keyId).toBe(pub.keyId);

    credentials.options = {};
    const byPasskey = await unlocked.addPasskey(passkeyOptions(credentials, { label: "Tablet" }), { passkey: { rpId: "example.com", credentials } });
    expect(byPasskey.label).toBe("Tablet");
    expect(byPasskey.credentialId).toBe(credentials.lastCredentialId());
    expect(byPasskey.credentialId).not.toBe(byRecovery.credentialId);
  });

  test("replaceRecoveryKey: a new display form and its wrap, which unlocks; the old key still opens its old wrap until it is removed", async () => {
    const unlocked = await unlockWithRecoveryKey(view, recoveryKey);
    const replaced = await unlocked.replaceRecoveryKey({ passkey: { rpId: "example.com", credentials } });
    expect(replaced.recoveryKey).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}$/);
    expect(replaced.recoveryKey).not.toBe(recoveryKey);
    expect(replaced.wrap).toMatchObject({ kind: "recovery", keyId: pub.keyId, credentialId: null, label: "Recovery key" });
    const rotated = { ...view, wraps: [...view.wraps.filter((w) => w.kind !== "recovery"), { ...replaced.wrap, createdAt: "2026-10-04T12:00:00.000Z", createdBy: "acc_owner" }] };
    expect((await unlockWithRecoveryKey(rotated, replaced.recoveryKey)).keyId).toBe(pub.keyId);
    await expect(unlockWithRecoveryKey(rotated, recoveryKey)).rejects.toBeInstanceOf(WrongRecoveryKey);
  });
});
