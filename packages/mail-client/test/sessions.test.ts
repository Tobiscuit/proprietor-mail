// D1d: sessions that trust a key ring (contracts/device-v1.md Part C K2′ and K3), hold every key the
// chain reaches (G40), offer a FreshFactor after a factor (K1′), and answer session challenges (A6,
// K4). The key-ring changes here are made from mail-crypto directly (test/keyring-support.ts), so the
// unlock is checked against chains it did not build itself.
import { describe, expect, test } from "vitest";
import { newId, sealMessage } from "@proprietor/mail-crypto";
import {
  FactorExpired,
  InvalidChallenge,
  KeySubstitutionDetected,
  MailboxChanged,
  StaleFactor,
  unlockWithPasskey,
  unlockWithRecoveryKey,
  WrongRecoveryKey,
  type MailboxView,
} from "../src/index";
import { FakeMailError } from "./fake-mail";
import { enrolledMailbox, rotateByHand, substituteKey, testClock } from "./keyring-support";
import { b64url, fromB64url, sampleHeader } from "./support";

const prompt = (e: { credentials: unknown }) => ({ rpId: "example.com", credentials: e.credentials as never });

describe("enrollment with factor keys: sessions are required from the start (device-v1 B5)", () => {
  test("every wrap carries its factor key and its tag under the new key, and the fake Mail accepts the request as Part B shapes it", async () => {
    const e = await enrolledMailbox();
    expect(e.fake.sessionsMode).toBe("required");
    const keyId = e.fake.activeKey.keyId;
    expect(e.request.wraps.map((w) => w.kind)).toEqual(["passkey-prf", "recovery"]);
    for (const w of e.request.wraps) {
      expect(fromB64url(w.factorKey!).length).toBe(32);
      expect(fromB64url(w.tag!).length).toBe(32);
      expect(w.tagKeyId).toBe(keyId);
    }
  });
});

describe("unlocking a mailbox whose sessions are required", () => {
  test.each(["recovery key", "passkey"] as const)("with the %s: K2 and K3 pass, the session holds the active key and offers the factor's FreshFactor", async (factor) => {
    const e = await enrolledMailbox();
    const view = e.fake.mailbox();
    const unlocked = factor === "passkey" ? await unlockWithPasskey(view, prompt(e)) : await unlockWithRecoveryKey(view, e.recoveryKey);
    expect(unlocked.keyId).toBe(e.fake.activeKey.keyId);
    expect(unlocked.keyIds).toEqual([e.fake.activeKey.keyId]);
    expect(unlocked.device).toBeNull();
    const ff = unlocked.freshFactor!;
    expect(ff.kind).toBe(factor === "passkey" ? "passkey-prf" : "recovery");
    expect(ff.factorId).toBe(view.wraps.find((w) => w.kind === ff.kind)!.id);
    expect(ff.expired).toBe(false);
    const { item } = await e.fake.deliver();
    expect((await unlocked.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
  });

  test("a view from a Mail Worker without spec 002 (a rollback) still unlocks, as a mailbox whose sessions are optional", async () => {
    const e = await enrolledMailbox({ legacy: true });
    const unlocked = await unlockWithRecoveryKey(e.fake.legacyMailbox(), e.recoveryKey);
    expect(unlocked.keyId).toBe(e.fake.activeKey.keyId);
  });
});

describe("G40: a session holds every key the chain reaches", () => {
  test("after two rotations, a recovery unlock (its wrap is of the first key) opens mail sealed to each of the three keys", async () => {
    const e = await enrolledMailbox();
    const first = await e.fake.deliver();
    await rotateByHand(e.fake, e.recoveryKey);
    const second = await e.fake.deliver();
    await rotateByHand(e.fake, e.recoveryKey);
    const third = await e.fake.deliver();
    expect(new Set([first.item.keyId, second.item.keyId, third.item.keyId]).size).toBe(3);
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    expect(unlocked.keyId).toBe(third.item.keyId);
    expect(unlocked.keyIds).toEqual([third.item.keyId, second.item.keyId, first.item.keyId]);
    const opened = await unlocked.openMessages([first.item, second.item, third.item]);
    expect(opened.map((m) => m.undecryptable)).toEqual([false, false, false]);
    expect((await unlocked.openBody(first.item, first.body)).text).toContain("quote for the kitchen");
    // Drafts are sealed to the active key only.
    expect((await unlocked.sealDraft(null, { to: [], cc: [], bcc: [], subject: "x", text: "", inReplyTo: null, references: [] })).keyId).toBe(third.item.keyId);
  });

  test("a passkey added at enrollment reaches the newest key through its seal, and every older key through the chain", async () => {
    const e = await enrolledMailbox();
    const first = await e.fake.deliver();
    await rotateByHand(e.fake, e.recoveryKey);
    await rotateByHand(e.fake, e.recoveryKey);
    const unlocked = await unlockWithPasskey(e.fake.mailbox(), prompt(e));
    expect(unlocked.keyIds.length).toBe(3);
    expect((await unlocked.openMessages([first.item]))[0]!.undecryptable).toBe(false);
  });

  test("mail sealed to a key the session does not hold is undecryptable, never an error", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const other = await enrolledMailbox();
    const { item } = await other.fake.deliver();
    expect((await unlocked.openMessages([{ ...item, id: newId("msg") }]))[0]!.undecryptable).toBe(true);
  });
});

describe("K2′: a key is accepted only along a chain to a trusted key", () => {
  test("a chain of three keys is accepted from a factor's anchor (its envelope v1 wrap is of the oldest key)", async () => {
    const e = await enrolledMailbox();
    const anchor = e.fake.activeKey.keyId;
    await rotateByHand(e.fake, e.recoveryKey);
    await rotateByHand(e.fake, e.recoveryKey);
    const view = e.fake.mailbox();
    expect(view.wraps.find((w) => w.kind === "recovery")!.keyId).toBe(anchor);
    const unlocked = await unlockWithRecoveryKey(view, e.recoveryKey);
    expect(unlocked.keyIds.at(-1)).toBe(anchor);
  });

  test.each(["none", "a key of its own"] as const)(
    "a key made by someone who never held the previous key is refused, though its seals open and its tags verify (successor seal: %s)",
    async (successor) => {
      const e = await enrolledMailbox();
      await substituteKey(e.fake, successor);
      const view = e.fake.mailbox();
      await expect(unlockWithRecoveryKey(view, e.recoveryKey)).rejects.toBeInstanceOf(KeySubstitutionDetected);
      await expect(unlockWithPasskey(view, prompt(e))).rejects.toBeInstanceOf(KeySubstitutionDetected);
    },
  );

  test("a real successor seal moved under a substituted key is refused too", async () => {
    const e = await enrolledMailbox();
    const honest = await enrolledMailbox();
    await rotateByHand(honest.fake, honest.recoveryKey);
    const copied = honest.fake.keys.find((k) => k.retiredAt !== null)!.successor!;
    await substituteKey(e.fake, "copied from a real rotation", copied);
    await expect(unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("a key ring that is not one chain is refused: two keys naming one successor, an active key with a successor, a key off the chain", async () => {
    const e = await enrolledMailbox();
    await rotateByHand(e.fake, e.recoveryKey);
    const base = e.fake.mailbox();
    const [retired, active] = [base.keys.find((k) => k.retiredAt !== null)!, base.keys.find((k) => k.retiredAt === null)!];
    const stray = { ...retired, keyId: "f".repeat(32), publicKey: b64url(crypto.getRandomValues(new Uint8Array(32))) };
    const variants: MailboxView[] = [
      // a retired key off the chain
      { ...base, keys: [...base.keys, { ...stray, successor: null }] },
      // two keys naming the same successor
      { ...base, keys: [...base.keys, { ...stray, successor: { keyId: active.keyId, sealed: retired.successor!.sealed } }] },
      // the active key naming a successor
      { ...base, keys: base.keys.map((k) => (k.retiredAt === null ? { ...k, successor: { keyId: retired.keyId, sealed: retired.successor!.sealed } } : k)) },
      // two active keys
      { ...base, keys: base.keys.map((k) => ({ ...k, retiredAt: null })) },
    ];
    for (const v of variants) await expect(unlockWithRecoveryKey(v, e.recoveryKey)).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });

  test("the advertised public key must be the key the factor opened (G7, K2), on both paths", async () => {
    const e = await enrolledMailbox();
    const view = e.fake.mailbox();
    const forged = { ...view, keys: [{ ...view.keys[0]!, publicKey: b64url(crypto.getRandomValues(new Uint8Array(32))) }] };
    await expect(unlockWithRecoveryKey(forged, e.recoveryKey)).rejects.toBeInstanceOf(KeySubstitutionDetected);
    await expect(unlockWithPasskey(forged, prompt(e))).rejects.toBeInstanceOf(KeySubstitutionDetected);
  });
});

describe("K3: every tag is checked at every unlock, and one that fails flags its recipient (amended 2026-10-19)", () => {
  test("a device the server added (it cannot make a tag under the mailbox key) is flagged; the unlock goes on", async () => {
    const e = await enrolledMailbox();
    const signing = crypto.getRandomValues(new Uint8Array(65));
    signing[0] = 0x04;
    const id = newId("dev");
    e.fake.devices.push({
      id,
      label: "Not yours",
      signingKey: b64url(signing), // pragma: allowlist secret (field names and public values, not secrets)
      unlockKey: null,
      tag: b64url(crypto.getRandomValues(new Uint8Array(32))),
      tagKeyId: e.fake.activeKey.keyId,
      createdAt: "2026-10-16T12:00:00.000Z",
      createdBy: "server",
      lastSeenAt: null,
      accountId: "acc_owner",
    });
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).flagged).toEqual({ devices: [id], factors: [] });
    expect((await unlockWithPasskey(e.fake.mailbox(), prompt(e))).flagged).toEqual({ devices: [id], factors: [] });
  });

  test("a factor key the server replaced, a renamed factor, a factor key without its tag, and a tag under a retired key each flag that factor", async () => {
    const e = await enrolledMailbox();
    await rotateByHand(e.fake, e.recoveryKey);
    const view = e.fake.mailbox();
    const passkey = view.wraps.findIndex((w) => w.kind === "passkey-prf");
    const changed = (patch: Partial<MailboxView["wraps"][number]>): MailboxView => ({ ...view, wraps: view.wraps.map((w, i) => (i === passkey ? { ...w, ...patch } : w)) });
    const retiredKeyId = view.keys.find((k) => k.retiredAt !== null)!.keyId;
    for (const v of [
      changed({ factorKey: b64url(crypto.getRandomValues(new Uint8Array(32))) }),
      changed({ label: "Renamed by someone" }),
      changed({ tag: null }),
      changed({ tagKeyId: retiredKeyId }),
    ]) {
      const unlocked = await unlockWithRecoveryKey(v, e.recoveryKey);
      expect(unlocked.flagged).toEqual({ devices: [], factors: [view.wraps[passkey]!.id] });
      expect(unlocked.keyIds.length).toBe(2);
    }
    expect((await unlockWithRecoveryKey(view, e.recoveryKey)).flagged).toEqual({ devices: [], factors: [] });
  });
});

describe("the FreshFactor (K1′)", () => {
  test("answers a factor challenge for its own factor, which Mail checks; refuses after 2 minutes on the injected clock", async () => {
    const clock = testClock();
    const e = await enrolledMailbox({ now: clock });
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { now: clock });
    const ff = unlocked.freshFactor!;
    expect(ff.expiresAt).toBe(clock() + 120_000);
    const challenge = await e.fake.challenge({ purpose: "factor", factorId: ff.factorId });
    const proof = await ff.answer(challenge);
    expect(Object.keys(proof).sort()).toEqual(["answer", "challengeId"]);
    expect(await e.fake.checkFactorProof(proof)).toBe(ff.factorId);
    clock.advance(119_999);
    expect(ff.expired).toBe(false);
    clock.advance(1);
    expect(ff.expired).toBe(true);
    await expect(ff.answer(await e.fake.challenge({ purpose: "factor", factorId: ff.factorId }))).rejects.toBeInstanceOf(FactorExpired);
  });

  test("dispose() ends it at once", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    unlocked.freshFactor!.dispose();
    expect(unlocked.freshFactor!.expired).toBe(true);
    await expect(unlocked.freshFactor!.answer(await e.fake.challenge({ purpose: "factor", factorId: unlocked.freshFactor!.factorId }))).rejects.toBeInstanceOf(FactorExpired);
  });

  test("answers nothing else: a session challenge or another factor's is a caller mistake, and bytes that are not its challenge are InvalidChallenge (K4)", async () => {
    const e = await enrolledMailbox();
    const view = e.fake.mailbox();
    const unlocked = await unlockWithRecoveryKey(view, e.recoveryKey);
    const ff = unlocked.freshFactor!;
    await expect(ff.answer(await e.fake.challenge({ purpose: "session" }))).rejects.toBeInstanceOf(TypeError);
    const passkeyId = view.wraps.find((w) => w.kind === "passkey-prf")!.id;
    await expect(ff.answer(await e.fake.challenge({ purpose: "factor", factorId: passkeyId }))).rejects.toBeInstanceOf(TypeError);
    // The passkey's challenge, relabelled as this factor's: it does not open under this factor's key.
    const theirs = await e.fake.challenge({ purpose: "factor", factorId: passkeyId });
    await expect(ff.answer({ ...theirs, factorId: ff.factorId })).rejects.toBeInstanceOf(InvalidChallenge);
  });

  test("reauthenticate gives a FreshFactor for a sensitive setting, with either factor; a wrong recovery key is WrongRecoveryKey", async () => {
    const e = await enrolledMailbox();
    const view = e.fake.mailbox();
    const unlocked = await unlockWithRecoveryKey(view, e.recoveryKey);
    const byPasskey = await unlocked.reauthenticate({ passkey: prompt(e) });
    expect(byPasskey.kind).toBe("passkey-prf");
    expect(await e.fake.checkFactorProof(await byPasskey.answer(await e.fake.challenge({ purpose: "factor", factorId: byPasskey.factorId })))).toBe(byPasskey.factorId);
    const byRecovery = await unlocked.reauthenticate({ recoveryKey: e.recoveryKey });
    expect(byRecovery.kind).toBe("recovery");
    const other = await enrolledMailbox();
    await expect(unlocked.reauthenticate({ recoveryKey: other.recoveryKey })).rejects.toBeInstanceOf(WrongRecoveryKey);
  });
});

describe("sessionProof: the key proof for openSession", () => {
  test("on a shared computer, the answer alone, which opens a mail session at Mail", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const proof = await unlocked.sessionProof(await e.fake.challenge({ purpose: "session" }));
    expect(Object.keys(proof).sort()).toEqual(["answer", "challengeId"]);
    const opened = await e.fake.openSession(proof);
    expect(opened.device).toBeNull();
    expect(fromB64url(opened.session).length).toBe(32);
  });

  test("a challenge sealed to another key (another browser rotated) is MailboxChanged; one that does not open is InvalidChallenge (K4)", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const before = await e.fake.challenge({ purpose: "session" });
    await rotateByHand(e.fake, e.recoveryKey);
    await expect(unlocked.sessionProof(await e.fake.challenge({ purpose: "session" }))).rejects.toBeInstanceOf(MailboxChanged);
    // A message's key envelope offered as a session challenge for the session's own key: answered with nothing.
    const messageId = newId("msg");
    const pub = { keyId: before.keyId!, publicKey: fromB64url(e.request.publicKey) };
    const sealed = await sealMessage(pub, { mailboxId: e.mailboxId, messageId }, sampleHeader, new Uint8Array(1));
    await expect(unlocked.sessionProof({ ...before, id: newId("chl"), sealed: sealed.keyEnvelope })).rejects.toBeInstanceOf(InvalidChallenge);
  });

  test("a wrong answer is refused by Mail, and the challenge is consumed anyway", async () => {
    const e = await enrolledMailbox();
    const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey);
    const challenge = await e.fake.challenge({ purpose: "session" });
    const proof = await unlocked.sessionProof(challenge);
    await expect(e.fake.openSession({ ...proof, answer: b64url(new Uint8Array(32)) })).rejects.toBeInstanceOf(FakeMailError);
    await expect(e.fake.openSession(proof)).rejects.toThrow(/ProofRejected/);
  });
});

describe("StaleFactor", () => {
  test("a passkey left out of the upgrade (no factor key) reaches no key after a rotation: unlock with the recovery key instead", async () => {
    const e = await enrolledMailbox();
    const passkey = e.fake.wraps.find((w) => w.kind === "passkey-prf")!;
    Object.assign(passkey, { factorKey: null, tag: null, tagKeyId: null });
    await rotateByHand(e.fake, e.recoveryKey);
    await expect(unlockWithPasskey(e.fake.mailbox(), prompt(e))).rejects.toBeInstanceOf(StaleFactor);
    expect((await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey)).keyIds.length).toBe(2);
  });
});
