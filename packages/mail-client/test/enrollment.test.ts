// Enrollment (contracts/mail-client-v1.md "Enrollment"): the key pair and both wraps are made in the
// browser; the passkey's PRF output comes from create() when the authenticator gives it there, else
// from one get(); the recovery key is shown once and proven saved before request() answers.
import { describe, expect, test } from "vitest";
import { Buffer } from "node:buffer";
import { bootstrapAdmitters, keyIdOf, parseRecoveryKey, prfInput, unwrapPrivateKey } from "@proprietor/mail-crypto";
import {
  MailboxLocked,
  MailboxNotProvisioned,
  memoryDeviceStore,
  PasskeyCancelled,
  PrfUnavailable,
  RecoveryNotConfirmed,
  resumeDevice,
  startEnrollment,
  unlockWithRecoveryKey,
} from "../src/index";
import { FakeMail } from "./fake-mail";
import { CredentialsDouble, fromB64url, mailboxAfterEnroll, passkeyOptions, publicKeyOf, sampleHeader, sealedItem } from "./support";

const mailbox = { id: "mbx_0000000000000000000000test", address: "hello@example.com", status: "provisioned" as const };

/** The characters at the check's positions, read from the display form without its hyphens. */
function charactersAt(display: string, positions: readonly number[]): string {
  const symbols = display.replace(/-/g, "");
  return positions.map((p) => symbols[p - 1]!).join("");
}

describe("startEnrollment", () => {
  test("refuses a mailbox that is not provisioned", async () => {
    await expect(startEnrollment({ ...mailbox, status: "active" }, null)).rejects.toBeInstanceOf(MailboxNotProvisioned);
  });

  test("with PRF at creation: one create(), no get(), a passkey wrap and a recovery wrap", async () => {
    const credentials = new CredentialsDouble();
    const enrollment = await startEnrollment(mailbox, passkeyOptions(credentials));
    expect(credentials.created.length).toBe(1);
    expect(credentials.got.length).toBe(0);
    expect(enrollment.passkey).toBe("prf");
    expect(enrollment.mailboxId).toBe(mailbox.id);
    expect(enrollment.fingerprint).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4}){7}$/);
    expect(enrollment.recoveryKey).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}$/);

    const created = credentials.created[0]!;
    expect(created.rp).toEqual({ id: "example.com", name: "Example" });
    expect(new Uint8Array(created.user.id as ArrayBuffer).length).toBe(16);
    expect(created.user.name).toBe("Mail key — hello@example.com");
    expect(created.authenticatorSelection).toEqual({ residentKey: "preferred", userVerification: "required" });
    expect(created.attestation).toBe("none");
    expect(created.pubKeyCredParams.map((p) => p.alg)).toEqual([-7, -8, -257]);
    expect(new Uint8Array(created.challenge as ArrayBuffer).length).toBeGreaterThanOrEqual(32);

    // request() refuses until the recovery key was proven saved.
    expect(() => enrollment.request()).toThrow(RecoveryNotConfirmed);
    expect(enrollment.recoveryCheck.positions.length).toBe(4);
    expect(new Set(enrollment.recoveryCheck.positions).size).toBe(4);
    for (const p of enrollment.recoveryCheck.positions) expect(p >= 1 && p <= 55).toBe(true);
    expect(enrollment.confirmRecovery("ZZZZ")).toBe(false);
    expect(() => enrollment.request()).toThrow(RecoveryNotConfirmed);
    const answer = charactersAt(enrollment.recoveryKey, enrollment.recoveryCheck.positions);
    expect(enrollment.confirmRecovery(answer.toLowerCase())).toBe(true);

    const request = enrollment.request();
    expect(fromB64url(request.publicKey).length).toBe(32);
    expect(request.wraps.map((w) => w.kind)).toEqual(["passkey-prf", "recovery"]);
    const keyId = await keyIdOf(fromB64url(request.publicKey));
    for (const w of request.wraps) {
      expect(w.id).toMatch(/^wrp_[0-9a-hjkmnp-tv-z]{26}$/);
      expect(w.keyId).toBe(keyId);
      expect(fromB64url(w.wrapped).length).toBe(77);
    }
    const [passkeyWrap, recoveryWrap] = request.wraps;
    expect(passkeyWrap!.label).toBe("Laptop passkey");
    expect(passkeyWrap!.credentialId).toBe(credentials.lastCredentialId());
    expect(recoveryWrap!.credentialId).toBeNull();
    expect(recoveryWrap!.label).toBe("Recovery key");

    // The PRF input was the contract's: SHA-256("proprietor-mail/v1/prf|" + mailboxId + "|" + wrapId).
    const evalInput = new Uint8Array(created.extensions!.prf!.eval!.first as ArrayBuffer);
    expect(Buffer.from(evalInput)).toEqual(Buffer.from(await prfInput(mailbox.id, passkeyWrap!.id)));

    // The recovery wrap opens with the recovery key to the advertised key.
    const secret = parseRecoveryKey(enrollment.recoveryKey); // pragma: allowlist secret (a variable or type name, not a value)
    const priv = await unwrapPrivateKey({ id: recoveryWrap!.id, keyId, kind: "recovery", wrapped: recoveryWrap!.wrapped }, { mailboxId: mailbox.id, secret });
    expect(priv.keyId).toBe(keyId);
  });

  test("with PRF only enabled at creation: one get() for that credential evaluates it", async () => {
    const credentials = new CredentialsDouble({ prfAtCreate: false });
    const enrollment = await startEnrollment(mailbox, passkeyOptions(credentials));
    expect(enrollment.passkey).toBe("prf");
    expect(credentials.created.length).toBe(1);
    expect(credentials.got.length).toBe(1);
    const got = credentials.got[0]!;
    expect(got.rpId).toBe("example.com");
    expect(got.userVerification).toBe("required");
    expect(got.allowCredentials!.length).toBe(1);
    expect(Object.keys(got.extensions!.prf!.evalByCredential!)).toEqual([credentials.lastCredentialId()]);
  });

  test("without PRF: PrfUnavailable, and a recovery-key-only setup is possible", async () => {
    const credentials = new CredentialsDouble({ prf: false });
    await expect(startEnrollment(mailbox, passkeyOptions(credentials))).rejects.toBeInstanceOf(PrfUnavailable);
    const enrollment = await startEnrollment(mailbox, null);
    expect(enrollment.passkey).toBe("none");
    enrollment.confirmRecovery(charactersAt(enrollment.recoveryKey, enrollment.recoveryCheck.positions));
    expect(enrollment.request().wraps.map((w) => w.kind)).toEqual(["recovery"]);
  });

  test("a dismissed prompt is PasskeyCancelled", async () => {
    await expect(startEnrollment(mailbox, passkeyOptions(new CredentialsDouble({ cancel: true })))).rejects.toBeInstanceOf(PasskeyCancelled);
  });

  test("unlocked() is a decrypt-only session for the new key, without another prompt", async () => {
    const credentials = new CredentialsDouble();
    const enrollment = await startEnrollment(mailbox, passkeyOptions(credentials));
    enrollment.confirmRecovery(charactersAt(enrollment.recoveryKey, enrollment.recoveryCheck.positions));
    const request = enrollment.request();
    const unlocked = enrollment.unlocked();
    expect(credentials.got.length).toBe(0);
    expect(unlocked.locked).toBe(false);
    expect(unlocked.keyId).toBe(request.wraps[0]!.keyId);

    const pub = await publicKeyOf(request);
    const { item } = await sealedItem(pub, mailbox.id, "msg_0000000000000000000000001");
    const [message] = await unlocked.openMessages([item]);
    expect(message!.header?.subject).toBe("Kitchen remodel quote");

    // K1′: the session cannot wrap its key; adding a passkey needs a fresh unlock (a FreshFactor).
    await expect(unlocked.reauthenticate({ recoveryKey: "not a key" })).rejects.toThrow();
    const fresh = await unlocked.reauthenticate({ recoveryKey: enrollment.recoveryKey });
    const added = (await unlocked.addPasskey(passkeyOptions(credentials, { label: "Phone" }), fresh)).request;
    expect(added.kind).toBe("passkey-prf");
    expect(added.label).toBe("Phone");
    expect(fromB64url(added.wrapped).length).toBe(77);
    expect(added.admission!.by).toBe(fresh.factorId); // K12: admitted by the FreshFactor's factor

    enrollment.discard();
    expect(() => enrollment.request()).toThrow();
    expect(() => enrollment.unlocked()).toThrow();
    // The session made earlier is unaffected by discard().
    expect(unlocked.locked).toBe(false);
    unlocked.lock();
    await expect(unlocked.openMessages([item])).rejects.toBeInstanceOf(MailboxLocked);
  });

  test("the recovery key from the enrollment unlocks the mailbox the server then describes", async () => {
    const enrollment = await startEnrollment(mailbox, null);
    enrollment.confirmRecovery(charactersAt(enrollment.recoveryKey, enrollment.recoveryCheck.positions));
    const request = enrollment.request();
    const view = mailboxAfterEnroll(mailbox.id, request);
    const unlocked = await unlockWithRecoveryKey(view, enrollment.recoveryKey);
    expect(unlocked.fingerprint).toBe(enrollment.fingerprint);
    const { item } = await sealedItem(await publicKeyOf(request), mailbox.id, "msg_0000000000000000000000002");
    expect((await unlocked.openMessages([item]))[0]!.header).toStrictEqual(sampleHeader);
  });

  test("every wrap carries its factor key, signing key, admission (A11's cycle) and tag under the new key (device-v1 B5), and the mailbox then requires sessions", async () => {
    const enrollment = await startEnrollment(mailbox, passkeyOptions(new CredentialsDouble()));
    enrollment.confirmRecovery(charactersAt(enrollment.recoveryKey, enrollment.recoveryCheck.positions));
    const request = enrollment.request();
    const keyId = await keyIdOf(fromB64url(request.publicKey));
    const cycle = new Map(bootstrapAdmitters(request.wraps.map((w) => w.id)).map((c) => [c.factorId, c.admitterId]));
    for (const w of request.wraps) {
      expect(fromB64url(w.factorKey!).length).toBe(32);
      expect(fromB64url(w.signingKey!).length).toBe(32);
      expect(w.admission!.by).toBe(cycle.get(w.id));
      expect(fromB64url(w.tag!).length).toBe(32);
      expect(w.tagKeyId).toBe(keyId);
    }
    expect("device" in request).toBe(false);
    const fake = new FakeMail({ mailboxId: mailbox.id });
    await fake.enroll(request);
    expect(fake.sessionsMode).toBe("required");
    await enrollment.commit(); // nothing to keep: a no-op
  });

  test("\"this device is mine\" at enrollment (F12): the request carries the device and its seal; commit() keeps it; unlocked() is its session; a reload opens with no prompt", async () => {
    const store = memoryDeviceStore();
    const enrollment = await startEnrollment(mailbox, passkeyOptions(new CredentialsDouble()), { keep: { store, accountId: "acc_owner", label: "Office laptop", signInId: "signin-1" } });
    enrollment.confirmRecovery(charactersAt(enrollment.recoveryKey, enrollment.recoveryCheck.positions));
    const request = enrollment.request();
    const keyId = await keyIdOf(fromB64url(request.publicKey));
    expect(Object.keys(request).sort()).toEqual(["device", "publicKey", "wraps"]);
    expect(Object.keys(request.device!).sort()).toEqual(["device", "seal"]);
    expect(request.device!.device).toMatchObject({ label: "Office laptop", tagKeyId: keyId });
    // A11: one of the factors made here (the recovery key) admits the device; the device signs its unlock key.
    expect(request.device!.device.admission.by).toBe(request.wraps.find((w) => w.kind === "recovery")!.id);
    expect(fromB64url(request.device!.device.unlockSignature!).length).toBe(64);
    expect(fromB64url(request.device!.seal!).length).toBe(142);
    expect(() => enrollment.unlocked()).toThrow(TypeError); // commit() first: the device is kept only once Mail has it
    expect(await store.get(mailbox.id, "acc_owner")).toBeNull();
    const fake = new FakeMail({ mailboxId: mailbox.id });
    await fake.enroll(request);
    await enrollment.commit();
    const unlocked = enrollment.unlocked();
    expect(unlocked.device).toEqual({ id: request.device!.device.id, label: "Office laptop", lockAfter: "sign-out", keepsUnlocked: true });
    expect((await fake.openSession(await unlocked.sessionProof(await fake.challenge({ purpose: "session" })))).device).toBe(request.device!.device.id);
    expect((await store.get(mailbox.id, "acc_owner"))!.trustRoot).toBe(request.wraps.find((w) => w.kind === "recovery")!.signingKey);
    expect((await resumeDevice(fake.mailbox(), { store, accountId: "acc_owner", signInId: "signin-1" })).state).toBe("unlocked");
  });
});
