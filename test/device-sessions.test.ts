import { runInDurableObject } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { publicCopy } from "../src/errors";
import { SESSION_NEEDS } from "../src/mailbox/sessions";
import { MailService } from "../src/service";
import { newId } from "@proprietor/mail-crypto";
import {
  actionInput,
  admitFactor,
  challenge,
  factorInput,
  factorProof,
  keyProof,
  legacyMailbox,
  newFactorKey,
  openChallenge,
  openSession,
  openSessionAction,
  plainSession,
  upgradeRequest,
  upgradedMailbox,
} from "./support/browser";
import { base64urlFromBytes, bytesFromBase64url } from "./support/capability-tokens";
import { testId } from "./support/ids";
import { capFor, newKeyPair, passkeyWrap, provisionMailbox, type TestMailbox } from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";

// contracts/device-v1.md B2, B3, B5, B6 and B8; domain-model M13-M16, M20.

const mail = () => exports.MailService;
const MINUTE = 60 * 1000;

const SESSION_REQUIRED = { name: "SessionRequired", message: "a live mail session is required" };
const PROOF_REJECTED = { name: "ProofRejected", message: "the proof was not accepted" };

const random = (n: number) => base64urlFromBytes(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = async (b64u: string) => base64urlFromBytes(new Uint8Array(await crypto.subtle.digest("SHA-256", bytesFromBase64url(b64u))));
const at = (mb: TestMailbox, ms = 0) => new Date(mb.ports.clock.now().getTime() + ms).toISOString();

async function sql<T = Record<string, unknown>>(mb: TestMailbox, query: string, ...args: unknown[]): Promise<T[]> {
  return runInDurableObject(mb.stub, (_i, state) => state.storage.sql.exec(query, ...args).toArray() as T[]);
}

async function latestAudit(mb: TestMailbox) {
  return (await sql<{ actor: string; action: string; detail: string }>(mb, "SELECT actor, action, detail FROM audit ORDER BY id DESC LIMIT 1")).map((r) => ({
    ...r,
    detail: JSON.parse(r.detail) as Record<string, unknown>,
  }))[0];
}

/** The reasons of the proof-rejected rows written for one challenge, oldest first. */
async function rejections(mb: TestMailbox, challengeId: string): Promise<unknown[]> {
  return (await sql<{ detail: string }>(mb, "SELECT detail FROM audit WHERE action = 'proof-rejected' ORDER BY id"))
    .map((r) => JSON.parse(r.detail) as Record<string, unknown>)
    .filter((d) => d.challenge === challengeId)
    .map((d) => d.reason);
}

async function openWith(mb: TestMailbox, request: Record<string, unknown>, sub?: string) {
  return mail().openSession(await capFor(mb, sub === undefined ? {} : { sub }), request);
}

describe("challenges (device-v1 B6, M16)", () => {
  it("seals a session challenge to the active key, which alone opens it; it names the key and lives 2 minutes", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    expect(c).toEqual({
      id: expect.stringMatching(/^chl_[0-9a-hjkmnp-tv-z]{26}$/),
      purpose: "session",
      keyId: mb.key!.keyId,
      factorId: null,
      nonce: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      sealed: expect.stringMatching(/^[A-Za-z0-9_-]{107}$/),
      descriptor: null,
      expiresAt: at(mb, 2 * MINUTE),
    });
    const answer = await openChallenge(mb.id, c, mailboxKey);
    expect(bytesFromBase64url(answer)).toHaveLength(32);
    // At rest: the nonce as it was sent (it is not a secret: the device signs it), the answer only as its SHA-256.
    expect(await sql(mb, "SELECT nonce, answer_hash FROM challenges WHERE id = ?", c.id)).toEqual([{ nonce: c.nonce, answer_hash: await sha256(answer) }]);
    const stranger = await newFactorKey(testId("wrp"), "recovery");
    await expect(openChallenge(mb.id, c, stranger.pair)).rejects.toThrow();
  });

  it("is used once", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    const answer = await openChallenge(mb.id, c, mailboxKey);
    valueOf(await openWith(mb, { challengeId: c.id, answer }));
    expect(refusalOf(await openWith(mb, { challengeId: c.id, answer }))).toEqual(PROOF_REJECTED);
  });

  it("lives 2 minutes: a millisecond before, it opens a session; at 2 minutes it is ProofRejected", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const early = await challenge(mb, { purpose: "session" });
    const late = await challenge(mb, { purpose: "session" });
    mb.ports.clock.advance(2 * MINUTE - 1);
    valueOf(await openWith(mb, { challengeId: early.id, answer: await openChallenge(mb.id, early, mailboxKey) }));
    mb.ports.clock.advance(1);
    expect(refusalOf(await openWith(mb, { challengeId: late.id, answer: await openChallenge(mb.id, late, mailboxKey) }))).toEqual(PROOF_REJECTED);
  });

  it("is consumed by a wrong answer, which is ProofRejected and audited as proof-rejected: the right answer then opens nothing", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    expect(refusalOf(await openWith(mb, { challengeId: c.id, answer: random(32) }))).toEqual(PROOF_REJECTED);
    expect(await latestAudit(mb)).toEqual({ actor: "acc_owner", action: "proof-rejected", detail: { challenge: c.id, purpose: "session", reason: "answer" } });
    expect(refusalOf(await openWith(mb, { challengeId: c.id, answer: await openChallenge(mb.id, c, mailboxKey) }))).toEqual(PROOF_REJECTED);
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM mail_sessions")).toEqual([{ n: 0 }]);
  });

  it("audits the replay of a spent challenge once: five tries, one proof-rejected row", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    const answer = await openChallenge(mb.id, c, mailboxKey);
    valueOf(await openWith(mb, { challengeId: c.id, answer }));
    for (let i = 0; i < 5; i++) expect(refusalOf(await openWith(mb, { challengeId: c.id, answer }))).toEqual(PROOF_REJECTED);
    expect(await rejections(mb, c.id)).toEqual(["used"]);
  });

  it("audits an expired challenge once: five tries, one proof-rejected row", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    const answer = await openChallenge(mb.id, c, mailboxKey);
    mb.ports.clock.advance(2 * MINUTE);
    for (let i = 0; i < 5; i++) expect(refusalOf(await openWith(mb, { challengeId: c.id, answer }))).toEqual(PROOF_REJECTED);
    expect(await rejections(mb, c.id)).toEqual(["expired"]);
  });

  it("allows 20 live per mailbox: the 21st is RateLimited until the oldest expires; a used or expired one makes room", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const made = [];
    for (let i = 0; i < 20; i++) {
      made.push(await challenge(mb, { purpose: "session" }));
      mb.ports.clock.advance(1000);
    }
    // The oldest was made 20 s ago and lives 120 s.
    expect(refusalOf(await mail().challenge(await capFor(mb), { purpose: "session" }))).toEqual({
      name: "RateLimited",
      message: "too many challenges are open; try again shortly",
      retryAfterSeconds: 100,
    });
    valueOf(await openWith(mb, { challengeId: made[5]!.id, answer: await openChallenge(mb.id, made[5]!, mailboxKey) }));
    await challenge(mb, { purpose: "session" });
    expect(refusalOf(await mail().challenge(await capFor(mb), { purpose: "session" }))).toMatchObject({ name: "RateLimited" });
    mb.ports.clock.advance(100 * 1000); // the oldest expires
    await challenge(mb, { purpose: "session" });
  });

  it("is per account and purpose: a factor challenge needs a factor with a factor key (NotFound otherwise)", async () => {
    const { mb, recoveryId } = await legacyMailbox();
    const action = await actionInput(openSessionAction(newId("chl")));
    expect(refusalOf(await mail().challenge(await capFor(mb), { purpose: "factor", factorId: recoveryId, action }))).toEqual({ name: "NotFound", message: "not found" });
    expect(refusalOf(await mail().challenge(await capFor(mb), { purpose: "factor", factorId: testId("wrp"), action }))).toEqual({ name: "NotFound", message: "not found" });
  });

  it("refuses a request outside the contract's shape", async () => {
    const { mb } = await legacyMailbox();
    for (const request of [{}, { purpose: "device" }, { purpose: "session", factorId: testId("wrp") }, { purpose: "factor" }, { purpose: "factor", factorId: "wrp_1" }, { purpose: "session", extra: 1 }, "session", null]) {
      expect([request, refusalOf(await mail().challenge(await capFor(mb), request)).name]).toEqual([request, "InvalidRequest"]);
    }
  });

  it("needs a role in openRoles, and a mailbox with a key", async () => {
    const { mb } = await legacyMailbox();
    expect(refusalOf(await mail().challenge(await capFor(mb, { role: "editor" }), { purpose: "session" }))).toEqual({ name: "Forbidden", message: "forbidden" });
    expect(refusalOf(await mail().openSession(await capFor(mb, { role: "editor" }), { challengeId: testId("wrp"), answer: random(32) }))).toEqual({ name: "Forbidden", message: "forbidden" });
    const fresh = await provisionMailbox({ status: "provisioned" });
    expect(refusalOf(await mail().challenge(await capFor(fresh), { purpose: "session" }))).toEqual({ name: "MailboxNotActive", message: "this mailbox is not active" });
  });
});

describe("openSession (B6, M15)", () => {
  it("opens a 60-minute session from a key proof, and Mail keeps only the token's SHA-256", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const opened = await openSession(mb, mailboxKey);
    expect(opened).toEqual({ session: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), expiresAt: at(mb, 60 * MINUTE), device: null });
    expect(bytesFromBase64url(opened.session)).toHaveLength(32);
    expect(await sql(mb, "SELECT * FROM mail_sessions")).toEqual([
      { token_hash: await sha256(opened.session), account_id: "acc_owner", device_id: null, created_at: at(mb), expires_at: at(mb, 60 * MINUTE) },
    ]);
  });

  it("does not open from another account's challenge, which stays usable by its own account", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    const answer = await openChallenge(mb.id, c, mailboxKey);
    const before = await sql(mb, "SELECT COUNT(*) AS n FROM audit");
    expect(refusalOf(await openWith(mb, { challengeId: c.id, answer }, "acc_other"))).toEqual(PROOF_REJECTED);
    // It spent nothing, so it writes nothing: one caller could repeat it without end, a row each time.
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM audit")).toEqual(before);
    valueOf(await openWith(mb, { challengeId: c.id, answer }));
  });

  it("refuses a challenge that does not exist, and writes no audit row for it", async () => {
    const { mb } = await legacyMailbox();
    const before = await sql(mb, "SELECT COUNT(*) AS n FROM audit");
    for (let i = 0; i < 3; i++) {
      expect(refusalOf(await openWith(mb, { challengeId: newId("chl"), answer: random(32) }))).toEqual(PROOF_REJECTED);
    }
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM audit")).toEqual(before);
  });

  it("does not open from a factor challenge: that is not a key proof", async () => {
    const u = await upgradedMailbox();
    // Round 3: a factor challenge (bound to an open-session action naming itself) in the key proof's place, with a good factor proof beside it.
    const asKeyProof = await challenge(u.mb, { purpose: "factor", factorId: u.passkey.id, action: await actionInput(openSessionAction(newId("chl"))) });
    const answer = await openChallenge(u.mb.id, asKeyProof, u.passkey.pair);
    const proof = await factorProof(u.mb, u.recovery, openSessionAction(asKeyProof.id));
    expect(refusalOf(await openWith(u.mb, { challengeId: asKeyProof.id, answer, factorProof: proof }))).toEqual(PROOF_REJECTED);
    expect(await rejections(u.mb, asKeyProof.id)).toEqual(["purpose"]);
  });

  it("refuses a request outside the contract's shape, and spends nothing on it", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const c = await challenge(mb, { purpose: "session" });
    const answer = await openChallenge(mb.id, c, mailboxKey);
    for (const request of [
      { challengeId: "chl_1", answer },
      { challengeId: c.id, answer: random(31) },
      { challengeId: c.id, answer, device: { id: "dev_1", signature: random(64) } },
      { challengeId: c.id, answer, device: { id: testId("wrp").replace("wrp", "dev"), signature: random(63) } },
      { challengeId: c.id, answer, extra: true },
      { challengeId: c.id },
    ]) {
      expect(refusalOf(await openWith(mb, request)).name).toBe("InvalidRequest");
    }
    valueOf(await openWith(mb, { challengeId: c.id, answer }));
  });
});

describe("sessions while optional (B2, R10)", () => {
  it("asks for none, accepts a live one, and refuses one that is malformed, unknown, expired or another account's: a token is never ignored", async () => {
    const { mb, mailboxKey } = await legacyMailbox();
    const list = async (auth?: unknown, sub?: string) => mail().list(await capFor(mb, sub === undefined ? {} : { sub }), { folder: "inbox" }, auth as never);
    valueOf(await list());
    valueOf(await list({}));
    const { session } = await openSession(mb, mailboxKey);
    valueOf(await list({ session }));
    expect(refusalOf(await list({ session: "not-a-token" }))).toEqual(SESSION_REQUIRED);
    expect(refusalOf(await list({ session: random(32) }))).toEqual(SESSION_REQUIRED);
    expect(refusalOf(await list({ session }, "acc_other"))).toEqual(SESSION_REQUIRED);
    mb.ports.clock.advance(60 * MINUTE);
    expect(refusalOf(await list({ session }))).toEqual(SESSION_REQUIRED);
    valueOf(await list());
  });
});

describe("the upgrade (B5, M20, M13)", () => {
  it("gives the named factors their keys, signing keys, admissions and tags and turns sessions on, in one step, audited as mailbox-upgraded", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey, recoveryId, passkeyId } = legacy;
    const recovery = await legacy.recovery();
    const passkey = await legacy.passkey();
    const { session } = await openSession(mb, mailboxKey);
    const request = await upgradeRequest(mb, [recovery, passkey], mb.key!.keyId);
    expect(await mail().upgrade(await capFor(mb), request, { session, keyProof: await keyProof(mb, mailboxKey, request) })).toEqual({ ok: true, value: null });
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect(view.sessions).toBe("required");
    for (const f of request.factors) {
      expect(view.wraps.find((w) => w.id === f.id)).toMatchObject({ factorKey: f.factorKey, signingKey: f.signingKey, admission: f.admission, tag: f.tag, tagKeyId: mb.key!.keyId }); // pragma: allowlist secret (public keys)
    }
    expect(await latestAudit(mb)).toEqual({ actor: "acc_owner", action: "mailbox-upgraded", detail: { factors: `${recoveryId},${passkeyId}` } });
    // The session it ran in still works.
    valueOf(await mail().list(await capFor(mb), { folder: "inbox" }, { session }));
  });

  it("needs a live session (it was opened with a key proof): without one it is SessionRequired and nothing changes", async () => {
    const legacy = await legacyMailbox();
    const { mb } = legacy;
    const request = await upgradeRequest(mb, [await legacy.recovery(), await legacy.passkey()], mb.key!.keyId);
    const proof = await keyProof(mb, legacy.mailboxKey, request);
    expect(refusalOf(await mail().upgrade(await capFor(mb), request, { keyProof: proof }))).toEqual(SESSION_REQUIRED);
    expect(refusalOf(await mail().upgrade(await capFor(mb), request, { session: random(32), keyProof: proof }))).toEqual(SESSION_REQUIRED);
    expect(valueOf(await mail().mailbox(await capFor(mb))).sessions).toBe("optional");
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM key_wraps WHERE factor_key IS NOT NULL")).toEqual([{ n: 0 }]);
    // The key proof was not spent: the session is checked first.
    expect(await sql(mb, "SELECT used_at FROM challenges WHERE id = ?", proof.challengeId)).toEqual([{ used_at: null }]);
  });

  it("round 3: needs a key proof bound to this very request (D36): none, one for another request, or a session challenge's is ProofRejected", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey } = legacy;
    const recovery = await legacy.recovery();
    const passkey = await legacy.passkey();
    const { session } = await openSession(mb, mailboxKey);
    const request = await upgradeRequest(mb, [recovery, passkey], mb.key!.keyId);
    expect(refusalOf(await mail().upgrade(await capFor(mb), request, { session }))).toEqual(PROOF_REJECTED);
    // A relay's own factor keys, with the owner's key proof for the owner's request.
    const relayed = await upgradeRequest(mb, [await legacy.recovery(), await legacy.passkey()], mb.key!.keyId);
    const forOwners = await keyProof(mb, mailboxKey, request);
    expect(refusalOf(await mail().upgrade(await capFor(mb), relayed, { session, keyProof: forOwners }))).toEqual(PROOF_REJECTED);
    const asKeyProof = await challenge(mb, { purpose: "session" });
    expect(refusalOf(await mail().upgrade(await capFor(mb), request, { session, keyProof: { challengeId: asKeyProof.id, answer: await openChallenge(mb.id, asKeyProof, mailboxKey) } }))).toEqual(PROOF_REJECTED);
    const wrong = await keyProof(mb, mailboxKey, request);
    expect(refusalOf(await mail().upgrade(await capFor(mb), request, { session, keyProof: { ...wrong, answer: random(32) } }))).toEqual(PROOF_REJECTED);
    expect([await rejections(mb, forOwners.challengeId), await rejections(mb, asKeyProof.id), await rejections(mb, wrong.challengeId)]).toEqual([["action"], ["purpose"], ["answer"]]);
    expect(valueOf(await mail().mailbox(await capFor(mb))).sessions).toBe("optional");
    // The owner's own request, with a fresh proof for it, then goes through; the spent one does not come back.
    expect(refusalOf(await mail().upgrade(await capFor(mb), request, { session, keyProof: forOwners }))).toEqual(PROOF_REJECTED);
    valueOf(await mail().upgrade(await capFor(mb), request, { session, keyProof: await keyProof(mb, mailboxKey, request) }));
  });

  it("round 3, M25: the admissions follow A11's cycle (each factor by the next in id order) and verify, or nothing changes", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey } = legacy;
    const recovery = await legacy.recovery();
    const passkey = await legacy.passkey();
    const { session } = await openSession(mb, mailboxKey);
    const keyId = mb.key!.keyId;
    const good = await upgradeRequest(mb, [recovery, passkey], keyId);
    const [first, second] = [recovery, passkey].sort((a, b) => (a.id < b.id ? -1 : 1));
    const selfAdmitted = { factors: [factorInput(recovery, keyId, await admitFactor(mb.id, recovery, recovery)), factorInput(passkey, keyId, await admitFactor(mb.id, passkey, passkey))] };
    const stranger = await newFactorKey(first!.id, first!.kind, { label: first!.label, credentialId: first!.credentialId }); // pragma: allowlist secret (a field name, not a value)
    const unsignedSelf = good.factors.map((f) => (f.id === first!.id ? { ...f, admission: { ...f.admission, selfSignature: random(64) } } : f));
    const otherKey = good.factors.map((f) => (f.id === second!.id ? { ...f, signingKey: base64urlFromBytes(stranger.signingKey) } : f)); // pragma: allowlist secret (a public Ed25519 key)
    for (const [name, request] of [
      ["each admitted by itself", selfAdmitted],
      ["a self-signature that does not verify", { factors: unsignedSelf }],
      ["a signing key the admission was not made for", { factors: otherKey }],
    ] as const) {
      const answer = await mail().upgrade(await capFor(mb), request, { session, keyProof: await keyProof(mb, mailboxKey, request) });
      expect([name, refusalOf(answer).name]).toEqual([name, "InvalidRequest"]);
    }
    expect(valueOf(await mail().mailbox(await capFor(mb))).sessions).toBe("optional");
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM key_wraps WHERE factor_key IS NOT NULL OR signing_key IS NOT NULL OR admission_by IS NOT NULL")).toEqual([{ n: 0 }]);
    valueOf(await mail().upgrade(await capFor(mb), good, { session, keyProof: await keyProof(mb, mailboxKey, good) }));
  });

  it("happens once (M20), and sessions never go back to optional (M13)", async () => {
    const u = await upgradedMailbox();
    const again = await upgradeRequest(u.mb, [u.recovery, u.passkey], u.mb.key!.keyId);
    expect(refusalOf(await mail().upgrade(await capFor(u.mb), again, { session: u.session, keyProof: await keyProof(u.mb, u.mailboxKey, again) }))).toEqual({
      name: "InvalidRequest",
      message: "invalid request: the mailbox is already upgraded",
    });
    expect(valueOf(await mail().mailbox(await capFor(u.mb))).sessions).toBe("required");
    // Nothing in the schema lets it go back except a direct write, and no method makes one.
    expect(await sql(u.mb, "SELECT sessions FROM policy")).toEqual([{ sessions: "required" }]);
  });

  it("names every wrap of the mailbox, exactly once (B5, M20): one left out is refused, and nothing changes", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey } = legacy;
    const recovery = await legacy.recovery();
    const passkey = await legacy.passkey();
    const { session } = await openSession(mb, mailboxKey);
    const keyId = mb.key!.keyId;
    const every = { name: "InvalidRequest", message: "invalid request: the upgrade must name every wrap of the mailbox, once each" };
    for (const factor of [recovery, passkey]) {
      const alone = await upgradeRequest(mb, [factor], keyId);
      expect(refusalOf(await mail().upgrade(await capFor(mb), alone, { session, keyProof: await keyProof(mb, mailboxKey, alone) }))).toEqual(every);
    }
    expect(valueOf(await mail().mailbox(await capFor(mb))).sessions).toBe("optional");
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM key_wraps WHERE factor_key IS NOT NULL OR tag IS NOT NULL")).toEqual([{ n: 0 }]);
    const both = await upgradeRequest(mb, [passkey, recovery], keyId);
    valueOf(await mail().upgrade(await capFor(mb), both, { session, keyProof: await keyProof(mb, mailboxKey, both) }));
    expect(valueOf(await mail().mailbox(await capFor(mb))).sessions).toBe("required");
  });

  it("takes a mailbox whose owner first removed a factor they no longer have: no proof is needed while sessions are optional", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey, recoveryId, passkeyId } = legacy;
    valueOf(await mail().removeWrap(await capFor(mb), passkeyId));
    const recovery = await legacy.recovery();
    const { session } = await openSession(mb, mailboxKey);
    const request = await upgradeRequest(mb, [recovery], mb.key!.keyId);
    valueOf(await mail().upgrade(await capFor(mb), request, { session, keyProof: await keyProof(mb, mailboxKey, request) }));
    const view = valueOf(await mail().mailbox(await capFor(mb)));
    expect([view.sessions, view.wraps.map((w) => [w.id, w.factorKey !== null])]).toEqual(["required", [[recoveryId, true]]]);
    // A single factor admits itself (A11).
    expect(view.wraps[0]!.admission!.by).toBe(recoveryId);
    // Optional mode removed the passkey's record outright: it never had keys to keep (M24 keeps keyed factors).
    expect(view.removedFactors).toEqual([]);
  });

  it("names wraps of the active key only, each once, with tags under the active key and usable keys", async () => {
    const legacy = await legacyMailbox();
    const { mb, mailboxKey, recoveryId } = legacy;
    const recovery = await legacy.recovery();
    const passkey = await legacy.passkey();
    const { session } = await openSession(mb, mailboxKey);
    const keyId = mb.key!.keyId;
    const other = (await newKeyPair()).keyId;
    const zeros = base64urlFromBytes(new Uint8Array(32));
    const admissions = (await upgradeRequest(mb, [recovery, passkey], keyId)).factors;
    const r = admissions.find((f) => f.id === recovery.id)!;
    const p = admissions.find((f) => f.id === passkey.id)!;
    const stranger = await newFactorKey(testId("wrp"), "recovery");
    for (const factors of [
      [],
      [r, r],
      [r, factorInput(stranger, keyId, await admitFactor(mb.id, stranger, recovery))],
      [{ ...r, tagKeyId: other }, p],
      [{ ...r, factorKey: zeros }, p],
      [{ ...r, factorKey: random(31) }, p],
      [{ ...r, signingKey: random(31) }, p], // pragma: allowlist secret (a test fixture: a malformed public key)
      [{ ...r, tag: random(31) }, p],
      [{ ...r, admission: { by: "wrp_x", signature: r.admission.signature, selfSignature: r.admission.selfSignature } }, p],
      [{ ...r, extra: "x" }, p],
      [{ id: recoveryId, tag: random(32), tagKeyId: keyId }, p],
      [p, { ...r, id: "wrp_x" }],
    ]) {
      const request = { factors };
      const answer = await mail().upgrade(await capFor(mb), request, { session, keyProof: await keyProof(mb, mailboxKey, request) });
      expect([JSON.stringify(factors).slice(0, 60), refusalOf(answer).name]).toEqual([JSON.stringify(factors).slice(0, 60), "InvalidRequest"]);
    }
    expect(valueOf(await mail().mailbox(await capFor(mb))).sessions).toBe("optional");
    expect(await sql(mb, "SELECT COUNT(*) AS n FROM key_wraps WHERE factor_key IS NOT NULL OR tag IS NOT NULL")).toEqual([{ n: 0 }]);
  });

  it("is the owner's: an editor is Forbidden", async () => {
    const legacy = await legacyMailbox();
    const { mb } = legacy;
    const request = await upgradeRequest(mb, [await legacy.recovery()], mb.key!.keyId);
    expect(refusalOf(await mail().upgrade(await capFor(mb, { role: "editor" }), request))).toEqual({
      name: "Forbidden",
      message: "forbidden",
    });
  });
});

/**
 * The contract's own list (B3), kept here and not read from SESSION_NEEDS: a
 * method dropped from the table's session check must fail this test too.
 * Each call is harmless: the session is checked before anything else.
 */
type Answer = Parameters<typeof refusalOf>[0];

function sessionMethods(mb: TestMailbox): [string, (cap: string, auth?: { session?: string }) => Promise<Answer>][] {
  const keyId = mb.key!.keyId;
  return [
    ["upgrade", (cap, auth) => mail().upgrade(cap, { factors: [] }, auth)],
    ["list", (cap, auth) => mail().list(cap, { folder: "inbox" }, auth)],
    ["body", (cap, auth) => mail().body(cap, testId("msg"), auth)],
    ["update", (cap, auth) => mail().update(cap, testId("msg"), { seen: true }, auth)],
    ["purge", (cap, auth) => mail().purge(cap, testId("msg"), auth)],
    ["drafts", (cap, auth) => mail().drafts(cap, auth)],
    ["saveDraft", (cap, auth) => mail().saveDraft(cap, { id: testId("drf"), keyId, keyEnvelope: random(80), sealed: random(40) }, auth)],
    ["deleteDraft", (cap, auth) => mail().deleteDraft(cap, testId("drf"), auth)],
    ["send", (cap, auth) => mail().send(cap, { idempotencyKey: `k-${crypto.randomUUID()}`, to: [{ address: "ana@example.com" }], subject: "s", text: "t", ...(auth ?? {}) })],
    ["setPolicy", (cap, auth) => mail().setPolicy(cap, { displayName: "Example" }, auth)],
    ["audit", (cap, auth) => mail().audit(cap, {}, auth)],
    ["addWrap", (cap, auth) => mail().addWrap(cap, passkeyWrap(keyId), auth)],
    ["removeWrap", (cap, auth) => mail().removeWrap(cap, testId("wrp"), auth)],
    ["registerDevice", (cap, auth) => mail().registerDevice(cap, {}, auth)],
    ["updateDevice", (cap, auth) => mail().updateDevice(cap, {}, auth)],
    ["removeDevices", (cap, auth) => mail().removeDevices(cap, {}, auth)],
  ];
}

describe("sessions once required (B2, B3, M14)", () => {
  it("refuses every method marked session without one, with another account's, and with an expired one", async () => {
    const u = await upgradedMailbox();
    for (const [method, call] of sessionMethods(u.mb)) {
      expect([method, refusalOf(await call(await capFor(u.mb)))]).toEqual([method, SESSION_REQUIRED]);
      expect([method, refusalOf(await call(await capFor(u.mb, { sub: "acc_other" }), { session: u.session }))]).toEqual([method, SESSION_REQUIRED]);
    }
    u.mb.ports.clock.advance(60 * MINUTE);
    for (const [method, call] of sessionMethods(u.mb)) {
      expect([method, refusalOf(await call(await capFor(u.mb), { session: u.session }))]).toEqual([method, SESSION_REQUIRED]);
    }
  });

  it("still answers mailboxes, mailbox and unread without a session (R2, G41)", async () => {
    const u = await upgradedMailbox();
    valueOf(await mail().mailboxes(await capFor(u.mb)));
    expect(valueOf(await mail().mailbox(await capFor(u.mb))).sessions).toBe("required");
    expect(valueOf(await mail().unread(await capFor(u.mb)))).toEqual({ inbox: 0 });
  });

  it("lasts 60 minutes: a millisecond before, it reads; at 60 minutes it is SessionRequired", async () => {
    const u = await upgradedMailbox();
    const session = await plainSession(u);
    u.mb.ports.clock.advance(60 * MINUTE - 1);
    valueOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session }));
    u.mb.ports.clock.advance(1);
    expect(refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, { session }))).toEqual(SESSION_REQUIRED);
  });

  it("send carries its session inside the request (D29), and SES never sees it", async () => {
    const u = await upgradedMailbox();
    const request = { idempotencyKey: "with-session", to: [{ address: "ana@example.com" }], subject: "s", text: "t" };
    expect(refusalOf(await mail().send(await capFor(u.mb), request))).toEqual(SESSION_REQUIRED);
    valueOf(await mail().send(await capFor(u.mb), { ...request, session: u.session }));
    const handed = u.mb.ports.mailer.sent[0]!;
    expect(new TextDecoder().decode(handed.raw)).not.toContain(u.session);
    expect(JSON.stringify({ ...handed, raw: undefined })).not.toContain(u.session);
    expect(JSON.stringify(u.mb.ports.mime.built[0]!.msg)).not.toContain(u.session);
    expect(refusalOf(await mail().send(await capFor(u.mb), { ...request, idempotencyKey: "bad", session: 7 }))).toMatchObject({ name: "InvalidRequest" });
  });

  it("refuses an auth argument outside the contract's shape (B1)", async () => {
    const u = await upgradedMailbox();
    for (const auth of [
      "a-token",
      5,
      [],
      { bearer: u.session },
      { session: 5 },
      { factorProof: "x" },
      { factorProof: { challengeId: "chl_1" } },
      { factorProof: { challengeId: 1, answer: "a" } },
      { keyProof: "x" },
      { keyProof: { challengeId: "chl_1", answer: "a", extra: 1 } },
      { session: u.session, keyProof: { challengeId: newId("chl"), answer: random(32) } },
    ]) {
      expect([auth, refusalOf(await mail().list(await capFor(u.mb), { folder: "inbox" }, auth as never)).name]).toEqual([auth, "InvalidRequest"]);
    }
  });
});

/** The public methods a WorkerEntrypoint class serves over RPC: the functions on its own prototype. */
function rpcMethods(cls: { prototype: object }): string[] {
  return Object.getOwnPropertyNames(cls.prototype).filter((n) => n !== "constructor" && typeof Object.getOwnPropertyDescriptor(cls.prototype, n)?.value === "function");
}

describe("SESSION_NEEDS (plan.md §4): one table names what every MailService method needs", () => {
  it("names every method MailService serves over RPC, and nothing else", () => {
    expect(rpcMethods(MailService).sort()).toEqual(Object.keys(SESSION_NEEDS).sort());
  });

  it("is device-v1 B3's table, written out here rather than read from the code", () => {
    expect(SESSION_NEEDS).toEqual({
      mailboxes: "bootstrap",
      mailbox: "bootstrap",
      unread: "bootstrap",
      enroll: "bootstrap",
      challenge: "bootstrap",
      openSession: "bootstrap",
      upgrade: "key",
      list: "session",
      body: "session",
      update: "session",
      purge: "session",
      drafts: "session",
      saveDraft: "session",
      deleteDraft: "session",
      send: "session",
      setPolicy: "session",
      audit: "session",
      addWrap: "factor",
      removeWrap: "factor",
      registerDevice: "factor",
      updateDevice: "device-session",
      removeDevices: "factor",
      revokeDevices: "email-confirmation",
    });
  });

  it("the check sees a method that is missing from the table", () => {
    class Extended extends MailService {
      async exportEverything(): Promise<null> {
        return null;
      }
    }
    expect(rpcMethods(Extended).filter((m) => !(m in SESSION_NEEDS))).toEqual(["exportEverything"]);
    expect(rpcMethods(class { a() {} b() {} })).toEqual(["a", "b"]);
  });
});

describe("the three error names (B8)", () => {
  it("each crosses with one fixed message, whatever the Worker knew about the cause", () => {
    for (const [name, message] of [
      ["SessionRequired", "a live mail session is required"],
      ["DeviceRevoked", "this device is not in the mailbox"],
      ["ProofRejected", "the proof was not accepted"],
    ] as const) {
      expect(publicCopy({ name, message: "the answer's hash did not match (wrong account)" })).toEqual({ name, message });
    }
  });
});
