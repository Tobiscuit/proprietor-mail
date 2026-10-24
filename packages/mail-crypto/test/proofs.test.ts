// The Worker's half of contracts/device-v1.md A6 and A7: sealing a challenge
// to a public key, and verifying a device's signature over one. Everything
// the browser does here (opening the challenge, signing the proof) is done by
// this test itself, straight on @hpke/core and Web Crypto, with its own copy
// of the contract's ctx() rule: a test-local opener, so a mistake shared by
// the package's own helpers cannot make this test pass.
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { describe, expect, test } from "vitest";
import * as api from "../src/index";
import { openChallenge as openWithPackage } from "../src/challenges";
import { deriveFactorKey } from "../src/factor-keys";
import { sealChallenge, verifyDeviceProof } from "../src/proofs";

const utf8 = (s: string) => new TextEncoder().encode(s);
const b64u = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (s: string) => {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
};
/** The contract's notation: UTF-8 of "proprietor-mail/v1/" + label + "|" + a + "|" + b + … */
const ctx = (label: string, ...parts: string[]) => utf8(`proprietor-mail/v1/${label}|${parts.join("|")}`);

const CHALLENGE_INFO = "proprietor-mail/v1/challenge";
const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

type Purpose = "session" | "factor" | "key";
interface ChallengeIds {
  mailboxId: string;
  challengeId: string;
  purpose: Purpose;
  targetId: string;
  /** Round 3 (A6): the action descriptor's digest, in the aad of "factor" and "key" challenges. */
  actionDigest?: string;
}

async function x25519Recipient(): Promise<{ pair: CryptoKeyPair; publicKey: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  return { pair, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

/** Opens a sealed challenge the way the contract says a browser does: HPKE base mode, A6's info and aad. */
async function openChallenge(sealed: string, recipient: CryptoKeyPair, ids: ChallengeIds, info = CHALLENGE_INFO): Promise<Uint8Array> {
  const bytes = fromB64u(sealed);
  const aad =
    ids.actionDigest === undefined
      ? ctx("challenge", ids.mailboxId, ids.challengeId, ids.purpose, ids.targetId)
      : ctx("challenge", ids.mailboxId, ids.challengeId, ids.purpose, ids.targetId, ids.actionDigest);
  return new Uint8Array(await suite.open({ recipientKey: recipient, enc: bytes.slice(0, 32), info: utf8(info) }, bytes.slice(32), aad));
}

const ID_CHARS = "0123456789abcdefghjkmnpqrstvwxyz";
const testId = (prefix: string) => `${prefix}_${Array.from(crypto.getRandomValues(new Uint8Array(26)), (b) => ID_CHARS[b % 32]).join("")}`;
const keyIdLike = () => Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, "0")).join("");

function sessionIds(over: Partial<ChallengeIds> = {}): ChallengeIds {
  return { mailboxId: testId("mbx"), challengeId: testId("chl"), purpose: "session", targetId: keyIdLike(), ...over };
}

/** A digest of the shape A10 names: base64url (no padding) of 32 bytes. */
const digestLike = () => b64u(crypto.getRandomValues(new Uint8Array(32)));

function boundIds(purpose: "factor" | "key", over: Partial<ChallengeIds> = {}): ChallengeIds {
  return sessionIds({ purpose, targetId: purpose === "factor" ? testId("wrp") : keyIdLike(), actionDigest: digestLike(), ...over });
}

describe("sealChallenge (device-v1 A6)", () => {
  test.each(["session", "factor", "key"] as const)("seals a fresh 32-byte answer in 80 bytes that the target's private key opens (%s)", async (purpose) => {
    const target = await x25519Recipient();
    const ids = purpose === "session" ? sessionIds() : boundIds(purpose);
    const { sealed, answer } = await sealChallenge({ publicKey: target.publicKey }, ids);
    expect(answer).toBeInstanceOf(Uint8Array);
    expect(answer.length).toBe(32);
    expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(fromB64u(sealed).length).toBe(80);
    expect(await openChallenge(sealed, target.pair, ids)).toEqual(answer);
  });

  test("draws a new answer and a new encapsulation for every challenge", async () => {
    const target = await x25519Recipient();
    const ids = sessionIds();
    const a = await sealChallenge({ publicKey: target.publicKey }, ids);
    const b = await sealChallenge({ publicKey: target.publicKey }, ids);
    expect(a.answer).not.toEqual(b.answer);
    expect(a.sealed.slice(0, 43)).not.toBe(b.sealed.slice(0, 43));
    expect(await openChallenge(b.sealed, target.pair, ids)).toEqual(b.answer);
  });

  test("opens under its own info only (K4: no other ciphertext is a challenge, and a challenge is nothing else)", async () => {
    const target = await x25519Recipient();
    const ids = sessionIds();
    const { sealed } = await sealChallenge({ publicKey: target.publicKey }, ids);
    for (const info of ["proprietor-mail/v1/message-key", "proprietor-mail/v1/challenge|", "proprietor-mail/v1/Challenge", ""]) {
      await expect(openChallenge(sealed, target.pair, ids, info), info).rejects.toThrow();
    }
  });

  test("opens under its own aad only: each id is bound", async () => {
    const target = await x25519Recipient();
    const ids = sessionIds();
    const { sealed } = await sealChallenge({ publicKey: target.publicKey }, ids);
    const changed: Partial<ChallengeIds>[] = [
      { mailboxId: testId("mbx") },
      { challengeId: testId("chl") },
      { purpose: "factor", actionDigest: digestLike() },
      { purpose: "key", actionDigest: digestLike() },
      { targetId: keyIdLike() },
    ];
    for (const over of changed) {
      await expect(openChallenge(sealed, target.pair, { ...ids, ...over }), JSON.stringify(Object.keys(over))).rejects.toThrow();
    }
  });

  test.each(["factor", "key"] as const)("round 3 (A6, D36): a %s challenge opens only with its own action digest in the aad", async (purpose) => {
    const target = await x25519Recipient();
    const ids = boundIds(purpose);
    const { sealed, answer } = await sealChallenge({ publicKey: target.publicKey }, ids);
    expect(await openChallenge(sealed, target.pair, ids)).toEqual(answer);
    // Another digest, and none at all (the session form of the aad), open nothing.
    await expect(openChallenge(sealed, target.pair, { ...ids, actionDigest: digestLike() })).rejects.toThrow();
    const { actionDigest: _digest, ...without } = ids;
    await expect(openChallenge(sealed, target.pair, without)).rejects.toThrow();
  });

  test("round 3: the browser's opener (src/challenges.ts) answers what this sealer seals, for its own digest only", async () => {
    const mailboxId = testId("mbx");
    const factorId = testId("wrp");
    const factor = await deriveFactorKey({ mailboxId, factorId, kind: "recovery", secret: crypto.getRandomValues(new Uint8Array(32)) }); // pragma: allowlist secret (a random test secret drawn at run time)
    const pk = api.factorPublicKey(factor);
    const ids = boundIds("factor", { mailboxId, targetId: factorId });
    const { sealed, answer } = await sealChallenge({ publicKey: pk }, ids);
    expect(await openWithPackage(factor, { mailboxId, challengeId: ids.challengeId, actionDigest: ids.actionDigest! }, sealed)).toEqual(answer);
    await expect(openWithPackage(factor, { mailboxId, challengeId: ids.challengeId, actionDigest: digestLike() }, sealed)).rejects.toThrow();
  });

  test("round 3: a factor or key challenge needs a digest of 32 bytes in base64url, and a session challenge takes none", async () => {
    const target = await x25519Recipient();
    for (const purpose of ["factor", "key"] as const) {
      for (const actionDigest of [undefined, "", digestLike().slice(1), `${digestLike()}=`, `${digestLike().slice(0, 42)}+`, b64u(new Uint8Array(31)), 7]) {
        const ids = { ...boundIds(purpose), actionDigest } as ChallengeIds;
        await expect(sealChallenge({ publicKey: target.publicKey }, ids), `${purpose} ${String(actionDigest)}`).rejects.toThrow(TypeError);
      }
    }
    await expect(sealChallenge({ publicKey: target.publicKey }, sessionIds({ actionDigest: digestLike() }))).rejects.toThrow(TypeError);
  });

  test("opens with the target's private key only", async () => {
    const target = await x25519Recipient();
    const other = await x25519Recipient();
    const ids = sessionIds();
    const { sealed } = await sealChallenge({ publicKey: target.publicKey }, ids);
    await expect(openChallenge(sealed, other.pair, ids)).rejects.toThrow();
  });

  test("refuses a target that is not a 32-byte X25519 public key", async () => {
    const ids = sessionIds();
    for (const publicKey of [new Uint8Array(31), new Uint8Array(33), new Uint8Array(65), "a".repeat(32)]) {
      await expect(sealChallenge({ publicKey: publicKey as Uint8Array }, ids)).rejects.toThrow(TypeError);
    }
  });

  test("refuses a target whose agreement is all zeros (a low-order point), rather than seal to it", async () => {
    await expect(sealChallenge({ publicKey: new Uint8Array(32) }, sessionIds())).rejects.toThrow();
  });

  test("refuses ids the contract's ctx() refuses, and a purpose it does not name", async () => {
    const target = await x25519Recipient();
    const bad: Partial<Record<keyof ChallengeIds, string>>[] = [
      { mailboxId: "" },
      { challengeId: "chl_a|b" },
      { targetId: "" },
      { purpose: "device" },
      { purpose: "" },
    ];
    for (const over of bad) {
      await expect(sealChallenge({ publicKey: target.publicKey }, { ...sessionIds(), ...over } as ChallengeIds), JSON.stringify(over)).rejects.toThrow(TypeError);
    }
  });
});

// ---- A7 -----------------------------------------------------------------------------

interface ProofIds {
  mailboxId: string;
  deviceId: string;
  challengeId: string;
  nonce: Uint8Array;
}

async function signingDevice(): Promise<{ pair: CryptoKeyPair; signingKey: Uint8Array }> { // pragma: allowlist secret (a type annotation: a public P-256 point)
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"])) as CryptoKeyPair;
  return { pair, signingKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

/** A7, signed the way a kept device signs it: ECDSA P-256 with SHA-256, Web Crypto's IEEE P1363 form. */
async function sign(device: { pair: CryptoKeyPair }, ids: ProofIds): Promise<Uint8Array> {
  const message = ctx("device-proof", ids.mailboxId, ids.deviceId, ids.challengeId, b64u(ids.nonce));
  return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, device.pair.privateKey, message));
}

function proofIds(over: Partial<ProofIds> = {}): ProofIds {
  return { mailboxId: testId("mbx"), deviceId: testId("dev"), challengeId: testId("chl"), nonce: crypto.getRandomValues(new Uint8Array(32)), ...over };
}

/** The same signature in X.509's DER form, which Web Crypto does not use. */
function der(p1363: Uint8Array): Uint8Array {
  const int = (x: Uint8Array) => {
    let i = 0;
    while (i < x.length - 1 && x[i] === 0) i++;
    const body = x[i]! & 0x80 ? Uint8Array.of(0, ...x.slice(i)) : x.slice(i);
    return Uint8Array.of(0x02, body.length, ...body);
  };
  const r = int(p1363.slice(0, 32));
  const s = int(p1363.slice(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

describe("verifyDeviceProof (device-v1 A7)", () => {
  test("accepts a real P-256 signature over the contract's message", async () => {
    const device = await signingDevice();
    const ids = proofIds();
    const signature = await sign(device, ids);
    expect(signature.length).toBe(64);
    expect(await verifyDeviceProof(device.signingKey, ids, signature)).toBe(true);
  });

  test("refuses a signature over another nonce, challenge, device or mailbox", async () => {
    const device = await signingDevice();
    const ids = proofIds();
    const signature = await sign(device, ids);
    const changed: Partial<ProofIds>[] = [
      { nonce: crypto.getRandomValues(new Uint8Array(32)) },
      { challengeId: testId("chl") },
      { deviceId: testId("dev") },
      { mailboxId: testId("mbx") },
    ];
    for (const over of changed) {
      expect(await verifyDeviceProof(device.signingKey, { ...ids, ...over }, signature), JSON.stringify(Object.keys(over))).toBe(false);
    }
  });

  test("refuses another device's signature, a changed signature, and one in DER or of the wrong length", async () => {
    const device = await signingDevice();
    const other = await signingDevice();
    const ids = proofIds();
    const signature = await sign(device, ids);
    expect(await verifyDeviceProof(device.signingKey, ids, await sign(other, ids))).toBe(false);
    for (let i = 0; i < 64; i += 21) {
      const flipped = signature.slice();
      flipped[i] = flipped[i]! ^ 0x01;
      expect(await verifyDeviceProof(device.signingKey, ids, flipped), `byte ${i}`).toBe(false);
    }
    for (const wrong of [der(signature), signature.slice(0, 63), Uint8Array.of(...signature, 0), new Uint8Array(0), new Uint8Array(64)]) {
      expect(await verifyDeviceProof(device.signingKey, ids, wrong)).toBe(false);
    }
  });

  test("throws on a signing key that is not a 65-byte uncompressed P-256 point: a caller's mistake, never a verdict", async () => {
    const device = await signingDevice();
    const ids = proofIds();
    const signature = await sign(device, ids);
    const compressed = Uint8Array.of(0x02 | (device.signingKey[64]! & 1), ...device.signingKey.slice(1, 33));
    const offCurve = device.signingKey.slice();
    offCurve[64] = offCurve[64]! ^ 0x01;
    for (const key of [compressed, device.signingKey.slice(1), offCurve, Uint8Array.of(0x05, ...device.signingKey.slice(1))]) {
      await expect(verifyDeviceProof(key, ids, signature)).rejects.toThrow(TypeError);
    }
  });

  test("throws on a nonce that is not 32 bytes and on ids the contract's ctx() refuses", async () => {
    const device = await signingDevice();
    const ids = proofIds();
    const signature = await sign(device, ids);
    for (const over of [{ nonce: new Uint8Array(31) }, { deviceId: "" }, { challengeId: "a|b" }] as Partial<ProofIds>[]) {
      await expect(verifyDeviceProof(device.signingKey, { ...ids, ...over }, signature)).rejects.toThrow(TypeError);
    }
  });
});

describe("the package exports both from its index, as the one re-export line", () => {
  test("sealChallenge and verifyDeviceProof are the index's own", () => {
    expect(api.sealChallenge).toBe(sealChallenge);
    expect(api.verifyDeviceProof).toBe(verifyDeviceProof);
  });
});
