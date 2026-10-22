// Writes contracts/device-v1.vectors.json (contracts/device-v1.md A9). Runs only on request:
//   npm run write-device-vectors -w @proprietor/mail-crypto
// (vitest.config.ts excludes *.write.test.ts from `npm test`). Every key and secret is SHA-256 of
// a public label, so they are recognisably test values; ids, HPKE encapsulations, IVs, answers,
// nonces and ECDSA signatures are fresh on each run, so regenerating changes the file.
// test/device-vectors.test.ts checks whatever is committed.
import { createECDH } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { expect, test } from "vitest";
import {
  actionDescriptorFor,
  actionDigest,
  bindingKey,
  bindingTag,
  buildActionDescriptor,
  deriveFactorKey,
  factorPublicKey,
  newId,
  requestDigest,
  sealKey,
  sealMessage,
  signDeviceProof,
  wrapPrivateKey,
  type TagRecipient,
} from "../src/index";
import { clamp, importPrivateScalar, materialOf } from "../src/keys";
import { recoveryDisplay } from "../src/recovery";
import { smallHeader, smallRaw } from "./fixtures";
import { b64urlEncode, hex, sha256, utf8 } from "./reference";

const vectorsPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../contracts/device-v1.vectors.json");

const LABELS = {
  mailboxKey: "proprietor-mail/device-v1 test vectors: mailbox private key (never use for real mail)",
  successorKey: "proprietor-mail/device-v1 test vectors: successor mailbox private key (never use for real mail)",
  prfOutput: "proprietor-mail/device-v1 test vectors: passkey PRF output (never use for real mail)",
  recoverySecret: "proprietor-mail/device-v1 test vectors: recovery secret (never use for real mail)",
  signingKey: "proprietor-mail/device-v1 test vectors: device signing key (never use for real mail)",
  unlockKey: "proprietor-mail/device-v1 test vectors: device unlock key (never use for real mail)",
};

/** The P-256 group order n: a scalar d must be in [1, n - 1]. */
const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const challengeSuite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

/** A6's sealer, written from the contract for the vectors (Mail's is sealChallenge in src/proofs.ts). */
async function sealChallengeForVectors(publicKey: Uint8Array, aad: string): Promise<{ sealed: string; answer: string }> {
  const answer = crypto.getRandomValues(new Uint8Array(32));
  const recipientPublicKey = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), { name: "X25519" }, true, []);
  const { enc, ct } = await challengeSuite.seal({ recipientPublicKey, info: utf8("proprietor-mail/v1/challenge") }, answer, utf8(aad));
  return { sealed: b64urlEncode(new Uint8Array([...new Uint8Array(enc), ...new Uint8Array(ct)])), answer: hex(answer) };
}

/** ikm and skF of a factor, computed from the contract's text with raw Web Crypto (for other implementations). */
async function factorScalars(secret: Uint8Array<ArrayBuffer>, mailboxId: string, factorId: string, kind: string) { // pragma: allowlist secret (a parameter type)
  const base = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
  const info = utf8(`proprietor-mail/v1/factor-key|${mailboxId}|${factorId}|${kind}`);
  const ikm = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: utf8(factorId), info }, base, 256)); // pragma: allowlist secret (HKDF parameter names)
  const suiteId = new Uint8Array([0x4b, 0x45, 0x4d, 0x00, 0x20]);
  const labeledIkm = new Uint8Array([...utf8("HPKE-v1"), ...suiteId, ...utf8("dkp_prk"), ...ikm]);
  const labeledInfo = new Uint8Array([0, 32, ...utf8("HPKE-v1"), ...suiteId, ...utf8("sk")]);
  const dkp = await crypto.subtle.importKey("raw", labeledIkm, "HKDF", false, ["deriveBits"]);
  const skF = new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: labeledInfo }, dkp, 256)); // pragma: allowlist secret (HKDF parameter names)
  return { ikm: hex(ikm), skF: hex(skF) };
}

async function p256Key(label: string) {
  const d = await sha256(utf8(label));
  const n = BigInt("0x" + hex(d));
  expect(n > 0n && n < P256_N).toBe(true);
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(d));
  return { label, d: hex(d), publicKey: hex(new Uint8Array(ecdh.getPublicKey())) };
}

/** A P-256 private CryptoKey from the vector's d and public point (JWK, non-extractable). */
async function importP256(d: string, publicKey: string, name: "ECDSA" | "ECDH") {
  const point = Buffer.from(publicKey, "hex");
  const jwk = { kty: "EC", crv: "P-256", d: Buffer.from(d, "hex").toString("base64url"), x: point.subarray(1, 33).toString("base64url"), y: point.subarray(33).toString("base64url") };
  return crypto.subtle.importKey("jwk", jwk, { name, namedCurve: "P-256" }, false, name === "ECDSA" ? ["sign"] : ["deriveBits"]);
}

test("write contracts/device-v1.vectors.json", async () => {
  const mailboxId = newId("mbx");
  const skK1 = clamp(await sha256(utf8(LABELS.mailboxKey)));
  const skK2 = clamp(await sha256(utf8(LABELS.successorKey)));
  const k1 = await importPrivateScalar(skK1, { wrappable: true });
  const k2 = await importPrivateScalar(skK2, { wrappable: true });
  const m1 = materialOf(k1);
  const m2 = materialOf(k2);

  // Factors: a passkey (PRF output) and the recovery key, with the factor keys they derive (A2).
  const passkeyId = newId("wrp");
  const recoveryId = newId("wrp");
  const prfOutput = await sha256(utf8(LABELS.prfOutput));
  const recoverySecret = await sha256(utf8(LABELS.recoverySecret));
  const passkey = await deriveFactorKey({ mailboxId, factorId: passkeyId, kind: "passkey-prf", secret: prfOutput }); // pragma: allowlist secret (a test vector)
  const recovery = await deriveFactorKey({ mailboxId, factorId: recoveryId, kind: "recovery", secret: recoverySecret }); // pragma: allowlist secret (a test vector)
  const factors = [
    {
      name: "passkey",
      kind: "passkey-prf",
      factorId: passkeyId,
      secretLabel: LABELS.prfOutput, // pragma: allowlist secret (a public label)
      secret: hex(prfOutput), // pragma: allowlist secret (a test vector)
      ...(await factorScalars(prfOutput, mailboxId, passkeyId, "passkey-prf")),
      pkF: hex(factorPublicKey(passkey)),
    },
    {
      name: "recovery",
      kind: "recovery",
      factorId: recoveryId,
      secretLabel: LABELS.recoverySecret, // pragma: allowlist secret (a public label)
      secret: hex(recoverySecret), // pragma: allowlist secret (a test vector)
      recoveryDisplay: recoveryDisplay(recoverySecret),
      ...(await factorScalars(recoverySecret, mailboxId, recoveryId, "recovery")),
      pkF: hex(factorPublicKey(recovery)),
    },
  ];

  // A kept device (A3): fixed signing and unlock keys.
  const deviceId = newId("dev");
  const signing = await p256Key(LABELS.signingKey);
  const unlock = await p256Key(LABELS.unlockKey);
  const device = { deviceId, label: "Kitchen laptop", signing, unlock };

  // Key seals of K1 (A4): to the device, to the recovery factor, and to K2 as its successor.
  const seals = [
    {
      name: "to a device",
      toKind: "device",
      toId: deviceId,
      sealedKeyId: m1.keyId,
      recipient: "device.unlock",
      sealed: await sealKey(k1, { mailboxId }, { kind: "device", deviceId, publicKey: Buffer.from(unlock.publicKey, "hex") }),
    },
    {
      name: "to a factor",
      toKind: "factor",
      toId: recoveryId,
      sealedKeyId: m1.keyId,
      recipient: "factors.recovery",
      sealed: await sealKey(k1, { mailboxId }, { kind: "factor", factorId: recoveryId, publicKey: factorPublicKey(recovery) }),
    },
    {
      name: "successor seal",
      toKind: "successor",
      toId: m2.keyId,
      sealedKeyId: m1.keyId,
      recipient: "successorKey",
      sealed: await sealKey(k1, { mailboxId }, { kind: "successor", publicKey: m2.publicKey }),
    },
  ];

  // Binding tags under K1 (A5): one device, one factor.
  const bk = await bindingKey(k1, { mailboxId });
  const deviceRecipient: TagRecipient = {
    kind: "device",
    deviceId,
    label: device.label,
    signingKey: Buffer.from(signing.publicKey, "hex"), // pragma: allowlist secret (a public test key)
    unlockKey: Buffer.from(unlock.publicKey, "hex"),
  };
  const factorRecipient: TagRecipient = {
    kind: "factor",
    factorId: passkeyId,
    factorKind: "passkey-prf",
    label: "Phone",
    factorKey: factorPublicKey(passkey),
    credentialId: b64urlEncode((await sha256(utf8("proprietor-mail/device-v1 test vectors: credential id"))).subarray(0, 16)), // pragma: allowlist secret (a public test value)
  };
  const tags = [
    {
      name: "device",
      keyId: m1.keyId,
      recipient: { kind: "device", deviceId, label: device.label, signingKey: b64urlEncode(Buffer.from(signing.publicKey, "hex")), unlockKey: b64urlEncode(Buffer.from(unlock.publicKey, "hex")) }, // pragma: allowlist secret (public test keys)
      message: `proprietor-mail/v1/recipient|${mailboxId}|${m1.keyId}|device|${deviceId}|${b64urlEncode(utf8(device.label))}|${b64urlEncode(Buffer.from(signing.publicKey, "hex"))}|${b64urlEncode(Buffer.from(unlock.publicKey, "hex"))}`,
      tag: await bindingTag(bk, deviceRecipient),
    },
    {
      name: "factor",
      keyId: m1.keyId,
      recipient: { kind: "factor", factorId: passkeyId, factorKind: "passkey-prf", label: "Phone", factorKey: b64urlEncode(factorPublicKey(passkey)), credentialId: factorRecipient.credentialId }, // pragma: allowlist secret (a public test key)
      message: `proprietor-mail/v1/recipient|${mailboxId}|${m1.keyId}|factor|${passkeyId}|passkey-prf|${b64urlEncode(utf8("Phone"))}|${b64urlEncode(factorPublicKey(passkey))}|${factorRecipient.credentialId}`,
      tag: await bindingTag(bk, factorRecipient),
    },
  ];

  // Challenges (A6): a key proof sealed to K1 (purpose session); round 3 (D36): a factor proof
  // sealed to the passkey's factor key for the action open-session, and a key proof sealed to K1 for
  // the action upgrade, each with its descriptor (A10, issued as Mail issues it), the request whose
  // digest the descriptor holds, and the descriptor's digest, which their associated data ends with.
  const sessionId = newId("chl");
  const factorChallengeId = newId("chl");
  const keyChallengeId = newId("chl");
  const issuedAt = 1792627200; // 2026-10-22T00:00:00Z
  async function described(action: { kind: "open-session" | "upgrade"; request: Record<string, unknown> }) {
    const descriptor = buildActionDescriptor(
      actionDescriptorFor({ kind: action.kind, request: await requestDigest(action.request) }, { mailboxId, nonce: b64urlEncode(crypto.getRandomValues(new Uint8Array(32))), issuedAt }),
    );
    return { request: action.request, requestDigest: await requestDigest(action.request), descriptor: b64urlEncode(descriptor), actionDigest: await actionDigest(descriptor) };
  }
  const openSession = await described({ kind: "open-session", request: { challengeId: sessionId } });
  const upgrade = await described({
    kind: "upgrade",
    request: { factors: [{ id: passkeyId, factorKey: b64urlEncode(factorPublicKey(passkey)), tagKeyId: m1.keyId }] },
  });
  const challenges = [
    { name: "session", purpose: "session", challengeId: sessionId, targetId: m1.keyId, ...(await sealChallengeForVectors(m1.publicKey, `proprietor-mail/v1/challenge|${mailboxId}|${sessionId}|session|${m1.keyId}`)) },
    {
      name: "factor",
      purpose: "factor",
      challengeId: factorChallengeId,
      targetId: passkeyId,
      ...openSession,
      ...(await sealChallengeForVectors(factorPublicKey(passkey), `proprietor-mail/v1/challenge|${mailboxId}|${factorChallengeId}|factor|${passkeyId}|${openSession.actionDigest}`)),
    },
    {
      name: "key",
      purpose: "key",
      challengeId: keyChallengeId,
      targetId: m1.keyId,
      ...upgrade,
      ...(await sealChallengeForVectors(m1.publicKey, `proprietor-mail/v1/challenge|${mailboxId}|${keyChallengeId}|key|${m1.keyId}|${upgrade.actionDigest}`)),
    },
  ];
  // Another action's digest: the same kinds, another request.
  const otherOpenSession = await described({ kind: "open-session", request: { challengeId: newId("chl") } });
  const otherUpgrade = await described({ kind: "upgrade", request: { factors: [] } });

  // A device proof (A7) over the session challenge's id and a nonce.
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const signingKey = await importP256(signing.d, signing.publicKey, "ECDSA");
  const deviceProof = {
    deviceId,
    challengeId: sessionId,
    nonce: b64urlEncode(nonce),
    message: `proprietor-mail/v1/device-proof|${mailboxId}|${deviceId}|${sessionId}|${b64urlEncode(nonce)}`,
    publicKey: signing.publicKey,
    signature: await signDeviceProof(signingKey, { mailboxId, deviceId, challengeId: sessionId, nonce }),
  };

  // Negative cases, each derived from a positive vector above.
  const messageId = newId("msg");
  const message = await sealMessage({ keyId: m1.keyId, publicKey: m1.publicKey }, { mailboxId, messageId }, smallHeader, smallRaw);
  const wrap = await wrapPrivateKey(k1, { mailboxId, wrapId: recoveryId, kind: "recovery", secret: recoverySecret }); // pragma: allowlist secret (a test vector)
  const otherNonce = crypto.getRandomValues(new Uint8Array(32));
  const negative = [
    { name: "a device seal opened with another device id", open: "seal", sealed: seals[0]!.sealed, toKind: "device", toId: newId("dev"), sealedKeyId: m1.keyId, recipient: "device.unlock", expect: "DecryptionFailed" },
    { name: "a factor seal opened with another factor id", open: "seal", sealed: seals[1]!.sealed, toKind: "factor", toId: passkeyId, sealedKeyId: m1.keyId, recipient: "factors.recovery", expect: "DecryptionFailed" },
    { name: "a successor seal opened with toKind factor", open: "seal", sealed: seals[2]!.sealed, toKind: "factor", toId: m2.keyId, sealedKeyId: m1.keyId, recipient: "successorKey", expect: "DecryptionFailed" },
    { name: "a factor seal opened with toKind successor", open: "seal", sealed: seals[1]!.sealed, toKind: "successor", toId: recoveryId, sealedKeyId: m1.keyId, recipient: "factors.recovery", expect: "DecryptionFailed" },
    { name: "a challenge opened as a key seal", open: "seal", sealed: challenges[0]!.sealed, toKind: "successor", toId: m1.keyId, sealedKeyId: m2.keyId, recipient: "mailboxKey", expect: "DecryptionFailed" },
    { name: "a key seal opened as a challenge", open: "challenge", sealed: seals[2]!.sealed, purpose: "session", challengeId: sessionId, targetId: m2.keyId, recipient: "successorKey", expect: "DecryptionFailed" },
    { name: "a message key envelope (envelope v1) presented as a challenge", open: "challenge", sealed: message.keyEnvelope, purpose: "session", challengeId: messageId, targetId: m1.keyId, recipient: "mailboxKey", expect: "DecryptionFailed" },
    { name: "a wrap (envelope v1) presented as a challenge", open: "challenge", sealed: wrap.wrapped, purpose: "session", challengeId: sessionId, targetId: m1.keyId, recipient: "mailboxKey", expect: "DecryptionFailed" },
    { name: "a factor challenge presented as a session challenge", open: "challenge", sealed: challenges[1]!.sealed, purpose: "session", challengeId: factorChallengeId, targetId: m1.keyId, recipient: "mailboxKey", expect: "DecryptionFailed" },
    { name: "a factor challenge opened with another action's digest", open: "challenge", sealed: challenges[1]!.sealed, purpose: "factor", challengeId: factorChallengeId, targetId: passkeyId, actionDigest: otherOpenSession.actionDigest, recipient: "factors.passkey", expect: "DecryptionFailed" },
    { name: "a key challenge opened with another action's digest", open: "challenge", sealed: challenges[2]!.sealed, purpose: "key", challengeId: keyChallengeId, targetId: m1.keyId, actionDigest: otherUpgrade.actionDigest, recipient: "mailboxKey", expect: "DecryptionFailed" },
    { name: "a key challenge opened as a session challenge", open: "challenge", sealed: challenges[2]!.sealed, purpose: "session", challengeId: keyChallengeId, targetId: m1.keyId, recipient: "mailboxKey", expect: "DecryptionFailed" },
    { name: "a tag over a changed label", open: "tag", of: "device", label: "Kitchen laptop (2)", tag: tags[0]!.tag, expect: "invalid" },
    { name: "a device proof over another nonce", open: "deviceProof", nonce: b64urlEncode(otherNonce), signature: deviceProof.signature, expect: "invalid" },
  ];

  const vectors = {
    contract: "contracts/device-v1.md",
    about:
      "Test vectors for device-v1 Part A, written by packages/mail-crypto (npm run write-device-vectors -w @proprietor/mail-crypto) " +
      "and checked by its test/device-vectors.test.ts. Every key and secret is SHA-256 of the public label next to it: test values " +
      "only, never used for real mail. Mailbox keys are clamped X25519 scalars; P-256 scalars d are SHA-256 of their label read as " +
      "a big-endian integer. Byte strings are lowercase hex, except the stored forms (sealed, tag, signature, nonce, keyEnvelope, " +
      "wrapped, descriptor) and the recipients' keys in tags, which are base64url without padding (RFC 4648 §5). The challenges and " +
      "the device proof were made by a sealer and a signer written from the contract; Mail's are src/proofs.ts. Round 3: the factor " +
      "and key challenges carry their action descriptor (contracts/action-descriptor-v1.md, as Mail issues it), the request it " +
      "digests and its digest, and their associated data ends with that digest (A6).",
    mailboxId,
    mailboxKey: { label: LABELS.mailboxKey, sk: hex(skK1), pk: hex(m1.publicKey), keyId: m1.keyId },
    successorKey: { label: LABELS.successorKey, sk: hex(skK2), pk: hex(m2.publicKey), keyId: m2.keyId },
    factors,
    device,
    seals,
    tags,
    challenges,
    deviceProof,
    negative,
  };
  writeFileSync(vectorsPath, JSON.stringify(vectors, null, 2) + "\n");
  expect(seals.map((s) => Buffer.from(s.sealed, "base64url").length)).toEqual([142, 109, 109]);
});
