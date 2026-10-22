// Round 3, contracts/device-v1.md A11: signed statements. ECDSA P-256 with SHA-256, IEEE P1363
// (r || s, 64 bytes), base64url. A factor signs with sS (A2b), a device with its signing key (A3):
//   admit-device = ctx("admit-device", mailboxId, deviceId, b64u(UTF-8(label)), b64u(signingKey), admitterId)
//   unlock-key   = ctx("unlock-key", mailboxId, deviceId, b64u(unlockKey))
//   admit-factor = ctx("admit-factor", mailboxId, factorId, kind, b64u(UTF-8(label)), b64u(factorKey),
//                      b64u(signingKey), credentialId ?? "-", admitterId, b64u(admitter's signingKey))
//   transition   = ctx("transition", mailboxId, fromKeyId, toKeyId, b64u(toPublicKey), signerId)
// Each message is also written here from the contract's text, and each signature checked with OpenSSL.
import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  deriveFactorKey,
  factorPublicKey,
  factorSigningKey,
  generateMailboxKey,
  generateSigningKey,
  generateUnlockKey,
  newId,
  signDeviceProof,
  signStatement,
  statementMessage,
  verifyStatement,
  type Statement,
} from "../src/index";
import { b64urlDecode, b64urlEncode, flipBit, utf8 } from "./reference";

const mailboxId = newId("mbx");
const secret = () => crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test values)
const admitterId = newId("wrp");
const newcomerId = newId("wrp");
const admitter = await deriveFactorKey({ mailboxId, factorId: admitterId, kind: "passkey-prf", secret: secret() }); // pragma: allowlist secret (public test keys, random test values)
const newcomer = await deriveFactorKey({ mailboxId, factorId: newcomerId, kind: "recovery", secret: secret() }); // pragma: allowlist secret (public test keys, random test values)
const outsider = await deriveFactorKey({ mailboxId, factorId: newId("wrp"), kind: "recovery", secret: secret() }); // pragma: allowlist secret (public test keys, random test values)
const device = await generateSigningKey();
const unlock = await generateUnlockKey();
const deviceId = newId("dev");
const from = await generateMailboxKey();
const to = await generateMailboxKey();

const admitDevice: Statement = { kind: "admit-device", mailboxId, deviceId, label: "Kitchen laptop", signingKey: device.publicKey, admitterId }; // pragma: allowlist secret (public test keys, random test values)
const unlockKey: Statement = { kind: "unlock-key", mailboxId, deviceId, unlockKey: unlock.publicKey };
const admitFactor: Statement = {
  kind: "admit-factor",
  mailboxId,
  factorId: newcomerId,
  factorKind: "recovery",
  label: "Recovery key",
  factorKey: factorPublicKey(newcomer),
  signingKey: factorSigningKey(newcomer), // pragma: allowlist secret (a public key)
  credentialId: null,
  admitterId,
  admitterSigningKey: factorSigningKey(admitter), // pragma: allowlist secret (public test keys, random test values)
};
const transition: Statement = { kind: "transition", mailboxId, fromKeyId: from.publicKey.keyId, toKeyId: to.publicKey.keyId, toPublicKey: to.publicKey.publicKey, signerId: admitterId };

/** The contract's message, written out from its text. */
function contractMessage(s: Statement): string {
  const b = (bytes: Uint8Array) => b64urlEncode(bytes);
  switch (s.kind) {
    case "admit-device":
      return `proprietor-mail/v1/admit-device|${s.mailboxId}|${s.deviceId}|${b(utf8(s.label))}|${b(s.signingKey)}|${s.admitterId}`;
    case "unlock-key":
      return `proprietor-mail/v1/unlock-key|${s.mailboxId}|${s.deviceId}|${b(s.unlockKey)}`;
    case "admit-factor":
      return `proprietor-mail/v1/admit-factor|${s.mailboxId}|${s.factorId}|${s.factorKind}|${b(utf8(s.label))}|${b(s.factorKey)}|${b(s.signingKey)}|${s.credentialId ?? "-"}|${s.admitterId}|${b(s.admitterSigningKey)}`;
    case "transition":
      return `proprietor-mail/v1/transition|${s.mailboxId}|${s.fromKeyId}|${s.toKeyId}|${b(s.toPublicKey)}|${s.signerId}`;
  }
}

function opensslVerify(point: Uint8Array, message: string, signature: string): boolean {
  const jwk = { kty: "EC", crv: "P-256", x: b64urlEncode(point.subarray(1, 33)), y: b64urlEncode(point.subarray(33)) };
  return nodeVerify("sha256", utf8(message), { key: createPublicKey({ key: jwk, format: "jwk" }), dsaEncoding: "ieee-p1363" }, b64urlDecode(signature));
}

/** Each statement with the signer(s) A11 names and the public key that verifies each signature. */
const cases = [
  { name: "admit-device", statement: admitDevice, signers: [{ by: admitter as Parameters<typeof signStatement>[0], key: factorSigningKey(admitter) }] },
  { name: "unlock-key", statement: unlockKey, signers: [{ by: device.privateKey as Parameters<typeof signStatement>[0], key: device.publicKey }] },
  {
    name: "admit-factor",
    statement: admitFactor,
    signers: [
      { by: admitter as Parameters<typeof signStatement>[0], key: factorSigningKey(admitter) },
      { by: newcomer as Parameters<typeof signStatement>[0], key: factorSigningKey(newcomer) },
    ],
  },
  { name: "transition", statement: transition, signers: [{ by: admitter as Parameters<typeof signStatement>[0], key: factorSigningKey(admitter) }] },
] as const;

/** One changed value for each field of each statement (bytes of the right length, ids of the right shape). */
async function changes(s: Statement): Promise<[string, Statement][]> {
  const otherPoint = (await generateSigningKey()).publicKey;
  const other32 = crypto.getRandomValues(new Uint8Array(32));
  switch (s.kind) {
    case "admit-device":
      return [
        ["mailboxId", { ...s, mailboxId: newId("mbx") }],
        ["deviceId", { ...s, deviceId: newId("dev") }],
        ["label", { ...s, label: "Kitchen laptop " }],
        ["signingKey", { ...s, signingKey: otherPoint }], // pragma: allowlist secret (public test keys, random test values)
        ["admitterId", { ...s, admitterId: newId("wrp") }],
      ];
    case "unlock-key":
      return [
        ["mailboxId", { ...s, mailboxId: newId("mbx") }],
        ["deviceId", { ...s, deviceId: newId("dev") }],
        ["unlockKey", { ...s, unlockKey: (await generateUnlockKey()).publicKey }],
      ];
    case "admit-factor":
      return [
        ["mailboxId", { ...s, mailboxId: newId("mbx") }],
        ["factorId", { ...s, factorId: newId("wrp") }],
        ["factorKind", { ...s, factorKind: "passkey-prf" }],
        ["label", { ...s, label: "Recovery key 2" }],
        ["factorKey", { ...s, factorKey: other32 }],
        ["signingKey", { ...s, signingKey: otherPoint }], // pragma: allowlist secret (public test keys, random test values)
        ["credentialId", { ...s, credentialId: b64urlEncode(crypto.getRandomValues(new Uint8Array(16))) }], // pragma: allowlist secret (public test keys, random test values)
        ["admitterId", { ...s, admitterId: newId("wrp") }],
        ["admitterSigningKey", { ...s, admitterSigningKey: otherPoint }], // pragma: allowlist secret (public test keys, random test values)
      ];
    case "transition":
      return [
        ["mailboxId", { ...s, mailboxId: newId("mbx") }],
        ["fromKeyId", { ...s, fromKeyId: (await generateMailboxKey()).publicKey.keyId }],
        ["toKeyId", { ...s, toKeyId: (await generateMailboxKey()).publicKey.keyId }],
        ["toPublicKey", { ...s, toPublicKey: other32 }],
        ["signerId", { ...s, signerId: newId("wrp") }],
      ];
  }
}

describe("A11 statements: the exact messages, signed and verified", () => {
  test.each(cases.map((c) => [c.name, c] as const))("%s: the message is the contract's; each signature verifies with the package and with OpenSSL", async (_, c) => {
    const message = contractMessage(c.statement);
    expect(new TextDecoder().decode(statementMessage(c.statement))).toBe(message);
    for (const signer of c.signers) {
      const signature = await signStatement(signer.by, c.statement);
      expect(signature).toMatch(/^[A-Za-z0-9_-]{86}$/);
      expect(await verifyStatement(signer.key, c.statement, signature)).toBe(true);
      expect(opensslVerify(signer.key, message, signature)).toBe(true);
    }
  });

  test("a factor's credential id is in the admission when it has one", async () => {
    const credentialId = b64urlEncode(crypto.getRandomValues(new Uint8Array(16))); // pragma: allowlist secret (public test keys, random test values)
    const s: Statement = { ...admitFactor, factorKind: "passkey-prf", credentialId } as Statement;
    expect(new TextDecoder().decode(statementMessage(s))).toBe(contractMessage(s));
    expect(new TextDecoder().decode(statementMessage(s))).toContain(`|${credentialId}|`);
  });

  test.each(cases.map((c) => [c.name, c] as const))("%s fails after any one field changes", async (_, c) => {
    for (const signer of c.signers) {
      const signature = await signStatement(signer.by, c.statement);
      for (const [field, changed] of await changes(c.statement)) {
        expect(await verifyStatement(signer.key, changed, signature), `${c.name}: ${field}`).toBe(false);
      }
    }
  });

  test("a signature verifies only with its signer's key, and not over a flipped bit", async () => {
    const signature = await signStatement(admitter, admitDevice);
    expect(await verifyStatement(factorSigningKey(outsider), admitDevice, signature)).toBe(false);
    expect(await verifyStatement(factorSigningKey(newcomer), admitDevice, signature)).toBe(false);
    const bytes = b64urlDecode(signature);
    for (let i = 0; i < 64; i += 7) expect(await verifyStatement(factorSigningKey(admitter), admitDevice, b64urlEncode(flipBit(bytes, i, i % 8)))).toBe(false);
  });

  test("domain separation: the labels keep statements apart from each other and from device proofs (A7)", async () => {
    // A device's unlock-key signature is not a device proof, and a device proof is not an unlock-key statement.
    const challengeId = newId("chl");
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const proof = await signDeviceProof(device.privateKey, { mailboxId, deviceId, challengeId, nonce });
    expect(await verifyStatement(device.publicKey, unlockKey, proof)).toBe(false);
    const unlockSignature = await signStatement(device.privateKey, unlockKey);
    const proofMessage = utf8(`proprietor-mail/v1/device-proof|${mailboxId}|${deviceId}|${challengeId}|${b64urlEncode(nonce)}`);
    const key = await crypto.subtle.importKey("raw", device.publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    expect(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64urlDecode(unlockSignature), proofMessage)).toBe(false);
    // Every message starts with its own label.
    const labels = cases.map((c) => new TextDecoder().decode(statementMessage(c.statement)).split("|")[0]);
    expect(labels).toEqual(["proprietor-mail/v1/admit-device", "proprietor-mail/v1/unlock-key", "proprietor-mail/v1/admit-factor", "proprietor-mail/v1/transition"]);
  });
});

describe("A11 who signs what", () => {
  test("an admission of a factor carries two signatures over one message: the admitter's and the factor's own", async () => {
    const signature = await signStatement(admitter, admitFactor);
    const selfSignature = await signStatement(newcomer, admitFactor);
    expect(await verifyStatement(factorSigningKey(admitter), admitFactor, signature)).toBe(true);
    expect(await verifyStatement(factorSigningKey(newcomer), admitFactor, selfSignature)).toBe(true);
    expect(await verifyStatement(factorSigningKey(newcomer), admitFactor, signature)).toBe(false);
    expect(await verifyStatement(factorSigningKey(admitter), admitFactor, selfSignature)).toBe(false);
  });

  test("a single factor admits itself: admitter and factor are one, and it signs both", async () => {
    const self: Statement = { ...admitFactor, admitterId: newcomerId, admitterSigningKey: factorSigningKey(newcomer) } as Statement; // pragma: allowlist secret (public test keys, random test values)
    const a = await signStatement(newcomer, self);
    const b = await signStatement(newcomer, self);
    expect(await verifyStatement(factorSigningKey(newcomer), self, a)).toBe(true);
    expect(await verifyStatement(factorSigningKey(newcomer), self, b)).toBe(true);
  });

  test.each([
    ["an unlock key signed by a factor", () => signStatement(admitter, unlockKey)],
    ["an admission of a device signed by a device", () => signStatement(device.privateKey, admitDevice)],
    ["a transition signed by a device", () => signStatement(device.privateKey, transition)],
    ["an admission of a device by a factor it does not name", () => signStatement(newcomer, admitDevice)],
    ["an admission of a factor by a third factor", () => signStatement(outsider, admitFactor)],
    ["an admission whose admitter key is not the admitter's", () => signStatement(admitter, { ...admitFactor, admitterSigningKey: factorSigningKey(outsider) } as Statement)], // pragma: allowlist secret (public test keys, random test values)
    ["an admission whose own keys are not the factor's", () => signStatement(newcomer, { ...admitFactor, factorKey: factorPublicKey(outsider) } as Statement)],
    ["a self-signature over another signing key", () => signStatement(newcomer, { ...admitFactor, signingKey: factorSigningKey(outsider) } as Statement)], // pragma: allowlist secret (public test keys, random test values)
    ["a transition by a factor it does not name", () => signStatement(newcomer, transition)],
    ["a transition whose toKeyId is not its public key's", () => signStatement(admitter, { ...transition, toKeyId: from.publicKey.keyId } as Statement)],
    ["a forged factor handle", () => signStatement({ factorId: admitterId, kind: "passkey-prf" }, admitDevice)],
    ["an extractable or non-signing CryptoKey", async () => signStatement((await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]) as CryptoKeyPair).privateKey, unlockKey)],
  ])("refuses %s with a TypeError", async (_, sign) => {
    await expect(sign()).rejects.toBeInstanceOf(TypeError);
  });
});

describe("A11 inputs", () => {
  test.each([
    ["an unknown kind", { ...admitDevice, kind: "admit-everything" }],
    ["an empty label", { ...admitDevice, label: "" }],
    ["a label with a lone surrogate", { ...admitDevice, label: "Lap\ud800top" }],
    ["an id with the separator", { ...admitDevice, deviceId: "dev_a|b" }],
    ["a signing key that is not a 65-byte point", { ...admitDevice, signingKey: new Uint8Array(65) }],
    ["an unlock key of 64 bytes", { ...unlockKey, unlockKey: unlock.publicKey.subarray(1) }],
    ["a factor key of 33 bytes", { ...admitFactor, factorKey: new Uint8Array(33) }],
    ["an unknown factor kind", { ...admitFactor, factorKind: "password" }],
    ["a credential id that is \"-\"", { ...admitFactor, credentialId: "-" }],
    ["a keyId that is not 32 hex digits", { ...transition, fromKeyId: "k1" }],
    ["a public key of 31 bytes", { ...transition, toPublicKey: new Uint8Array(31) }],
  ])("statementMessage refuses %s (TypeError), and verifyStatement answers false, never throws", async (_, s) => {
    expect(() => statementMessage(s as Statement)).toThrow(TypeError);
    const signature = await signStatement(admitter, admitDevice);
    expect(await verifyStatement(factorSigningKey(admitter), s as Statement, signature)).toBe(false);
  });

  test("verifyStatement answers false for a malformed signature or public key", async () => {
    const signature = await signStatement(admitter, admitDevice);
    const key = factorSigningKey(admitter);
    for (const bad of ["", "*", signature.slice(0, 85), `${signature}A`, b64urlEncode(new Uint8Array(70)), 42 as unknown as string]) {
      expect(await verifyStatement(key, admitDevice, bad)).toBe(false);
    }
    const offCurve = new Uint8Array(key);
    offCurve[64] = offCurve[64]! ^ 1;
    for (const badKey of [key.subarray(1), new Uint8Array(65), offCurve, "not bytes" as unknown as Uint8Array]) {
      expect(await verifyStatement(badKey, admitDevice, signature)).toBe(false);
    }
  });
});
