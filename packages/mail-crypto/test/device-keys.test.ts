// D1a, contracts/device-v1.md A3 (device keys) and A7 (device proofs). A kept device holds an
// ECDSA P-256 signing key and an ECDH P-256 unlock key, private halves non-extractable, public
// halves as raw uncompressed points (65 bytes). The signing key signs only
// ctx("device-proof", mailboxId, deviceId, challengeId, b64u(nonce)), as IEEE P1363 (r || s).
import { describe, expect, test } from "vitest";
import { generateSigningKey, generateUnlockKey, isDeviceSigningKey, isDeviceUnlockKey, newId, signDeviceProof } from "../src/index";
import { b64urlDecode, b64urlEncode, utf8 } from "./reference";

const mailboxId = newId("mbx");
const deviceId = newId("dev");
const challengeId = newId("chl");
const nonce = crypto.getRandomValues(new Uint8Array(32));

/** A7 read straight from the contract: a test-local verifier (the Worker's is src/proofs.ts, slice D2's). */
async function referenceVerify(publicKey: Uint8Array<ArrayBuffer>, ids: { mailboxId: string; deviceId: string; challengeId: string; nonce: Uint8Array }, signature: string): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const message = utf8(`proprietor-mail/v1/device-proof|${ids.mailboxId}|${ids.deviceId}|${ids.challengeId}|${b64urlEncode(ids.nonce)}`);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, b64urlDecode(signature), message);
}

describe("A3 device keys", () => {
  test("the signing key: ECDSA P-256, private half non-extractable for sign only, public half a 65-byte uncompressed point", async () => {
    const pair = await generateSigningKey();
    expect(pair.privateKey.type).toBe("private");
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm).toEqual({ name: "ECDSA", namedCurve: "P-256" });
    expect(pair.privateKey.usages).toEqual(["sign"]);
    await expect(crypto.subtle.exportKey("pkcs8", pair.privateKey)).rejects.toThrow();
    expect(pair.publicKey.length).toBe(65);
    expect(pair.publicKey[0]).toBe(0x04);
    expect(isDeviceSigningKey(pair.privateKey)).toBe(true);
    expect(isDeviceUnlockKey(pair.privateKey)).toBe(false);
  });

  test("the unlock key: ECDH P-256, private half non-extractable for deriveBits only, public half a 65-byte uncompressed point", async () => {
    const pair = await generateUnlockKey();
    expect(pair.privateKey.type).toBe("private");
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.privateKey.algorithm).toEqual({ name: "ECDH", namedCurve: "P-256" });
    expect(pair.privateKey.usages).toEqual(["deriveBits"]);
    await expect(crypto.subtle.exportKey("jwk", pair.privateKey)).rejects.toThrow();
    expect(pair.publicKey.length).toBe(65);
    expect(pair.publicKey[0]).toBe(0x04);
    expect(isDeviceUnlockKey(pair.privateKey)).toBe(true);
    expect(isDeviceSigningKey(pair.privateKey)).toBe(false);
  });

  test("every pair is new", async () => {
    const [a, b] = [await generateSigningKey(), await generateSigningKey()];
    expect(b64urlEncode(a.publicKey)).not.toBe(b64urlEncode(b.publicKey));
  });

  test("the key checks refuse extractable keys, other curves, public keys and things that are not keys", async () => {
    const extractable = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const p384 = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-384" }, false, ["deriveBits"]);
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const x25519 = (await crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveBits"])) as CryptoKeyPair;
    expect(isDeviceSigningKey(extractable.privateKey)).toBe(false);
    expect(isDeviceUnlockKey(p384.privateKey)).toBe(false);
    expect(isDeviceSigningKey(pair.publicKey)).toBe(false);
    expect(isDeviceUnlockKey(x25519.privateKey)).toBe(false);
    expect(isDeviceSigningKey({ type: "private" })).toBe(false);
    expect(isDeviceUnlockKey(null)).toBe(false);
  });
});

describe("A7 device proofs", () => {
  test("a 64-byte IEEE P1363 signature over the contract's message, which a verifier written from the contract accepts", async () => {
    const pair = await generateSigningKey();
    const signature = await signDeviceProof(pair.privateKey, { mailboxId, deviceId, challengeId, nonce });
    expect(b64urlDecode(signature).length).toBe(64);
    expect(await referenceVerify(pair.publicKey, { mailboxId, deviceId, challengeId, nonce }, signature)).toBe(true);
  });

  test("the signature is bound to the mailbox, the device, the challenge and the nonce", async () => {
    const pair = await generateSigningKey();
    const signature = await signDeviceProof(pair.privateKey, { mailboxId, deviceId, challengeId, nonce });
    const otherNonce = crypto.getRandomValues(new Uint8Array(32));
    for (const ids of [
      { mailboxId: newId("mbx"), deviceId, challengeId, nonce },
      { mailboxId, deviceId: newId("dev"), challengeId, nonce },
      { mailboxId, deviceId, challengeId: newId("chl"), nonce },
      { mailboxId, deviceId, challengeId, nonce: otherNonce },
    ]) {
      expect(await referenceVerify(pair.publicKey, ids, signature)).toBe(false);
    }
    const other = await generateSigningKey();
    expect(await referenceVerify(other.publicKey, { mailboxId, deviceId, challengeId, nonce }, signature)).toBe(false);
  });

  test("refuses a key that is not a device signing key, a nonce that is not 32 bytes, and ids holding the separator", async () => {
    const unlock = await generateUnlockKey();
    const signing = await generateSigningKey();
    await expect(signDeviceProof(unlock.privateKey, { mailboxId, deviceId, challengeId, nonce })).rejects.toBeInstanceOf(TypeError);
    await expect(signDeviceProof(signing.privateKey, { mailboxId, deviceId, challengeId, nonce: new Uint8Array(31) })).rejects.toBeInstanceOf(TypeError);
    await expect(signDeviceProof(signing.privateKey, { mailboxId, deviceId: `${deviceId}|x`, challengeId, nonce })).rejects.toBeInstanceOf(TypeError);
  });
});
