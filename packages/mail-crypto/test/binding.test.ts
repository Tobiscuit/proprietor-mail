// D1a, contracts/device-v1.md A5: the binding key and binding tags.
//   z     = X25519(sk, pk), the mailbox private key with its own public key
//   kbind = HKDF-SHA256(ikm = z, empty salt, info = ctx("binding", mailboxId, keyId), L = 32), an HMAC-SHA-256 key
//   tag   = HMAC-SHA-256(kbind, ctx("recipient", ...)), 32 bytes
import { createPrivateKey, createPublicKey, diffieHellman } from "node:crypto";
import { describe, expect, test } from "vitest";
import {
  bindingKey,
  bindingTag,
  generateSigningKey,
  generateUnlockKey,
  newId,
  verifyBindingTag,
  type TagRecipient,
} from "../src/index";
import { bindingMaterialOf } from "../src/binding";
import { importPrivateScalar } from "../src/keys";
import { b64urlDecode, b64urlEncode, flipBit, utf8 } from "./reference";

const mailboxId = newId("mbx");
const scalar = crypto.getRandomValues(new Uint8Array(32));
const priv = await importPrivateScalar(scalar);
const keyId = priv.keyId;
const signing = await generateSigningKey();
const unlock = await generateUnlockKey();
const factorKey = crypto.getRandomValues(new Uint8Array(32));

const device: TagRecipient = { kind: "device", deviceId: newId("dev"), label: "Kitchen laptop", signingKey: signing.publicKey, unlockKey: unlock.publicKey }; // pragma: allowlist secret (public test keys)
const factor: TagRecipient = { kind: "factor", factorId: newId("wrp"), factorKind: "passkey-prf", label: "Security key", factorKey, credentialId: "AQIDBAUGBwgJCgsMDQ4PEA" }; // pragma: allowlist secret (a test credential id: bytes 1 to 16)

/** z with OpenSSL, a second X25519 implementation. */
function opensslZ(): string {
  const der = Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(scalar)]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" }); // pragma: allowlist secret (a test variable)
  return diffieHellman({ privateKey, publicKey: createPublicKey(privateKey) }).toString("hex"); // pragma: allowlist secret (a test variable)
}

/** A5 read straight from the contract, with raw Web Crypto. */
async function referenceTag(mbx: string, kid: string, message: string): Promise<string> {
  const z = new Uint8Array(Buffer.from(opensslZ(), "hex"));
  const base = await crypto.subtle.importKey("raw", z, "HKDF", false, ["deriveBits"]);
  const kbind = await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(`proprietor-mail/v1/binding|${mbx}|${kid}`) }, base, 256); // pragma: allowlist secret (HKDF parameter names)
  const hmac = await crypto.subtle.importKey("raw", kbind, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64urlEncode(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, utf8(message))));
}

const b64 = (s: string) => b64urlEncode(utf8(s));

function deviceMessage(d: Extract<TagRecipient, { kind: "device" }>, kid = keyId, mbx = mailboxId): string {
  const unlockPart = d.unlockKey === null ? "-" : b64urlEncode(d.unlockKey);
  return `proprietor-mail/v1/recipient|${mbx}|${kid}|device|${d.deviceId}|${b64(d.label)}|${b64urlEncode(d.signingKey)}|${unlockPart}`;
}

function factorMessage(f: Extract<TagRecipient, { kind: "factor" }>, kid = keyId, mbx = mailboxId): string {
  return `proprietor-mail/v1/recipient|${mbx}|${kid}|factor|${f.factorId}|${f.factorKind}|${b64(f.label)}|${b64urlEncode(f.factorKey)}|${f.credentialId ?? "-"}`;
}

describe("A5 the binding key", () => {
  test("is HKDF of X25519(sk, own pk): a non-extractable HMAC-SHA-256 key for sign and verify, under the key it names", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    expect(bk).toEqual({ mailboxId, keyId });
    expect(Object.isFrozen(bk)).toBe(true);
    const hmac = bindingMaterialOf(bk);
    expect(hmac.extractable).toBe(false);
    expect(hmac.algorithm).toEqual({ name: "HMAC", hash: { name: "SHA-256" }, length: 256 });
    expect([...hmac.usages].sort()).toEqual(["sign", "verify"]);
  });

  test("a decrypt-only (non-extractable) mailbox key can make it: deriveBits with its own public key works", async () => {
    const decryptOnly = await importPrivateScalar(scalar, { wrappable: false });
    const tag = await bindingTag(await bindingKey(decryptOnly, { mailboxId }), device);
    expect(tag).toBe(await referenceTag(mailboxId, keyId, deviceMessage(device as Extract<TagRecipient, { kind: "device" }>)));
  });
});

describe("A5 tags", () => {
  test("a device's tag is HMAC over ctx(\"recipient\", ..., \"device\", ...), 32 bytes, as the contract computes it", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    const tag = await bindingTag(bk, device);
    expect(b64urlDecode(tag).length).toBe(32);
    expect(tag).toBe(await referenceTag(mailboxId, keyId, deviceMessage(device as Extract<TagRecipient, { kind: "device" }>)));
    expect(await verifyBindingTag(bk, device, tag)).toBe(true);
  });

  test("a device without an unlock key is tagged with \"-\" in its place", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    const locked = { ...device, unlockKey: null } as Extract<TagRecipient, { kind: "device" }>;
    const tag = await bindingTag(bk, locked);
    expect(tag).toBe(await referenceTag(mailboxId, keyId, deviceMessage(locked)));
    expect(tag).not.toBe(await bindingTag(bk, device));
  });

  test("a factor's tag covers its id, kind, label, factor key and credential id (\"-\" for none)", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    const f = factor as Extract<TagRecipient, { kind: "factor" }>;
    expect(await bindingTag(bk, f)).toBe(await referenceTag(mailboxId, keyId, factorMessage(f)));
    const recovery = { ...f, factorKind: "recovery" as const, label: "Recovery key", credentialId: null };
    expect(await bindingTag(bk, recovery)).toBe(await referenceTag(mailboxId, keyId, factorMessage(recovery)));
  });

  test("a tag changes when any field changes: label, either key, id, keyId, mailbox, kind, credential id", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    const d = device as Extract<TagRecipient, { kind: "device" }>;
    const f = factor as Extract<TagRecipient, { kind: "factor" }>;
    const deviceTag = await bindingTag(bk, d);
    const factorTag = await bindingTag(bk, f);
    const otherSigning = (await generateSigningKey()).publicKey;
    const otherUnlock = (await generateUnlockKey()).publicKey;
    const changedDevices: TagRecipient[] = [
      { ...d, label: "Kitchen laptop 2" },
      { ...d, label: "Kitchen Laptop" },
      { ...d, signingKey: otherSigning }, // pragma: allowlist secret (a public test key)
      { ...d, unlockKey: otherUnlock },
      { ...d, unlockKey: null },
      { ...d, deviceId: newId("dev") },
    ];
    for (const changed of changedDevices) {
      expect(await bindingTag(bk, changed)).not.toBe(deviceTag);
      expect(await verifyBindingTag(bk, changed, deviceTag)).toBe(false);
    }
    const changedFactors: TagRecipient[] = [
      { ...f, label: "Security key (old)" },
      { ...f, factorKey: flipBit(f.factorKey, 31) },
      { ...f, factorId: newId("wrp") },
      { ...f, factorKind: "recovery" },
      { ...f, credentialId: null },
      { ...f, credentialId: "AQIDBAUGBwgJCgsMDQ4PEQ" }, // pragma: allowlist secret (a test credential id)
    ];
    for (const changed of changedFactors) {
      expect(await bindingTag(bk, changed)).not.toBe(factorTag);
      expect(await verifyBindingTag(bk, changed, factorTag)).toBe(false);
    }
    // Under another key, or for another mailbox, the same recipient has another tag.
    const otherKey = await bindingKey(await importPrivateScalar(crypto.getRandomValues(new Uint8Array(32))), { mailboxId });
    const otherMailbox = await bindingKey(priv, { mailboxId: newId("mbx") });
    for (const bk2 of [otherKey, otherMailbox]) {
      expect(await bindingTag(bk2, d)).not.toBe(deviceTag);
      expect(await verifyBindingTag(bk2, d, deviceTag)).toBe(false);
    }
  });

  test("verification refuses a flipped bit, a truncated tag and text that is not base64url, and never throws on what Mail sent", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    const tag = await bindingTag(bk, device);
    const bytes = b64urlDecode(tag);
    for (let i = 0; i < bytes.length; i++) expect(await verifyBindingTag(bk, device, b64urlEncode(flipBit(bytes, i, i % 8)))).toBe(false);
    expect(await verifyBindingTag(bk, device, b64urlEncode(bytes.subarray(0, 31)))).toBe(false);
    expect(await verifyBindingTag(bk, device, "not base64url!")).toBe(false);
    expect(await verifyBindingTag(bk, device, "")).toBe(false);
    // Malformed recipient data from a view: a refusal, not an exception.
    expect(await verifyBindingTag(bk, { ...(device as Extract<TagRecipient, { kind: "device" }>), signingKey: new Uint8Array(64) }, tag)).toBe(false);
    expect(await verifyBindingTag(bk, { ...(device as Extract<TagRecipient, { kind: "device" }>), label: "" }, tag)).toBe(false);
  });

  test("making a tag refuses what would make the message ambiguous: an empty label, a lone surrogate, wrong key lengths, a credential id of \"-\"", async () => {
    const bk = await bindingKey(priv, { mailboxId });
    const d = device as Extract<TagRecipient, { kind: "device" }>;
    const f = factor as Extract<TagRecipient, { kind: "factor" }>;
    // TextEncoder turns every lone surrogate into U+FFFD, so two different labels would share a tag.
    for (const bad of [
      { ...d, label: "" },
      { ...d, label: "laptop \uD800" },
      { ...d, signingKey: new Uint8Array(64) },
      { ...d, unlockKey: new Uint8Array(33) },
      { ...f, factorKey: new Uint8Array(31) },
      { ...f, credentialId: "-" },
      { ...f, credentialId: "" },
      { ...f, factorId: `${f.factorId}|x` },
    ]) {
      await expect(bindingTag(bk, bad)).rejects.toBeInstanceOf(TypeError);
      expect(await verifyBindingTag(bk, bad, await bindingTag(bk, device))).toBe(false);
    }
  });

  test("a forged or cloned binding key is refused", async () => {
    await expect(bindingTag({ mailboxId, keyId }, device)).rejects.toBeInstanceOf(TypeError);
  });
});
