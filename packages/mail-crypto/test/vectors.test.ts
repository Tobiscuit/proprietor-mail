// S1f: contracts/envelope-v1.vectors.json - opens every positive vector with the package, refuses
// every negative one, and decodes each vector a second time straight from the contract's text
// (raw Web Crypto and @hpke/core, none of src/), so the vectors cannot merely agree with the code.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Aes256Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  fingerprint,
  openBody,
  openDraft,
  openHeader,
  parseRecoveryKey,
  prfInput,
  publicKeyMatches,
  RecoveryKeyTypo,
  unwrapPrivateKey,
  type Draft,
  type KeyWrap,
  type MessageHeader,
} from "../src/index";
import { importPrivateScalar } from "../src/keys";
import { b64urlDecode, b64urlEncode, fromHex, hex, sha256, utf8 } from "./reference";

const vectorsPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../contracts/envelope-v1.vectors.json");

interface MessageVector {
  name: string;
  messageId: string;
  dek: string;
  sealed: { keyId: string; keyEnvelope: string; header: string; bodyB64url: string };
  header: MessageHeader;
  raw: string;
}
interface DraftVector {
  name: string;
  draftId: string;
  dek: string;
  sealed: { keyId: string; keyEnvelope: string; sealed: string };
  draft: Draft;
}
interface WrapVector {
  name: string;
  secretLabel: string;
  prfInput?: string;
  prfOutput?: string;
  recoveryKey?: string;
  recoveryDisplay?: string;
  wrap: KeyWrap;
}
interface NegativeVector {
  name: string;
  open: "header" | "body" | "draft" | "recoveryDisplay";
  mailboxId?: string;
  objectId?: string;
  sealed?: { keyEnvelope: string; header?: string; bodyB64url?: string; sealed?: string };
  recoveryDisplay?: string;
  expect: "DecryptionFailed" | "RecoveryKeyTypo";
}
interface Vectors {
  contract: string;
  suite: { mode: string; kem: string; kdf: string; aead: string };
  mailboxKey: { label: string; skRm: string; pkRm: string; keyId: string; fingerprint: string };
  mailboxId: string;
  messages: MessageVector[];
  drafts: DraftVector[];
  wraps: WrapVector[];
  negative: NegativeVector[];
}

const vectors: Vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
const { mailboxId, mailboxKey } = vectors;
const pub = { keyId: mailboxKey.keyId, publicKey: fromHex(mailboxKey.pkRm) };
const priv = await importPrivateScalar(fromHex(mailboxKey.skRm));

// ---- The contract, read independently -----------------------------------------------------

const suite = new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

async function contractMessageKey(objectId: string, keyEnvelopeB64url: string): Promise<Uint8Array> {
  const envelope = b64urlDecode(keyEnvelopeB64url);
  expect(envelope.length).toBe(80);
  const recipientKey = await suite.kem.deserializePrivateKey(fromHex(mailboxKey.skRm));
  const dek = await suite.open(
    { recipientKey, enc: envelope.slice(0, 32), info: utf8("platform-mail/v1/message-key") },
    envelope.slice(32),
    utf8("platform-mail/v1/message-key|" + mailboxId + "|" + objectId),
  );
  return new Uint8Array(dek);
}

async function contractBlock(lead: Uint8Array, dek: Uint8Array, aad: string, block: Uint8Array): Promise<Uint8Array> {
  expect(hex(block.subarray(0, lead.length))).toBe(hex(lead));
  const key = await crypto.subtle.importKey("raw", new Uint8Array(dek), "AES-GCM", false, ["decrypt"]);
  const iv = block.subarray(lead.length, lead.length + 12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: 128 }, key, block.subarray(lead.length + 12));
  return new Uint8Array(pt);
}

async function contractUnwrap(v: WrapVector, ikm: Uint8Array<ArrayBuffer>): Promise<Uint8Array> {
  const { id, kind, keyId, wrapped } = v.wrap;
  const base = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  const kek = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8(id), info: utf8("platform-mail/v1/kek/" + kind) }, // pragma: allowlist secret (HKDF parameter names)
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const block = b64urlDecode(wrapped);
  expect(block.length).toBe(61);
  expect(block[0]).toBe(0x01);
  const aad = "platform-mail/v1/wrap|" + mailboxId + "|" + id + "|" + kind + "|" + keyId;
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: block.subarray(1, 13), additionalData: utf8(aad) }, kek, block.subarray(13)));
}

// ---- Tests ----------------------------------------------------------------------------------

describe("S1f vectors: the file has what the contract's Test vectors section lists", () => {
  test("a fixed mailbox key pair, two messages (one non-ASCII with an attachment), a draft, both wrap kinds, the four negative cases", () => {
    expect(vectors.contract).toBe("contracts/envelope-v1.md");
    expect(vectors.suite).toMatchObject({ mode: "base" });
    expect(vectors.messages.map((m) => m.name)).toEqual(["small message", "non-ASCII subject and an attachment"]);
    expect(vectors.messages[1]!.header.subject).not.toMatch(/^[\x00-\x7f]*$/);
    expect(vectors.messages[1]!.header.attachments.length).toBeGreaterThan(0);
    expect(vectors.drafts.length).toBe(1);
    expect(vectors.wraps.map((w) => w.wrap.kind)).toEqual(["passkey-prf", "recovery"]);
    const negatives = vectors.negative.map((n) => n.name);
    for (const required of [
      "header moved to another message id",
      "body moved to another mailbox",
      "truncated tag",
      "recovery key with a one-character typo",
    ]) {
      expect(negatives.some((n) => n.startsWith(required)), required).toBe(true);
    }
  });
});

describe("S1f vectors: the mailbox key pair", () => {
  test("skRm is SHA-256 of its public label, clamped; pkRm = X25519(skRm, 9); keyId and fingerprint follow", async () => {
    const expected = await sha256(utf8(mailboxKey.label));
    expected[0] = expected[0]! & 248;
    expected[31] = (expected[31]! & 127) | 64;
    expect(mailboxKey.skRm).toBe(hex(expected));
    // pkRm through JWK export, a different path from the package's deriveBits(k, 9).
    const pkcs8 = fromHex("302e020100300506032b656e04220420" + mailboxKey.skRm);
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "X25519" }, true, ["deriveBits"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    expect(hex(b64urlDecode(jwk.x!))).toBe(mailboxKey.pkRm);
    expect(mailboxKey.keyId).toBe(hex((await sha256(fromHex(mailboxKey.pkRm))).subarray(0, 16)));
    expect(mailboxKey.fingerprint).toBe(fingerprint(mailboxKey.keyId));
    expect(priv.keyId).toBe(mailboxKey.keyId);
  });
});

describe("S1f vectors: every positive vector opens", () => {
  test.each(vectors.messages.map((m) => [m.name, m] as const))("message: %s", async (_, m) => {
    const ids = { mailboxId, messageId: m.messageId };
    const body = b64urlDecode(m.sealed.bodyB64url);
    expect(m.sealed.keyId).toBe(mailboxKey.keyId);
    // With the package:
    expect(await openHeader(priv, ids, m.sealed)).toStrictEqual(m.header);
    expect(hex(await openBody(priv, ids, { keyEnvelope: m.sealed.keyEnvelope, body }))).toBe(hex(utf8(m.raw)));
    // From the contract's text:
    const dek = await contractMessageKey(m.messageId, m.sealed.keyEnvelope);
    expect(hex(dek)).toBe(m.dek);
    const headerJson = await contractBlock(Uint8Array.of(0x01), dek, "platform-mail/v1/header|" + mailboxId + "|" + m.messageId, b64urlDecode(m.sealed.header));
    expect(JSON.parse(new TextDecoder().decode(headerJson))).toStrictEqual(m.header);
    const raw = await contractBlock(utf8("PMB1"), dek, "platform-mail/v1/body|" + mailboxId + "|" + m.messageId, body);
    expect(hex(raw)).toBe(hex(utf8(m.raw)));
  });

  test.each(vectors.drafts.map((d) => [d.name, d] as const))("draft: %s", async (_, d) => {
    expect(await openDraft(priv, { mailboxId, draftId: d.draftId }, d.sealed)).toStrictEqual(d.draft);
    const dek = await contractMessageKey(d.draftId, d.sealed.keyEnvelope);
    expect(hex(dek)).toBe(d.dek);
    const json = await contractBlock(Uint8Array.of(0x01), dek, "platform-mail/v1/draft|" + mailboxId + "|" + d.draftId, b64urlDecode(d.sealed.sealed));
    expect(JSON.parse(new TextDecoder().decode(json))).toStrictEqual(d.draft);
  });

  test("passkey wrap (fixed PRF output): prf input, unwrap, public key check", async () => {
    const v = vectors.wraps.find((w) => w.wrap.kind === "passkey-prf")!;
    expect(v.prfOutput).toBe(hex(await sha256(utf8(v.secretLabel))));
    expect(v.prfInput).toBe(hex(await sha256(utf8("platform-mail/v1/prf|" + mailboxId + "|" + v.wrap.id))));
    expect(hex(await prfInput(mailboxId, v.wrap.id))).toBe(v.prfInput);
    const unwrapped = await unwrapPrivateKey(v.wrap, { mailboxId, secret: fromHex(v.prfOutput!) }); // pragma: allowlist secret (a test vector field)
    expect(unwrapped.keyId).toBe(mailboxKey.keyId);
    expect(await publicKeyMatches(unwrapped, pub)).toBe(true);
    expect(hex(await contractUnwrap(v, fromHex(v.prfOutput!)))).toBe(mailboxKey.skRm);
  });

  test("recovery wrap (with its display string): parse, unwrap, public key check", async () => {
    const v = vectors.wraps.find((w) => w.wrap.kind === "recovery")!;
    expect(v.recoveryKey).toBe(hex(await sha256(utf8(v.secretLabel))));
    expect(v.recoveryDisplay).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){10}$/);
    const parsed = parseRecoveryKey(v.recoveryDisplay!);
    expect(hex(parsed)).toBe(v.recoveryKey);
    const unwrapped = await unwrapPrivateKey(v.wrap, { mailboxId, secret: parsed }); // pragma: allowlist secret (a test variable)
    expect(unwrapped.keyId).toBe(mailboxKey.keyId);
    expect(await publicKeyMatches(unwrapped, pub)).toBe(true);
    expect(hex(await contractUnwrap(v, fromHex(v.recoveryKey!)))).toBe(mailboxKey.skRm);
  });
});

describe("S1f vectors: every negative vector is refused", () => {
  test.each(vectors.negative.map((n) => [n.name, n] as const))("%s", async (_, n) => {
    if (n.open === "recoveryDisplay") {
      expect(() => parseRecoveryKey(n.recoveryDisplay!)).toThrow(RecoveryKeyTypo);
      return;
    }
    const ids = { mailboxId: n.mailboxId!, messageId: n.objectId! };
    const s = n.sealed!;
    const attempt =
      n.open === "header"
        ? openHeader(priv, ids, { keyEnvelope: s.keyEnvelope, header: s.header! })
        : n.open === "body"
          ? openBody(priv, ids, { keyEnvelope: s.keyEnvelope, body: b64urlDecode(s.bodyB64url!) })
          : openDraft(priv, { mailboxId: n.mailboxId!, draftId: n.objectId! }, { keyId: mailboxKey.keyId, keyEnvelope: s.keyEnvelope, sealed: s.sealed! });
    expect(n.expect).toBe("DecryptionFailed");
    await expect(attempt).rejects.toBeInstanceOf(DecryptionFailed);
  });

  test("each negative differs from a positive vector in exactly the way its name says", () => {
    const [small] = vectors.messages;
    const byName = (prefix: string) => vectors.negative.filter((n) => n.name.startsWith(prefix));
    for (const n of byName("header moved to another message id")) {
      expect(n.mailboxId).toBe(mailboxId);
      expect(n.objectId).not.toBe(small!.messageId);
      expect(n.sealed!.header).toBe(small!.sealed.header);
    }
    for (const n of byName("body moved to another mailbox")) {
      expect(n.mailboxId).not.toBe(mailboxId);
      expect(n.objectId).toBe(small!.messageId);
      expect(n.sealed!.bodyB64url).toBe(small!.sealed.bodyB64url);
    }
    for (const n of byName("truncated tag")) {
      const original = n.open === "header" ? b64urlDecode(small!.sealed.header) : b64urlDecode(small!.sealed.bodyB64url);
      const truncated = n.open === "header" ? b64urlDecode(n.sealed!.header!) : b64urlDecode(n.sealed!.bodyB64url!);
      expect(b64urlEncode(original.subarray(0, original.length - 1))).toBe(b64urlEncode(truncated));
    }
    const recovery = vectors.wraps.find((w) => w.wrap.kind === "recovery")!.recoveryDisplay!;
    for (const n of byName("recovery key with a one-character typo")) {
      const typo = n.recoveryDisplay!;
      expect(typo.length).toBe(recovery.length);
      expect([...typo].filter((c, i) => c !== recovery[i]).length).toBe(1);
    }
  });
});
