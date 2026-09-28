// Writes contracts/envelope-v1.vectors.json. Runs only on request:
//   npm run write-vectors -w @proprietor/mail-crypto
// (vitest.config.ts excludes this file from `npm test`). Every key and secret is derived from a
// public label, so they are recognisably test values; ids, message keys and IVs are fresh on each
// run, so regenerating changes the file. test/vectors.test.ts checks whatever is committed.
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import {
  fingerprint,
  newId,
  parseRecoveryKey,
  prfInput,
  RecoveryKeyTypo,
  sealDraft,
  sealMessage,
  wrapPrivateKey,
  type MailboxPublicKey,
} from "../src/index";
import { openKeyEnvelope, sealKeyEnvelope } from "../src/envelope";
import { clamp, importPrivateScalar, materialOf } from "../src/keys";
import { recoveryDisplay } from "../src/recovery";
import { draft, smallHeader, smallRaw, unicodeHeader, unicodeRaw } from "./fixtures";
import { b64urlDecode, b64urlEncode, hex, sha256, utf8 } from "./reference";

const vectorsPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../contracts/envelope-v1.vectors.json");

const LABELS = {
  mailboxKey: "platform-mail/v1 test vectors: mailbox private key (never use for real mail)",
  prfOutput: "platform-mail/v1 test vectors: passkey PRF output (never use for real mail)",
  recoveryKey: "platform-mail/v1 test vectors: recovery secret (never use for real mail)",
};

test("write contracts/envelope-v1.vectors.json", async () => {
  const skRm = clamp(await sha256(utf8(LABELS.mailboxKey)));
  const priv = await importPrivateScalar(skRm);
  const { keyId, publicKey, keyPair } = materialOf(priv);
  const pub: MailboxPublicKey = { keyId, publicKey };
  const mailboxId = newId("mbx");
  const dekOf = async (objectId: string, keyEnvelope: string) =>
    hex(await openKeyEnvelope(keyPair, mailboxId, objectId, b64urlDecode(keyEnvelope)));

  const messages = [];
  for (const [name, header, raw] of [
    ["small message", smallHeader, smallRaw],
    ["non-ASCII subject and an attachment", unicodeHeader, unicodeRaw],
  ] as const) {
    const messageId = newId("msg");
    const sealed = await sealMessage(pub, { mailboxId, messageId }, header, raw);
    messages.push({
      name,
      messageId,
      dek: await dekOf(messageId, sealed.keyEnvelope),
      sealed: { keyId: sealed.keyId, keyEnvelope: sealed.keyEnvelope, header: sealed.header, bodyB64url: b64urlEncode(sealed.body) },
      header,
      raw: new TextDecoder("utf-8", { fatal: true }).decode(raw),
    });
  }

  const draftId = newId("drf");
  const sealedDraft = await sealDraft(pub, { mailboxId, draftId }, draft);
  const drafts = [{ name: "draft", draftId, dek: await dekOf(draftId, sealedDraft.keyEnvelope), sealed: sealedDraft, draft }];

  const prfOutput = await sha256(utf8(LABELS.prfOutput));
  const passkeyWrapId = newId("wrp");
  const recovery = await sha256(utf8(LABELS.recoveryKey));
  const display = recoveryDisplay(recovery);
  const wraps = [
    {
      name: "passkey wrap",
      secretLabel: LABELS.prfOutput, // pragma: allowlist secret (a public label)
      prfInput: hex(await prfInput(mailboxId, passkeyWrapId)),
      prfOutput: hex(prfOutput),
      wrap: await wrapPrivateKey(priv, { mailboxId, wrapId: passkeyWrapId, kind: "passkey-prf", secret: prfOutput }), // pragma: allowlist secret (a test vector)
    },
    {
      name: "recovery wrap",
      secretLabel: LABELS.recoveryKey, // pragma: allowlist secret (a public label)
      recoveryKey: hex(recovery),
      recoveryDisplay: display,
      wrap: await wrapPrivateKey(priv, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret: recovery }), // pragma: allowlist secret (a test vector)
    },
  ];

  // Negative cases, all derived from the small message.
  const small = messages[0]!;
  const otherMessageId = newId("msg");
  const otherMailboxId = newId("mbx");
  const dek = new Uint8Array(Buffer.from(small.dek, "hex"));
  const resealed = async (mbx: string, objectId: string) => b64urlEncode(await sealKeyEnvelope(keyPair.publicKey, mbx, objectId, dek));
  const header = b64urlDecode(small.sealed.header);
  const body = b64urlDecode(small.sealed.bodyB64url);
  let typo = display;
  for (let i = 6; typo === display; i++) {
    const replacement = display[i] === "7" ? "8" : "7";
    const candidate = display.slice(0, i) + replacement + display.slice(i + 1);
    try {
      parseRecoveryKey(candidate);
    } catch (e) {
      if (e instanceof RecoveryKeyTypo) typo = candidate;
    }
  }
  const negative = [
    {
      name: "header moved to another message id",
      open: "header",
      mailboxId,
      objectId: otherMessageId,
      sealed: { keyEnvelope: small.sealed.keyEnvelope, header: small.sealed.header },
      expect: "DecryptionFailed",
    },
    {
      name: "header moved to another message id, with its message key re-sealed for that id (only the header's own associated data can refuse it)",
      open: "header",
      mailboxId,
      objectId: otherMessageId,
      sealed: { keyEnvelope: await resealed(mailboxId, otherMessageId), header: small.sealed.header },
      expect: "DecryptionFailed",
    },
    {
      name: "body moved to another mailbox",
      open: "body",
      mailboxId: otherMailboxId,
      objectId: small.messageId,
      sealed: { keyEnvelope: small.sealed.keyEnvelope, bodyB64url: small.sealed.bodyB64url },
      expect: "DecryptionFailed",
    },
    {
      name: "body moved to another mailbox, with its message key re-sealed for that mailbox (only the body's own associated data can refuse it)",
      open: "body",
      mailboxId: otherMailboxId,
      objectId: small.messageId,
      sealed: { keyEnvelope: await resealed(otherMailboxId, small.messageId), bodyB64url: small.sealed.bodyB64url },
      expect: "DecryptionFailed",
    },
    {
      name: "truncated tag: header block missing its last byte",
      open: "header",
      mailboxId,
      objectId: small.messageId,
      sealed: { keyEnvelope: small.sealed.keyEnvelope, header: b64urlEncode(header.subarray(0, header.length - 1)) },
      expect: "DecryptionFailed",
    },
    {
      name: "truncated tag: body object missing its last byte",
      open: "body",
      mailboxId,
      objectId: small.messageId,
      sealed: { keyEnvelope: small.sealed.keyEnvelope, bodyB64url: b64urlEncode(body.subarray(0, body.length - 1)) },
      expect: "DecryptionFailed",
    },
    {
      name: "recovery key with a one-character typo",
      open: "recoveryDisplay",
      recoveryDisplay: typo,
      expect: "RecoveryKeyTypo",
    },
  ];

  const vectors = {
    contract: "contracts/envelope-v1.md",
    about:
      "Test vectors for envelope v1, written by packages/mail-crypto (npm run write-vectors -w @proprietor/mail-crypto) " +
      "and checked by its test/vectors.test.ts. Every key and secret is SHA-256 of the public label next to it: " +
      "test values only, never used for real mail. Byte strings are lowercase hex, except the stored forms " +
      "(keyEnvelope, header, sealed, wrapped) and fields ending in B64url, which are base64url without padding " +
      "(RFC 4648 §5). Strings are UTF-8; raw is the message's exact bytes as a UTF-8 string (CRLF line ends).",
    suite: {
      mode: "base",
      kem: "0x0020 DHKEM(X25519, HKDF-SHA256)",
      kdf: "0x0001 HKDF-SHA256",
      aead: "0x0002 AES-256-GCM",
    },
    mailboxKey: {
      label: LABELS.mailboxKey,
      derivation: "skRm = SHA-256(UTF-8(label)), clamped (RFC 7748 decodeScalar25519); pkRm = X25519(skRm, 9)",
      skRm: hex(skRm),
      pkRm: hex(publicKey),
      keyId,
      fingerprint: fingerprint(keyId),
    },
    mailboxId,
    messages,
    drafts,
    wraps,
    negative,
  };
  writeFileSync(vectorsPath, JSON.stringify(vectors, null, 2) + "\n");
  expect(typo).not.toBe(display);
});
