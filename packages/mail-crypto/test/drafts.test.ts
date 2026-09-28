// S1c: sealDraft, openDraft (contracts/envelope-v1.md "Drafts").
import { describe, expect, test } from "vitest";
import {
  DecryptionFailed,
  generateMailboxKey,
  newId,
  openDraft,
  sealDraft,
  sealMessage,
  type Draft,
} from "../src/index";
import { openKeyEnvelope, sealKeyEnvelope } from "../src/envelope";
import { materialOf } from "../src/keys";
import { draft, smallHeader, smallRaw } from "./fixtures";
import { b64urlDecode, b64urlEncode, flipBit, hex, utf8 } from "./reference";

const mailboxId = newId("mbx");
const draftId = newId("drf");
const ids = { mailboxId, draftId };
const { publicKey: pub, privateKey: priv } = await generateMailboxKey();

async function expectDecryptionFailed(p: Promise<unknown>) {
  await expect(p).rejects.toBeInstanceOf(DecryptionFailed);
}

describe("S1c drafts", () => {
  test("seal → open returns the exact draft", async () => {
    const sealed = await sealDraft(pub, ids, draft);
    expect(await openDraft(priv, ids, sealed)).toStrictEqual(draft);
  });

  test("the sealed draft has the contract's layout", async () => {
    const sealed = await sealDraft(pub, ids, draft);
    expect(sealed.keyId).toBe(pub.keyId);
    expect(b64urlDecode(sealed.keyEnvelope).length).toBe(80);
    const block = b64urlDecode(sealed.sealed);
    expect(block[0]).toBe(0x01);
    expect(block.length).toBe(1 + 12 + utf8(JSON.stringify(draft)).length + 16);
  });

  test("a draft opened with another draft id or another mailbox id throws DecryptionFailed", async () => {
    const sealed = await sealDraft(pub, ids, draft);
    await expectDecryptionFailed(openDraft(priv, { mailboxId, draftId: newId("drf") }, sealed));
    await expectDecryptionFailed(openDraft(priv, { mailboxId: newId("mbx"), draftId }, sealed));
  });

  test("the draft block is bound on its own: moved with a key envelope re-sealed for the new id, it still fails", async () => {
    const sealed = await sealDraft(pub, ids, draft);
    const { keyPair } = materialOf(priv);
    const dek = await openKeyEnvelope(keyPair, mailboxId, draftId, b64urlDecode(sealed.keyEnvelope));
    const other = newId("drf");
    const keyEnvelope = b64urlEncode(await sealKeyEnvelope(keyPair.publicKey, mailboxId, other, dek));
    await expectDecryptionFailed(openDraft(priv, { mailboxId, draftId: other }, { ...sealed, keyEnvelope }));
  });

  test("a message header block presented as a draft under the same id fails: the block kind is bound", async () => {
    const sameId = newId("msg");
    const message = await sealMessage(pub, { mailboxId, messageId: sameId }, smallHeader, smallRaw);
    const disguised = { keyId: message.keyId, keyEnvelope: message.keyEnvelope, sealed: message.header };
    await expectDecryptionFailed(openDraft(priv, { mailboxId, draftId: sameId }, disguised));
  });

  test("a flipped bit anywhere in a sealed draft throws DecryptionFailed", async () => {
    const sealed = await sealDraft(pub, ids, draft);
    const envelope = b64urlDecode(sealed.keyEnvelope);
    const block = b64urlDecode(sealed.sealed);
    for (let i = 0; i < envelope.length; i++) {
      await expectDecryptionFailed(openDraft(priv, ids, { ...sealed, keyEnvelope: b64urlEncode(flipBit(envelope, i, i % 8)) }));
    }
    for (let i = 0; i < block.length; i++) {
      await expectDecryptionFailed(openDraft(priv, ids, { ...sealed, sealed: b64urlEncode(flipBit(block, i, i % 8)) }));
    }
    await expectDecryptionFailed(openDraft(priv, ids, { ...sealed, sealed: b64urlEncode(block.subarray(0, block.length - 1)) }));
  });

  test("every save uses a fresh message key and IV", async () => {
    const a = await sealDraft(pub, ids, draft);
    const b = await sealDraft(pub, ids, draft);
    const { keyPair } = materialOf(priv);
    const dekA = await openKeyEnvelope(keyPair, mailboxId, draftId, b64urlDecode(a.keyEnvelope));
    const dekB = await openKeyEnvelope(keyPair, mailboxId, draftId, b64urlDecode(b.keyEnvelope));
    expect(hex(dekA)).not.toBe(hex(dekB));
    expect(a.sealed).not.toBe(b.sealed);
  });

  test("a Draft without one of its keys is refused", async () => {
    const { text: _, ...missing } = draft;
    await expect(sealDraft(pub, ids, missing as Draft)).rejects.toBeInstanceOf(TypeError);
  });
});
