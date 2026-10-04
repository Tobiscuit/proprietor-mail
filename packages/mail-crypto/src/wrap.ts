/**
 * Wrapping the mailbox private key (contracts/envelope-v1.md "Wrapping the
 * private key"): kek = HKDF-SHA256(ikm = secret, salt = wrapId,
 * info = "proprietor-mail/v1/kek/" + kind), and one AES-256-GCM block over the
 * key's PKCS #8 PrivateKeyInfo (RFC 8410, 48 bytes), bound to mailbox, wrap
 * id, kind and key id.
 *
 * D21 (domain-model K1): the block is made by Web Crypto's `wrapKey` and
 * opened by `unwrapKey`, so the private key never exists as bytes in
 * JavaScript. An unwrapped key is non-extractable and decrypt-only unless the
 * caller asks for `wrappable`, which an unlock does only for the one
 * operation that wraps the key again (a new passkey, a new recovery key).
 */
import { base64url, concat, copy, fromBase64url, randomBytes, utf8 } from "./bytes";
import { context, failClosed, WRAP_BLOCK } from "./envelope";
import { DecryptionFailed } from "./errors";
import type { KeyWrap, MailboxPrivateKey, WrapKind } from "./index";
import { fromPrivateCryptoKey, materialOf, PKCS8_X25519_BYTES } from "./keys";

const WRAP_KINDS: readonly string[] = ["passkey-prf", "recovery"] satisfies WrapKind[];
const IV_BYTES = 12;
const TAG_BYTES = 16;
/** 0x01 || iv (12) || AES-256-GCM(PKCS #8 PrivateKeyInfo, 48 bytes) || tag (16) = 77 bytes. */
export const WRAP_BYTES = WRAP_BLOCK.length + IV_BYTES + PKCS8_X25519_BYTES + TAG_BYTES;

/** A plain `{ name }`: @cloudflare/workers-types has no global `Algorithm` type. */
const X25519: { name: string } = { name: "X25519" };

function assertSecret(secret: unknown): asserts secret is Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new TypeError("a wrap secret (PRF output or recovery secret) is exactly 32 bytes");
  }
}

async function kek(ikm: Uint8Array, wrapId: string, kind: string, usage: "wrapKey" | "unwrapKey"): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", copy(ikm), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8(wrapId), info: utf8(`proprietor-mail/v1/kek/${kind}`) }, // pragma: allowlist secret (HKDF parameter names, no value)
    base,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function prfInput(mailboxId: string, wrapId: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", context("prf", mailboxId, wrapId)));
}

export async function wrapPrivateKey(
  priv: MailboxPrivateKey,
  ctx: { mailboxId: string; wrapId: string; kind: WrapKind; secret: Uint8Array }, // pragma: allowlist secret (a type)
): Promise<KeyWrap> {
  const material = materialOf(priv);
  if (!WRAP_KINDS.includes(ctx.kind)) throw new TypeError(`unknown wrap kind: ${String(ctx.kind)}`);
  assertSecret(ctx.secret);
  if (!material.wrappable) {
    throw new TypeError("this key is decrypt-only (K1): unlock again with `wrappable` for the one operation that wraps it");
  }
  const aad = context("wrap", ctx.mailboxId, ctx.wrapId, ctx.kind, material.keyId);
  const key = await kek(ctx.secret, ctx.wrapId, ctx.kind, "wrapKey");
  const iv = randomBytes(IV_BYTES);
  // The private key leaves Web Crypto only as this ciphertext: wrapKey serializes it (PKCS #8) and encrypts it in one step.
  const ct = new Uint8Array(
    await crypto.subtle.wrapKey("pkcs8", material.keyPair.privateKey, key, { name: "AES-GCM", iv, additionalData: aad, tagLength: 128 }),
  );
  if (ct.length !== PKCS8_X25519_BYTES + TAG_BYTES) throw new Error("internal: an X25519 PKCS #8 PrivateKeyInfo is 48 bytes");
  return { id: ctx.wrapId, keyId: material.keyId, kind: ctx.kind, wrapped: base64url(concat(WRAP_BLOCK, iv, ct)) };
}

export async function unwrapPrivateKey(
  wrap: KeyWrap,
  ctx: { mailboxId: string; secret: Uint8Array }, // pragma: allowlist secret (a type)
  options?: { wrappable?: boolean },
): Promise<MailboxPrivateKey> {
  assertSecret(ctx.secret);
  const wrappable = options?.wrappable === true;
  const { key, aad, block } = await failClosed(async () => {
    const aad = context("wrap", ctx.mailboxId, wrap.id, wrap.kind, wrap.keyId);
    const block = fromBase64url(wrap.wrapped);
    if (block === null || block.length !== WRAP_BYTES || block[0] !== WRAP_BLOCK[0]) throw new DecryptionFailed();
    return { key: await kek(ctx.secret, wrap.id, wrap.kind, "unwrapKey"), aad, block };
  });
  let privateKey: CryptoKey; // pragma: allowlist secret (a type annotation, not a value)
  try {
    privateKey = await crypto.subtle.unwrapKey(
      "pkcs8",
      block.subarray(WRAP_BLOCK.length + IV_BYTES),
      key,
      { name: "AES-GCM", iv: block.subarray(WRAP_BLOCK.length, WRAP_BLOCK.length + IV_BYTES), additionalData: aad, tagLength: 128 },
      X25519,
      wrappable,
      ["deriveBits"],
    );
  } catch (e) {
    // A runtime without X25519 is not a decryption failure; everything else (a bad tag, a malformed key) is.
    if (e instanceof DOMException && e.name === "NotSupportedError") throw e;
    throw new DecryptionFailed();
  }
  const priv = await fromPrivateCryptoKey(privateKey);
  if (priv.keyId !== wrap.keyId) throw new DecryptionFailed("the wrap holds a different key from the one it names");
  return priv;
}
