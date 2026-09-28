/**
 * Wrapping the mailbox private key (contracts/envelope-v1.md "Wrapping the
 * private key"): kek = HKDF-SHA256(ikm = secret, salt = wrapId,
 * info = "platform-mail/v1/kek/" + kind), and one AES-256-GCM block over the
 * raw 32-byte private key, bound to mailbox, wrap id, kind and key id.
 */
import { base64url, copy, fromBase64url, utf8 } from "./bytes";
import { context, failClosed, openBlock, sealBlock, WRAP_BLOCK } from "./envelope";
import { DecryptionFailed } from "./errors";
import type { KeyWrap, MailboxPrivateKey, WrapKind } from "./index";
import { importPrivateScalar, materialOf } from "./keys";

const WRAP_KINDS: readonly string[] = ["passkey-prf", "recovery"] satisfies WrapKind[];
const WRAP_BYTES = 1 + 12 + 32 + 16;

function assertSecret(secret: unknown): asserts secret is Uint8Array {
  if (!(secret instanceof Uint8Array) || secret.length !== 32) {
    throw new TypeError("a wrap secret (PRF output or recovery secret) is exactly 32 bytes");
  }
}

async function kek(ikm: Uint8Array, wrapId: string, kind: string, usage: "encrypt" | "decrypt"): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey("raw", copy(ikm), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8(wrapId), info: utf8(`platform-mail/v1/kek/${kind}`) }, // pragma: allowlist secret (HKDF parameter names, no value)
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
  const aad = context("wrap", ctx.mailboxId, ctx.wrapId, ctx.kind, material.keyId);
  const key = await kek(ctx.secret, ctx.wrapId, ctx.kind, "encrypt");
  // The only place the raw private key is read: RFC 9180 §7.1.2 serialization (clamped raw 32 bytes).
  const block = await sealBlock(WRAP_BLOCK, key, aad, material.scalar);
  return { id: ctx.wrapId, keyId: material.keyId, kind: ctx.kind, wrapped: base64url(block) };
}

export async function unwrapPrivateKey(
  wrap: KeyWrap,
  ctx: { mailboxId: string; secret: Uint8Array }, // pragma: allowlist secret (a type)
): Promise<MailboxPrivateKey> {
  assertSecret(ctx.secret);
  const raw = await failClosed(async () => {
    const aad = context("wrap", ctx.mailboxId, wrap.id, wrap.kind, wrap.keyId);
    const block = fromBase64url(wrap.wrapped);
    if (block === null || block.length !== WRAP_BYTES) throw new DecryptionFailed();
    const key = await kek(ctx.secret, wrap.id, wrap.kind, "decrypt");
    return openBlock(WRAP_BLOCK, key, aad, block);
  });
  try {
    // Outside failClosed on purpose: a runtime without X25519 is not a decryption failure.
    const priv = await importPrivateScalar(raw);
    if (priv.keyId !== wrap.keyId) throw new DecryptionFailed("the wrap holds a different key from the one it names");
    return priv;
  } finally {
    raw.fill(0);
  }
}
