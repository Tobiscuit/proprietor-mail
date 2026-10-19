/**
 * The binding key and binding tags (contracts/device-v1.md A5). A browser
 * that holds a mailbox key can tell whether a device or a factor key in the
 * key ring was put there by another holder of that key, or by whoever
 * controls the server: only key holders can make or check these tags.
 *
 *   z     = X25519(sk, pk), the mailbox private key with its own public key
 *   kbind = HKDF-SHA256(ikm = z, empty salt, info = ctx("binding", mailboxId, keyId), L = 32),
 *           a non-extractable HMAC-SHA-256 key for sign and verify
 *   tag   = HMAC-SHA-256(kbind, message), 32 bytes
 *
 *   device: ctx("recipient", mailboxId, keyId, "device", deviceId, b64u(UTF-8(label)),
 *               b64u(signingKey), unlockKey === null ? "-" : b64u(unlockKey))
 *   factor: ctx("recipient", mailboxId, keyId, "factor", factorId, kind, b64u(UTF-8(label)),
 *               b64u(factorKey), credentialId ?? "-")
 *
 * z works from a decrypt-only key: it needs only deriveBits. It is bytes for
 * the moment it takes to import it into HKDF, and is zeroed then; kbind is
 * derived inside Web Crypto (deriveKey) and never exists as bytes. Labels
 * must be well-formed Unicode: TextEncoder turns every lone surrogate into
 * U+FFFD, so two different labels would otherwise share one tag.
 */
import { base64url, fromBase64url } from "./bytes";
import { context } from "./envelope";
import type { MailboxPrivateKey, WrapKind } from "./index";
import { materialOf } from "./keys";

const WRAP_KINDS: readonly string[] = ["passkey-prf", "recovery"] satisfies WrapKind[];
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const TAG_BYTES = 32;

/**
 * The binding key of one mailbox key: an opaque, frozen `{ mailboxId, keyId }`
 * handle. The HMAC key lives in a module-private WeakMap.
 */
export interface BindingKey {
  readonly mailboxId: string;
  readonly keyId: string;
}

/** A recipient as its tag covers it. Keys are raw bytes; the message encodes them as base64url. */
export type TagRecipient =
  | {
      kind: "device";
      deviceId: string;
      label: string;
      /** The ECDSA P-256 signing key, a 65-byte uncompressed point. */
      signingKey: Uint8Array; // pragma: allowlist secret (a field type)
      /** The ECDH P-256 unlock key, 65 bytes, or null while the device keeps none. */
      unlockKey: Uint8Array | null;
    }
  | {
      kind: "factor";
      factorId: string;
      factorKind: WrapKind;
      label: string;
      /** pkF, 32 bytes (A2). */
      factorKey: Uint8Array;
      /** The passkey's credential id (base64url), or null for the recovery key. */
      credentialId: string | null;
    };

const keys = new WeakMap<object, CryptoKey>();

type DeriveBitsParams = Parameters<SubtleCrypto["deriveBits"]>[0];

/** X25519 deriveBits parameters with the peer key under `public` (see keys.ts: workers-types names it `$public`). */
function x25519Peer(publicKey: CryptoKey): DeriveBitsParams {
  return { name: "X25519", public: publicKey } as unknown as DeriveBitsParams;
}

export async function bindingKey(priv: MailboxPrivateKey, ids: { mailboxId: string }): Promise<BindingKey> {
  const material = materialOf(priv);
  const info = context("binding", ids.mailboxId, material.keyId);
  const z = new Uint8Array(await crypto.subtle.deriveBits(x25519Peer(material.keyPair.publicKey), material.keyPair.privateKey, 256));
  let base: CryptoKey;
  try {
    base = await crypto.subtle.importKey("raw", z, "HKDF", false, ["deriveKey"]);
  } finally {
    z.fill(0);
  }
  const hmac = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info }, // pragma: allowlist secret (HKDF parameter names)
    base,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"],
  );
  const handle: BindingKey = Object.freeze({ mailboxId: ids.mailboxId, keyId: material.keyId });
  keys.set(handle, hmac);
  return handle;
}

export function bindingMaterialOf(bk: BindingKey): CryptoKey {
  const key = typeof bk === "object" && bk !== null ? keys.get(bk) : undefined;
  if (!key) throw new TypeError("not a BindingKey from bindingKey in this page");
  return key;
}

function label(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || LONE_SURROGATE.test(value)) {
    throw new TypeError("a label is a non-empty string of well-formed Unicode");
  }
  return base64url(new TextEncoder().encode(value));
}

function bytesOfLength(value: unknown, length: number, what: string): string {
  if (!(value instanceof Uint8Array) || value.length !== length) throw new TypeError(`${what} is exactly ${length} bytes`);
  return base64url(value);
}

function point(value: unknown, what: string): string {
  if (!(value instanceof Uint8Array) || value.length !== 65 || value[0] !== 0x04) throw new TypeError(`${what} is a 65-byte uncompressed P-256 point`);
  return base64url(value);
}

/** The message a tag covers; throws TypeError for anything that could make it ambiguous. */
function messageOf(bk: BindingKey, recipient: TagRecipient): Uint8Array<ArrayBuffer> {
  if (recipient.kind === "device") {
    return context(
      "recipient",
      bk.mailboxId,
      bk.keyId,
      "device",
      recipient.deviceId,
      label(recipient.label),
      point(recipient.signingKey, "a signing key"),
      recipient.unlockKey === null ? "-" : point(recipient.unlockKey, "an unlock key"),
    );
  }
  if (recipient.kind === "factor") {
    if (!WRAP_KINDS.includes(recipient.factorKind)) throw new TypeError(`unknown factor kind: ${String(recipient.factorKind)}`);
    const credentialId = recipient.credentialId; // pragma: allowlist secret (a variable name)
    // "-" stands for no credential, so it can never be one (a valid base64url credential id is never one character).
    if (credentialId !== null && (typeof credentialId !== "string" || credentialId === "-")) throw new TypeError("a credential id is base64url, or null");
    return context(
      "recipient",
      bk.mailboxId,
      bk.keyId,
      "factor",
      recipient.factorId,
      recipient.factorKind,
      label(recipient.label),
      bytesOfLength(recipient.factorKey, 32, "a factor key"),
      credentialId ?? "-",
    );
  }
  throw new TypeError(`unknown recipient kind: ${String((recipient as { kind?: unknown }).kind)}`);
}

/** The recipient's tag under the binding key, base64url of 32 bytes. */
export async function bindingTag(bk: BindingKey, recipient: TagRecipient): Promise<string> {
  const hmac = bindingMaterialOf(bk);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", hmac, messageOf(bk, recipient))));
}

/**
 * True only when `tag` is the recipient's tag under this binding key. Every
 * other input, including a malformed recipient or tag from a view, is false:
 * a check of what Mail sent never throws.
 */
export async function verifyBindingTag(bk: BindingKey, recipient: TagRecipient, tag: string): Promise<boolean> {
  const hmac = bindingMaterialOf(bk);
  const bytes = typeof tag === "string" ? fromBase64url(tag) : null;
  if (bytes === null || bytes.length !== TAG_BYTES) return false;
  let message: Uint8Array<ArrayBuffer>;
  try {
    message = messageOf(bk, recipient);
  } catch {
    return false;
  }
  // Web Crypto's HMAC verify compares in constant time.
  return crypto.subtle.verify("HMAC", hmac, bytes, message);
}
