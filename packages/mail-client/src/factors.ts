/**
 * Factors (spec 002 §3: a security key or passkey with PRF, or the recovery
 * key). Using one opens its envelope v1 wrap AND derives its factor key
 * (contracts/device-v1.md A2) from the same secret, which is zeroed at once.
 * The wrap's key is the factor's anchor for K2′ (a). When the wrap is of a
 * retired key, the active key comes from the factor's seal (K2′ (b)), and the
 * chain walk must then lead back to the anchor.
 */
import {
  bindingTag,
  DecryptionFailed,
  deriveFactorKey,
  factorPublicKey,
  newId,
  newRecoveryKey,
  openKeySeal,
  parseRecoveryKey,
  RecoveryKeyTypo as CryptoRecoveryKeyTypo,
  unwrapPrivateKey,
  wrapPrivateKey,
  type BindingKey,
  type FactorPrivateKey,
  type MailboxPrivateKey,
} from "@proprietor/mail-crypto";
import { base64url } from "./bytes";
import { KeySubstitutionDetected, NoMatchingWrap, RecoveryKeyTypo, WrongRecoveryKey } from "./errors";
import type { Ring, RingWrap } from "./keyring";
import { assertPasskeyPrf, createPasskeyWithPrf } from "./passkeys";
import type { PasskeyOptions, ReAuth, WrapInput } from "./types";

export const RECOVERY_LABEL = "Recovery key";

export interface OpenedFactor {
  wrap: RingWrap;
  /** The key the factor's own wrap holds, non-extractable: its anchor (K2′ (a)). */
  wrapKey: MailboxPrivateKey;
  /** The same key, wrappable, for a FreshFactor when it is the active key. */
  wrapKeyWrappable: MailboxPrivateKey;
  factorKey: FactorPrivateKey;
}

async function opened(ring: Ring, wrap: RingWrap, secret: Uint8Array): Promise<OpenedFactor> { // pragma: allowlist secret (a parameter type)
  const ctx = { mailboxId: ring.mailboxId, secret };
  const asWrap = { id: wrap.id, keyId: wrap.keyId, kind: wrap.kind, wrapped: wrap.wrapped };
  const wrapKey = await unwrapPrivateKey(asWrap, ctx);
  const wrapKeyWrappable = await unwrapPrivateKey(asWrap, ctx, { wrappable: true });
  const factorKey = await deriveFactorKey({ mailboxId: ring.mailboxId, factorId: wrap.id, kind: wrap.kind, secret });
  return { wrap, wrapKey, wrapKeyWrappable, factorKey };
}

/** Wraps of the active key first: they need no seal. */
function activeFirst(ring: Ring, wraps: RingWrap[]): RingWrap[] {
  return [...wraps].sort((a, b) => Number(b.keyId === ring.active.keyId) - Number(a.keyId === ring.active.keyId));
}

/**
 * Uses a factor: one passkey prompt over every passkey wrap (the credential the
 * person used selects the wrap), or the recovery key tried on every recovery
 * wrap. The secret is zeroed before this returns.
 */
export async function openFactor(ring: Ring, factor: ReAuth): Promise<OpenedFactor> {
  if ("passkey" in factor) {
    // One entry per credential (evalByCredential has one input per credential id), the wrap of the active key preferred.
    const candidates: RingWrap[] = [];
    for (const w of activeFirst(ring, ring.wraps.filter((x) => x.kind === "passkey-prf" && x.credentialId !== null))) {
      if (!candidates.some((c) => c.credentialId === w.credentialId)) candidates.push(w);
    }
    if (candidates.length === 0) throw new NoMatchingWrap("the mailbox has no passkey");
    const { wrap, secret } = await assertPasskeyPrf(factor.passkey, ring.mailboxId, candidates);
    try {
      return await opened(ring, wrap, secret);
    } catch (e) {
      if (e instanceof DecryptionFailed) throw new NoMatchingWrap("the passkey's wrap did not open");
      throw e;
    } finally {
      secret.fill(0);
    }
  }
  let secret: Uint8Array; // pragma: allowlist secret (a variable name)
  try {
    secret = parseRecoveryKey(factor.recoveryKey); // pragma: allowlist secret (a variable name)
  } catch (e) {
    if (e instanceof CryptoRecoveryKeyTypo) throw new RecoveryKeyTypo();
    throw e;
  }
  try {
    for (const wrap of activeFirst(ring, ring.wraps.filter((w) => w.kind === "recovery"))) {
      try {
        return await opened(ring, wrap, secret);
      } catch (e) {
        if (!(e instanceof DecryptionFailed)) throw e;
      }
    }
    throw new WrongRecoveryKey();
  } finally {
    secret.fill(0);
  }
}

/**
 * The active key the factor reaches: its own wrap's key when that is the
 * active key, else the factor's seal of the active key, opened with its factor
 * key. Null when it reaches none (StaleFactor at an unlock). A seal to the
 * factor that does not open to the active key stops everything.
 */
export async function activeOfFactor(ring: Ring, f: OpenedFactor): Promise<{ key: MailboxPrivateKey; wrappable: MailboxPrivateKey } | null> {
  if (f.wrap.keyId === ring.active.keyId) return { key: f.wrapKey, wrappable: f.wrapKeyWrappable };
  const seal = ring.seals.find((s) => s.keyId === ring.active.keyId && s.to.kind === "factor" && s.to.id === f.wrap.id);
  if (seal === undefined) return null;
  const by = { kind: "factor" as const, key: f.factorKey };
  const ids = { mailboxId: ring.mailboxId, sealedKeyId: ring.active.keyId };
  try {
    return { key: await openKeySeal(by, ids, seal.sealed), wrappable: await openKeySeal(by, ids, seal.sealed, { wrappable: true }) };
  } catch {
    throw new KeySubstitutionDetected("the factor's seal does not open to the advertised key");
  }
}

/** A factor's tag under the binding key (A5), for the facts a wrap request names. */
export function factorTag(binding: BindingKey, facts: Pick<RingWrap, "id" | "kind" | "label" | "credentialId">, factorKey: Uint8Array): Promise<string> {
  return bindingTag(binding, { kind: "factor", factorId: facts.id, factorKind: facts.kind, label: facts.label, factorKey, credentialId: facts.credentialId }); // pragma: allowlist secret (field names and public values, not secrets)
}

async function withFactorKey(wrap: WrapInput, mailboxId: string, secret: Uint8Array, binding: BindingKey | null): Promise<WrapInput> { // pragma: allowlist secret (a parameter type)
  if (binding === null) return wrap;
  const key = await deriveFactorKey({ mailboxId, factorId: wrap.id, kind: wrap.kind, secret });
  const factorKey = factorPublicKey(key);
  return { ...wrap, factorKey: base64url(factorKey), tag: await factorTag(binding, wrap, factorKey), tagKeyId: binding.keyId };
}

/**
 * A passkey wrap of `priv` (which must be wrappable) for a new passkey: one
 * create(), maybe one get(). With a binding key (sessions required), the wrap
 * also carries the passkey's factor key, from the same PRF output, and its tag.
 */
export async function makePasskeyWrap(mailboxId: string, priv: MailboxPrivateKey, passkey: PasskeyOptions, binding: BindingKey | null): Promise<WrapInput> {
  const wrapId = newId("wrp");
  const { credentialId, secret } = await createPasskeyWithPrf(passkey, mailboxId, wrapId);
  try {
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId, kind: "passkey-prf", secret });
    return await withFactorKey({ ...wrap, credentialId, label: passkey.label }, mailboxId, secret, binding);
  } finally {
    secret.fill(0);
  }
}

/** A recovery wrap of `priv` with a new recovery key, shown once; with its factor key and tag when sessions are required. */
export async function makeRecoveryWrap(mailboxId: string, priv: MailboxPrivateKey, binding: BindingKey | null): Promise<{ recoveryKey: string; wrap: WrapInput }> {
  const { secret, display } = newRecoveryKey();
  try {
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
    return { recoveryKey: display, wrap: await withFactorKey({ ...wrap, credentialId: null, label: RECOVERY_LABEL }, mailboxId, secret, binding) };
  } finally {
    secret.fill(0);
  }
}
