/**
 * Trusting a mailbox's key ring (contracts/device-v1.md Part C, K2′ and K3).
 *
 * K2′: the advertised active key is accepted only when its private key was
 * opened from (a) an envelope v1 wrap with the factor just used, or (b) a seal
 * (to this device, or to that factor) AND the successor seals lead from it
 * back to a key the browser already trusts: the key (a) opened, or the key
 * this device last accepted. Walking back: for the key k, find the key whose
 * successor.keyId is k, open its successor seal with k, require the keyId it
 * names, and repeat. A key that does not lead back stops everything, and so
 * does an advertised key older than the one this device last accepted (a
 * rollback: that key is then not on the walk). The opened active key must also
 * be the advertised one (K2, domain-model G7). A session holds every key the
 * walk reaches (G40), so old mail still opens after a rotation.
 *
 * K3: at every unlock, every tag in the key ring is checked under the active
 * key. Anyone can seal to a public key, and whoever controls the server could
 * add a recipient: only holders of the mailbox key can make a tag. A device or
 * factor whose tag fails is flagged, not trusted: it is never sealed to, it is
 * shown, and it can be removed. The key itself is trusted (K2′), so the rest
 * of the inbox works. (Amended 2026-10-19: a failing tag stopped everything.)
 *
 * A failure of K2 or K2′ is KeySubstitutionDetected: the screen stops and
 * shows the key-substitution warning.
 */
import {
  bindingKey,
  openKeySeal,
  publicKeyMatches,
  verifyBindingTag,
  type BindingKey,
  type MailboxPrivateKey,
  type TagRecipient,
} from "@proprietor/mail-crypto";
import { fromBase64url } from "./bytes";
import { KeySubstitutionDetected, NoActiveKey } from "./errors";
import type { DeviceView, FlaggedRecipients, MailboxView, SealView } from "./types";

const KEY_ID = /^[0-9a-f]{32}$/;

export interface RingKey {
  keyId: string;
  publicKey: Uint8Array<ArrayBuffer>;
  retiredAt: string | null;
  successor: { keyId: string; sealed: string } | null;
}

export interface RingWrap {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  label: string;
  wrapped: string;
  factorKey: string | null;
  tag: string | null;
  tagKeyId: string | null;
}

/** A view, read: the fields spec 002 adds are filled in for a view that lacks them (a Worker without spec 002). */
export interface Ring {
  mailboxId: string;
  sessions: "optional" | "required";
  keys: RingKey[];
  active: RingKey;
  wraps: RingWrap[];
  /** null when the view has no `devices` at all (a Worker without spec 002): not the same as none. */
  devices: DeviceView[] | null;
  seals: SealView[];
}

/** Decodes base64url of exactly `length` bytes, or null. */
export function bytesOf(value: unknown, length: number): Uint8Array<ArrayBuffer> | null {
  const bytes = typeof value === "string" ? fromBase64url(value) : null;
  return bytes !== null && bytes.length === length ? bytes : null;
}

export function readRing(view: MailboxView): Ring {
  if (typeof view !== "object" || view === null || !Array.isArray(view.keys) || !Array.isArray(view.wraps)) {
    throw new TypeError("a MailboxView has keys and wraps");
  }
  const keys: RingKey[] = view.keys.map((k) => ({
    keyId: k.keyId,
    publicKey: bytesOf(k.publicKey, 32) ?? new Uint8Array(0),
    retiredAt: k.retiredAt ?? null,
    successor: k.successor ?? null,
  }));
  const actives = keys.filter((k) => k.retiredAt === null);
  if (actives.length === 0) throw new NoActiveKey();
  if (actives.length > 1) throw new KeySubstitutionDetected("the mailbox advertises more than one active key");
  const active = actives[0]!;
  if (!KEY_ID.test(active.keyId) || active.publicKey.length !== 32) throw new NoActiveKey("the advertised public key is malformed");
  if (new Set(keys.map((k) => k.keyId)).size !== keys.length) throw new KeySubstitutionDetected("a key is listed twice");
  return {
    mailboxId: view.id,
    sessions: view.sessions === "required" ? "required" : "optional",
    keys,
    active,
    wraps: view.wraps.map((w) => ({
      id: w.id,
      keyId: w.keyId,
      kind: w.kind,
      credentialId: w.credentialId ?? null, // pragma: allowlist secret (field names and public values, not secrets)
      label: w.label,
      wrapped: w.wrapped,
      factorKey: w.factorKey ?? null,
      tag: w.tag ?? null,
      tagKeyId: w.tagKeyId ?? null,
    })),
    devices: Array.isArray(view.devices) ? view.devices.map((d) => ({ ...d })) : null,
    seals: Array.isArray(view.seals) ? view.seals.map((s) => ({ keyId: s.keyId, to: { kind: s.to.kind, id: s.to.id }, sealed: s.sealed })) : [],
  };
}

/** K2: the opened key is the advertised one, its public half included (G7). */
export async function checkAdvertisedKey(priv: MailboxPrivateKey, key: Pick<RingKey, "keyId" | "publicKey">): Promise<void> {
  if (!(await publicKeyMatches(priv, { keyId: key.keyId, publicKey: key.publicKey }))) throw new KeySubstitutionDetected();
}

/**
 * K2′: from the opened active key, walk the successor seals back through every
 * key of the ring. Every key in `anchors` (keys this browser trusts already)
 * must be on the walk, and the walk must reach every key the ring lists (they
 * form one chain). Returns every key reached, non-extractable, by keyId, the
 * active key first.
 */
export async function trustChain(ring: Ring, opened: MailboxPrivateKey, anchors: readonly string[]): Promise<Map<string, MailboxPrivateKey>> {
  await checkAdvertisedKey(opened, ring.active);
  if (ring.active.successor !== null) throw new KeySubstitutionDetected("the active key names a successor");
  const reached = new Map<string, MailboxPrivateKey>([[ring.active.keyId, opened]]);
  let current = ring.active;
  for (;;) {
    const predecessors = ring.keys.filter((k) => k.successor?.keyId === current.keyId);
    if (predecessors.length === 0) break;
    if (predecessors.length > 1) throw new KeySubstitutionDetected("two keys name the same successor");
    const previous = predecessors[0]!;
    if (previous.retiredAt === null || reached.has(previous.keyId)) throw new KeySubstitutionDetected("the key chain loops");
    let key: MailboxPrivateKey;
    try {
      key = await openKeySeal({ kind: "successor", key: reached.get(current.keyId)! }, { mailboxId: ring.mailboxId, sealedKeyId: previous.keyId }, previous.successor!.sealed);
    } catch {
      throw new KeySubstitutionDetected("a successor seal does not open to the key it names");
    }
    await checkAdvertisedKey(key, previous);
    reached.set(previous.keyId, key);
    current = previous;
  }
  for (const anchor of anchors) {
    if (!reached.has(anchor)) throw new KeySubstitutionDetected("the advertised key does not lead back to a key this browser trusts");
  }
  if (reached.size !== ring.keys.length) throw new KeySubstitutionDetected("a key is not on the chain");
  return reached;
}

/** The recipient a device's tag covers, from the view (null when its keys are malformed). */
export function deviceRecipient(d: Pick<DeviceView, "id" | "label" | "signingKey" | "unlockKey">): TagRecipient | null {
  const signingKey = bytesOf(d.signingKey, 65); // pragma: allowlist secret (a public key)
  const unlockKey = d.unlockKey === null ? null : bytesOf(d.unlockKey, 65);
  if (signingKey === null || (d.unlockKey !== null && unlockKey === null)) return null;
  return { kind: "device", deviceId: d.id, label: d.label, signingKey, unlockKey };
}

/** The recipient a factor's tag covers (null when it has no factor key, or a malformed one). */
export function factorRecipient(w: Pick<RingWrap, "id" | "kind" | "label" | "credentialId" | "factorKey">): TagRecipient | null {
  const factorKey = w.factorKey === null ? null : bytesOf(w.factorKey, 32);
  if (factorKey === null) return null;
  return { kind: "factor", factorId: w.id, factorKind: w.kind, label: w.label, factorKey, credentialId: w.credentialId }; // pragma: allowlist secret (field names and public values, not secrets)
}

/** Nothing flagged. */
export const NONE_FLAGGED: FlaggedRecipients = Object.freeze({ devices: Object.freeze([]), factors: Object.freeze([]) });

/** Frozen lists, without repeats, in the order given. */
export function flaggedOf(devices: Iterable<string>, factors: Iterable<string>): FlaggedRecipients {
  return Object.freeze({ devices: Object.freeze([...new Set(devices)]), factors: Object.freeze([...new Set(factors)]) });
}

/**
 * K3: every tag in the ring, under the active key's binding key. Answers the
 * recipients whose tag fails, is malformed, or is made under another key:
 * flagged, never sealed to. A factor with no factor key at all (before the
 * upgrade) has nothing to check.
 */
export async function checkTags(ring: Ring, binding: BindingKey): Promise<FlaggedRecipients> {
  if (binding.keyId !== ring.active.keyId || binding.mailboxId !== ring.mailboxId) throw new TypeError("the binding key is not the active key's");
  const devices: string[] = [];
  for (const d of ring.devices ?? []) {
    const recipient = deviceRecipient(d);
    if (recipient === null || d.tagKeyId !== ring.active.keyId || !(await verifyBindingTag(binding, recipient, d.tag))) devices.push(d.id);
  }
  const factors: string[] = [];
  for (const w of ring.wraps) {
    const keyed = [w.factorKey, w.tag, w.tagKeyId].filter((x) => x !== null).length;
    if (keyed === 0) continue; // a factor not yet given its key (before the upgrade)
    const recipient = keyed === 3 ? factorRecipient(w) : null;
    if (recipient === null || w.tagKeyId !== ring.active.keyId || !(await verifyBindingTag(binding, recipient, w.tag!))) factors.push(w.id);
  }
  return flaggedOf(devices, factors);
}

/** The binding key of the ring's active key (A5). */
export function bindingOf(ring: Ring, active: MailboxPrivateKey): Promise<BindingKey> {
  return bindingKey(active, { mailboxId: ring.mailboxId });
}
