import {
  type ActionInput,
  type ActionKind,
  type ActionPurpose,
  actionDescriptorFor,
  actionPurpose,
  buildActionDescriptor,
  readActionDescriptor,
  requestDigest,
} from "@proprietor/mail-crypto";
import { InvalidRequest } from "../errors";
import { rows } from "./store";
import type { MailboxStore } from "./store";
import * as v from "./validate";

/**
 * Confirmations bound to their action (contracts/device-v1.md A6, A10, B3,
 * B7a; action-descriptor-v1; domain-model M17′, M22; spec D36). The one
 * module that
 *
 *   - issues an action descriptor with `challenge` (the kind checked against
 *     the purpose, the devices against Mail's own records, their labels from
 *     those records, Mail's nonce and time);
 *   - checks that a factor or key proof's challenge names the very call that
 *     carries it: its kind, the devices it names, and the digest of the
 *     call's own request, which Mail computes again from the call's
 *     arguments (A10's table, below);
 *   - checks the dashboard's attestation of an email code (B7a).
 *
 * Every byte format comes from @proprietor/mail-crypto: one RFC 8785
 * serializer, one descriptor builder and reader. Nothing here serializes
 * JSON canonically by itself.
 */

/** The kinds a factor or key proof confirms (A10): every kind but revoke-device, which only an email code confirms. */
export type ProvedKind = Exclude<ActionKind, "revoke-device">;

/**
 * What a call's proof must confirm, as the call itself carries it (A10's
 * table): the kind, the request object exactly as sent (the digest is taken
 * over it), and for remove-devices and register-device what the descriptor's
 * targets must be. Built by each Mailbox method from its own raw arguments.
 */
export interface Bound {
  kind: ProvedKind;
  /** remove-devices `{ deviceIds, rotation }`, register-device `{ device, seal }`, add-factor the wrap, remove-factor `{ wrapId }`, open-session `{ challengeId }`, upgrade `{ factors }`. */
  request: unknown;
  /** remove-devices: the call's deviceIds (the descriptor's targets, sorted). */
  deviceIds?: unknown;
  /** register-device: the call's device (the descriptor's one target is its id and label). */
  device?: unknown;
}

/** A Bound with its digest computed (the one await), ready for the synchronous check. */
export interface PreparedBinding {
  kind: ProvedKind;
  /** A10's request digest; null when the request does not serialize (it holds a number, a boolean, bytes…). */
  digest: string | null;
  /** The targets the descriptor must name, as comparable text; null when the call's own are malformed. */
  targets: string;
}

/** The digest of the call's request, computed before anything is spent, so that the spend and the comparison happen with no await between them. */
export async function prepareBinding(bound: Bound): Promise<PreparedBinding> {
  let digest: string | null;
  try {
    digest = await requestDigest(bound.request as { readonly [member: string]: unknown });
  } catch {
    digest = null;
  }
  return { kind: bound.kind, digest, targets: targetsOfCall(bound) };
}

function targetsOfCall(bound: Bound): string {
  if (bound.kind === "remove-devices") {
    const ids = bound.deviceIds;
    return Array.isArray(ids) && ids.every((id) => typeof id === "string") ? JSON.stringify([...(ids as string[])].sort()) : "malformed";
  }
  if (bound.kind === "register-device") {
    const d = bound.device as { id?: unknown; label?: unknown } | null | undefined;
    return typeof d === "object" && d !== null && typeof d.id === "string" && typeof d.label === "string"
      ? JSON.stringify([{ deviceId: d.id, label: d.label }])
      : "malformed";
  }
  return JSON.stringify([]);
}

function targetsOfDescriptor(kind: ProvedKind, targets: readonly { deviceId: string; label: string }[]): string {
  if (kind === "remove-devices") return JSON.stringify(targets.map((t) => t.deviceId));
  if (kind === "register-device") return JSON.stringify(targets.map((t) => ({ deviceId: t.deviceId, label: t.label })));
  return JSON.stringify(targets.map((t) => t.deviceId));
}

/** The columns of a challenge this module reads. */
export interface BoundChallenge {
  kind: string | null;
  descriptor: string | null;
}

/**
 * M17′, synchronous: does the spent challenge's descriptor name this call?
 * "request" when the call's request does not serialize (no descriptor can
 * name it: InvalidRequest), "action" when the descriptor names another
 * action (ProofRejected), null when it is this call's.
 */
export function bindingProblem(challenge: BoundChallenge, prepared: PreparedBinding): "request" | "action" | null {
  if (prepared.digest === null) return "request";
  if (challenge.kind !== prepared.kind || challenge.descriptor === null) return "action";
  const d = readActionDescriptor(v.decodeBase64url(challenge.descriptor));
  if (d === null || d.kind !== prepared.kind || d.request !== prepared.digest) return "action";
  return targetsOfDescriptor(prepared.kind, d.targets) === prepared.targets ? null : "action";
}

/**
 * B6, A10: the descriptor `challenge` issues for `purpose`: the action's kind
 * must belong to the purpose, every device it names must be one Mail holds
 * (labels from Mail's records), and the bytes must pass every rule of
 * action-descriptor-v1. Anything else is InvalidRequest. Synchronous, so the
 * labels are read and the bytes made against one state.
 */
export function describeAction(
  store: MailboxStore,
  purpose: ActionPurpose,
  action: unknown,
  issue: { nonce: string; issuedAt: number },
): { kind: ActionKind; bytes: Uint8Array } {
  if (typeof action !== "object" || action === null || Array.isArray(action)) throw new InvalidRequest("a challenge of this purpose names its action");
  const kind = (action as { kind?: unknown }).kind;
  let kindPurpose: ActionPurpose;
  try {
    kindPurpose = actionPurpose(kind as ActionKind);
  } catch {
    throw new InvalidRequest("an unknown action kind");
  }
  if (kindPurpose !== purpose) throw new InvalidRequest("the action's kind does not belong to this purpose");
  const labels = new Map(rows<{ id: string; label: string }>(store.sql, "SELECT id, label FROM devices").map((d) => [d.id, d.label]));
  try {
    const bytes = buildActionDescriptor(actionDescriptorFor(structuredClone(action) as ActionInput, { mailboxId: store.mailboxId, nonce: issue.nonce, issuedAt: issue.issuedAt, labels }));
    return { kind: kind as ActionKind, bytes };
  } catch {
    // A device Mail does not hold, a malformed action, a label outside the rule, more than 20 devices…
    throw new InvalidRequest("the action cannot be described: a device that is not in the mailbox, or an action outside the contract");
  }
}

// ---- the dashboard's attestation of an email code (B7a, action-descriptor-v1) ----------------------

/** action-descriptor-v1's attestation table: Mail's own list of kinds an email code may confirm. Nothing else is on it (D35). */
export const EMAIL_CODE_KINDS: readonly ActionKind[] = Object.freeze(["revoke-device"] as const);
/** `at` is at most 300 seconds before Mail's clock, and at most 5 seconds after it. */
export const ATTESTATION_MAX_AGE_SECONDS = 300;
export const ATTESTATION_MAX_AHEAD_SECONDS = 5;

/** The attestation rules that need no challenge: the first one `attestation` breaks, or null. */
export function attestationProblem(
  attestation: { method: string; accountId: string; actionKind: string; at: number },
  expected: { sub: string; nowSeconds: number; issuedAt: number; descriptorKind: string },
): string | null {
  if (attestation.method !== "email-code") return "method";
  if (attestation.accountId !== expected.sub) return "account";
  if (!(EMAIL_CODE_KINDS as readonly string[]).includes(attestation.actionKind) || attestation.actionKind !== expected.descriptorKind) return "kind";
  if (attestation.at < expected.nowSeconds - ATTESTATION_MAX_AGE_SECONDS) return "late";
  if (attestation.at > expected.nowSeconds + ATTESTATION_MAX_AHEAD_SECONDS) return "early";
  if (attestation.at < expected.issuedAt) return "before-issue";
  return null;
}

/** The devices a revoke-device descriptor names, sorted as it names them; null when the bytes are not such a descriptor. */
export function revokeTargets(descriptor: string): { deviceIds: string[]; issuedAt: number; kind: ActionKind } | null {
  const d = readActionDescriptor(v.decodeBase64url(descriptor));
  return d === null ? null : { deviceIds: d.targets.map((t) => t.deviceId), issuedAt: d.issuedAt, kind: d.kind };
}
