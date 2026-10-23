/**
 * Confirmations bound to their action (contracts/device-v1.md A6, A10, Part C
 * K4 and K12; round 3, D36).
 *
 * Every factor proof and key proof answers a challenge whose action descriptor
 * names the very call that carries it. The browser never takes Mail's word for
 * which action that is: it builds the descriptor it expects from its OWN
 * request (the kind, the mailbox, the devices with the labels its view lists,
 * and the request's digest), with only Mail's nonce and time taken from Mail's
 * bytes, compares the two byte strings, and opens the challenge with the
 * associated data made from its own digest. A challenge issued for another
 * action is answered with nothing (InvalidChallenge).
 */
import {
  actionDescriptorFor,
  actionDigest,
  actionPurpose,
  buildActionDescriptor,
  readActionDescriptor,
  requestDigest,
  type ActionInput,
  type ActionKind,
} from "@proprietor/mail-crypto";
import { bytesEqual, fromBase64url } from "./bytes";
import { InvalidChallenge } from "./errors";
import type { ChallengeView, Confirmation, MailboxView, RevokeRequest } from "./types";

/** A frozen Confirmation of `action`, with the labels of the devices it names. */
export function confirmationOf(action: ActionInput, labels: Readonly<Record<string, string>> = {}): Confirmation {
  const copy = structuredClone(action) as ActionInput;
  for (const value of Object.values(copy)) if (typeof value === "object" && value !== null) Object.freeze(value);
  return Object.freeze({ action: Object.freeze(copy), labels: Object.freeze({ ...labels }) });
}

/** The Confirmation of a call whose request Mail digests (A10): its kind, the request's digest, and what else the kind names. */
export async function confirmationFor(
  kind: Exclude<ActionKind, "revoke-device">,
  request: { readonly [member: string]: unknown },
  more: { deviceIds?: readonly string[]; device?: { id: string; label: string }; labels?: Readonly<Record<string, string>> } = {},
): Promise<Confirmation> {
  const digest = await requestDigest(request);
  let action: ActionInput;
  switch (kind) {
    case "remove-devices":
      action = { kind, deviceIds: [...(more.deviceIds ?? [])], request: digest };
      break;
    case "register-device":
      if (more.device === undefined) throw new TypeError("register-device names its device");
      action = { kind, device: { id: more.device.id, label: more.device.label }, request: digest };
      break;
    case "upgrade":
      action = { kind, request: digest };
      break;
    default:
      action = { kind, request: digest };
  }
  return confirmationOf(action, more.labels ?? {});
}

function isConfirmation(value: unknown): value is Confirmation {
  if (typeof value !== "object" || value === null) return false;
  const c = value as { action?: unknown; labels?: unknown };
  return typeof c.action === "object" && c.action !== null && typeof c.labels === "object" && c.labels !== null;
}

/**
 * K4, K12: the digest to open `challenge` with, after Mail's descriptor proved to be exactly the one
 * `confirmation` makes (Mail's nonce and time aside). InvalidChallenge, and nothing answered, when Mail's
 * bytes are missing, malformed, or describe anything else; a TypeError when the confirmation is not one
 * for `purpose` (a caller's mistake).
 */
export async function expectedDigest(challenge: ChallengeView, confirmation: Confirmation, mailboxId: string, purpose: "factor" | "key"): Promise<string> {
  if (!isConfirmation(confirmation)) throw new TypeError("a Confirmation: the action this proof confirms");
  let kindPurpose: string;
  try {
    kindPurpose = actionPurpose(confirmation.action.kind);
  } catch {
    throw new TypeError("an unknown action kind");
  }
  if (kindPurpose !== purpose) throw new TypeError(`a ${purpose} proof does not confirm ${confirmation.action.kind}`);
  const bytes = typeof challenge.descriptor === "string" ? fromBase64url(challenge.descriptor) : null;
  const theirs = bytes === null ? null : readActionDescriptor(bytes);
  if (bytes === null || theirs === null) throw new InvalidChallenge("the challenge carries no readable action descriptor");
  let expected: Uint8Array;
  try {
    const labels = new Map(Object.entries(confirmation.labels));
    expected = buildActionDescriptor(actionDescriptorFor(confirmation.action, { mailboxId, nonce: theirs.nonce, issuedAt: theirs.issuedAt, labels }));
  } catch {
    throw new InvalidChallenge("the action this proof confirms cannot be described");
  }
  if (!bytesEqual(expected, bytes)) throw new InvalidChallenge("the challenge was issued for another action");
  return actionDigest(expected);
}

/**
 * F13, B7a: the email challenge's action and revokeDevices' request, for devices the view lists (1 to 20,
 * each once, sorted by id as the descriptor names them). An email code revokes and does nothing else: no
 * key is opened, made or sealed here, and no unlock is needed.
 */
export function revokeRequest(view: MailboxView, deviceIds: readonly string[]): RevokeRequest {
  if (typeof view !== "object" || view === null || !Array.isArray(view.devices)) throw new TypeError("a MailboxView that lists its devices");
  if (!Array.isArray(deviceIds) || deviceIds.length < 1 || deviceIds.length > 20 || !deviceIds.every((id) => typeof id === "string")) {
    throw new TypeError("1 to 20 device ids");
  }
  const ids = [...new Set(deviceIds)].sort();
  if (ids.length !== deviceIds.length) throw new TypeError("each device appears once");
  for (const id of ids) if (!view.devices.some((d) => d.id === id)) throw new TypeError("the view does not list that device");
  return Object.freeze({
    action: Object.freeze({ kind: "revoke-device" as const, deviceIds: Object.freeze([...ids]) as string[] }),
    request: Object.freeze({ deviceIds: Object.freeze([...ids]) as string[] }),
  });
}
