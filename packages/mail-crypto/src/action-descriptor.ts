/**
 * Action descriptors (contracts/action-descriptor-v1.md) and the actions they
 * describe (contracts/device-v1.md A10).
 *
 * A descriptor is the UTF-8 of the RFC 8785 serialization of one object. Mail
 * issues it with a challenge; the browser builds the descriptor it expects
 * for the request it is about to send and compares bytes; the dashboard shows
 * an email code's action from the same bytes it hashes. Every reader does the
 * contract's four steps, in order, and refuses at the first failure:
 *
 *   1. at most 8,192 bytes, strict UTF-8, no byte order mark;
 *   2. JSON.parse, serialize again with RFC 8785: the bytes must be the bytes
 *      read (this refuses whitespace, members out of order, duplicate
 *      members, escapes RFC 8785 does not write, and lone surrogates);
 *   3. an object with exactly the members of the table, for its kind;
 *   4. every rule of the table.
 *
 * The digest is base64url SHA-256 of the exact bytes; nothing re-serializes
 * to compute it.
 */
import { base64url, bytesEqual, fromBase64url, fromUtf8, utf8 } from "./bytes";
import { canonicalJson } from "./canonical-json";

export type ActionKind = "revoke-device" | "remove-devices" | "register-device" | "add-factor" | "remove-factor" | "open-session" | "upgrade";

/** What confirms an action: an email code (attested by the dashboard), a factor proof, or a key proof. */
export type ActionPurpose = "email" | "factor" | "key";

export const ACTION_KINDS: readonly ActionKind[] = Object.freeze([
  "revoke-device",
  "remove-devices",
  "register-device",
  "add-factor",
  "remove-factor",
  "open-session",
  "upgrade",
] as const);

const PURPOSE: Readonly<Record<ActionKind, ActionPurpose>> = Object.freeze({
  "revoke-device": "email",
  "remove-devices": "factor",
  "register-device": "factor",
  "add-factor": "factor",
  "remove-factor": "factor",
  "open-session": "factor",
  upgrade: "key",
});

/** How many targets each kind names, inclusive. */
const TARGETS: Readonly<Record<ActionKind, readonly [number, number]>> = Object.freeze({
  "revoke-device": [1, 20],
  "remove-devices": [0, 20],
  "register-device": [1, 1],
  "add-factor": [0, 0],
  "remove-factor": [0, 0],
  "open-session": [0, 0],
  upgrade: [0, 0],
});

export interface ActionTarget {
  readonly deviceId: string;
  readonly label: string;
}

/** The descriptor's object. `request` is present exactly for the kinds other than revoke-device. */
export interface ActionDescriptor {
  version: 1;
  kind: ActionKind;
  mailboxId: string;
  targets: ActionTarget[];
  /** 32 random bytes drawn by Mail, base64url without padding (43 characters). */
  nonce: string;
  /** Whole seconds since 1970-01-01T00:00:00Z when Mail issued it. */
  issuedAt: number;
  /** base64url SHA-256 of the RFC 8785 request the confirmed call carries (requestDigest). */
  request?: string;
}

/** contracts/device-v1.md A10: the action `challenge` takes. */
export type ActionInput =
  | { kind: "revoke-device"; deviceIds: string[] }
  | { kind: "remove-devices"; deviceIds: string[]; request: string }
  | { kind: "register-device"; device: { id: string; label: string }; request: string }
  | { kind: "add-factor" | "remove-factor" | "open-session"; request: string }
  | { kind: "upgrade"; request: string };

export const MAX_ACTION_DESCRIPTOR_BYTES = 8192;

const MAILBOX_ID = /^mbx_[0-7][0-9a-hjkmnp-tv-z]{25}$/;
const DEVICE_ID = /^dev_[0-7][0-9a-hjkmnp-tv-z]{25}$/;
const DIGEST = /^[A-Za-z0-9_-]{43}$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const FORBIDDEN_IN_LABEL = /[\u0000-\u001F\u007F-\u009F\u2028\u2029]/;
const BASE_MEMBERS = ["issuedAt", "kind", "mailboxId", "nonce", "targets", "version"];

function isKind(value: unknown): value is ActionKind {
  return typeof value === "string" && (ACTION_KINDS as readonly string[]).includes(value);
}

/** The purpose whose challenge confirms `kind`. */
export function actionPurpose(kind: ActionKind): ActionPurpose {
  if (!isKind(kind)) throw new TypeError(`unknown action kind: ${String(kind)}`);
  return PURPOSE[kind];
}

/**
 * A device's label as Mail holds it (action-descriptor-v1 `targets[].label`,
 * and device-v1 B7's DeviceInput): 1 to 40 code points, none of U+0000 to
 * U+001F, U+007F to U+009F, U+2028 or U+2029, and no lone surrogate.
 */
export function isDeviceLabel(label: unknown): label is string {
  if (typeof label !== "string" || label.length === 0 || LONE_SURROGATE.test(label) || FORBIDDEN_IN_LABEL.test(label)) return false;
  let codePoints = 0;
  for (const _ of label) codePoints++;
  return codePoints <= 40;
}

/** 43 base64url characters that decode, strictly, to 32 bytes. */
function isDigest(value: unknown): value is string {
  return typeof value === "string" && DIGEST.test(value) && fromBase64url(value)?.length === 32;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function hasExactly(value: Record<string, unknown>, members: readonly string[]): boolean {
  const own = Object.keys(value).sort();
  const want = [...members].sort();
  return own.length === want.length && own.every((m, i) => m === want[i]);
}

/** Steps 3 and 4: the first rule `value` breaks, or null when it is a descriptor. */
function problemOf(value: unknown): string | null {
  if (!isPlainObject(value)) return "a descriptor is a JSON object";
  if (!isKind(value.kind)) return "an unknown kind";
  const kind = value.kind;
  if (!hasExactly(value, kind === "revoke-device" ? BASE_MEMBERS : [...BASE_MEMBERS, "request"])) {
    return kind === "revoke-device" ? "revoke-device has exactly six members, and no request" : `${kind} has exactly seven members, its request included`;
  }
  if (value.version !== 1) return "version is the number 1";
  if (typeof value.mailboxId !== "string" || !MAILBOX_ID.test(value.mailboxId)) return "mailboxId is mbx_ and 26 lowercase Crockford symbols";
  if (!isDigest(value.nonce)) return "nonce is base64url (no padding) of 32 bytes";
  if (typeof value.issuedAt !== "number" || !Number.isSafeInteger(value.issuedAt) || value.issuedAt < 0) return "issuedAt is a whole number of seconds, at least 0";
  if (kind !== "revoke-device" && !isDigest(value.request)) return "request is base64url (no padding) of a 32-byte SHA-256 digest";
  const targets = value.targets;
  if (!Array.isArray(targets)) return "targets is an array";
  const [min, max] = TARGETS[kind];
  if (targets.length < min || targets.length > max) return `${kind} names ${min === max ? min : `${min} to ${max}`} devices`;
  let previous: string | null = null;
  for (const target of targets as unknown[]) {
    if (!isPlainObject(target) || !hasExactly(target, ["deviceId", "label"])) return "a target is exactly { deviceId, label }";
    if (typeof target.deviceId !== "string" || !DEVICE_ID.test(target.deviceId)) return "deviceId is dev_ and 26 lowercase Crockford symbols";
    if (!isDeviceLabel(target.label)) return "a label has 1 to 40 code points, one line, well-formed";
    if (previous !== null && !(previous < target.deviceId)) return "targets are sorted by deviceId, each device once";
    previous = target.deviceId;
  }
  return null;
}

function frozen(value: ActionDescriptor): ActionDescriptor {
  for (const target of value.targets) Object.freeze(target);
  Object.freeze(value.targets);
  return Object.freeze(value);
}

/**
 * The descriptor's bytes, from its fields. Targets are sorted by deviceId on
 * the way (the caller's array is left as it is); every other rule of the
 * table is checked, and a descriptor that breaks one is a TypeError.
 */
export function buildActionDescriptor(descriptor: ActionDescriptor): Uint8Array<ArrayBuffer> {
  if (!isPlainObject(descriptor)) throw new TypeError("a descriptor is a JSON object");
  const sorted: Record<string, unknown> = { ...descriptor };
  if (Array.isArray(descriptor.targets)) {
    sorted.targets = [...descriptor.targets].sort((a, b) => {
      const x = (a as { deviceId?: unknown } | null)?.deviceId;
      const y = (b as { deviceId?: unknown } | null)?.deviceId;
      return typeof x === "string" && typeof y === "string" ? (x < y ? -1 : x > y ? 1 : 0) : 0;
    });
  }
  const problem = problemOf(sorted);
  if (problem !== null) throw new TypeError(`not an action descriptor: ${problem}`);
  const bytes = utf8(canonicalJson(sorted));
  if (bytes.length > MAX_ACTION_DESCRIPTOR_BYTES) throw new TypeError("an action descriptor is at most 8,192 bytes");
  return bytes;
}

/** Reads a descriptor by the contract's four steps: the object, frozen, or null at the first failure. */
export function readActionDescriptor(bytes: Uint8Array): ActionDescriptor | null {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_ACTION_DESCRIPTOR_BYTES) return null;
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return null; // a byte order mark
  let value: unknown;
  let again: Uint8Array;
  try {
    value = JSON.parse(fromUtf8(bytes));
    again = utf8(canonicalJson(value));
  } catch {
    return null;
  }
  if (!bytesEqual(again, bytes)) return null;
  if (problemOf(value) !== null) return null;
  return frozen(value as ActionDescriptor);
}

/** base64url (no padding) of SHA-256 over the descriptor's exact bytes. */
export async function actionDigest(bytes: Uint8Array): Promise<string> {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("a descriptor's digest is taken over its bytes");
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes))));
}

function exactly(action: Record<string, unknown>, members: readonly string[]): void {
  if (!hasExactly(action, members)) throw new TypeError(`${String(action.kind)} takes exactly ${members.join(", ")}`);
}

function deviceIdsOf(value: unknown): string[] {
  if (!Array.isArray(value) || !value.every((id) => typeof id === "string")) throw new TypeError("deviceIds is an array of device ids");
  if (new Set(value).size !== value.length) throw new TypeError("each device appears once");
  return value as string[];
}

/**
 * The descriptor of an action (A10's ActionInput) as Mail issues it: the
 * devices of revoke-device and remove-devices with the labels from Mail's own
 * records (`labels`, by device id; a device it does not hold is a
 * TypeError), the device of register-device with the label from its request,
 * and the request digest for every kind but revoke-device. The browser calls
 * it with Mail's nonce and issuedAt to build the bytes it expects.
 */
export function actionDescriptorFor(
  action: ActionInput,
  issue: { mailboxId: string; nonce: string; issuedAt: number; labels?: ReadonlyMap<string, string> },
): ActionDescriptor {
  if (!isPlainObject(action) || !isKind(action.kind)) throw new TypeError(`unknown action kind: ${String((action as { kind?: unknown } | null)?.kind)}`);
  const record = action as Record<string, unknown>;
  const labelOf = (deviceId: string): string => {
    const label = issue.labels?.get(deviceId);
    if (label === undefined) throw new TypeError(`no device ${deviceId} in this mailbox`);
    return label;
  };
  let targets: ActionTarget[] = [];
  switch (action.kind) {
    case "revoke-device":
      exactly(record, ["kind", "deviceIds"]);
      targets = deviceIdsOf(record.deviceIds).map((deviceId) => ({ deviceId, label: labelOf(deviceId) }));
      break;
    case "remove-devices":
      exactly(record, ["kind", "deviceIds", "request"]);
      targets = deviceIdsOf(record.deviceIds).map((deviceId) => ({ deviceId, label: labelOf(deviceId) }));
      break;
    case "register-device": {
      exactly(record, ["kind", "device", "request"]);
      const device = record.device;
      if (!isPlainObject(device) || !hasExactly(device, ["id", "label"])) throw new TypeError("register-device's device is exactly { id, label }");
      targets = [{ deviceId: device.id as string, label: device.label as string }];
      break;
    }
    default:
      exactly(record, ["kind", "request"]);
  }
  const descriptor: ActionDescriptor = { version: 1, kind: action.kind, mailboxId: issue.mailboxId, targets, nonce: issue.nonce, issuedAt: issue.issuedAt };
  if (action.kind !== "revoke-device") descriptor.request = record.request as string;
  const bytes = buildActionDescriptor(descriptor); // every rule of the table, and the targets sorted
  return readActionDescriptor(bytes)!;
}
