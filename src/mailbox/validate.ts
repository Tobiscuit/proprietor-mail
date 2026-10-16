import { InvalidRequest } from "../errors";

/**
 * Strict shape checks for what crosses the RPC boundary. Every request object
 * is checked against an allow-list of fields and an unknown field is refused:
 * nothing the caller adds is stored or acted on by accident, and in
 * particular no method accepts a private key under any name (domain-model M3).
 *
 * Error messages name the field, never echo a value.
 */

export type Plain = Record<string, unknown>;

function fieldName(name: string): string {
  return /^[A-Za-z_][A-Za-z0-9_]{0,40}$/.test(name) ? name : "(unnamed)";
}

export function object(value: unknown, what: string, allowed: readonly string[]): Plain {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new InvalidRequest(`${what} must be an object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new InvalidRequest(`${what} must be a plain object`);
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new InvalidRequest(`unexpected field ${fieldName(key)} in ${what}`);
  }
  return value as Plain;
}

const CONTROL = /[\u0000-\u001f\u007f]/;

export function text(value: unknown, what: string, opts: { max: number; min?: number; singleLine?: boolean }): string {
  if (typeof value !== "string") throw new InvalidRequest(`${what} must be a string`);
  if (value.length < (opts.min ?? 0)) throw new InvalidRequest(`${what} is too short`);
  if (value.length > opts.max) throw new InvalidRequest(`${what} is too long`);
  if (opts.singleLine && CONTROL.test(value)) throw new InvalidRequest(`${what} must not contain control characters`);
  return value;
}

export function optional<T>(value: unknown, parse: (v: unknown) => T): T | undefined {
  return value === undefined ? undefined : parse(value);
}

export function bool(value: unknown, what: string): boolean {
  if (typeof value !== "boolean") throw new InvalidRequest(`${what} must be true or false`);
  return value;
}

export function integer(value: unknown, what: string, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw new InvalidRequest(`${what} must be an integer from ${min} to ${max}`);
  }
  return value;
}

export function oneOf<T extends string>(value: unknown, what: string, options: readonly T[]): T {
  if (typeof value !== "string" || !(options as readonly string[]).includes(value)) {
    throw new InvalidRequest(`${what} must be one of ${options.join(", ")}`);
  }
  return value as T;
}

export function array(value: unknown, what: string, max: number): unknown[] {
  if (!Array.isArray(value)) throw new InvalidRequest(`${what} must be a list`);
  if (value.length > max) throw new InvalidRequest(`${what} has too many entries`);
  return value;
}

const B64URL = /^[A-Za-z0-9_-]*$/;

/** base64url without padding; `bytes` pins the decoded length. */
export function base64url(value: unknown, what: string, opts: { bytes?: number; maxChars?: number }): string {
  if (typeof value !== "string" || !B64URL.test(value) || value.length % 4 === 1) {
    throw new InvalidRequest(`${what} must be base64url`);
  }
  if (opts.maxChars !== undefined && value.length > opts.maxChars) throw new InvalidRequest(`${what} is too long`);
  if (opts.bytes !== undefined && Math.floor((value.length * 3) / 4) !== opts.bytes) {
    throw new InvalidRequest(`${what} must be ${opts.bytes} bytes`);
  }
  return value;
}

export function decodeBase64url(value: string): Uint8Array {
  const b64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function encodeBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const CROCKFORD_ID = (prefix: string) => new RegExp(`^${prefix}_[0-9abcdefghjkmnpqrstvwxyz]{26}$`);
const IDS = {
  msg: CROCKFORD_ID("msg"),
  drf: CROCKFORD_ID("drf"),
  wrp: CROCKFORD_ID("wrp"),
  mbx: CROCKFORD_ID("mbx"),
  // contracts/device-v1.md A1: a kept device (made by the browser) and a challenge (made by Mail).
  dev: CROCKFORD_ID("dev"),
  chl: CROCKFORD_ID("chl"),
};

export function id(value: unknown, what: string, prefix: keyof typeof IDS): string {
  if (typeof value !== "string" || !IDS[prefix].test(value)) throw new InvalidRequest(`${what} must be a ${prefix}_ id`);
  return value;
}

export const KEY_ID = /^[0-9a-f]{32}$/;

// An address the platform will put in an envelope: no spaces, brackets,
// quotes or line breaks, one @, at most 254 characters.
const ADDRESS = /^[^\s@<>()[\]",;:\\]+@[^\s@<>()[\]",;:\\]+\.[^\s@<>()[\]",;:\\]+$/;

export function address(value: unknown, what: string): string {
  if (typeof value !== "string" || value.length > 254 || !ADDRESS.test(value) || CONTROL.test(value)) {
    throw new InvalidRequest(`${what} must be an email address`);
  }
  return value;
}

export interface Recipient {
  name?: string;
  address: string;
}

export function recipient(value: unknown, what: string): Recipient {
  const v = object(value, what, ["name", "address"]);
  const name = optional(v.name, (n) => text(n, `${what} name`, { max: 200, singleLine: true }));
  return name === undefined ? { address: address(v.address, `${what} address`) } : { name, address: address(v.address, `${what} address`) };
}
