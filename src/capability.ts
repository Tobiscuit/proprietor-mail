import { base64url, decodeProtectedHeader, errors, jwtVerify } from "jose";
import { CapabilityRejected } from "./errors";
import type { Attestation } from "./mailbox/types";

/**
 * Verifies a Mail capability (contracts/capability-v1.md): a ≤ 60-second HS256
 * JWT the dashboard mints for one person, one business and (usually) one
 * mailbox. Mail never sees how the person logged in; it sees this statement
 * and checks it. The rule numbers below are the contract's.
 *
 * Rules 7 and 8 (the Directory row and the mailbox policy) are the caller's:
 * MailService and the Mailbox apply them after this returns.
 */

export type Role = "owner" | "editor";

export interface Capability {
  iss: typeof ISSUER;
  aud: typeof AUDIENCE;
  /** The dashboard's account id of the person acting. */
  sub: string;
  business: string;
  /** Absent only for `mailboxes()`. */
  mbx?: string;
  role: Role;
  iat: number;
  exp: number;
  /** Random, required; logged on every call so one request can be traced across both Workers. */
  jti: string;
  /**
   * Round 3 (amended 2026-10-22): the dashboard's attestation of an email
   * code, present only when the caller asked for it to be read (only
   * `revokeDevices` does, B7a) and the token carries one. Read strictly: a
   * malformed claim there is CapabilityRejected (invalid). Every other method
   * never reads it, so for them it is ignored, whatever it holds.
   */
  confirmation?: Attestation;
}

export type CapabilityKeys = ReadonlyMap<string, Uint8Array>;

const ISSUER = "proprietor-dashboard";
const AUDIENCE = "proprietor-mail";
const TOLERANCE_SECONDS = 5;
const MAX_LIFETIME_SECONDS = 60;

/**
 * `MAIL_CAPABILITY_KEYS`: a JSON object of key id → base64url 32-byte key.
 * Fails closed: anything malformed yields no usable key, so every capability
 * is refused. A bad entry is reported by its key id only, never its value.
 */
export function parseCapabilityKeys(json: string | undefined): CapabilityKeys {
  const keys = new Map<string, Uint8Array>();
  if (json === undefined) return keys;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    console.error(JSON.stringify({ event: "capability-keys-misconfigured", problem: "not JSON" }));
    return keys;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    console.error(JSON.stringify({ event: "capability-keys-misconfigured", problem: "not an object" }));
    return keys;
  }
  for (const [kid, value] of Object.entries(parsed)) {
    let bytes: Uint8Array | null = null;
    try {
      bytes = typeof value === "string" ? base64url.decode(value) : null;
    } catch {
      bytes = null;
    }
    if (bytes === null || bytes.length !== 32) {
      console.error(JSON.stringify({ event: "capability-keys-misconfigured", problem: "not a 32-byte key", kid }));
      continue;
    }
    keys.set(kid, bytes);
  }
  return keys;
}

const isNonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * capability-v1's `confirmation` claim, in shape: exactly the six members of
 * action-descriptor-v1's attestation, with their types (`at` a whole number,
 * `actionDigest` 43 base64url characters, `codeId` at most 64 characters of
 * [A-Za-z0-9_-]). What it is worth (the method, the account, the kind, the
 * digest of a live email challenge, the time) is the Mailbox's to check
 * (src/mailbox/devices.ts, revokeDevices). Anything else is
 * CapabilityRejected (invalid).
 */
export function readConfirmation(claim: unknown): Attestation {
  if (typeof claim !== "object" || claim === null || Array.isArray(claim)) throw new CapabilityRejected("invalid");
  const c = claim as Record<string, unknown>;
  const members = Object.keys(c).sort();
  const expected = ["accountId", "actionDigest", "actionKind", "at", "codeId", "method"];
  if (members.length !== expected.length || members.some((m, i) => m !== expected[i])) throw new CapabilityRejected("invalid");
  const { method, accountId, actionKind, actionDigest, at, codeId } = c;
  if (!isNonEmptyString(method) || !isNonEmptyString(accountId) || !isNonEmptyString(actionKind)) throw new CapabilityRejected("invalid");
  if (typeof actionDigest !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(actionDigest)) throw new CapabilityRejected("invalid");
  if (typeof at !== "number" || !Number.isSafeInteger(at) || at < 0) throw new CapabilityRejected("invalid");
  if (typeof codeId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(codeId)) throw new CapabilityRejected("invalid");
  return { method, accountId, actionKind, actionDigest, at, codeId };
}

export async function verifyCapability(token: string, keys: CapabilityKeys, nowSeconds: number, options: { confirmation?: boolean } = {}): Promise<Capability> {
  // Rule 1, before any key is looked up: HS256 and nothing else, `none` included.
  let kid: unknown;
  try {
    const header = decodeProtectedHeader(token);
    if (header.alg !== "HS256") throw new CapabilityRejected("invalid");
    kid = header.kid;
  } catch {
    throw new CapabilityRejected("invalid");
  }

  // Rule 2: the kid names a configured key.
  const key = typeof kid === "string" ? keys.get(kid) : undefined;
  if (key === undefined) throw new CapabilityRejected("invalid");

  // Rules 3-5 in jose: the signature (constant-time), iss and aud exactly, exp
  // with 5 s of tolerance. A passed exp is the one refusal that says `expired`.
  let payload: Record<string, unknown>;
  try {
    ({ payload } = await jwtVerify(token, key, {
      algorithms: ["HS256"],
      issuer: ISSUER,
      audience: AUDIENCE,
      currentDate: new Date(nowSeconds * 1000),
      clockTolerance: TOLERANCE_SECONDS,
      requiredClaims: ["iat", "exp", "sub", "jti"],
    }));
  } catch (err) {
    throw new CapabilityRejected(err instanceof errors.JWTExpired ? "expired" : "invalid");
  }

  // Rule 4, exactly: jose also accepts an `aud` array that contains ours.
  if (payload.aud !== AUDIENCE || payload.iss !== ISSUER) throw new CapabilityRejected("invalid");

  // Rule 5, the parts jose leaves to us: iat at most 5 s ahead, 1 ≤ exp - iat ≤ 60.
  const { iat, exp } = payload;
  if (typeof iat !== "number" || typeof exp !== "number") throw new CapabilityRejected("invalid");
  if (iat > nowSeconds + TOLERANCE_SECONDS) throw new CapabilityRejected("invalid");
  const lifetime = exp - iat;
  if (lifetime < 1 || lifetime > MAX_LIFETIME_SECONDS) throw new CapabilityRejected("invalid");

  // Rule 6, plus the required jti (contract amendment, 2026-09-26).
  const { sub, business, mbx, role, jti } = payload;
  if (!isNonEmptyString(sub) || !isNonEmptyString(business) || !isNonEmptyString(jti)) {
    throw new CapabilityRejected("invalid");
  }
  if (role !== "owner" && role !== "editor") throw new CapabilityRejected("invalid");
  if (mbx !== undefined && !isNonEmptyString(mbx)) throw new CapabilityRejected("invalid");

  // Exactly the claims that were checked, in the contract's order.
  const capability: Capability =
    mbx === undefined
      ? { iss: ISSUER, aud: AUDIENCE, sub, business, role, iat, exp, jti }
      : { iss: ISSUER, aud: AUDIENCE, sub, business, mbx, role, iat, exp, jti };
  // The confirmation claim, only for the one method that reads it (B7a); everywhere else it is never looked at.
  if (options.confirmation === true && payload.confirmation !== undefined) capability.confirmation = readConfirmation(payload.confirmation);
  return capability;
}

/**
 * The jti as it may appear in a log line: printable, bounded. For a refused
 * token it comes from the UNVERIFIED payload (so both sides can still find the
 * request), which is why it is filtered rather than trusted.
 */
export function loggableJti(token: string): string | null {
  const payloadPart = token.split(".")[1];
  if (payloadPart === undefined) return null;
  try {
    const jti = (JSON.parse(new TextDecoder().decode(base64url.decode(payloadPart))) as { jti?: unknown }).jti;
    return typeof jti === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(jti) ? jti : null;
  } catch {
    return null;
  }
}
