import { base64url, decodeProtectedHeader, errors, jwtVerify } from "jose";
import { CapabilityRejected } from "./errors";

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

export async function verifyCapability(token: string, keys: CapabilityKeys, nowSeconds: number): Promise<Capability> {
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
  return mbx === undefined
    ? { iss: ISSUER, aud: AUDIENCE, sub, business, role, iat, exp, jti }
    : { iss: ISSUER, aud: AUDIENCE, sub, business, mbx, role, iat, exp, jti };
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
