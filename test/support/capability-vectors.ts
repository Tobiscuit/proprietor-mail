/**
 * contracts/capability-v1.vectors.json, built deterministically: a fixed key,
 * a fixed clock and fixed jti values, so the committed file can be checked
 * byte for byte against this builder (test/capability-vectors.test.ts) and
 * regenerated with scripts/generate-capability-vectors.ts.
 *
 * Self-contained apart from its sibling support modules (explicit .ts
 * extensions, Web Crypto only), so the Node script can load it directly.
 */
import {
  base64urlFromBytes,
  bytesFromBase64url,
  canonicalClaims,
  canonicalHeader,
  flipPayloadByte,
  signToken,
  type Json,
} from "./capability-tokens.ts";
import { TEST_CAPABILITY_KEYS, TEST_KEY_B64URL, TEST_KID } from "./test-keys.ts";

export const VECTOR_NOW = 1_790_424_000; // 2026-09-26T12:00:00.000Z

const KEY = bytesFromBase64url(TEST_KEY_B64URL);
// A second fixed key (0xff, 0xfe, … 0xe0), for "signed with another key".
const OTHER_KEY = Uint8Array.from({ length: 32 }, (_, i) => 255 - i);

export interface RefusedVector {
  name: string;
  rule: number;
  reason: "invalid" | "expired";
  breaks: string;
  token: string;
}

export interface CapabilityVectors {
  contract: string;
  version: 1;
  conformance: string[];
  algorithm: "HS256";
  keys: Record<string, string>;
  kid: string;
  now: number;
  nowIso: string;
  clockToleranceSeconds: number;
  maxLifetimeSeconds: number;
  valid: { header: Json; claims: Json; canonicalToken: string };
  refused: RefusedVector[];
}

export async function buildCapabilityVectors(): Promise<CapabilityVectors> {
  const now = VECTOR_NOW;
  const base = {
    sub: "acc_vector_owner",
    business: "biz_vector",
    mbx: "mbx_0123456789abcdefghjkmnpqrs",
    role: "owner" as const,
  };
  const claims = (over: Json = {}, lifetime = 60, iat = now, jti = "vector-jti-0000"): Json => {
    const c: Json = { ...canonicalClaims({ ...base, iat, jti, lifetime }), ...over };
    for (const [k, v] of Object.entries(c)) if (v === undefined) delete c[k];
    return c;
  };
  const header = canonicalHeader(TEST_KID);
  const validClaims = claims();
  const canonicalToken = await signToken(header, validClaims, KEY);

  const businessAt = JSON.stringify(validClaims).indexOf('"business":"') + '"business":"'.length;
  const flipped = flipPayloadByte(canonicalToken, businessAt);

  const refused: RefusedVector[] = [
    { name: "alg-none", rule: 1, reason: "invalid", breaks: 'alg is "none" and the signature is empty', token: await signToken(canonicalHeader(TEST_KID, "none"), claims({}, 60, now, "vector-jti-0001"), KEY) },
    { name: "alg-hs512", rule: 1, reason: "invalid", breaks: "alg is HS512 (signed correctly for HS512 with the right key)", token: await signToken(canonicalHeader(TEST_KID, "HS512"), claims({}, 60, now, "vector-jti-0002"), KEY) },
    { name: "unknown-kid", rule: 2, reason: "invalid", breaks: "kid names no configured key", token: await signToken(canonicalHeader("unknown-2026-01"), claims({}, 60, now, "vector-jti-0003"), KEY) },
    { name: "flipped-payload-byte", rule: 3, reason: "invalid", breaks: "bit 0 of the first byte of the business value is flipped after signing", token: flipped },
    { name: "wrong-key", rule: 3, reason: "invalid", breaks: "signed with a key that is not the one kid names", token: await signToken(header, claims({}, 60, now, "vector-jti-0004"), OTHER_KEY) },
    { name: "wrong-aud", rule: 4, reason: "invalid", breaks: 'aud is "proprietor-dashboard"', token: await signToken(header, claims({ aud: "proprietor-dashboard" }, 60, now, "vector-jti-0005"), KEY) },
    { name: "wrong-iss", rule: 4, reason: "invalid", breaks: 'iss is "proprietor-mail"', token: await signToken(header, claims({ iss: "proprietor-mail" }, 60, now, "vector-jti-0006"), KEY) },
    { name: "lifetime-61", rule: 5, reason: "invalid", breaks: "exp - iat = 61", token: await signToken(header, claims({}, 61, now, "vector-jti-0007"), KEY) },
    { name: "expired-by-6s", rule: 5, reason: "expired", breaks: "exp is 6 seconds before now (iat = now - 66)", token: await signToken(header, claims({}, 60, now - 66, "vector-jti-0008"), KEY) },
    { name: "iat-6s-in-future", rule: 5, reason: "invalid", breaks: "iat is 6 seconds after now", token: await signToken(header, claims({}, 60, now + 6, "vector-jti-0009"), KEY) },
    { name: "missing-business", rule: 6, reason: "invalid", breaks: "no business claim", token: await signToken(header, claims({ business: undefined }, 60, now, "vector-jti-0010"), KEY) },
    { name: "missing-jti", rule: 6, reason: "invalid", breaks: "no jti claim (jti is required: amendment of 2026-09-26)", token: await signToken(header, claims({ jti: undefined }), KEY) },
    { name: "role-admin", rule: 6, reason: "invalid", breaks: 'role is "admin"', token: await signToken(header, claims({ role: "admin" }, 60, now, "vector-jti-0011"), KEY) },
  ];

  return {
    contract: "contracts/capability-v1.md",
    version: 1,
    conformance: [
      "Minting: a token conforms when it verifies under the reference verifier (proprietor-mail src/capability.ts, verifyCapability) with `keys` at `now` and decodes to exactly `valid.claims`.",
      "Byte-identical tokens are NOT a conformance requirement. `valid.canonicalToken` is what the canonical serialization produces (header keys in the order alg, typ, kid; claims in the order iss, aud, sub, business, mbx, role, iat, exp, jti; exp = iat + 60), given as a convenience.",
      "Verifying: a verifier conforms when it accepts `valid.canonicalToken` at `now`, returning `valid.claims`, and refuses every token in `refused` with exactly the listed `reason`.",
      "`keys` is the MAIL_CAPABILITY_KEYS form (key id -> base64url of 32 bytes). It is a fixed, public TEST key: 32 sequential bytes 0x00..0x1f. It must never be configured in a deployed Worker.",
    ],
    algorithm: "HS256",
    keys: { ...TEST_CAPABILITY_KEYS },
    kid: TEST_KID,
    now,
    nowIso: new Date(now * 1000).toISOString(),
    clockToleranceSeconds: 5,
    maxLifetimeSeconds: 60,
    valid: { header, claims: validClaims, canonicalToken },
    refused,
  };
}

const SCAN = "pragma: allowlist secret (fixed public test key, test vector)";

/**
 * The file's exact text: two-space JSON, except that every line holding a
 * token (or the key) carries the secret scanner's reviewable allowlist marker,
 * which is why those objects are written on one line each.
 */
export function renderCapabilityVectors(v: CapabilityVectors): string {
  const line = (value: unknown) => JSON.stringify(value);
  const keysLine = Object.entries(v.keys)
    .map(([kid, key]) => `${line(kid)}: ${line(key)}`)
    .join(", ");
  const out = [
    "{",
    `  "contract": ${line(v.contract)},`,
    `  "version": ${v.version},`,
    `  "conformance": [`,
    v.conformance.map((c) => `    ${line(c)}`).join(",\n") + "",
    `  ],`,
    `  "algorithm": ${line(v.algorithm)},`,
    `  "keys": { ${keysLine} }, "secretScan": ${line(SCAN)},`,
    `  "kid": ${line(v.kid)},`,
    `  "now": ${v.now},`,
    `  "nowIso": ${line(v.nowIso)},`,
    `  "clockToleranceSeconds": ${v.clockToleranceSeconds},`,
    `  "maxLifetimeSeconds": ${v.maxLifetimeSeconds},`,
    `  "valid": {`,
    `    "header": ${line(v.valid.header)},`,
    `    "claims": ${line(v.valid.claims)},`,
    `    "canonicalToken": ${line(v.valid.canonicalToken)}, "secretScan": ${line(SCAN)}`,
    `  },`,
    `  "refused": [`,
    v.refused.map((r) => `    ${line({ ...r, secretScan: SCAN })}`).join(",\n"),
    `  ]`,
    "}",
    "",
  ];
  return out.join("\n");
}

// Re-exported for the test, which decodes tokens to show what each one says.
export { base64urlFromBytes, bytesFromBase64url };
