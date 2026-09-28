/**
 * Builds capability tokens byte by byte, for the tests and for
 * scripts/generate-capability-vectors.ts. Hand-built rather than minted with a
 * library so that every refused case (alg `none`, a flipped byte, a missing
 * claim) is exactly the bytes the vector says, and so that the header and
 * claims keep the canonical order the contract names:
 *   header  alg, typ, kid
 *   claims  iss, aud, sub, business, mbx, role, iat, exp, jti
 *
 * Self-contained (Web Crypto only, no relative imports) so that the Node
 * script can load it directly.
 */

export type Json = Record<string, unknown>;

export function base64urlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function bytesFromBase64url(text: string): Uint8Array {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

const utf8 = (text: string) => new TextEncoder().encode(text);

export async function hmac(hash: "SHA-256" | "SHA-384" | "SHA-512", key: Uint8Array, data: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, utf8(data)));
}

/** header.payload.signature, signed with HS256 unless the header says otherwise; `none` gets an empty signature. */
export async function signToken(header: Json, claims: Json, key: Uint8Array): Promise<string> {
  const input = `${base64urlFromBytes(utf8(JSON.stringify(header)))}.${base64urlFromBytes(utf8(JSON.stringify(claims)))}`;
  const alg = header.alg;
  if (alg === "none") return `${input}.`;
  const hash = alg === "HS384" ? "SHA-384" : alg === "HS512" ? "SHA-512" : "SHA-256";
  return `${input}.${base64urlFromBytes(await hmac(hash, key, input))}`;
}

/** The canonical claims, in the contract's order, with `exp = iat + 60`. */
export function canonicalClaims(opts: {
  sub: string;
  business: string;
  mbx?: string;
  role: "owner" | "editor";
  iat: number;
  jti: string;
  lifetime?: number;
}): Json {
  const claims: Json = {
    iss: "proprietor-dashboard",
    aud: "proprietor-mail",
    sub: opts.sub,
    business: opts.business,
  };
  if (opts.mbx !== undefined) claims.mbx = opts.mbx;
  claims.role = opts.role;
  claims.iat = opts.iat;
  claims.exp = opts.iat + (opts.lifetime ?? 60);
  claims.jti = opts.jti;
  return claims;
}

export function canonicalHeader(kid: string, alg = "HS256"): Json {
  return { alg, typ: "JWT", kid };
}

/** The same token with bit 0 of one payload byte flipped, signature untouched. */
export function flipPayloadByte(token: string, index: number): string {
  const [h, p, s] = token.split(".") as [string, string, string];
  const payload = bytesFromBase64url(p);
  payload[index] = (payload[index] ?? 0) ^ 0x01;
  return `${h}.${base64urlFromBytes(payload)}.${s}`;
}

export function randomJti(): string {
  return base64urlFromBytes(crypto.getRandomValues(new Uint8Array(16)));
}
