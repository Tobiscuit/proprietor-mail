/**
 * WebAuthn with the PRF extension (contracts/mail-client-v1.md "Enrollment",
 * "Unlocking"), behind the `credentials` port so that the rest of the
 * package is testable without an authenticator.
 *
 * The passkey authenticates nothing: no server verifies the attestation or
 * any assertion. It only derives, through the PRF extension and after user
 * verification on the authenticator, the 32-byte secret that wraps the
 * mailbox key. The challenge is therefore random bytes made here.
 */
import { prfInput } from "@proprietor/mail-crypto";
import { base64url, bytesOf, fromBase64url, randomBytes } from "./bytes";
import { NoMatchingWrap, PasskeyCancelled, PrfUnavailable, UnsupportedBrowser } from "./errors";
import type { PasskeyOptions, PasskeyPrompt } from "./types";

type Credentials = Pick<CredentialsContainer, "create" | "get">; // pragma: allowlist secret (a variable or type name, not a value)

const DEFAULT_TIMEOUT_MS = 120_000;
/** ES256, EdDSA, RS256: what the WebAuthn spec recommends a Relying Party accept. */
const ALGORITHMS: PublicKeyCredentialParameters[] = [
  { type: "public-key", alg: -7 },
  { type: "public-key", alg: -8 },
  { type: "public-key", alg: -257 },
];

export interface PrfCredential {
  /** base64url of the credential's rawId: the wrap's `credentialId`. */
  credentialId: string;
  /** The 32-byte PRF output for the wrap's input. */
  secret: Uint8Array; // pragma: allowlist secret (a variable or type name, not a value)
}

function containerOf(options: { credentials?: Credentials }): Credentials {
  if (options.credentials) return options.credentials;
  const nav = (globalThis as { navigator?: { credentials?: Credentials } }).navigator;
  if (nav?.credentials && typeof nav.credentials.create === "function" && typeof nav.credentials.get === "function") return nav.credentials;
  throw new UnsupportedBrowser("this browser has no WebAuthn");
}

function rpIdOf(rpId: string): string {
  if (typeof rpId !== "string" || !/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i.test(rpId)) {
    throw new TypeError("rpId is the dashboard's exact host (spec D5)");
  }
  return rpId;
}

/** A thrown WebAuthn failure, mapped to the contract's errors. */
function mapFailure(e: unknown): never {
  if (e instanceof DOMException) {
    if (e.name === "NotAllowedError" || e.name === "AbortError") throw new PasskeyCancelled();
    if (e.name === "NotSupportedError") throw new PrfUnavailable("the browser does not support what this passkey ceremony asks for");
  }
  throw e;
}

interface CredentialLike {
  rawId: ArrayBuffer;
  getClientExtensionResults(): AuthenticationExtensionsClientOutputs;
}

function asCredential(value: Credential | null): CredentialLike {
  if (value === null) throw new PasskeyCancelled();
  const c = value as unknown as Partial<CredentialLike>;
  if (!(c.rawId instanceof ArrayBuffer) || typeof c.getClientExtensionResults !== "function") {
    throw new PrfUnavailable("the browser returned something other than a public-key credential");
  }
  return c as CredentialLike;
}

function prfOutputOf(credential: CredentialLike): Uint8Array | null { // pragma: allowlist secret (a variable or type name, not a value)
  const first = credential.getClientExtensionResults().prf?.results?.first;
  if (first === undefined) return null;
  const secret = new Uint8Array(bytesOf(first)); // a copy: the buffer the browser gave is not ours to keep
  if (secret.length !== 32) throw new PrfUnavailable("the PRF output is not 32 bytes");
  return secret;
}

async function evaluateByGet(
  credentials: Credentials, // pragma: allowlist secret (a variable or type name, not a value)
  rpId: string,
  timeoutMs: number,
  entries: { credentialId: string; rawId: Uint8Array<ArrayBuffer>; input: Uint8Array<ArrayBuffer> }[],
): Promise<{ credentialId: string; secret: Uint8Array }> { // pragma: allowlist secret (a variable or type name, not a value)
  const evalByCredential: Record<string, AuthenticationExtensionsPRFValues> = {}; // pragma: allowlist secret (a variable or type name, not a value)
  for (const entry of entries) evalByCredential[entry.credentialId] = { first: entry.input };
  const assertion = asCredential(
    await credentials
      .get({
        publicKey: {
          rpId,
          challenge: randomBytes(32),
          allowCredentials: entries.map((e) => ({ type: "public-key", id: e.rawId })), // pragma: allowlist secret (a variable or type name, not a value)
          userVerification: "required",
          timeout: timeoutMs,
          extensions: { prf: { evalByCredential } },
        },
      })
      .catch(mapFailure),
  );
  const credentialId = base64url(new Uint8Array(assertion.rawId)); // pragma: allowlist secret (a variable or type name, not a value)
  if (!entries.some((e) => e.credentialId === credentialId)) throw new NoMatchingWrap();
  const secret = prfOutputOf(assertion); // pragma: allowlist secret (a variable or type name, not a value)
  if (secret === null) throw new PrfUnavailable();
  return { credentialId, secret };
}

/**
 * Creates a passkey and evaluates its PRF for the wrap `wrapId` of `mailboxId`.
 * If the authenticator returns the PRF output at creation, no second prompt;
 * if it only reports `prf.enabled`, one get() evaluates it; if PRF is not
 * enabled, PrfUnavailable.
 */
export async function createPasskeyWithPrf(options: PasskeyOptions, mailboxId: string, wrapId: string): Promise<PrfCredential> {
  const credentials = containerOf(options); // pragma: allowlist secret (a variable or type name, not a value)
  const rpId = rpIdOf(options.rpId);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const input = new Uint8Array(await prfInput(mailboxId, wrapId));
  const created = asCredential(
    await credentials
      .create({
        publicKey: {
          rp: { id: rpId, name: options.rpName },
          user: { id: randomBytes(16), name: options.userName, displayName: options.userDisplayName },
          challenge: randomBytes(32),
          pubKeyCredParams: ALGORITHMS,
          authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
          attestation: "none",
          timeout: timeoutMs,
          extensions: { prf: { eval: { first: input } } },
        },
      })
      .catch(mapFailure),
  );
  const rawId = new Uint8Array(created.rawId);
  const credentialId = base64url(rawId); // pragma: allowlist secret (a variable or type name, not a value)
  const prf = created.getClientExtensionResults().prf;
  const atCreation = prfOutputOf(created);
  if (atCreation !== null) return { credentialId, secret: atCreation }; // pragma: allowlist secret (a variable or type name, not a value)
  if (prf?.enabled !== true) throw new PrfUnavailable();
  return evaluateByGet(credentials, rpId, timeoutMs, [{ credentialId, rawId, input }]);
}

/**
 * One get() over the mailbox's passkey wraps, each with its own PRF input;
 * the credential the person used selects the wrap.
 */
export async function assertPasskeyPrf<W extends { id: string; credentialId: string | null }>(
  prompt: PasskeyPrompt,
  mailboxId: string,
  wraps: W[],
): Promise<{ wrap: W; secret: Uint8Array }> { // pragma: allowlist secret (a variable or type name, not a value)
  const entries: { wrap: W; credentialId: string; rawId: Uint8Array<ArrayBuffer>; input: Uint8Array<ArrayBuffer> }[] = [];
  for (const wrap of wraps) {
    const rawId = wrap.credentialId === null ? null : fromBase64url(wrap.credentialId);
    if (rawId === null || rawId.length === 0) continue;
    entries.push({ wrap, credentialId: wrap.credentialId!, rawId, input: new Uint8Array(await prfInput(mailboxId, wrap.id)) }); // pragma: allowlist secret (a variable or type name, not a value)
  }
  if (entries.length === 0) throw new NoMatchingWrap("the mailbox has no passkey for its active key");
  const credentials = containerOf(prompt); // pragma: allowlist secret (a variable or type name, not a value)
  const { credentialId, secret } = await evaluateByGet(credentials, rpIdOf(prompt.rpId), prompt.timeoutMs ?? DEFAULT_TIMEOUT_MS, entries);
  return { wrap: entries.find((e) => e.credentialId === credentialId)!.wrap, secret };
}
