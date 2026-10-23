/**
 * Signed statements (contracts/device-v1.md A11, round 3, D39, D44). A factor
 * signs with its signing key sS (A2b), through its FactorPrivateKey handle:
 * Ed25519 (RFC 8032), 64 bytes, over a 32-byte public key. A device signs
 * with its signing key (A3): ECDSA P-256 with SHA-256, IEEE P1363 (r || s,
 * 64 bytes), as device proofs (A7). All base64url. Which algorithm verifies
 * follows from the statement: an unlock key is the device's, everything
 * else a factor's. Safari's Ed25519 signatures are randomized, so nothing
 * here compares signature bytes; it verifies them.
 *
 *
 *   admit-device = ctx("admit-device", mailboxId, deviceId, b64u(UTF-8(label)), b64u(signingKey), admitterId)
 *                  signed by the admitting factor
 *   unlock-key   = ctx("unlock-key", mailboxId, deviceId, b64u(unlockKey))
 *                  signed by the device itself
 *   admit-factor = ctx("admit-factor", mailboxId, factorId, kind, b64u(UTF-8(label)), b64u(factorKey),
 *                      b64u(signingKey), credentialId ?? "-", admitterId, b64u(admitter's signingKey))
 *                  signed by the admitting factor (signature) and by the factor itself (selfSignature)
 *   transition   = ctx("transition", mailboxId, fromKeyId, toKeyId, b64u(toPublicKey), signerId)
 *                  signed by the factor whose proof the rotation spends
 *
 * Each message begins with its own label, so no statement, and no device
 * proof, verifies as another. A signer is refused (TypeError) when it is not
 * the one the statement names, so a statement this package signs is one
 * that verifies. Verification never throws: anything malformed is false.
 */
import { base64url, bytesEqual, fromBase64url } from "./bytes";
import { isDeviceSigningKey } from "./device-keys";
import { context } from "./envelope";
import { factorMaterialOf, isFactorKey, type FactorPrivateKey } from "./factor-keys";
import type { WrapKind } from "./index";
import { keyIdOf } from "./keys";

const WRAP_KINDS: readonly string[] = ["passkey-prf", "recovery"] satisfies WrapKind[];
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const KEY_ID = /^[0-9a-f]{32}$/;
const SIGNATURE_BYTES = 64;
const ECDSA_P256 = { name: "ECDSA", namedCurve: "P-256" };
const ECDSA_SHA256 = { name: "ECDSA", hash: "SHA-256" };
const ED25519 = { name: "Ed25519" };

/** A statement of A11. Keys are raw bytes; the message holds them as base64url. */
export type Statement =
  | {
      kind: "admit-device";
      mailboxId: string;
      deviceId: string;
      label: string;
      /** The device's signing key, a 65-byte uncompressed P-256 point. */
      signingKey: Uint8Array; // pragma: allowlist secret (a field type)
      admitterId: string;
    }
  | {
      kind: "unlock-key";
      mailboxId: string;
      deviceId: string;
      /** The device's unlock key, a 65-byte uncompressed P-256 point. */
      unlockKey: Uint8Array;
    }
  | {
      kind: "admit-factor";
      mailboxId: string;
      factorId: string;
      factorKind: WrapKind;
      label: string;
      /** pkF, 32 bytes (A2). */
      factorKey: Uint8Array;
      /** vS, the factor's Ed25519 public key, 32 bytes (A2b). */
      signingKey: Uint8Array; // pragma: allowlist secret (a field type)
      /** The passkey's credential id (base64url), or null for the recovery key. */
      credentialId: string | null;
      admitterId: string;
      /** The admitter's vS, 32 bytes. */
      admitterSigningKey: Uint8Array; // pragma: allowlist secret (a field type)
    }
  | {
      kind: "transition";
      mailboxId: string;
      fromKeyId: string;
      toKeyId: string;
      /** The new mailbox public key, 32 bytes (X25519). */
      toPublicKey: Uint8Array;
      signerId: string;
    };

export type StatementKind = Statement["kind"];

function label(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || LONE_SURROGATE.test(value)) throw new TypeError("a label is a non-empty string of well-formed Unicode");
  return base64url(new TextEncoder().encode(value));
}

function point(value: unknown, what: string): string {
  if (!(value instanceof Uint8Array) || value.length !== 65 || value[0] !== 0x04) throw new TypeError(`${what} is a 65-byte uncompressed P-256 point`);
  return base64url(value);
}

function bytes32(value: unknown, what: string): string {
  if (!(value instanceof Uint8Array) || value.length !== 32) throw new TypeError(`${what} is exactly 32 bytes`);
  return base64url(value);
}

function keyId(value: unknown): string {
  if (typeof value !== "string" || !KEY_ID.test(value)) throw new TypeError("a keyId is 32 lowercase hex digits");
  return value;
}

/** The exact bytes a statement's signature covers; a TypeError for anything that could make them ambiguous. */
export function statementMessage(statement: Statement): Uint8Array<ArrayBuffer> {
  const s = statement as Statement | null;
  switch (s?.kind) {
    case "admit-device":
      return context("admit-device", s.mailboxId, s.deviceId, label(s.label), point(s.signingKey, "a device's signing key"), s.admitterId);
    case "unlock-key":
      return context("unlock-key", s.mailboxId, s.deviceId, point(s.unlockKey, "an unlock key"));
    case "admit-factor": {
      if (!WRAP_KINDS.includes(s.factorKind)) throw new TypeError(`unknown factor kind: ${String(s.factorKind)}`);
      const credentialId = s.credentialId; // pragma: allowlist secret (a variable name)
      // "-" stands for no credential, so it can never be one (a base64url credential id is never one character).
      if (credentialId !== null && (typeof credentialId !== "string" || credentialId === "-")) throw new TypeError("a credential id is base64url, or null");
      return context(
        "admit-factor",
        s.mailboxId,
        s.factorId,
        s.factorKind,
        label(s.label),
        bytes32(s.factorKey, "a factor key"),
        bytes32(s.signingKey, "a factor's signing key (Ed25519)"),
        credentialId ?? "-",
        s.admitterId,
        bytes32(s.admitterSigningKey, "the admitter's signing key (Ed25519)"),
      );
    }
    case "transition":
      return context("transition", s.mailboxId, keyId(s.fromKeyId), keyId(s.toKeyId), bytes32(s.toPublicKey, "a mailbox public key"), s.signerId);
    default:
      throw new TypeError(`unknown statement kind: ${String((s as { kind?: unknown } | null)?.kind)}`);
  }
}

/** Throws a TypeError unless `factor` is the one `statement` says signs it. */
function checkFactorSigner(factor: FactorPrivateKey, statement: Statement): void {
  const material = factorMaterialOf(factor);
  switch (statement.kind) {
    case "admit-device":
      if (statement.admitterId !== material.factorId) throw new TypeError("an admission of a device is signed by the factor it names as admitter");
      return;
    case "transition":
      if (statement.signerId !== material.factorId) throw new TypeError("a transition is signed by the factor it names as signer");
      return;
    case "admit-factor": {
      const asAdmitter = statement.admitterId === material.factorId;
      const asItself = statement.factorId === material.factorId;
      if (!asAdmitter && !asItself) throw new TypeError("an admission of a factor is signed by its admitter and by the factor itself, nobody else");
      if (asAdmitter && !(statement.admitterSigningKey instanceof Uint8Array && bytesEqual(statement.admitterSigningKey, material.signingPublicKey))) {
        throw new TypeError("the admitter's signing key in the statement is not this factor's");
      }
      if (
        asItself &&
        !(
          statement.signingKey instanceof Uint8Array &&
          bytesEqual(statement.signingKey, material.signingPublicKey) &&
          statement.factorKey instanceof Uint8Array &&
          bytesEqual(statement.factorKey, material.publicKey) &&
          statement.factorKind === material.kind
        )
      ) {
        throw new TypeError("the factor's own keys and kind in the statement are not this factor's");
      }
      return;
    }
    default:
      throw new TypeError(`a factor does not sign a statement of kind ${String(statement.kind)}`);
  }
}

/** Statements a device signs (ECDSA P-256); a factor signs every other kind (Ed25519). */
function signedByDevice(statement: Statement): boolean {
  return statement.kind === "unlock-key";
}

/**
 * Signs `statement` as A11 says: a factor (its FactorPrivateKey handle, with
 * Ed25519) signs admissions and transitions, a device (its signing CryptoKey,
 * with ECDSA P-256) its own unlock key. Returns base64url of the 64 bytes.
 */
export async function signStatement(signer: FactorPrivateKey | CryptoKey, statement: Statement): Promise<string> {
  const message = statementMessage(statement);
  let signature: Uint8Array;
  if (isFactorKey(signer)) {
    if (signedByDevice(statement)) throw new TypeError("an unlock key is signed by its device, not by a factor");
    checkFactorSigner(signer, statement);
    if (statement.kind === "transition" && (await keyIdOf(statement.toPublicKey)) !== statement.toKeyId) {
      throw new TypeError("the transition's toKeyId is not its public key's keyId");
    }
    signature = new Uint8Array(await crypto.subtle.sign(ED25519, factorMaterialOf(signer).signingKey, message));
  } else if (isDeviceSigningKey(signer)) {
    if (!signedByDevice(statement)) throw new TypeError("a device signs only its own unlock key (and device proofs, A7)");
    signature = new Uint8Array(await crypto.subtle.sign(ECDSA_SHA256, signer, message));
  } else {
    throw new TypeError("a statement is signed with a FactorPrivateKey from this page or a device's signing key");
  }
  if (signature.length !== SIGNATURE_BYTES) throw new Error("internal: an Ed25519 signature, and an ECDSA P-256 one in IEEE P1363 form, are 64 bytes");
  return base64url(signature);
}

/**
 * True only when `signature` (base64url, 64 bytes) is a signature of
 * `statement` under `publicKey`: for an unlock key, the device's signing key
 * (a 65-byte uncompressed P-256 point, ECDSA); for every other statement, a
 * factor's signing key (32 bytes, Ed25519). Every other input, including
 * anything malformed from a view, is false.
 */
export async function verifyStatement(publicKey: Uint8Array, statement: Statement, signature: string): Promise<boolean> {
  try {
    const message = statementMessage(statement);
    const bytes = typeof signature === "string" ? fromBase64url(signature) : null;
    if (bytes === null || bytes.length !== SIGNATURE_BYTES || !(publicKey instanceof Uint8Array)) return false;
    if (signedByDevice(statement)) {
      if (publicKey.length !== 65 || publicKey[0] !== 0x04) return false;
      const key = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), ECDSA_P256, false, ["verify"]);
      return await crypto.subtle.verify(ECDSA_SHA256, key, bytes, message);
    }
    if (publicKey.length !== 32) return false;
    const key = await crypto.subtle.importKey("raw", new Uint8Array(publicKey), ED25519, false, ["verify"]);
    return await crypto.subtle.verify(ED25519, key, bytes, message);
  } catch {
    return false;
  }
}
