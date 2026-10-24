import { rows } from "./store";
import type { DeviceView, KeyView, RemovedFactorView, RotationDueView, SealView, WrapView } from "./types";
import { encodeBase64url } from "./validate";

/**
 * The key ring as the Mailbox stores it (domain-model §3, KeyRing; plan.md
 * §2 and §10.1): keys with their successor seals and transitions, wraps that
 * are also factors (with a factor key, a signing key, an admission and a tag
 * once they have them), removed factors (M24), kept devices, seals of the
 * active key, and the rotation an email-code revocation left due. Public
 * keys, signatures, seals and tags only: nothing here opens a key (M3). This
 * module reads and shows them; sessions.ts, confirmations.ts and devices.ts
 * change them.
 */

export type SessionsMode = "optional" | "required";

export interface KeyRow {
  key_id: string;
  public_key: ArrayBuffer;
  created_at: string;
  created_by: string;
  retired_at: string | null;
  successor_key_id: string | null;
  successor_seal: string | null;
  successor_signed_by: string | null;
  successor_sig: string | null;
}

export interface WrapRow {
  id: string;
  key_id: string;
  kind: "passkey-prf" | "recovery";
  credential_id: string | null;
  label: string;
  wrapped: string;
  created_at: string;
  created_by: string;
  factor_key: ArrayBuffer | null;
  signing_key: ArrayBuffer | null; // pragma: allowlist secret (a column type: a public Ed25519 key)
  admission_by: string | null;
  admission_sig: string | null;
  admission_self_sig: string | null;
  tag: string | null;
  tag_key_id: string | null;
}

export interface RemovedFactorRow {
  id: string;
  kind: "passkey-prf" | "recovery";
  credential_id: string | null;
  label: string;
  factor_key: ArrayBuffer;
  signing_key: ArrayBuffer; // pragma: allowlist secret (a column type: a public Ed25519 key)
  admission_by: string;
  admission_sig: string;
  admission_self_sig: string;
  created_at: string;
  created_by: string;
  removed_at: string;
  removed_by: string;
}

export interface DeviceRow {
  id: string;
  account_id: string;
  label: string;
  signing_key: ArrayBuffer; // pragma: allowlist secret (a column type: a public P-256 point)
  unlock_key: ArrayBuffer | null;
  unlock_sig: string | null;
  admission_by: string;
  admission_sig: string;
  tag: string;
  tag_key_id: string;
  created_at: string;
  created_by: string;
  last_seen_at: string | null;
}

interface SealRow {
  key_id: string;
  to_kind: "device" | "factor";
  to_id: string;
  sealed: string;
}

interface RotationDueRow {
  since: string;
  by_account: string;
  devices: string;
}

const b64 = (bytes: ArrayBuffer) => encodeBase64url(new Uint8Array(bytes));

export function sessionsMode(sql: SqlStorage): SessionsMode {
  const row = rows<{ sessions: SessionsMode }>(sql, "SELECT sessions FROM policy")[0];
  if (row === undefined) throw new Error("mailbox policy missing");
  return row.sessions;
}

export function deviceRow(sql: SqlStorage, id: string): DeviceRow | null {
  return rows<DeviceRow>(sql, "SELECT * FROM devices WHERE id = ?", id)[0] ?? null;
}

export function wrapRow(sql: SqlStorage, id: string): WrapRow | null {
  return rows<WrapRow>(sql, "SELECT * FROM key_wraps WHERE id = ?", id)[0] ?? null;
}

/** A factor Mail can check (B3's "factor"): a wrap with its factor key and signing key, not removed (removed ones are not in key_wraps, M24). */
export function keyedFactor(sql: SqlStorage, id: string): (WrapRow & { factor_key: ArrayBuffer; signing_key: ArrayBuffer }) | null { // pragma: allowlist secret (column types: public keys)
  const w = wrapRow(sql, id);
  return w !== null && w.factor_key !== null && w.signing_key !== null ? (w as WrapRow & { factor_key: ArrayBuffer; signing_key: ArrayBuffer }) : null; // pragma: allowlist secret (column types: public keys)
}

/** The rotation an email-code revocation left due (B7a), or null. */
export function rotationDue(sql: SqlStorage): RotationDueView | null {
  const row = rows<RotationDueRow>(sql, "SELECT since, by_account, devices FROM rotation_due")[0];
  return row === undefined ? null : { since: row.since, by: row.by_account, devices: JSON.parse(row.devices) as string[] };
}

export function deviceView(d: DeviceRow): DeviceView {
  return {
    id: d.id,
    label: d.label,
    signingKey: b64(d.signing_key), // pragma: allowlist secret (a field name: a public P-256 point)
    unlockKey: d.unlock_key === null ? null : b64(d.unlock_key),
    unlockSignature: d.unlock_sig,
    admission: { by: d.admission_by, signature: d.admission_sig },
    tag: d.tag,
    tagKeyId: d.tag_key_id,
    createdAt: d.created_at,
    createdBy: d.created_by,
    lastSeenAt: d.last_seen_at,
  };
}

function admissionOf(by: string | null, signature: string | null, selfSignature: string | null): WrapView["admission"] {
  return by === null || signature === null || selfSignature === null ? null : { by, signature, selfSignature };
}

/** The key ring's part of `mailbox()` (device-v1 B4). */
export function keyRingView(sql: SqlStorage): {
  keys: KeyView[];
  wraps: WrapView[];
  removedFactors: RemovedFactorView[];
  devices: DeviceView[];
  seals: SealView[];
  rotationDue: RotationDueView | null;
} {
  return {
    keys: rows<KeyRow>(sql, "SELECT * FROM keys ORDER BY created_at").map((k) => ({
      keyId: k.key_id,
      publicKey: b64(k.public_key),
      createdAt: k.created_at,
      createdBy: k.created_by,
      retiredAt: k.retired_at,
      successor:
        k.successor_key_id === null || k.successor_seal === null || k.successor_signed_by === null || k.successor_sig === null
          ? null
          : { keyId: k.successor_key_id, sealed: k.successor_seal, signedBy: k.successor_signed_by, signature: k.successor_sig },
    })),
    wraps: rows<WrapRow>(sql, "SELECT * FROM key_wraps ORDER BY created_at, id").map((w) => ({
      id: w.id,
      keyId: w.key_id,
      kind: w.kind,
      credentialId: w.credential_id, // pragma: allowlist secret (a field name, not a value)
      label: w.label,
      wrapped: w.wrapped,
      createdAt: w.created_at,
      createdBy: w.created_by,
      factorKey: w.factor_key === null ? null : b64(w.factor_key),
      signingKey: w.signing_key === null ? null : b64(w.signing_key), // pragma: allowlist secret (a field name: a public Ed25519 key)
      admission: admissionOf(w.admission_by, w.admission_sig, w.admission_self_sig),
      tag: w.tag,
      tagKeyId: w.tag_key_id,
    })),
    removedFactors: rows<RemovedFactorRow>(sql, "SELECT * FROM removed_factors ORDER BY removed_at, id").map((f) => ({
      id: f.id,
      kind: f.kind,
      credentialId: f.credential_id, // pragma: allowlist secret (a field name, not a value)
      label: f.label,
      factorKey: b64(f.factor_key),
      signingKey: b64(f.signing_key), // pragma: allowlist secret (a field name: a public Ed25519 key)
      admission: { by: f.admission_by, signature: f.admission_sig, selfSignature: f.admission_self_sig },
      removedAt: f.removed_at,
    })),
    devices: rows<DeviceRow>(sql, "SELECT * FROM devices ORDER BY created_at, id").map(deviceView),
    seals: rows<SealRow>(sql, "SELECT key_id, to_kind, to_id, sealed FROM key_seals ORDER BY to_kind, to_id").map((s) => ({
      keyId: s.key_id,
      to: { kind: s.to_kind, id: s.to_id },
      sealed: s.sealed,
    })),
    rotationDue: rotationDue(sql),
  };
}
