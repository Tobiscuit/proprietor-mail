import { rows } from "./store";
import type { DeviceView, KeyView, SealView, WrapView } from "./types";
import { encodeBase64url } from "./validate";

/**
 * The key ring as the Mailbox stores it (domain-model §3, KeyRing; plan.md
 * §2): keys with their successor seals, wraps that are also factors (with a
 * factor key and a tag once they have one), kept devices, and seals of the
 * active key. Public keys, seals and tags only: nothing here opens a key
 * (M3). This module reads and shows them; sessions.ts and devices.ts change
 * them.
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
  tag: string | null;
  tag_key_id: string | null;
}

export interface DeviceRow {
  id: string;
  account_id: string;
  label: string;
  signing_key: ArrayBuffer; // pragma: allowlist secret (a column type: a public P-256 point)
  unlock_key: ArrayBuffer | null;
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

export function deviceView(d: DeviceRow): DeviceView {
  return {
    id: d.id,
    label: d.label,
    signingKey: b64(d.signing_key), // pragma: allowlist secret (a field name: a public P-256 point)
    unlockKey: d.unlock_key === null ? null : b64(d.unlock_key),
    tag: d.tag,
    tagKeyId: d.tag_key_id,
    createdAt: d.created_at,
    createdBy: d.created_by,
    lastSeenAt: d.last_seen_at,
  };
}

/** The key ring's part of `mailbox()` (device-v1 B4). */
export function keyRingView(sql: SqlStorage): { keys: KeyView[]; wraps: WrapView[]; devices: DeviceView[]; seals: SealView[] } {
  return {
    keys: rows<KeyRow>(sql, "SELECT * FROM keys ORDER BY created_at").map((k) => ({
      keyId: k.key_id,
      publicKey: b64(k.public_key),
      createdAt: k.created_at,
      createdBy: k.created_by,
      retiredAt: k.retired_at,
      successor: k.successor_key_id === null || k.successor_seal === null ? null : { keyId: k.successor_key_id, sealed: k.successor_seal },
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
      tag: w.tag,
      tagKeyId: w.tag_key_id,
    })),
    devices: rows<DeviceRow>(sql, "SELECT * FROM devices ORDER BY created_at, id").map(deviceView),
    seals: rows<SealRow>(sql, "SELECT key_id, to_kind, to_id, sealed FROM key_seals ORDER BY to_kind, to_id").map((s) => ({
      keyId: s.key_id,
      to: { kind: s.to_kind, id: s.to_id },
      sealed: s.sealed,
    })),
  };
}
