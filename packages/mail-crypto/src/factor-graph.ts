/**
 * The factor graph (contracts/device-v1.md A11, K2″ and K3′, round 3, D39):
 * what a browser trusts, as pure functions over a view-like input (the
 * `mailbox()` view's `id`, `wraps` and `removedFactors`; keys base64url).
 *
 *   - Nodes (A11 as clarified 2026-10-22): a factor record, removed ones
 *     included, is a node only when its own admission verifies (its
 *     `signature` with the listed signing key of the factor it names as
 *     admitter, its `selfSignature` with its own listed signing key, both
 *     over the admit-factor statement built from the listed records, so the
 *     admitter key inside it is the admitter's listed one) and its id is
 *     listed once. That admission is the edge between the node and its
 *     admitter. So a trusted factor's listed factor key is always one its
 *     own signing key vouched for, and a view that shows one factor two ways
 *     is not believed.
 *   - Trusted factors: the connected component of the start nodes, the nodes
 *     whose signing key is the start key (the factor just used, once K9
 *     confirms its keys; or a kept device's trustRoot). A node lists a key
 *     only if that key signed its admission.
 *   - Factor signing keys are Ed25519 public keys, 32 bytes (A2b, D44);
 *     device signing keys are P-256 points, 65 bytes (A3).
 *   - Trusted recipients: a device admitted by a trusted factor (removed or
 *     not) whose unlock key, while it has one, its own signing key signed; a
 *     factor that is trusted, keyed and not removed. Each must also pass its
 *     binding tag (A5), which the caller checks with the mailbox key.
 *   - Trusted transitions: a successor step whose transition verifies with a
 *     trusted factor's signing key, removed or not.
 *
 * Nothing here throws on what a view holds: a malformed record is simply no
 * node, a malformed device or step simply untrusted.
 */
import { fromBase64url } from "./bytes";
import type { WrapKind } from "./index";
import { keyIdOf } from "./keys";
import { verifyStatement, type Statement } from "./statements";

/** A factor's admission (A11): by its admitter, and countersigned by the factor itself. */
export interface FactorAdmission {
  by: string;
  signature: string;
  selfSignature: string;
}

/** A factor record as the view lists it (B4's wraps and removedFactors); round 3's fields may be absent or null. */
export interface GraphFactor {
  id: string;
  kind: WrapKind;
  label: string;
  credentialId: string | null;
  /** pkF, base64url of 32 bytes. */
  factorKey?: string | null;
  /** vS, base64url of the 32-byte Ed25519 public key. */
  signingKey?: string | null; // pragma: allowlist secret (a field type)
  admission?: FactorAdmission | null;
}

/** A kept device as the view lists it (B4). */
export interface GraphDevice {
  id: string;
  label: string;
  signingKey: string; // pragma: allowlist secret (a field type)
  unlockKey: string | null;
  unlockSignature?: string | null;
  admission?: { by: string; signature: string } | null;
}

/** What trustedFactors reads: the mailbox id and its factor records. */
export interface FactorGraphView {
  /** The mailbox id (the view's `id`). */
  id: string;
  wraps: readonly GraphFactor[];
  removedFactors?: readonly GraphFactor[] | null;
}

/** A successor step with its transition (B4's `keys[].successor`, with the successor's public key). */
export interface TransitionStep {
  fromKeyId: string;
  toKeyId: string;
  /** The successor's public key, base64url of 32 bytes (or the bytes). */
  toPublicKey: string | Uint8Array;
  signedBy: string;
  signature: string;
}

/**
 * The trusted component: an opaque, frozen `{ mailboxId, ids }` handle (ids
 * sorted). What each trusted factor's record held lives in a module-private
 * WeakMap; a forged or copied handle is refused with a TypeError.
 */
export interface TrustedFactors {
  readonly mailboxId: string;
  readonly ids: readonly string[];
}

interface Node {
  readonly id: string;
  readonly signingKey: Uint8Array; // pragma: allowlist secret (a field type)
  readonly factorKey: Uint8Array | null;
  readonly removed: boolean;
}

const components = new WeakMap<object, ReadonlyMap<string, Node>>();

function decoded(value: unknown, length: number): Uint8Array<ArrayBuffer> | null {
  if (typeof value !== "string") return null;
  const bytes = fromBase64url(value);
  return bytes !== null && bytes.length === length ? bytes : null;
}

function decodedPoint(value: unknown): Uint8Array<ArrayBuffer> | null {
  const bytes = decoded(value, 65);
  return bytes !== null && bytes[0] === 0x04 ? bytes : null;
}

function startKey(start: Uint8Array | string): Uint8Array<ArrayBuffer> {
  const bytes = typeof start === "string" ? decoded(start, 32) : start instanceof Uint8Array && start.length === 32 ? new Uint8Array(start) : null;
  if (bytes === null) throw new TypeError("a start is a factor signing key: a 32-byte Ed25519 public key (or its base64url)");
  return bytes;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** The records of the view that can be nodes before any signature is checked, by id; ids listed twice are dropped. */
function candidates(view: FactorGraphView): Map<string, { record: GraphFactor; removed: boolean; signingKey: Uint8Array; factorKey: Uint8Array | null }> { // pragma: allowlist secret (field names; public keys only)
  const seen = new Map<string, number>();
  const listed: { record: GraphFactor; removed: boolean }[] = [];
  const add = (records: unknown, removed: boolean) => {
    if (!Array.isArray(records)) return;
    for (const record of records as unknown[]) {
      if (typeof record !== "object" || record === null) continue;
      const id = (record as { id?: unknown }).id;
      if (typeof id !== "string") continue;
      seen.set(id, (seen.get(id) ?? 0) + 1);
      listed.push({ record: record as GraphFactor, removed });
    }
  };
  add(view.wraps, false);
  add(view.removedFactors, true);
  const out = new Map<string, { record: GraphFactor; removed: boolean; signingKey: Uint8Array; factorKey: Uint8Array | null }>(); // pragma: allowlist secret (field names; public keys only)
  for (const { record, removed } of listed) {
    if (seen.get(record.id) !== 1) continue;
    const signingKey = decoded(record.signingKey, 32); // pragma: allowlist secret (field names; public keys only)
    const admission = record.admission;
    if (signingKey === null || typeof admission !== "object" || admission === null) continue;
    const factorKey = record.factorKey === null || record.factorKey === undefined ? null : decoded(record.factorKey, 32);
    if (record.factorKey !== null && record.factorKey !== undefined && factorKey === null) continue;
    out.set(record.id, { record, removed, signingKey, factorKey });
  }
  return out;
}

/**
 * The connected component of the start nodes, the nodes whose signing key is
 * `start` (a factor signing key, 32 bytes or its base64url), in the view's
 * factor graph. No such node gives an empty component: nothing is trusted,
 * and K2″ stops everything.
 */
export async function trustedFactors(view: FactorGraphView, start: Uint8Array | string): Promise<TrustedFactors> {
  const key = startKey(start);
  const mailboxId = typeof view === "object" && view !== null && typeof view.id === "string" ? view.id : null;
  const nodes = new Map<string, Node>();
  const edges = new Map<string, Set<string>>();
  if (mailboxId !== null) {
    const pool = candidates(view);
    for (const [id, c] of pool) {
      const admission = c.record.admission!;
      const admitter = typeof admission.by === "string" ? pool.get(admission.by) : undefined;
      if (admitter === undefined || c.factorKey === null) continue; // an admission covers the factor key: a node has one
      const statement: Statement = {
        kind: "admit-factor",
        mailboxId,
        factorId: id,
        factorKind: c.record.kind,
        label: c.record.label,
        factorKey: c.factorKey,
        signingKey: c.signingKey, // pragma: allowlist secret (a public key)
        credentialId: c.record.credentialId, // pragma: allowlist secret (field names; public keys only)
        admitterId: admission.by,
        admitterSigningKey: admitter.signingKey, // pragma: allowlist secret (field names; public keys only)
      };
      const verified =
        (await verifyStatement(admitter.signingKey, statement, admission.signature)) && (await verifyStatement(c.signingKey, statement, admission.selfSignature));
      if (!verified) continue;
      nodes.set(id, { id, signingKey: c.signingKey, factorKey: c.factorKey, removed: c.removed }); // pragma: allowlist secret (field names; public keys only)
      for (const [a, b] of [[id, admission.by], [admission.by, id]] as const) {
        if (!edges.has(a)) edges.set(a, new Set());
        edges.get(a)!.add(b);
      }
    }
  }
  // An edge counts only between two nodes; walk the component from every node that lists the start key.
  const trusted = new Map<string, Node>();
  const queue = [...nodes.values()].filter((n) => sameBytes(n.signingKey, key)).map((n) => n.id);
  while (queue.length > 0) {
    const id = queue.shift()!;
    const node = nodes.get(id);
    if (node === undefined || trusted.has(id)) continue;
    trusted.set(id, node);
    for (const next of edges.get(id) ?? []) if (nodes.has(next) && !trusted.has(next)) queue.push(next);
  }
  const handle: TrustedFactors = Object.freeze({ mailboxId: mailboxId ?? "", ids: Object.freeze([...trusted.keys()].sort()) });
  components.set(handle, trusted);
  return handle;
}

function componentOf(trusted: TrustedFactors): ReadonlyMap<string, Node> {
  const nodes = typeof trusted === "object" && trusted !== null ? components.get(trusted) : undefined;
  if (!nodes) throw new TypeError("not a TrustedFactors from trustedFactors in this page");
  return nodes;
}

/** A11: a factor is a recipient when it is trusted, keyed and not removed. (Its binding tag is the caller's check.) */
export function isFactorRecipient(trusted: TrustedFactors, factorId: string): boolean {
  const node = componentOf(trusted).get(factorId);
  return node !== undefined && !node.removed && node.factorKey !== null;
}

/**
 * A11: a device is trusted when its admission verifies with a trusted
 * factor's signing key (removed or not) and, while it has an unlock key, its
 * unlock-key signature verifies with its own signing key; a device without
 * an unlock key carries no unlock signature. (Its binding tag is the
 * caller's check.)
 */
export async function isTrustedDevice(trusted: TrustedFactors, device: GraphDevice): Promise<boolean> {
  const nodes = componentOf(trusted);
  if (typeof device !== "object" || device === null || typeof device.id !== "string") return false;
  const admission = device.admission;
  if (typeof admission !== "object" || admission === null || typeof admission.by !== "string") return false;
  const admitter = nodes.get(admission.by);
  const signingKey = decodedPoint(device.signingKey); // pragma: allowlist secret (field names; public keys only)
  if (admitter === undefined || signingKey === null || typeof device.label !== "string") return false;
  const admitted = await verifyStatement(
    admitter.signingKey,
    { kind: "admit-device", mailboxId: trusted.mailboxId, deviceId: device.id, label: device.label, signingKey, admitterId: admission.by },
    admission.signature,
  );
  if (!admitted) return false;
  const unlockSignature = device.unlockSignature ?? null;
  if (device.unlockKey === null) return unlockSignature === null;
  const unlockKey = decodedPoint(device.unlockKey);
  if (unlockKey === null || unlockSignature === null) return false;
  return verifyStatement(signingKey, { kind: "unlock-key", mailboxId: trusted.mailboxId, deviceId: device.id, unlockKey }, unlockSignature);
}

/**
 * A11: a successor step is accepted only when its transition verifies with a
 * trusted factor's signing key, removed or not, and the successor's public
 * key is the one its keyId names.
 */
export async function isTrustedTransition(trusted: TrustedFactors, step: TransitionStep): Promise<boolean> {
  const nodes = componentOf(trusted);
  if (typeof step !== "object" || step === null || typeof step.signedBy !== "string" || typeof step.signature !== "string") return false;
  const signer = nodes.get(step.signedBy);
  if (signer === undefined) return false;
  const toPublicKey = typeof step.toPublicKey === "string" ? decoded(step.toPublicKey, 32) : step.toPublicKey instanceof Uint8Array && step.toPublicKey.length === 32 ? step.toPublicKey : null;
  if (toPublicKey === null || (await keyIdOf(toPublicKey)) !== step.toKeyId) return false;
  return verifyStatement(
    signer.signingKey,
    { kind: "transition", mailboxId: trusted.mailboxId, fromKeyId: step.fromKeyId, toKeyId: step.toKeyId, toPublicKey, signerId: step.signedBy },
    step.signature,
  );
}

/**
 * A11's rule at enrollment and at the upgrade, where every factor is present:
 * the factors sorted by id (UTF-16 code units), each admitted by the next,
 * the last by the first; a single factor admits itself.
 */
export function bootstrapAdmitters(factorIds: readonly string[]): { factorId: string; admitterId: string }[] {
  if (!Array.isArray(factorIds) || factorIds.length === 0 || !factorIds.every((id) => typeof id === "string" && id.length > 0)) {
    throw new TypeError("the factors are one or more ids");
  }
  if (new Set(factorIds).size !== factorIds.length) throw new TypeError("each factor appears once");
  const sorted = [...factorIds].sort();
  return sorted.map((factorId, i) => ({ factorId, admitterId: sorted[(i + 1) % sorted.length]! }));
}
