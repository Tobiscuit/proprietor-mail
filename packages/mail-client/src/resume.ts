/**
 * A kept device loads the inbox (plan.md F2, F3, F10; contracts/device-v1.md
 * Part C, K6 and K7).
 *
 * In this order:
 *  1. K6, the browser's own lock settings, before anything else: "right away"
 *     keeps nothing; 15 minutes or 1 hour since the last use; for "when I sign
 *     out", another sign-in id than the one it was unlocked under. A lock that
 *     fell due deletes the unlock key first, so a lock is never just skipped.
 *  2. K7: a device the view no longer lists is wiped, and the answer is
 *     "removed". A view with no devices at all comes from a Mail Worker
 *     without spec 002: the record is kept, and the device waits (no-seal).
 *  3. The device's seal of the active key, opened with its unlock key; none,
 *     or one that does not open, means a factor is needed, and the useless
 *     unlock key is deleted.
 *  4. K2′ from the key this device last accepted (a rollback, or a key the
 *     server sealed to the device, has no chain back to it), and K3, which
 *     flags a recipient whose tag fails instead of stopping.
 *  5. The device accepts the active key (lastKeyId) and records the use.
 */
import { openKeySeal, type MailboxPrivateKey } from "@proprietor/mail-crypto";
import { fromBase64url } from "./bytes";
import { KeySubstitutionDetected, StorageUnavailable } from "./errors";
import { bindingOf, checkTags, readRing, trustChain } from "./keyring";
import { idleLockMsOf, LOCK_AFTER_MS, Session } from "./session";
import type { DeviceInfo, KeptDevice, LockReason, MailboxView, ResumeOptions, ResumeResult } from "./types";

/** K6: why this kept device must be unlocked with a factor now, or null when it may open without a prompt. */
export function lockDue(record: KeptDevice, signInId: string | null, now: number): LockReason | null {
  if (record.lockAfter === "right-away") return "right-away";
  if (record.unlockKey === null) return "locked";
  if (record.lockAfter === "sign-out") return record.signInId === signInId ? null : "signed-out";
  return now - record.lastActiveAt >= LOCK_AFTER_MS[record.lockAfter] ? "idle" : null;
}

function infoOf(record: KeptDevice): DeviceInfo {
  return Object.freeze({ id: record.deviceId, label: record.label, lockAfter: record.lockAfter, keepsUnlocked: record.unlockKey !== null });
}

export async function resumeDevice(view: MailboxView, options: ResumeOptions): Promise<ResumeResult> {
  const ring = readRing(view);
  const store = options.store;
  const now = options.now ?? Date.now;
  const idleLockMs = idleLockMsOf(options);
  const failed = (e: unknown): never => {
    throw e instanceof TypeError ? e : new StorageUnavailable();
  };
  let record = await store.get(ring.mailboxId).catch(failed);
  if (record === null) return { state: "none" };

  const dropUnlockKey = async (r: KeptDevice): Promise<KeptDevice> =>
    r.unlockKey === null ? r : ((await store.update(ring.mailboxId, r.deviceId, { unlockKey: null, unlockPublic: null }).catch(failed)) ?? { ...r, unlockKey: null, unlockPublic: null });

  // 1. K6: a lock that fell due deletes the unlock key before anything else.
  const due = lockDue(record, options.signInId, now());
  if (due !== null) record = await dropUnlockKey(record);

  // 2. K7: removed from the mailbox means wiped. (A view without devices is from a Worker without spec 002.)
  if (ring.devices !== null && !ring.devices.some((d) => d.id === record!.deviceId)) {
    await store.delete(ring.mailboxId, record.deviceId).catch(failed);
    return { state: "removed" };
  }
  if (due !== null) return { state: "locked", reason: due, device: infoOf(record) };
  if (ring.devices === null) return { state: "locked", reason: "no-seal", device: infoOf(record) };
  const listed = ring.devices.find((d) => d.id === record!.deviceId)!;
  if (listed.signingKey !== record.signingPublic) throw new KeySubstitutionDetected("Mail lists this device with another signing key");

  // 3. Its seal of the active key, opened with its unlock key.
  const seal = ring.seals.find((s) => s.keyId === ring.active.keyId && s.to.kind === "device" && s.to.id === record!.deviceId);
  let active: MailboxPrivateKey | null = null;
  if (seal !== undefined) {
    try {
      active = await openKeySeal(
        { kind: "device", deviceId: record.deviceId, privateKey: record.unlockKey!, publicKey: fromBase64url(record.unlockPublic!)! }, // pragma: allowlist secret (a non-extractable CryptoKey reference)
        { mailboxId: ring.mailboxId, sealedKeyId: ring.active.keyId },
        seal.sealed,
      );
    } catch {
      active = null;
    }
  }
  if (active === null) {
    record = await dropUnlockKey(record);
    return { state: "locked", reason: "no-seal", device: infoOf(record) };
  }

  // 4. K2′ from the key this device last accepted, then K3 (a recipient whose tag fails is flagged).
  const keys = await trustChain(ring, active, [record.lastKeyId]);
  const binding = await bindingOf(ring, active);
  const flagged = await checkTags(ring, binding);

  // 5. The device accepts the active key.
  const current = (await store.update(ring.mailboxId, record.deviceId, { lastKeyId: ring.active.keyId, lastActiveAt: now() }).catch(failed)) ?? record;
  const session = new Session({ ring, keys, binding, store, signInId: options.signInId, now, freshFactor: null, idleLockMs, flagged });
  await session.bindDevice(current);
  return { state: "unlocked", mailbox: session };
}
