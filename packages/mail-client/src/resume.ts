/**
 * A kept device loads the inbox (plan.md F2, F3, F10; contracts/device-v1.md
 * Part C, K6, K7, K10, K11).
 *
 * In this order:
 *  0. K10: only the signed-in account's record is read. Another account's
 *     record of the same mailbox, on the same browser, is never read, opened,
 *     used or deleted: for that account this is a browser with no device.
 *  1. K6, the browser's own lock settings, before anything else: "right away"
 *     keeps nothing; 15 minutes or 1 hour since the last use; for "when I sign
 *     out", another sign-in id than the one it was unlocked under, a null
 *     after a non-null included (D34). A lock that fell due deletes the unlock
 *     key first, so a lock is never just skipped.
 *  2. K7: a device the view no longer lists is wiped (this account's record),
 *     and the answer is "removed". A view with no devices at all comes from a
 *     Mail Worker without spec 002: the record is kept, and the device waits
 *     (no-seal).
 *  3. The device's seal of the active key, opened with its unlock key; none,
 *     or one that does not open, means a factor is needed, and the useless
 *     unlock key is deleted.
 *  4. K2″ from the key this device last accepted, each step signed by a factor
 *     connected to the record's trustRoot (a rollback, or a key the server
 *     sealed to the device, has no chain back to it; a key from a removed
 *     device has no transition a trusted factor signed), and K3′, which flags
 *     a recipient whose tag fails or whom no trusted factor admitted.
 *  5. K11: the device accepts the active key only while its record still holds
 *     the key the walk started from, read and written in one transaction.
 *     When another page moved it meanwhile, this page resumes again from the
 *     record as it now is.
 */
import { openKeySeal, type MailboxPrivateKey } from "@proprietor/mail-crypto";
import { fromBase64url } from "./bytes";
import { accountIdOk } from "./device-store";
import { MailboxChanged, StorageUnavailable } from "./errors";
import { bindingOf, checkRecipients, readRing, trustChain, trustOf } from "./keyring";
import { checkListedDevice, idleLockMsOf, LOCK_AFTER_MS, Session, SWAP_ATTEMPTS } from "./session";
import type { DeviceInfo, KeptDevice, LockReason, MailboxView, ResumeOptions, ResumeResult } from "./types";

/**
 * K6 and D34: why this kept device must be unlocked with a factor now, or null when it may open without
 * a prompt. "When I sign out" locks when the sign-in id differs from the one it was unlocked under: a new
 * sign-in, or none after one. Two nulls never lock (a preview, where the dashboard has no sign-in of its own).
 */
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
  const accountId = options.accountId;
  if (!accountIdOk(accountId)) throw new TypeError("resumeDevice reads the signed-in account's record only: its account id (K10)");
  const now = options.now ?? Date.now;
  const idleLockMs = idleLockMsOf(options);
  const failed = (e: unknown): never => {
    throw e instanceof TypeError ? e : new StorageUnavailable();
  };
  const mailboxId = ring.mailboxId;
  const dropUnlockKey = async (r: KeptDevice): Promise<KeptDevice> =>
    r.unlockKey === null ? r : ((await store.update(mailboxId, accountId, r.deviceId, { unlockKey: null, unlockPublic: null }).catch(failed)) ?? { ...r, unlockKey: null, unlockPublic: null });

  for (let attempt = 0; ; attempt++) {
    // 0. K10: this account's record, and no other.
    let record = await store.get(mailboxId, accountId).catch(failed);
    if (record === null) return { state: "none" };

    // 1. K6: a lock that fell due deletes the unlock key before anything else.
    const due = lockDue(record, options.signInId, now());
    if (due !== null) record = await dropUnlockKey(record);

    // 2. K7: removed from the mailbox means wiped (this account's record). (A view without devices is from a Worker without spec 002.)
    if (ring.devices !== null && !ring.devices.some((d) => d.id === record!.deviceId)) {
      await store.delete(mailboxId, accountId, record.deviceId).catch(failed);
      return { state: "removed" };
    }
    if (due !== null) return { state: "locked", reason: due, device: infoOf(record) };
    if (ring.devices === null) return { state: "locked", reason: "no-seal", device: infoOf(record) };
    checkListedDevice(ring, record);

    // 3. Its seal of the active key, opened with its unlock key.
    const seal = ring.seals.find((s) => s.keyId === ring.active.keyId && s.to.kind === "device" && s.to.id === record!.deviceId);
    let active: MailboxPrivateKey | null = null;
    if (seal !== undefined) {
      try {
        active = await openKeySeal(
          { kind: "device", deviceId: record.deviceId, privateKey: record.unlockKey!, publicKey: fromBase64url(record.unlockPublic!)! }, // pragma: allowlist secret (a non-extractable CryptoKey reference)
          { mailboxId, sealedKeyId: ring.active.keyId },
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

    // 4. K2″ from the key this device last accepted, each step signed by a factor connected to its
    // trustRoot; then K3′ (a recipient whose tag fails or whom no trusted factor admitted is flagged).
    const trustStart = fromBase64url(record.trustRoot);
    const trusted = await trustOf(ring, trustStart);
    const keys = await trustChain(ring, active, [record.lastKeyId], trusted, attempt > 0);
    const binding = await bindingOf(ring, active);
    const flagged = await checkRecipients(ring, binding, trusted);

    // 5. K11: the device accepts the active key only from the key the walk started from.
    const swap = await store.swapLastKeyId(mailboxId, accountId, record.deviceId, record.lastKeyId, { lastKeyId: ring.active.keyId, lastActiveAt: now() }).catch(failed);
    if (!swap.swapped) {
      // Another page moved the last accepted key, or forgot the device, meanwhile: resume again from the record as it now is.
      if (attempt + 1 >= SWAP_ATTEMPTS) throw new MailboxChanged();
      continue;
    }
    const session = new Session({ ring, keys, binding, store, accountId, signInId: options.signInId, now, freshFactor: null, idleLockMs, flagged, trustStart });
    await session.bindDevice(swap.record!);
    return { state: "unlocked", mailbox: session };
  }
}
