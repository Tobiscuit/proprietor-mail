// The round 3 flows (plan.md §10.2) as the dashboard's inbox runs them, against the fake Mail: a mail
// session (a kept device's signature, or D38's factor proof of kind open-session), a factor proof bound
// to the change it confirms (K4, K12: challenge with the change's action, answer with its confirmation),
// and F1, keeping this browser.
import type { ConfirmedChange, DeviceStore, FactorProof, FreshFactor, KeyProof, LockAfter, RegisterDeviceRequest, UnlockedMailbox } from "../src/index";
import type { FakeMail } from "./fake-mail";
import type { Enrolled } from "./keyring-support";
import { unlockWithRecoveryKey } from "../src/index";

/** The account the tests act as: the capability's `sub`. */
export const OWNER = "acc_owner";

/** A factor proof bound to `change` (A10): Mail's challenge for its action, answered only for it. */
export async function proofFor(fake: FakeMail, ff: FreshFactor, change: Pick<ConfirmedChange<unknown>, "confirmation">): Promise<FactorProof> {
  const challenge = await fake.challenge({ purpose: "factor", factorId: ff.factorId, action: change.confirmation.action });
  return ff.answer(challenge, change.confirmation);
}

/** The upgrade's key proof (round 3): a key challenge for its action, answered with the mailbox key. */
export async function keyProofFor(fake: FakeMail, unlocked: UnlockedMailbox, change: Pick<ConfirmedChange<unknown>, "confirmation">): Promise<KeyProof> {
  return unlocked.keyProof(await fake.challenge({ purpose: "key", action: change.confirmation.action }), change.confirmation);
}

/**
 * A mail session for `unlocked`: on a kept device its signature; where sessions are required and no
 * device is kept, D38's factor proof of kind open-session from `ff`; where sessions are optional, the
 * key proof alone.
 */
export async function openSession(fake: FakeMail, unlocked: UnlockedMailbox, ff: FreshFactor | null = unlocked.freshFactor) {
  const challenge = await fake.challenge({ purpose: "session" });
  if (unlocked.device !== null || fake.sessionsMode === "optional") return fake.openSession(await unlocked.sessionProof(challenge));
  if (ff === null) throw new Error("a deviceless session needs a FreshFactor (D38)");
  const confirmation = await unlocked.sessionConfirmation(challenge);
  const factorChallenge = await fake.challenge({ purpose: "factor", factorId: ff.factorId, action: confirmation.action });
  return fake.openSession(await unlocked.sessionProof(challenge, await ff.answer(factorChallenge, confirmation)));
}

/** F1: unlock with the recovery key, open a session with a factor proof, keep this device with another, commit. */
export async function keepDevice(
  e: Enrolled,
  store: DeviceStore,
  options: { lockAfter?: LockAfter; signInId?: string | null; now?: () => number; label?: string; accountId?: string } = {},
): Promise<{ unlocked: UnlockedMailbox; session: string; request: RegisterDeviceRequest }> {
  const signInId = options.signInId === undefined ? "signin-1" : options.signInId;
  const accountId = options.accountId ?? OWNER;
  const unlocked = await unlockWithRecoveryKey(e.fake.mailbox(), e.recoveryKey, { store, accountId, signInId, ...(options.now ? { now: options.now } : {}) });
  const { session } = await openSession(e.fake, unlocked);
  const ff = unlocked.freshFactor!;
  const pending = await unlocked.keepThisDevice({ label: options.label ?? "Kitchen laptop", ...(options.lockAfter ? { lockAfter: options.lockAfter } : {}) }, ff);
  await e.fake.registerDevice(pending.request, { session, factorProof: await proofFor(e.fake, ff, pending) });
  await pending.commit();
  return { unlocked, session, request: pending.request };
}
