/**
 * The FreshFactor (contracts/device-v1.md Part C, K1′; plan.md §3): what the
 * browser holds just after a factor was used, for at most 2 minutes or until
 * disposed. Namely the factor's own key (A2), which answers factor challenges
 * (D25: Mail checks a fresh factor for every sensitive setting), and a
 * wrappable copy of the active key, for the one step that seals or wraps it
 * again (keeping a device, removing one, adding a passkey, a new recovery
 * key). Nothing else in the package holds an extractable mailbox key.
 *
 * Expiry is checked against the injected clock at every use; after it, or
 * after dispose(), the keys are dropped and every use throws FactorExpired.
 *
 * Round 3: the factor's key also signs (A2b, A11: Ed25519), so the FreshFactor
 * is what admits a device or a factor and signs a rotation's transition (K12).
 * And it answers a factor challenge only for the action the caller is about to
 * send: answer() takes that action's Confirmation, builds the descriptor it
 * expects, compares it with Mail's bytes, and opens the challenge with its own
 * digest (K4).
 */
import { DecryptionFailed, openChallenge, type FactorPrivateKey, type MailboxPrivateKey } from "@proprietor/mail-crypto";
import { base64url } from "./bytes";
import { expectedDigest } from "./confirmations";
import { FactorExpired, InvalidChallenge } from "./errors";
import type { RingWrap } from "./keyring";
import type { ChallengeView, Confirmation, FactorProof, FreshFactor } from "./types";

/** How long a FreshFactor lasts: 2 minutes, as a challenge does (device-v1 B6). */
export const FRESH_FACTOR_MS = 2 * 60_000;

const CHALLENGE_ID = /^chl_[0-9a-hjkmnp-tv-z]{26}$/;

/** The parts of the factor's wrap a request names: never its secret. */
export type FactorFacts = Pick<RingWrap, "id" | "keyId" | "kind" | "label" | "credentialId">;

interface Material {
  /** The factor's own key (A2), which also signs (A2b). */
  factorKey: FactorPrivateKey;
  factorPublic: Uint8Array<ArrayBuffer>;
  /** vS, the factor's Ed25519 signing key (A2b), 32 bytes. */
  signingPublic: Uint8Array<ArrayBuffer>;
  /** The active key, wrappable; null when this factor cannot reach it (StaleFactor). */
  active: MailboxPrivateKey | null;
}

export class FreshFactorImpl implements FreshFactor {
  readonly factorId: string;
  readonly kind: "passkey-prf" | "recovery";
  readonly expiresAt: number;
  readonly mailboxId: string;
  readonly facts: FactorFacts;
  private material: Material | null;
  private readonly now: () => number;

  constructor(mailboxId: string, facts: FactorFacts, material: Material, now: () => number) {
    this.mailboxId = mailboxId;
    this.facts = Object.freeze({ ...facts });
    this.factorId = facts.id;
    this.kind = facts.kind;
    this.material = material;
    this.now = now;
    this.expiresAt = now() + FRESH_FACTOR_MS;
  }

  get expired(): boolean {
    if (this.material !== null && this.now() >= this.expiresAt) this.material = null;
    return this.material === null;
  }

  /** The keys, for this package's own steps; FactorExpired once the 2 minutes are over. */
  use(mailboxId: string): Material {
    if (this.expired) throw new FactorExpired();
    if (mailboxId !== this.mailboxId) throw new TypeError("this FreshFactor belongs to another mailbox");
    return this.material!;
  }

  /** After a rotation this browser committed, the wrappable key is the new active key (still for the same 2 minutes). */
  retarget(active: MailboxPrivateKey): void {
    if (this.material !== null) this.material = { ...this.material, active };
  }

  async answer(challenge: ChallengeView, confirmation: Confirmation): Promise<FactorProof> {
    const { factorKey } = this.use(this.mailboxId);
    if (
      typeof challenge !== "object" ||
      challenge === null ||
      challenge.purpose !== "factor" ||
      challenge.factorId !== this.factorId ||
      typeof challenge.id !== "string" ||
      !CHALLENGE_ID.test(challenge.id)
    ) {
      throw new TypeError("not a factor challenge for this factor");
    }
    // K4, K12: only the challenge of the action this browser is about to send; its own digest opens it.
    const actionDigest = await expectedDigest(challenge, confirmation, this.mailboxId, "factor");
    if (typeof challenge.sealed !== "string") throw new InvalidChallenge();
    let answer: Uint8Array;
    try {
      answer = await openChallenge(factorKey, { mailboxId: this.mailboxId, challengeId: challenge.id, actionDigest }, challenge.sealed);
    } catch (e) {
      // K4: anything that does not open as this factor's challenge is answered with nothing.
      if (e instanceof DecryptionFailed) throw new InvalidChallenge();
      throw e;
    }
    try {
      return { challengeId: challenge.id, answer: base64url(answer) };
    } finally {
      answer.fill(0);
    }
  }

  dispose(): void {
    this.material = null;
  }
}

/** The package's own FreshFactor behind the interface, or a TypeError for anything else. */
export function freshFactorOf(value: FreshFactor): FreshFactorImpl {
  if (!(value instanceof FreshFactorImpl)) throw new TypeError("not a FreshFactor from this package");
  return value;
}
