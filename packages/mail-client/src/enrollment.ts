/**
 * Enrollment (contracts/mail-client-v1.md "Enrollment"): the key pair is
 * made in the browser and wrapped twice, under the passkey's PRF output and
 * under a recovery key the owner is shown once and must prove saved.
 */
import { fingerprint, generateMailboxKey, newId, unwrapPrivateKey, wrapPrivateKey, x25519Supported, type MailboxPrivateKey, type MailboxPublicKey } from "@proprietor/mail-crypto";
import { base64url, randomBytes } from "./bytes";
import { EnrollmentDiscarded, MailboxNotProvisioned, RecoveryNotConfirmed, UnsupportedBrowser } from "./errors";
import { makePasskeyWrap, makeRecoveryWrap, Session } from "./session";
import type { EnrollRequest, Enrollment, MailboxView, PasskeyOptions, UnlockedMailbox, UnlockOptions, WrapInput } from "./types";

const RECOVERY_SYMBOLS = 55;
const CHECK_POSITIONS = 4;

/** Four distinct 1-based positions among the recovery key's 55 symbols, in order. */
function checkPositions(): number[] {
  const chosen = new Set<number>();
  while (chosen.size < CHECK_POSITIONS) {
    const [byte] = randomBytes(1);
    if (byte! < 220) chosen.add((byte! % RECOVERY_SYMBOLS) + 1); // 220 = 4 × 55: no modulo bias
  }
  return [...chosen].sort((a, b) => a - b);
}

/** The same forgiveness as parseRecoveryKey: case, spaces and hyphens, I/L as 1, O as 0. */
function canonicalSymbols(input: string): string {
  return input.replace(/[\s-]/g, "").toUpperCase().replace(/[IL]/g, "1").replace(/O/g, "0");
}

/**
 * A decrypt-only copy of a wrappable key, without a prompt: the key is wrapped
 * under a throwaway secret and unwrapped non-extractable, so the session holds
 * no key that can be wrapped again (K1).
 */
export async function decryptOnlyCopy(mailboxId: string, priv: MailboxPrivateKey): Promise<MailboxPrivateKey> {
  const secret = randomBytes(32); // pragma: allowlist secret (a variable or type name, not a value)
  try {
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
    return await unwrapPrivateKey(wrap, { mailboxId, secret });
  } finally {
    secret.fill(0);
  }
}

class EnrollmentImpl implements Enrollment {
  readonly mailboxId: string;
  readonly fingerprint: string;
  readonly recoveryKey: string;
  readonly passkey: "prf" | "none";
  readonly recoveryCheck: { readonly positions: readonly number[] };
  private priv: MailboxPrivateKey | null;
  private readonly pub: MailboxPublicKey;
  private readonly wraps: WrapInput[];
  private readonly expected: string;
  private confirmed = false;
  private discarded = false;

  constructor(mailboxId: string, priv: MailboxPrivateKey, pub: MailboxPublicKey, recoveryKey: string, wraps: WrapInput[], passkey: "prf" | "none") {
    this.mailboxId = mailboxId;
    this.fingerprint = fingerprint(pub.keyId);
    this.recoveryKey = recoveryKey;
    this.passkey = passkey;
    this.priv = priv;
    this.pub = pub;
    this.wraps = wraps;
    const positions = checkPositions();
    this.recoveryCheck = Object.freeze({ positions: Object.freeze(positions) });
    const symbols = recoveryKey.replace(/-/g, "");
    this.expected = positions.map((p) => symbols[p - 1]!).join("");
  }

  private alive(): void {
    if (this.discarded) throw new EnrollmentDiscarded();
  }

  confirmRecovery(characters: string): boolean {
    this.alive();
    const given = canonicalSymbols(String(characters));
    const ok = given.length === this.expected.length && given === this.expected;
    if (ok) this.confirmed = true;
    return ok;
  }

  request(): EnrollRequest {
    this.alive();
    if (!this.confirmed) throw new RecoveryNotConfirmed();
    return { publicKey: base64url(this.pub.publicKey), wraps: this.wraps.map((w) => ({ ...w })) };
  }

  unlocked(options?: UnlockOptions): UnlockedMailbox {
    this.alive();
    if (this.priv === null) throw new EnrollmentDiscarded("unlocked() was already called");
    // The session takes the decrypt-only copy made at startEnrollment; the wrappable key is dropped here (K1).
    const session = new Session(this.mailboxId, this.priv, this.pub, this.wraps, options);
    this.priv = null;
    return session;
  }

  discard(): void {
    this.discarded = true;
    this.priv = null;
    this.wraps.length = 0;
  }
}

export async function startEnrollment(
  mailbox: Pick<MailboxView, "id" | "address" | "status">,
  passkey: PasskeyOptions | null,
): Promise<Enrollment> {
  if (mailbox.status !== "provisioned") throw new MailboxNotProvisioned();
  if (!(await x25519Supported())) throw new UnsupportedBrowser("this browser's Web Crypto has no X25519 with key wrapping");
  const { publicKey, privateKey } = await generateMailboxKey();
  const wraps: WrapInput[] = [];
  if (passkey !== null) wraps.push(await makePasskeyWrap(mailbox.id, privateKey, passkey));
  const recovery = await makeRecoveryWrap(mailbox.id, privateKey);
  wraps.push(recovery.wrap);
  // Both wraps are made; from here on only a decrypt-only copy of the key exists in this page (K1).
  const decryptOnly = await decryptOnlyCopy(mailbox.id, privateKey);
  return new EnrollmentImpl(mailbox.id, decryptOnly, publicKey, recovery.recoveryKey, wraps, passkey === null ? "none" : "prf");
}
