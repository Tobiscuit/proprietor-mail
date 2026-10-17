/**
 * Enrollment (contracts/mail-client-v1.md "Enrollment", as amended by spec
 * 002): the key pair is made in the browser and wrapped twice, under the
 * passkey's PRF output and under a recovery key the owner is shown once and
 * must prove saved. Each wrap carries its factor's key (device-v1 A2, from
 * the same secret) and its tag under the new key (A5), so the mailbox
 * requires sessions from the start (B5).
 */
import {
  bindingKey,
  bindingTag,
  fingerprint,
  generateMailboxKey,
  generateSigningKey,
  generateUnlockKey,
  newId,
  sealKey,
  x25519Supported,
  type BindingKey,
  type MailboxPrivateKey,
  type MailboxPublicKey,
} from "@proprietor/mail-crypto";
import { base64url, randomBytes } from "./bytes";
import { deviceLabelOk } from "./device-store";
import { EnrollmentDiscarded, InvalidDeviceLabel, MailboxNotProvisioned, RecoveryNotConfirmed, StorageUnavailable, UnsupportedBrowser } from "./errors";
import { decryptOnlyCopy, makePasskeyWrap, makeRecoveryWrap } from "./factors";
import type { Ring } from "./keyring";
import { DEFAULT_IDLE_LOCK_MS, LOCK_AFTER_MS, Session } from "./session";
import type {
  DeviceStore,
  EnrollmentOptions,
  EnrollRequest,
  Enrollment,
  KeptDevice,
  LockAfter,
  MailboxView,
  PasskeyOptions,
  RegisterDeviceRequest,
  UnlockedMailbox,
  UnlockOptions,
  WrapInput,
} from "./types";

/** "This device is mine" at enrollment: the device's request, and the record to keep once Mail has it. */
interface KeepAtEnrollment {
  store: DeviceStore;
  request: RegisterDeviceRequest;
  record: Omit<KeptDevice, "lastActiveAt">;
  lockedTag: string;
}

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

class EnrollmentImpl implements Enrollment {
  readonly mailboxId: string;
  readonly fingerprint: string;
  readonly recoveryKey: string;
  readonly passkey: "prf" | "none";
  readonly recoveryCheck: { readonly positions: readonly number[] };
  private priv: MailboxPrivateKey | null;
  private readonly pub: MailboxPublicKey;
  private readonly binding: BindingKey;
  private readonly wraps: WrapInput[];
  private readonly keep: KeepAtEnrollment | null;
  private readonly now: () => number;
  private kept: KeptDevice | null = null;
  private readonly expected: string;
  private confirmed = false;
  private discarded = false;

  constructor(
    mailboxId: string,
    priv: MailboxPrivateKey,
    pub: MailboxPublicKey,
    binding: BindingKey,
    recoveryKey: string,
    wraps: WrapInput[],
    passkey: "prf" | "none",
    keep: KeepAtEnrollment | null,
    now: () => number,
  ) {
    this.mailboxId = mailboxId;
    this.fingerprint = fingerprint(pub.keyId);
    this.recoveryKey = recoveryKey;
    this.passkey = passkey;
    this.priv = priv;
    this.pub = pub;
    this.binding = binding;
    this.wraps = wraps;
    this.keep = keep;
    this.now = now;
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
    const request: EnrollRequest = { publicKey: base64url(this.pub.publicKey), wraps: this.wraps.map((w) => ({ ...w })) };
    if (this.keep !== null) request.device = { device: { ...this.keep.request.device }, seal: this.keep.request.seal };
    return request;
  }

  async commit(): Promise<void> {
    this.alive();
    if (this.keep === null || this.kept !== null) return;
    const record: KeptDevice = { ...this.keep.record, lastActiveAt: this.now() };
    await this.keep.store.put(record).catch((e: unknown) => {
      throw e instanceof TypeError ? e : new StorageUnavailable();
    });
    this.kept = record;
  }

  unlocked(options?: UnlockOptions): UnlockedMailbox {
    this.alive();
    if (this.priv === null) throw new EnrollmentDiscarded("unlocked() was already called");
    if (this.keep !== null && this.kept === null) throw new TypeError("commit() first: the device is kept once Mail has it");
    // The session takes the decrypt-only copy made at startEnrollment; the wrappable key is dropped here (K1′).
    const ring = this.ring();
    const session = new Session({
      ring,
      keys: new Map([[this.pub.keyId, this.priv]]),
      binding: this.binding,
      store: options?.store ?? this.keep?.store ?? null,
      signInId: options?.signInId !== undefined ? options.signInId : (this.keep?.record.signInId ?? null),
      now: options?.now ?? this.now,
      freshFactor: null,
      idleLockMs: options?.idleLockMs ?? DEFAULT_IDLE_LOCK_MS,
    });
    if (this.kept !== null) session.attachDevice(this.kept, this.keep!.lockedTag);
    this.priv = null;
    return session;
  }

  /** The key ring Mail will hold once it accepted request(). */
  private ring(): Ring {
    const active = { keyId: this.pub.keyId, publicKey: new Uint8Array(this.pub.publicKey), retiredAt: null, successor: null };
    return {
      mailboxId: this.mailboxId,
      sessions: "required",
      keys: [active],
      active,
      wraps: this.wraps.map((w) => ({ ...w, factorKey: w.factorKey ?? null, tag: w.tag ?? null, tagKeyId: w.tagKeyId ?? null })),
      devices: this.keep === null ? [] : [{ ...this.keep.request.device, createdAt: "", createdBy: "", lastSeenAt: null }],
      seals: this.keep?.request.seal ? [{ keyId: this.pub.keyId, to: { kind: "device", id: this.keep.request.device.id }, sealed: this.keep.request.seal }] : [],
    };
  }

  discard(): void {
    this.discarded = true;
    this.priv = null;
    this.wraps.length = 0;
  }
}

/** The kept device made with the mailbox key (F12): its keys, its seal and its tag under the new key. */
async function keepAtEnrollment(mailboxId: string, priv: MailboxPrivateKey, binding: BindingKey, keep: NonNullable<EnrollmentOptions["keep"]>): Promise<KeepAtEnrollment> {
  if (!deviceLabelOk(keep.label)) throw new InvalidDeviceLabel();
  const lockAfter: LockAfter = keep.lockAfter ?? "sign-out";
  if (!(lockAfter in LOCK_AFTER_MS)) throw new TypeError("an unknown lock setting");
  const deviceId = newId("dev");
  const signing = await generateSigningKey();
  const unlock = lockAfter === "right-away" ? null : await generateUnlockKey();
  const seal = unlock === null ? null : await sealKey(priv, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
  const tag = await bindingTag(binding, { kind: "device", deviceId, label: keep.label, signingKey: signing.publicKey, unlockKey: unlock?.publicKey ?? null }); // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
  const lockedTag = unlock === null ? tag : await bindingTag(binding, { kind: "device", deviceId, label: keep.label, signingKey: signing.publicKey, unlockKey: null }); // pragma: allowlist secret (a pattern, public keys or a test double, not a secret)
  const request: RegisterDeviceRequest = {
    device: { id: deviceId, label: keep.label, signingKey: base64url(signing.publicKey), unlockKey: unlock === null ? null : base64url(unlock.publicKey), tag, tagKeyId: binding.keyId },
    seal,
  };
  return {
    store: keep.store,
    request,
    record: {
      mailboxId,
      deviceId,
      label: keep.label,
      signingKey: signing.privateKey, // pragma: allowlist secret (a non-extractable CryptoKey reference)
      unlockKey: unlock?.privateKey ?? null,
      signingPublic: request.device.signingKey,
      unlockPublic: request.device.unlockKey,
      lastKeyId: binding.keyId,
      lockAfter,
      signInId: keep.signInId ?? null,
    },
    lockedTag,
  };
}

export async function startEnrollment(
  mailbox: Pick<MailboxView, "id" | "address" | "status">,
  passkey: PasskeyOptions | null,
  options?: EnrollmentOptions,
): Promise<Enrollment> {
  if (mailbox.status !== "provisioned") throw new MailboxNotProvisioned();
  if (!(await x25519Supported())) throw new UnsupportedBrowser("this browser's Web Crypto has no X25519 with key wrapping");
  const { publicKey, privateKey } = await generateMailboxKey();
  // Every factor gets its factor key and a tag under the new key: the mailbox requires sessions from the start (device-v1 B5).
  const binding = await bindingKey(privateKey, { mailboxId: mailbox.id });
  const wraps: WrapInput[] = [];
  if (passkey !== null) wraps.push(await makePasskeyWrap(mailbox.id, privateKey, passkey, binding));
  const recovery = await makeRecoveryWrap(mailbox.id, privateKey, binding);
  wraps.push(recovery.wrap);
  const keep = options?.keep === undefined ? null : await keepAtEnrollment(mailbox.id, privateKey, binding, options.keep);
  // Every wrap and seal is made; from here on only a decrypt-only copy of the key exists in this page (K1′).
  const decryptOnly = await decryptOnlyCopy(mailbox.id, privateKey);
  return new EnrollmentImpl(mailbox.id, decryptOnly, publicKey, binding, recovery.recoveryKey, wraps, passkey === null ? "none" : "prf", keep, options?.now ?? Date.now);
}
