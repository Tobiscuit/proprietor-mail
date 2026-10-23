/**
 * Unlocking, and the unlocked mailbox (contracts/mail-client-v1.md
 * "Unlocking", "Reading", "Drafts and sending", as amended by spec 002;
 * contracts/device-v1.md Part C).
 *
 * A session holds EVERY key the key ring's chain reaches (G40), each a
 * non-extractable, decrypt-only CryptoKey inside mail-crypto's handle, by
 * keyId; the active key's public half; its binding key (A5); and the public
 * facts it needs to use a factor again. It is accepted only after K2″ (the
 * active key leads back to a key this browser trusts, each step signed by a
 * trusted factor), and K3′ checks every recipient in the ring: one whose tag
 * fails or whom no trusted factor admitted is flagged (`flagged`), never
 * sealed to, and removable, while the rest of the inbox works. Its trust
 * starts from one factor signing key (the factor just used, once K9 confirms
 * its keys; or a kept device's trustRoot): the factors connected to it in the
 * factor graph (A11) are the ones whose signatures it accepts. After a factor,
 * it offers that factor's FreshFactor for 2 minutes (K1′), which also signs
 * what this browser asks Mail to accept (K12); nothing else in it can be
 * wrapped or sealed again.
 *
 * On a kept device (K5 to K7, K10, K11) it also holds the device's record,
 * this account's: it signs the device's proofs, keeps the record's last use
 * current, and locks by the device's own setting (K6): Lock now, 15 minutes or
 * 1 hour without use, or never on idle for "when I sign out". Locking drops
 * every key at once and deletes the unlock key from the store, and hands back
 * the request that clears it at Mail; its tag is made when the device is
 * bound, because no key is left to make it once locked.
 */
import {
  bindingKey,
  bindingTag,
  bootstrapAdmitters,
  DecryptionFailed,
  factorPublicKey,
  factorSigningKey,
  fingerprint,
  generateMailboxKey,
  generateSigningKey,
  generateUnlockKey,
  keyIdOf,
  newId,
  openChallenge,
  openDraft,
  openHeader,
  openKeySeal,
  openBody as openSealedBody,
  sealDraft as sealDraftBlock,
  sealKey,
  signDeviceProof,
  signStatement,
  verifyStatement,
  type BindingKey,
  type FactorPrivateKey,
  type MailboxPrivateKey,
  type MailboxPublicKey,
  type TrustedFactors,
} from "@proprietor/mail-crypto";
import { base64url, fromBase64url } from "./bytes";
import { confirmationFor, expectedDigest } from "./confirmations";
import { accountIdOk, deviceLabelOk } from "./device-store";
import {
  DeviceRemoved,
  FlaggedRecipient,
  InvalidChallenge,
  InvalidDeviceLabel,
  KeySubstitutionDetected,
  MailboxChanged,
  MailboxLocked,
  MissingFactors,
  NoRecoveryFactor,
  RotationDue,
  RotationUnproven,
  StaleFactor,
  StorageUnavailable,
  UndecryptableBody,
} from "./errors";
import { activeOfFactor, admissionOf, decryptOnlyCopy, factorTag, listedKeyMatches, makePasskeyWrap, makeRecoveryWrap, openFactor, type OpenedFactor } from "./factors";
import { FreshFactorImpl, freshFactorOf } from "./fresh-factor";
import { bindingOf, checkAdvertisedKey, checkRecipients, deviceRecipient, factorRecipient, flaggedOf, NONE_FLAGGED, readRing, trustChain, trustOf, type Ring, type RingWrap } from "./keyring";
import { parseMail } from "./mime";
import type {
  ChallengeView,
  Confirmation,
  ConfirmedChange,
  DeviceInfo,
  DeviceStore,
  DraftInput,
  DraftRecord,
  FactorProof,
  FlaggedRecipients,
  FreshFactor,
  KeptDevice,
  KeptDeviceChange,
  KeyProof,
  LockAfter,
  LockEvent,
  LockResult,
  MailBody,
  MailboxView,
  MessageItem,
  NewRecoveryKey,
  OpenedDraft,
  OpenedMessage,
  OpenSessionRequest,
  PasskeyOptions,
  PasskeyPrompt,
  PendingChange,
  ReAuth,
  RegisterDeviceRequest,
  RemoveDevicesRequest,
  RemoveWrapRequest,
  Rotation,
  RotationDueView,
  SaveDraftRequest,
  UnlockedMailbox,
  UnlockOptions,
  UpdateDeviceRequest,
  UpgradeRequest,
  WrapInput,
} from "./types";

export const DEFAULT_IDLE_LOCK_MS = 15 * 60_000;
export { RECOVERY_LABEL } from "./factors";

/** R3: how long each lock setting lets a kept device go unused. "right-away" keeps nothing between pages; "sign-out" never locks on idle. */
export const LOCK_AFTER_MS: Readonly<Record<LockAfter, number>> = Object.freeze({
  "right-away": 0,
  "15-minutes": 15 * 60_000,
  "1-hour": 60 * 60_000,
  "sign-out": Number.POSITIVE_INFINITY,
});
const LOCK_SETTINGS = Object.keys(LOCK_AFTER_MS) as LockAfter[];
/** A kept device's last use is written at most this often. */
const ACTIVITY_WRITE_MS = 30_000;
const CHALLENGE_ID = /^chl_[0-9a-hjkmnp-tv-z]{26}$/;
/** B7, D40: a rotation names at most 20 devices. */
const MAX_REMOVED = 20;

/** The mailbox's active key, as advertised (domain-model G7: checked against every key opened for it). */
export function activeKeyOf(view: Pick<MailboxView, "keys" | "wraps" | "id">): MailboxPublicKey {
  const { active } = readRing(view as MailboxView);
  return { keyId: active.keyId, publicKey: active.publicKey };
}

export function idleLockMsOf(options?: { idleLockMs?: number }): number {
  const ms = options?.idleLockMs ?? DEFAULT_IDLE_LOCK_MS;
  if (typeof ms !== "number" || Number.isNaN(ms) || ms <= 0) throw new TypeError("idleLockMs is a positive number of milliseconds, or Infinity");
  return ms;
}

/** A request for Mail and what to do here once Mail accepted it; commit() runs once. */
export function pendingChange<T>(request: T, apply: () => Promise<void>): PendingChange<T> {
  let done: Promise<void> | null = null;
  return Object.freeze({ request, commit: () => (done ??= apply()) });
}

/** A PendingChange that Mail takes only with a proof bound to `confirmation` (A10, K12). */
export function confirmedChange<T>(request: T, confirmation: Confirmation, apply: () => Promise<void>): ConfirmedChange<T> {
  let done: Promise<void> | null = null;
  return Object.freeze({ request, confirmation, commit: () => (done ??= apply()) });
}

/** Store failures are StorageUnavailable; a record K5 refuses stays the caller's TypeError. */
function storageFailure(e: unknown): never {
  throw e instanceof TypeError || e instanceof StorageUnavailable ? e : new StorageUnavailable();
}

/** Everything a session is made of; built by the unlock paths after K2″ and K3′. */
export interface SessionParts {
  ring: Ring;
  keys: Map<string, MailboxPrivateKey>;
  binding: BindingKey;
  store: DeviceStore | null;
  /** K10: the signed-in account; required with a store. */
  accountId: string | null;
  signInId: string | null;
  now: () => number;
  freshFactor: FreshFactorImpl | null;
  idleLockMs: number;
  /** The signing key this session's trust starts from (A11): the factor just used, or the device's trustRoot. Null trusts nothing. */
  trustStart: Uint8Array | null;
  /** K3′ at the unlock: the recipients flagged. */
  flagged?: FlaggedRecipients;
  /** K9 at the unlock: the factor used, when the key ring lists other keys for it. */
  mismatched?: readonly string[];
}

export class Session implements UnlockedMailbox {
  readonly mailboxId: string;
  readonly freshFactor: FreshFactor | null;
  private keys: Map<string, MailboxPrivateKey> | null;
  private binding: BindingKey;
  /** The key ring as this session knows it: the view it was unlocked or refreshed with, and what it committed since. */
  private ring: Ring;
  private keptDevice: KeptDevice | null = null;
  /** K3′: the recipients of this.ring flagged under the active key. */
  private tagFlags: FlaggedRecipients;
  /** K9: factors used in this session whose listed keys are not the ones they derive. */
  private readonly mismatched: Set<string>;
  /** The device's tag over "no unlock key" under the active key: what Lock now sends, made while a key is held. */
  private lockedTag: string | null = null;
  private lastActivityWrite = Number.NEGATIVE_INFINITY;
  private readonly store: DeviceStore | null;
  private readonly accountId: string | null;
  private readonly signInId: string | null;
  private trustStart: Uint8Array | null;
  private readonly now: () => number;
  private readonly idleLockMs: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly listeners = new Set<(event: LockEvent) => void>();
  private readonly factors = new Set<FreshFactorImpl>();

  constructor(parts: SessionParts) {
    if (parts.store !== null && !accountIdOk(parts.accountId)) throw new TypeError("a store comes with the signed-in account's id (K10)");
    this.mailboxId = parts.ring.mailboxId;
    this.ring = parts.ring;
    this.keys = parts.keys;
    this.binding = parts.binding;
    this.store = parts.store;
    this.accountId = parts.accountId;
    this.signInId = parts.signInId;
    this.trustStart = parts.trustStart === null ? null : new Uint8Array(parts.trustStart);
    this.now = parts.now;
    this.idleLockMs = parts.idleLockMs;
    this.freshFactor = parts.freshFactor;
    this.tagFlags = parts.flagged ?? NONE_FLAGGED;
    this.mismatched = new Set(parts.mismatched ?? []);
    if (parts.freshFactor !== null) this.factors.add(parts.freshFactor);
    this.arm();
  }

  /** The active key's public half. */
  private get active(): MailboxPublicKey {
    return { keyId: this.ring.active.keyId, publicKey: this.ring.active.publicKey };
  }

  get keyId(): string {
    return this.ring.active.keyId;
  }

  get fingerprint(): string {
    return fingerprint(this.ring.active.keyId);
  }

  get keyIds(): readonly string[] {
    return this.keys === null ? [] : Object.freeze([...this.keys.keys()]);
  }

  get locked(): boolean {
    return this.keys === null;
  }

  get flagged(): FlaggedRecipients {
    return this.flaggedIn(this.ring);
  }

  get rotationDue(): RotationDueView | null {
    const due = this.ring.rotationDue;
    return due === null ? null : Object.freeze({ since: due.since, by: due.by, devices: Object.freeze([...due.devices]) as string[] });
  }

  /** K3′'s flags for `ring` and the factors K9 flagged, as long as the ring still lists them. */
  private flaggedIn(ring: Ring, tagFlags: FlaggedRecipients = this.tagFlags): FlaggedRecipients {
    const k9 = ring.wraps.filter((w) => this.mismatched.has(w.id)).map((w) => w.id);
    return k9.length === 0 ? tagFlags : flaggedOf(tagFlags.devices, [...tagFlags.factors, ...k9]);
  }

  /** K9 for a factor just used: its derived keys against the ones the ring lists. */
  private noteFactorMatch(factorId: string, matches: boolean | null): void {
    if (matches === false) this.mismatched.add(factorId);
    else if (matches === true) this.mismatched.delete(factorId);
  }

  /** The factors this session trusts in `ring` (A11), from its start. */
  private trusted(ring: Ring = this.ring): Promise<TrustedFactors> {
    return trustOf(ring, this.trustStart);
  }

  /** K12: the FreshFactor's factor signs only when its keys are the listed ones (K9) and it is a trusted factor; else FlaggedRecipient. */
  private async requireTrustedSigner(ff: FreshFactorImpl): Promise<void> {
    if (this.mismatched.has(ff.factorId) || !(await this.trusted()).ids.includes(ff.factorId)) {
      throw new FlaggedRecipient("this factor is not one the key ring trusts: use another", { factors: [ff.factorId] });
    }
  }

  /** K13: while a rotation is due, it comes before any other change. */
  private dueFirst(): void {
    if (this.ring.rotationDue !== null) throw new RotationDue();
  }

  get device(): DeviceInfo | null {
    const d = this.keptDevice;
    return d === null ? null : Object.freeze({ id: d.deviceId, label: d.label, lockAfter: d.lockAfter, keepsUnlocked: d.unlockKey !== null });
  }

  // ---- The lock engine (K6) ----

  /** The idle lock: a kept device's own setting, else the page's (15 minutes by default). */
  private idleMs(): number {
    const d = this.keptDevice;
    return d === null || d.lockAfter === "right-away" ? this.idleLockMs : LOCK_AFTER_MS[d.lockAfter];
  }

  private arm(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    const ms = this.idleMs();
    this.timer = Number.isFinite(ms) ? setTimeout(() => void this.lockFor("idle").catch(() => undefined), ms) : null;
  }

  /** The keys, after proving the session is unlocked; every method starts here and counts as activity. */
  private unlockedKeys(): Map<string, MailboxPrivateKey> {
    if (this.keys === null) throw new MailboxLocked();
    this.arm();
    this.noteActivity();
    return this.keys;
  }

  private activeKey(): MailboxPrivateKey {
    return this.unlockedKeys().get(this.ring.active.keyId)!;
  }

  /**
   * Writes a kept device's last use (at most every 30 seconds), and notices
   * another page of this browser locking or forgetting the device: then this
   * page locks too.
   */
  private noteActivity(): void {
    const d = this.keptDevice;
    const store = this.store;
    const now = this.now();
    if (d === null || store === null || now - this.lastActivityWrite < ACTIVITY_WRITE_MS) return;
    this.lastActivityWrite = now;
    store.update(this.mailboxId, this.accountId!, d.deviceId, { lastActiveAt: now }).then(
      (current) => {
        if (current === null) {
          void this.lockFor("removed", { forgotten: true }).catch(() => undefined);
        } else if (d.unlockKey !== null && current.unlockKey === null && d.lockAfter !== "right-away") {
          void this.lockFor("lock").catch(() => undefined);
        } else if (this.keptDevice !== null) {
          this.keptDevice = current;
        }
      },
      () => undefined,
    );
  }

  touch(): void {
    this.unlockedKeys();
  }

  lock(): Promise<LockResult> {
    return this.lockFor("lock");
  }

  /**
   * Drops every key now; on a kept device that keeps an unlock key, deletes
   * it from the store and answers the request that clears it at Mail (send it
   * with the session while one is live, then forget the session).
   */
  private lockFor(reason: LockEvent["reason"], options: { forgotten?: boolean } = {}): Promise<LockResult> {
    if (this.keys === null) return Promise.resolve({ updateDevice: null });
    const device = this.keptDevice;
    const updateDevice: UpdateDeviceRequest | null =
      device !== null && device.unlockKey !== null && this.lockedTag !== null && !options.forgotten
        ? { unlockKey: null, unlockSignature: null, tag: this.lockedTag, tagKeyId: this.ring.active.keyId, seal: null }
        : null;
    this.keys = null;
    for (const ff of this.factors) ff.dispose();
    this.factors.clear();
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    if (options.forgotten) {
      this.keptDevice = null;
      this.lockedTag = null;
    }
    const event: LockEvent = Object.freeze({ reason, updateDevice });
    for (const listener of [...this.listeners]) listener(event);
    if (device === null || device.unlockKey === null || this.store === null || options.forgotten) return Promise.resolve({ updateDevice });
    return this.store.update(this.mailboxId, this.accountId!, device.deviceId, { unlockKey: null, unlockPublic: null }).then((current) => {
      if (this.keptDevice !== null) this.keptDevice = current;
      return { updateDevice };
    }, storageFailure);
  }

  onLock(listener: (event: LockEvent) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  // ---- The kept device (K5 to K7, K10, K11) ----

  /** Binds this session to its kept device: its proofs are signed with the device's key, and it locks by the device's setting. */
  async bindDevice(record: KeptDevice): Promise<void> {
    const signingKey = fromBase64url(record.signingPublic)!; // pragma: allowlist secret (a public key)
    this.attachDevice(record, await bindingTag(this.binding, { kind: "device", deviceId: record.deviceId, label: record.label, signingKey, unlockKey: null }));
  }

  /** bindDevice with the device's tag over "no unlock key" (under the active key) made already. */
  attachDevice(record: KeptDevice, lockedTag: string): void {
    if (record.accountId !== this.accountId) throw new TypeError("another account's device (K10)");
    this.lockedTag = lockedTag;
    this.keptDevice = record;
    this.lastActivityWrite = this.now();
    if (this.keys !== null) this.arm();
  }

  private requireDevice(): KeptDevice {
    if (this.keptDevice === null) throw new TypeError("this browser is not a kept device of this mailbox");
    return this.keptDevice;
  }

  /** The record after a change, or DeviceRemoved when another page forgot it (this session then forgets it too). */
  private async changeDevice(change: KeptDeviceChange): Promise<KeptDevice> {
    const d = this.requireDevice();
    const current = await this.store!.update(this.mailboxId, this.accountId!, d.deviceId, change).catch(storageFailure);
    if (current === null) {
      this.keptDevice = null;
      this.lockedTag = null;
      throw new DeviceRemoved();
    }
    this.keptDevice = current;
    return current;
  }

  /** The wrappable active key a FreshFactor holds, for one sealing step (K1′). */
  private wrappableActive(freshFactor: FreshFactor): MailboxPrivateKey {
    const { active } = freshFactorOf(freshFactor).use(this.mailboxId);
    if (active === null) throw new StaleFactor();
    if (active.keyId !== this.ring.active.keyId) throw new MailboxChanged();
    return active;
  }

  async keepThisDevice(options: { label: string; lockAfter?: LockAfter }, freshFactor: FreshFactor): Promise<ConfirmedChange<RegisterDeviceRequest>> {
    this.unlockedKeys();
    const store = this.store;
    if (store === null) throw new StorageUnavailable("this browser was unlocked as a shared computer: it keeps nothing");
    if (this.keptDevice !== null) throw new TypeError("this browser is a kept device of this mailbox already");
    if (this.ring.sessions !== "required") throw new TypeError("upgrade the mailbox before keeping a device (upgradeRequest)");
    this.dueFirst();
    if (!deviceLabelOk(options.label)) throw new InvalidDeviceLabel();
    const lockAfter = options.lockAfter ?? "sign-out";
    if (!LOCK_SETTINGS.includes(lockAfter)) throw new TypeError("an unknown lock setting");
    const ff = freshFactorOf(freshFactor);
    const material = ff.use(this.mailboxId);
    await this.requireTrustedSigner(ff);
    const active = this.wrappableActive(freshFactor);
    const mailboxId = this.mailboxId;
    const deviceId = newId("dev");
    const signing = await generateSigningKey();
    const unlock = lockAfter === "right-away" ? null : await generateUnlockKey();
    const seal = unlock === null ? null : await sealKey(active, { mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
    const tag = await bindingTag(this.binding, { kind: "device", deviceId, label: options.label, signingKey: signing.publicKey, unlockKey: unlock?.publicKey ?? null }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    // K12: the device signs its own unlock key; the FreshFactor's factor admits the device (A11).
    const unlockSignature = unlock === null ? null : await signStatement(signing.privateKey, { kind: "unlock-key", mailboxId, deviceId, unlockKey: unlock.publicKey });
    const admission = { by: ff.factorId, signature: await signStatement(material.factorKey, { kind: "admit-device", mailboxId, deviceId, label: options.label, signingKey: signing.publicKey, admitterId: ff.factorId }) }; // pragma: allowlist secret (a public key)
    const keyId = this.ring.active.keyId;
    const request: RegisterDeviceRequest = {
      device: {
        id: deviceId,
        label: options.label,
        signingKey: base64url(signing.publicKey), // pragma: allowlist secret (a public key)
        unlockKey: unlock === null ? null : base64url(unlock.publicKey),
        unlockSignature,
        admission,
        tag,
        tagKeyId: keyId,
      },
      seal,
    };
    const confirmation = await confirmationFor("register-device", { device: request.device, seal }, { device: { id: deviceId, label: options.label } });
    const accountId = this.accountId!;
    return confirmedChange(request, confirmation, async () => {
      const record: KeptDevice = {
        mailboxId,
        accountId,
        deviceId,
        label: options.label,
        signingKey: signing.privateKey, // pragma: allowlist secret (a non-extractable CryptoKey reference)
        unlockKey: unlock?.privateKey ?? null,
        signingPublic: request.device.signingKey,
        unlockPublic: request.device.unlockKey,
        lastKeyId: keyId,
        trustRoot: base64url(material.signingPublic),
        lockAfter,
        lastActiveAt: this.now(),
        signInId: this.signInId,
      };
      await store.put(record).catch(storageFailure);
      this.ring.devices = [...(this.ring.devices ?? []), { ...request.device, createdAt: new Date(this.now()).toISOString(), createdBy: accountId, lastSeenAt: null }];
      if (seal !== null) this.ring.seals = [...this.ring.seals, { keyId, to: { kind: "device", id: deviceId }, sealed: seal }];
      await this.bindDevice(record);
    });
  }

  async rekeyThisDevice(freshFactor: FreshFactor): Promise<PendingChange<UpdateDeviceRequest>> {
    this.unlockedKeys();
    const d = this.requireDevice();
    if (d.lockAfter === "right-away") throw new TypeError("a device locked right away keeps no unlock key");
    this.dueFirst();
    const active = this.wrappableActive(freshFactor);
    const unlock = await generateUnlockKey();
    const seal = await sealKey(active, { mailboxId: this.mailboxId }, { kind: "device", deviceId: d.deviceId, publicKey: unlock.publicKey });
    const signingKey = fromBase64url(d.signingPublic)!; // pragma: allowlist secret (a public key)
    const tag = await bindingTag(this.binding, { kind: "device", deviceId: d.deviceId, label: d.label, signingKey, unlockKey: unlock.publicKey });
    const unlockSignature = await signStatement(d.signingKey, { kind: "unlock-key", mailboxId: this.mailboxId, deviceId: d.deviceId, unlockKey: unlock.publicKey });
    const keyId = this.ring.active.keyId;
    const request: UpdateDeviceRequest = { unlockKey: base64url(unlock.publicKey), unlockSignature, tag, tagKeyId: keyId, seal };
    return pendingChange(request, async () => {
      await this.changeDevice({ unlockKey: unlock.privateKey, unlockPublic: request.unlockKey, lastActiveAt: this.now(), signInId: this.signInId });
      this.ring.seals = [...this.ring.seals.filter((s) => !(s.to.kind === "device" && s.to.id === d.deviceId)), { keyId, to: { kind: "device", id: d.deviceId }, sealed: seal }];
      this.ring.devices = (this.ring.devices ?? []).map((x) => (x.id === d.deviceId ? { ...x, unlockKey: request.unlockKey, unlockSignature, tag, tagKeyId: keyId } : x));
      if (this.keys !== null) this.arm();
    });
  }

  async setLockAfter(lockAfter: LockAfter): Promise<{ updateDevice: UpdateDeviceRequest | null; needsRekey: boolean }> {
    this.unlockedKeys();
    if (!LOCK_SETTINGS.includes(lockAfter)) throw new TypeError("an unknown lock setting");
    const d = this.requireDevice();
    const drops = lockAfter === "right-away" && d.unlockKey !== null;
    const updateDevice: UpdateDeviceRequest | null = drops ? { unlockKey: null, unlockSignature: null, tag: this.lockedTag!, tagKeyId: this.ring.active.keyId, seal: null } : null;
    const current = await this.changeDevice({ lockAfter, lastActiveAt: this.now(), ...(drops ? { unlockKey: null, unlockPublic: null } : {}) });
    this.arm();
    return { updateDevice, needsRekey: lockAfter !== "right-away" && current.unlockKey === null };
  }

  async forget(): Promise<void> {
    const d = this.keptDevice;
    await this.lockFor("removed", { forgotten: true });
    this.keptDevice = null;
    this.lockedTag = null;
    // K10: this account's record only; another account's on the same browser is never touched.
    if (d !== null && this.store !== null) await this.store.delete(this.mailboxId, this.accountId!, d.deviceId).catch(storageFailure);
  }

  // ---- Reading ----

  async openMessages(items: MessageItem[]): Promise<OpenedMessage[]> {
    const keys = this.unlockedKeys();
    return Promise.all(
      items.map(async (item): Promise<OpenedMessage> => {
        const { keyId: _keyId, keyEnvelope: _env, header: _h, ...rest } = item;
        const key = keys.get(item.keyId);
        try {
          if (key === undefined) throw new DecryptionFailed();
          const header = await openHeader(key, { mailboxId: this.mailboxId, messageId: item.id }, item);
          return { ...rest, header, undecryptable: false };
        } catch {
          return { ...rest, header: null, undecryptable: true };
        }
      }),
    );
  }

  async openBody(item: MessageItem, sealedBody: Uint8Array): Promise<MailBody> {
    const key = this.unlockedKeys().get(item.keyId);
    let raw: Uint8Array;
    try {
      if (key === undefined) throw new DecryptionFailed();
      raw = await openSealedBody(key, { mailboxId: this.mailboxId, messageId: item.id }, { keyEnvelope: item.keyEnvelope, body: sealedBody });
    } catch {
      throw new UndecryptableBody();
    }
    return parseMail(raw);
  }

  async sealDraft(draftId: string | null, draft: DraftInput): Promise<SaveDraftRequest> {
    this.unlockedKeys();
    const id = draftId ?? newId("drf");
    const sealed = await sealDraftBlock(
      this.active,
      { mailboxId: this.mailboxId, draftId: id },
      {
        v: 1,
        to: draft.to,
        cc: draft.cc,
        bcc: draft.bcc,
        subject: draft.subject,
        text: draft.text,
        inReplyTo: draft.inReplyTo,
        references: draft.references,
        updatedAt: new Date(this.now()).toISOString(),
      },
    );
    return { id, keyId: sealed.keyId, keyEnvelope: sealed.keyEnvelope, sealed: sealed.sealed };
  }

  async openDrafts(records: DraftRecord[]): Promise<OpenedDraft[]> {
    const keys = this.unlockedKeys();
    return Promise.all(
      records.map(async (record): Promise<OpenedDraft> => {
        const key = keys.get(record.keyId);
        try {
          if (key === undefined) throw new DecryptionFailed();
          const draft = await openDraft(key, { mailboxId: this.mailboxId, draftId: record.id }, record);
          return { id: record.id, updatedAt: record.updatedAt, draft, undecryptable: false };
        } catch {
          return { id: record.id, updatedAt: record.updatedAt, draft: null, undecryptable: true };
        }
      }),
    );
  }

  // ---- Sessions at Mail (device-v1 A6, A7, B6) ----

  async sessionConfirmation(challenge: ChallengeView): Promise<Confirmation> {
    this.unlockedKeys();
    if (typeof challenge !== "object" || challenge === null || challenge.purpose !== "session" || typeof challenge.id !== "string" || !CHALLENGE_ID.test(challenge.id)) {
      throw new TypeError("not a session challenge");
    }
    // D38: a deviceless session's factor proof is bound to this very session challenge.
    return confirmationFor("open-session", { challengeId: challenge.id });
  }

  async sessionProof(challenge: ChallengeView, factorProof?: FactorProof): Promise<OpenSessionRequest> {
    const key = this.activeKey();
    if (typeof challenge !== "object" || challenge === null || challenge.purpose !== "session" || typeof challenge.id !== "string" || !CHALLENGE_ID.test(challenge.id)) {
      throw new TypeError("not a session challenge");
    }
    // Mail seals a session challenge to its active key: another key means another browser rotated it.
    if (challenge.keyId !== this.ring.active.keyId) throw new MailboxChanged();
    const device = this.keptDevice;
    // B6, D38: while sessions are required, exactly one of a device's signature and a factor proof.
    if (device !== null && factorProof !== undefined) throw new TypeError("a kept device proves itself with its signature, not a factor proof");
    if (device === null && this.ring.sessions === "required" && factorProof === undefined) {
      throw new TypeError("no device is kept here: a session needs a factor proof of kind open-session (sessionConfirmation)");
    }
    if (device === null && this.ring.sessions === "optional" && factorProof !== undefined) throw new TypeError("a mailbox whose sessions are optional takes no factor proof here");
    if (factorProof !== undefined && (typeof factorProof !== "object" || factorProof === null || typeof factorProof.challengeId !== "string" || typeof factorProof.answer !== "string")) {
      throw new TypeError("a factor proof is { challengeId, answer }");
    }
    if (typeof challenge.sealed !== "string") throw new InvalidChallenge();
    let answer: Uint8Array;
    try {
      answer = await openChallenge(key, { mailboxId: this.mailboxId, challengeId: challenge.id }, challenge.sealed);
    } catch (e) {
      // K4: what does not open as a challenge is answered with nothing.
      if (e instanceof DecryptionFailed) throw new InvalidChallenge();
      throw e;
    }
    const request: OpenSessionRequest = { challengeId: challenge.id, answer: base64url(answer) };
    answer.fill(0);
    if (device !== null) {
      const nonce = fromBase64url(challenge.nonce);
      if (nonce === null || nonce.length !== 32) throw new InvalidChallenge("the challenge's nonce is malformed");
      request.device = { id: device.deviceId, signature: await signDeviceProof(device.signingKey, { mailboxId: this.mailboxId, deviceId: device.deviceId, challengeId: challenge.id, nonce }) };
    } else if (factorProof !== undefined) {
      request.factorProof = { challengeId: factorProof.challengeId, answer: factorProof.answer };
    }
    return request;
  }

  async keyProof(challenge: ChallengeView, confirmation: Confirmation): Promise<KeyProof> {
    const key = this.activeKey();
    if (typeof challenge !== "object" || challenge === null || challenge.purpose !== "key" || typeof challenge.id !== "string" || !CHALLENGE_ID.test(challenge.id)) {
      throw new TypeError("not a key challenge");
    }
    if (challenge.keyId !== this.ring.active.keyId) throw new MailboxChanged();
    // K4: only the challenge of the action this browser is about to send; its own digest opens it.
    const actionDigest = await expectedDigest(challenge, confirmation, this.mailboxId, "key");
    if (typeof challenge.sealed !== "string") throw new InvalidChallenge();
    let answer: Uint8Array;
    try {
      answer = await openChallenge(key, { mailboxId: this.mailboxId, challengeId: challenge.id, actionDigest }, challenge.sealed);
    } catch (e) {
      if (e instanceof DecryptionFailed) throw new InvalidChallenge();
      throw e;
    }
    try {
      return { challengeId: challenge.id, answer: base64url(answer) };
    } finally {
      answer.fill(0);
    }
  }

  // ---- Factors again (K1′) ----

  /** A FreshFactor of a factor used now. The session's key ring is trusted already, so no chain walk is needed. */
  async reauthenticate(reauth: ReAuth): Promise<FreshFactor> {
    const keys = this.unlockedKeys();
    const opened = await openFactor(this.ring, reauth);
    if (!keys.has(opened.wrap.keyId)) throw new KeySubstitutionDetected("the factor's wrap is of a key the session does not hold");
    this.noteFactorMatch(opened.wrap.id, opened.listedKeyMatches);
    const active = await activeOfFactor(this.ring, opened);
    if (active !== null) await checkAdvertisedKey(active.wrappable, this.ring.active);
    // A session unlocked by a factor whose listed keys are not its own trusts nothing (no start); a factor
    // used now whose keys K9 confirms becomes its start (A11), and K3′ is checked again from it.
    if (this.trustStart === null && opened.listedKeyMatches === true) {
      this.trustStart = factorSigningKey(opened.factorKey);
      this.tagFlags = await checkRecipients(this.ring, this.binding, await this.trusted());
    }
    const ff = freshFactorFor(this.mailboxId, opened, active?.wrappable ?? null, this.now);
    this.factors.add(ff);
    return ff;
  }

  /** A newer view of the same active key: K3′ again (flagging what fails), then its wraps, seals and devices are this session's. */
  async refresh(view: MailboxView): Promise<void> {
    const keys = this.unlockedKeys();
    const ring = readRing(view);
    if (ring.mailboxId !== this.mailboxId) throw new TypeError("a view of another mailbox");
    if (ring.active.keyId !== this.ring.active.keyId || ring.keys.some((k) => !keys.has(k.keyId))) throw new MailboxChanged();
    this.tagFlags = await checkRecipients(ring, this.binding, await this.trusted(ring));
    this.ring = ring;
  }

  // ---- Removing devices: the rotation (device-v1 B7, M18′, D40; plan.md F6, F14) ----

  async removeDevices(view: MailboxView, deviceIds: readonly string[], freshFactor: FreshFactor): Promise<ConfirmedChange<RemoveDevicesRequest>> {
    const keys = this.unlockedKeys();
    const ring = readRing(view);
    if (ring.mailboxId !== this.mailboxId) throw new TypeError("a view of another mailbox");
    if (ring.sessions !== "required") throw new TypeError("upgrade the mailbox before removing a device");
    // The view must be of this session's key ring; one of a newer key means another browser rotated first.
    if (ring.active.keyId !== this.ring.active.keyId || ring.keys.some((k) => !keys.has(k.keyId))) throw new MailboxChanged();
    if (!Array.isArray(deviceIds) || !deviceIds.every((id) => typeof id === "string")) throw new TypeError("deviceIds is a list of device ids");
    const devices = ring.devices ?? [];
    for (const id of deviceIds) if (!devices.some((d) => d.id === id)) throw new MailboxChanged("the view does not list that device");
    const active = this.wrappableActive(freshFactor);
    const used = freshFactorOf(freshFactor);
    const material = used.use(this.mailboxId);
    // K9 for the factor that proves and signs this, against the view.
    const usedWrap = ring.wraps.find((w) => w.id === used.factorId);
    if (usedWrap !== undefined) this.noteFactorMatch(used.factorId, listedKeyMatches(usedWrap, material.factorKey));
    // K3′: the view's recipients under the active key, before anything is sealed. Every flagged device goes
    // in this rotation (D40); a flagged factor is in the way (it would be sealed to): remove it first.
    // M5′, D28: the new key must reach a recovery factor; without one no removal can ever be made.
    if (!ring.wraps.some((w) => w.kind === "recovery" && w.factorKey !== null)) throw new NoRecoveryFactor();
    const trusted = await this.trusted(ring);
    const flagged = this.flaggedIn(ring, await checkRecipients(ring, this.binding, trusted));
    if (flagged.factors.length > 0) throw new FlaggedRecipient(undefined, { factors: flagged.factors });
    if (this.mismatched.has(used.factorId) || !trusted.ids.includes(used.factorId)) {
      throw new FlaggedRecipient("this factor is not one the key ring trusts: use another", { factors: [used.factorId] });
    }
    const removed = [...new Set([...deviceIds, ...flagged.devices])].sort();
    if (removed.length === 0 && ring.rotationDue === null) throw new TypeError("name the devices to remove (none only to finish a rotation that is due)");
    if (removed.length > MAX_REMOVED) throw new TypeError("at most 20 devices in one rotation");
    const remaining = devices.filter((d) => !removed.includes(d.id));
    const factors = ring.wraps.filter((w) => w.factorKey !== null);

    const next = await generateMailboxKey();
    const mailboxId = this.mailboxId;
    const successorSeal = await sealKey(active, { mailboxId }, { kind: "successor", publicKey: next.publicKey.publicKey });
    const nextBinding = await bindingKey(next.privateKey, { mailboxId });
    const seals: Rotation["seals"] = [];
    const tags: Rotation["tags"] = [];
    const deviceTags = new Map<string, string>();
    const factorTags = new Map<string, string>();
    for (const d of remaining) {
      const recipient = deviceRecipient(d)!; // K3′ proved it well-formed and trusted
      if (recipient.kind !== "device") throw new Error("internal: a device recipient");
      if (recipient.unlockKey !== null) {
        seals.push({ to: { kind: "device", id: d.id }, sealed: await sealKey(next.privateKey, { mailboxId }, { kind: "device", deviceId: d.id, publicKey: recipient.unlockKey }) });
      }
      const tag = await bindingTag(nextBinding, recipient);
      deviceTags.set(d.id, tag);
      tags.push({ to: { kind: "device", id: d.id }, tag });
    }
    for (const w of factors) {
      const recipient = factorRecipient(w)!;
      if (recipient.kind !== "factor") throw new Error("internal: a factor recipient");
      seals.push({ to: { kind: "factor", id: w.id }, sealed: await sealKey(next.privateKey, { mailboxId }, { kind: "factor", factorId: w.id, publicKey: recipient.factorKey }) });
      const tag = await bindingTag(nextBinding, recipient);
      factorTags.set(w.id, tag);
      tags.push({ to: { kind: "factor", id: w.id }, tag });
    }
    // K12: the factor whose proof this call spends signs the transition (A11).
    const transitionStatement = { kind: "transition" as const, mailboxId, fromKeyId: ring.active.keyId, toKeyId: next.publicKey.keyId, toPublicKey: next.publicKey.publicKey, signerId: used.factorId };
    const transition = { signedBy: used.factorId, signature: await signStatement(material.factorKey, transitionStatement) };
    const request: RemoveDevicesRequest = {
      deviceIds: removed,
      rotation: { from: ring.active.keyId, publicKey: base64url(next.publicKey.publicKey), successorSeal, transition, seals, tags },
    };
    // K8: the rotation proves itself before it is sent. The new key opens the successor seal to the old
    // key, the factor just used opens the new key's seal for it, and its transition verifies with the
    // factor's signing key; mail that arrives after a rotation whose seals do not open would be readable
    // only in this page.
    try {
      const old = await openKeySeal({ kind: "successor", key: next.privateKey }, { mailboxId, sealedKeyId: ring.active.keyId }, successorSeal);
      const own = seals.find((x) => x.to.kind === "factor" && x.to.id === used.factorId);
      if (own === undefined) throw new RotationUnproven("the factor just used receives no seal of the new key");
      const back = await openKeySeal({ kind: "factor", key: material.factorKey }, { mailboxId, sealedKeyId: next.publicKey.keyId }, own.sealed);
      if (old.keyId !== ring.active.keyId || back.keyId !== next.publicKey.keyId) throw new RotationUnproven();
      if (!(await verifyStatement(material.signingPublic, transitionStatement, transition.signature))) throw new RotationUnproven("the transition does not verify");
    } catch (e) {
      throw e instanceof RotationUnproven ? e : new RotationUnproven();
    }
    const labels = Object.fromEntries(devices.map((d) => [d.id, d.label]));
    const confirmation = await confirmationFor("remove-devices", { deviceIds: request.deviceIds, rotation: request.rotation }, { deviceIds: removed, labels });
    const ff = used;
    return confirmedChange(request, confirmation, async () => {
      // Mail applied M18′. This session moves to the new key: a decrypt-only copy (K1′), the old keys kept.
      const decryptOnly = await decryptOnlyCopy(mailboxId, next.privateKey);
      const oldKeyId = ring.active.keyId;
      const newKeyId = next.publicKey.keyId;
      const at = new Date(this.now()).toISOString();
      const newActive = { keyId: newKeyId, publicKey: new Uint8Array(next.publicKey.publicKey), retiredAt: null, successor: null };
      const retired = { ...ring.active, retiredAt: at, successor: { keyId: newKeyId, sealed: successorSeal, signedBy: transition.signedBy, signature: transition.signature } };
      this.ring = {
        ...ring,
        keys: [...ring.keys.filter((k) => k.keyId !== oldKeyId), retired, newActive],
        active: newActive,
        devices: remaining.map((d) => ({ ...d, tag: deviceTags.get(d.id)!, tagKeyId: newKeyId })),
        wraps: ring.wraps.map((w) => (factorTags.has(w.id) ? { ...w, tag: factorTags.get(w.id)!, tagKeyId: newKeyId } : w)),
        seals: seals.map((x) => ({ keyId: newKeyId, to: x.to, sealed: x.sealed })),
        rotationDue: null,
      };
      if (this.keys !== null) this.keys = new Map([[newKeyId, decryptOnly], ...this.keys]);
      this.binding = nextBinding;
      // Every recipient left was checked above and is tagged under the new key by this browser.
      this.tagFlags = NONE_FLAGGED;
      this.mismatched.clear();
      // The FreshFactor's 2 minutes go on with the new key, so a second removal needs no new prompt.
      ff.retarget(next.privateKey);
      const d = this.keptDevice;
      if (d !== null && removed.includes(d.deviceId)) {
        // This device removed itself (K7): it keeps nothing; the session goes on as a shared computer's.
        this.keptDevice = null;
        this.lockedTag = null;
        if (this.store !== null) await this.store.delete(mailboxId, this.accountId!, d.deviceId).catch(storageFailure);
      } else if (d !== null) {
        // This device accepts the new key (K11: only from the key it held), and its tag at Mail is under it now.
        const swap = await this.store!.swapLastKeyId(mailboxId, this.accountId!, d.deviceId, oldKeyId, { lastKeyId: newKeyId, lastActiveAt: this.now() }).catch(storageFailure);
        if (swap.record === null) {
          this.keptDevice = null;
          this.lockedTag = null;
          throw new DeviceRemoved();
        }
        await this.bindDevice(swap.record);
      }
      if (this.keys !== null) this.arm();
    });
  }

  // ---- The upgrade (device-v1 B5, M20 as amended; plan.md F5) ----

  async upgradeRequest(factors: readonly FreshFactor[]): Promise<ConfirmedChange<UpgradeRequest>> {
    this.unlockedKeys();
    if (this.ring.sessions !== "optional") throw new TypeError("the mailbox's sessions are required already: there is no upgrade");
    if (this.ring.wraps.some((w) => w.factorKey !== null)) throw new TypeError("a factor has its key already (M20: the upgrade happens once)");
    const used = factors.map((f) => {
      const ff = freshFactorOf(f);
      return { ff, material: ff.use(this.mailboxId) };
    });
    if (new Set(used.map((u) => u.ff.factorId)).size !== used.length) throw new TypeError("a factor is named twice");
    if (used.some((u) => u.ff.facts.keyId !== this.ring.active.keyId || !this.ring.wraps.some((w) => w.id === u.ff.factorId))) throw new MailboxChanged();
    // M20: every factor of the mailbox at once, so that none is left without a key after the first rotation.
    const missing = this.ring.wraps.filter((w) => !used.some((u) => u.ff.factorId === w.id));
    if (missing.length > 0) throw new MissingFactors(undefined, missing.map((w) => ({ id: w.id, kind: w.kind, label: w.label })));
    const keyId = this.ring.active.keyId;
    // A11: at the upgrade every factor is present: sorted by id, each admitted by the next, the last by the first.
    const admitterOf = new Map(bootstrapAdmitters(used.map((u) => u.ff.factorId)).map((c) => [c.factorId, c.admitterId]));
    const request: UpgradeRequest = {
      factors: await Promise.all(
        used.map(async ({ ff, material }) => {
          const admitter = used.find((u) => u.ff.factorId === admitterOf.get(ff.factorId))!;
          return {
            id: ff.factorId,
            factorKey: base64url(material.factorPublic),
            signingKey: base64url(material.signingPublic), // pragma: allowlist secret (a public key)
            admission: await admissionOf(this.mailboxId, { facts: ff.facts, key: material.factorKey }, admitter.material.factorKey),
            tag: await factorTag(this.binding, ff.facts, material.factorPublic),
            tagKeyId: keyId,
          };
        }),
      ),
    };
    const confirmation = await confirmationFor("upgrade", { factors: request.factors });
    // The session's trust starts from the factor that unlocked it, else the first one used here.
    const start = (used.find((u) => u.ff === this.freshFactor) ?? used[0])?.material.signingPublic ?? null;
    return confirmedChange(request, confirmation, async () => {
      this.ring.sessions = "required";
      for (const f of request.factors) {
        this.ring.wraps = this.ring.wraps.map((w) => (w.id === f.id ? { ...w, factorKey: f.factorKey, signingKey: f.signingKey, admission: f.admission, tag: f.tag, tagKeyId: keyId } : w)); // pragma: allowlist secret (public values)
      }
      if (start !== null) this.trustStart = new Uint8Array(start);
    });
  }

  // ---- Factors added or removed (contracts/mail-client-v1.md: a fresh factor for each, K1′, K12) ----

  /** A new factor's admission by the FreshFactor's factor, countersigned by the new factor (A11), once sessions are required. */
  private async admitted(made: { wrap: WrapInput; factor: FactorPrivateKey | null }, admitter: FreshFactorImpl): Promise<WrapInput> {
    if (made.factor === null) return made.wrap;
    return { ...made.wrap, admission: await admissionOf(this.mailboxId, { facts: made.wrap, key: made.factor }, admitter.use(this.mailboxId).factorKey) };
  }

  async addPasskey(passkey: PasskeyOptions, freshFactor: FreshFactor): Promise<ConfirmedChange<WrapInput>> {
    this.unlockedKeys();
    this.dueFirst();
    // A flagged factor is removed first (removeFactor, with a proof from another factor).
    if (this.flagged.factors.length > 0) throw new FlaggedRecipient(undefined, { factors: this.flagged.factors });
    const ff = freshFactorOf(freshFactor);
    const keyed = this.ring.sessions === "required";
    if (keyed) await this.requireTrustedSigner(ff);
    const wrappable = this.wrappableActive(freshFactor);
    const wrap = await this.admitted(await makePasskeyWrap(this.mailboxId, wrappable, passkey, keyed ? this.binding : null), ff);
    const confirmation = await confirmationFor("add-factor", { ...wrap });
    return confirmedChange(wrap, confirmation, async () => {
      this.ring.wraps.push(ringWrapOf(wrap));
    });
  }

  async replaceRecoveryKey(freshFactor: FreshFactor): Promise<NewRecoveryKey> {
    this.unlockedKeys();
    this.dueFirst();
    // A flagged passkey is removed first. A flagged recovery factor is what this replaces: Mail keeps the
    // only recovery factor until another one is there (M5′), so it could not be removed first.
    const inTheWay = this.flagged.factors.filter((id) => this.ring.wraps.find((w) => w.id === id)?.kind !== "recovery");
    if (inTheWay.length > 0) throw new FlaggedRecipient(undefined, { factors: inTheWay });
    const ff = freshFactorOf(freshFactor);
    const keyed = this.ring.sessions === "required";
    if (keyed) await this.requireTrustedSigner(ff);
    const wrappable = this.wrappableActive(freshFactor);
    const made = await makeRecoveryWrap(this.mailboxId, wrappable, keyed ? this.binding : null);
    const wrap = await this.admitted(made, ff);
    const confirmation = await confirmationFor("add-factor", { ...wrap });
    const change = confirmedChange(wrap, confirmation, async () => {
      this.ring.wraps.push(ringWrapOf(wrap));
    });
    return Object.freeze({ request: change.request, confirmation: change.confirmation, commit: change.commit, recoveryKey: made.recoveryKey });
  }

  async removeFactor(factorId: string): Promise<ConfirmedChange<RemoveWrapRequest>> {
    this.unlockedKeys();
    this.dueFirst();
    const wrap = this.ring.wraps.find((w) => w.id === factorId);
    if (wrap === undefined) throw new MailboxChanged("the key ring does not list that factor");
    // M5′: the active key stays reachable by a recovery factor (its wrap, or its seal).
    const activeKeyId = this.ring.active.keyId;
    const reaches = (w: RingWrap) => w.kind === "recovery" && (w.keyId === activeKeyId || this.ring.seals.some((s) => s.keyId === activeKeyId && s.to.kind === "factor" && s.to.id === w.id));
    if (reaches(wrap) && !this.ring.wraps.some((w) => w.id !== factorId && reaches(w))) throw new NoRecoveryFactor();
    const request: RemoveWrapRequest = { wrapId: factorId };
    const confirmation = await confirmationFor("remove-factor", { wrapId: factorId });
    return confirmedChange(request, confirmation, async () => {
      this.ring.wraps = this.ring.wraps.filter((w) => w.id !== factorId);
      this.ring.seals = this.ring.seals.filter((s) => !(s.to.kind === "factor" && s.to.id === factorId));
      // M24: a keyed factor's record stays, for the signatures it made.
      if (wrap.factorKey !== null && wrap.signingKey !== null && wrap.admission !== null) {
        this.ring.removedFactors = [
          ...this.ring.removedFactors,
          { id: wrap.id, kind: wrap.kind, credentialId: wrap.credentialId, label: wrap.label, factorKey: wrap.factorKey, signingKey: wrap.signingKey, admission: wrap.admission, removedAt: new Date(this.now()).toISOString() }, // pragma: allowlist secret (public values)
        ];
      }
      this.mismatched.delete(factorId);
      this.tagFlags = flaggedOf(this.tagFlags.devices, this.tagFlags.factors.filter((id) => id !== factorId));
    });
  }
}

// ---- Unlocking with a factor ----

/** This account's kept device of the mailbox, read safely: a store that fails is a browser that keeps nothing (K10: never another account's). */
export async function keptDeviceOf(store: DeviceStore | null, mailboxId: string, accountId: string | null): Promise<KeptDevice | null> {
  if (store === null || accountId === null) return null;
  try {
    return await store.get(mailboxId, accountId);
  } catch {
    return null;
  }
}

/** K10: the device Mail lists for this record must be this account's, with this signing key. */
export function checkListedDevice(ring: Ring, record: KeptDevice): void {
  const listed = ring.devices!.find((d) => d.id === record.deviceId)!;
  if (listed.signingKey !== record.signingPublic) throw new KeySubstitutionDetected("Mail lists this device with another signing key");
  if (typeof listed.createdBy === "string" && listed.createdBy !== "" && listed.createdBy !== record.accountId) {
    throw new KeySubstitutionDetected("Mail lists this device under another account");
  }
}

/** How many times a page resumes again after another page moved its last accepted key (K11). */
export const SWAP_ATTEMPTS = 3;

async function unlockWithFactor(view: MailboxView, factor: ReAuth, options?: UnlockOptions): Promise<UnlockedMailbox> {
  const ring = readRing(view);
  const now = options?.now ?? Date.now;
  const store = options?.store ?? null;
  const accountId = options?.accountId ?? null;
  if (store !== null && !accountIdOk(accountId)) throw new TypeError("a store comes with the signed-in account's id (K10)");
  const idleLockMs = idleLockMsOf(options);
  // This account's kept device, if any (K10: another account's record is never read). K7 first: one the
  // view no longer lists is forgotten, and the browser unlocks as a new one. A view without devices at all
  // (a Worker without spec 002) binds none.
  let record = await keptDeviceOf(store, ring.mailboxId, accountId);
  if (record !== null && ring.devices !== null && !ring.devices.some((d) => d.id === record!.deviceId)) {
    await store!.delete(ring.mailboxId, accountId!, record.deviceId).catch(() => undefined);
    record = null;
  }
  if (record !== null && ring.devices === null) record = null;
  if (record !== null) checkListedDevice(ring, record);
  const opened = await openFactor(ring, factor);
  // The factor opened a real key (its wrap names it, and unwrap checked it). A key ring that does not list that key lies.
  if (!ring.keys.some((k) => k.keyId === opened.wrap.keyId)) throw new KeySubstitutionDetected("the factor's key is not in the key ring");
  const active = await activeOfFactor(ring, opened);
  if (active === null) throw new StaleFactor();
  // A11: trust starts from the factor just used, once K9 confirms its keys are the listed ones.
  const start = opened.listedKeyMatches === false ? null : factorSigningKey(opened.factorKey);
  const trusted = await trustOf(ring, start);
  const binding = await bindingOf(ring, active.key);
  const flagged = await checkRecipients(ring, binding, trusted);
  const freshFactor = freshFactorFor(ring.mailboxId, opened, active.wrappable, now);
  // K9: a factor whose listed keys are not the ones it derives is flagged too; its wrap stays its anchor.
  const mismatched = opened.listedKeyMatches === false ? [opened.wrap.id] : [];
  for (let attempt = 0; ; attempt++) {
    // K2″ (a)/(b): the factor's own wrap is its anchor; on a kept device, so is the key it last accepted (no rollback).
    const anchors = record === null ? [opened.wrap.keyId] : [opened.wrap.keyId, record.lastKeyId];
    const keys = await trustChain(ring, active.key, anchors, trusted, attempt > 0);
    const session = new Session({ ring, keys, binding, store, accountId, signInId: options?.signInId ?? null, now, freshFactor, idleLockMs, flagged, mismatched, trustStart: start });
    if (record === null) return session;
    // K11: the device accepts the active key only while it still holds the key the walk started from; the
    // factor just used becomes its trustRoot (F4).
    const change = { lastKeyId: ring.active.keyId, lastActiveAt: now(), ...(start === null ? {} : { trustRoot: base64url(start) }) };
    const swap = await store!.swapLastKeyId(ring.mailboxId, accountId!, record.deviceId, record.lastKeyId, change).catch(() => ({ swapped: false, record: null }));
    if (swap.swapped && swap.record !== null) {
      await session.bindDevice(swap.record);
      return session;
    }
    // Another page moved it, or forgot the device: walk again from the record as it now is.
    record = swap.record;
    if (record === null) return session;
    if (attempt + 1 >= SWAP_ATTEMPTS) throw new MailboxChanged();
  }
}

/** The FreshFactor of a factor just used (K1′): its own key, and the active key wrappable when it reaches it. */
function freshFactorFor(mailboxId: string, opened: OpenedFactor, active: MailboxPrivateKey | null, now: () => number): FreshFactorImpl {
  return new FreshFactorImpl(
    mailboxId,
    opened.wrap,
    { factorKey: opened.factorKey, factorPublic: factorPublicKey(opened.factorKey), signingPublic: factorSigningKey(opened.factorKey), active },
    now,
  );
}

/** A wrap this browser made, as the session's ring lists it. */
function ringWrapOf(wrap: WrapInput): RingWrap {
  return {
    id: wrap.id,
    keyId: wrap.keyId,
    kind: wrap.kind,
    credentialId: wrap.credentialId, // pragma: allowlist secret (field names and public keys)
    label: wrap.label,
    wrapped: wrap.wrapped,
    factorKey: wrap.factorKey ?? null,
    signingKey: wrap.signingKey ?? null, // pragma: allowlist secret (a public key)
    admission: wrap.admission ?? null,
    tag: wrap.tag ?? null,
    tagKeyId: wrap.tagKeyId ?? null,
  };
}

export async function unlockWithPasskey(mailbox: MailboxView, passkey: PasskeyPrompt, options?: UnlockOptions): Promise<UnlockedMailbox> {
  return unlockWithFactor(mailbox, { passkey }, options);
}

export async function unlockWithRecoveryKey(mailbox: MailboxView, recoveryKey: string, options?: UnlockOptions): Promise<UnlockedMailbox> {
  return unlockWithFactor(mailbox, { recoveryKey }, options);
}

/** The keyId of a base64url public key, for callers that only have the view. */
export async function keyIdOfView(publicKey: string): Promise<string | null> {
  const bytes = fromBase64url(publicKey);
  return bytes === null || bytes.length !== 32 ? null : keyIdOf(bytes);
}
