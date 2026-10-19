/**
 * Unlocking, and the unlocked mailbox (contracts/mail-client-v1.md
 * "Unlocking", "Reading", "Drafts and sending", as amended by spec 002;
 * contracts/device-v1.md Part C).
 *
 * A session holds EVERY key the key ring's chain reaches (G40), each a
 * non-extractable, decrypt-only CryptoKey inside mail-crypto's handle, by
 * keyId; the active key's public half; its binding key (A5); and the public
 * facts it needs to use a factor again. It is accepted only after K2′ (the
 * active key leads back to a key this browser trusts), and K3 checks every tag
 * in the ring: a recipient whose tag fails is flagged (`flagged`), never sealed
 * to, and removable, while the rest of the inbox works. After a factor, it
 * offers that factor's FreshFactor for 2 minutes (K1′); nothing else in it can
 * be wrapped or sealed again.
 *
 * On a kept device (K5 to K7) it also holds the device's record: it signs the
 * device's proofs, keeps the record's last use current, and locks by the
 * device's own setting (K6): Lock now, 15 minutes or 1 hour without use, or
 * never on idle for "when I sign out". Locking drops every key at once and
 * deletes the unlock key from the store, and hands back the request that
 * clears it at Mail; its tag is made when the device is bound, because no key
 * is left to make it once locked.
 */
import {
  bindingKey,
  bindingTag,
  DecryptionFailed,
  factorPublicKey,
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
  type BindingKey,
  type MailboxPrivateKey,
  type MailboxPublicKey,
} from "@proprietor/mail-crypto";
import { base64url, fromBase64url } from "./bytes";
import { deviceLabelOk } from "./device-store";
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
  RotationUnproven,
  StaleFactor,
  StorageUnavailable,
  UndecryptableBody,
} from "./errors";
import { activeOfFactor, decryptOnlyCopy, factorTag, listedKeyMatches, makePasskeyWrap, makeRecoveryWrap, openFactor, type OpenedFactor } from "./factors";
import { FreshFactorImpl, freshFactorOf } from "./fresh-factor";
import { bindingOf, checkAdvertisedKey, checkTags, deviceRecipient, factorRecipient, flaggedOf, NONE_FLAGGED, readRing, trustChain, type Ring, type RingWrap } from "./keyring";
import { parseMail } from "./mime";
import type {
  ChallengeView,
  DeviceInfo,
  DeviceStore,
  DraftInput,
  DraftRecord,
  FlaggedRecipients,
  FreshFactor,
  KeptDevice,
  KeptDeviceChange,
  LockAfter,
  LockEvent,
  LockResult,
  MailBody,
  MailboxView,
  MessageItem,
  OpenedDraft,
  OpenedMessage,
  OpenSessionRequest,
  PasskeyOptions,
  PasskeyPrompt,
  PendingChange,
  ReAuth,
  RegisterDeviceRequest,
  RemoveDeviceRequest,
  Rotation,
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

/** Store failures are StorageUnavailable; a record K5 refuses stays the caller's TypeError. */
function storageFailure(e: unknown): never {
  throw e instanceof TypeError || e instanceof StorageUnavailable ? e : new StorageUnavailable();
}

/** Everything a session is made of; built by the unlock paths after K2′ and K3. */
export interface SessionParts {
  ring: Ring;
  keys: Map<string, MailboxPrivateKey>;
  binding: BindingKey;
  store: DeviceStore | null;
  signInId: string | null;
  now: () => number;
  freshFactor: FreshFactorImpl | null;
  idleLockMs: number;
  /** K3 at the unlock: the recipients whose tag failed. */
  flagged?: FlaggedRecipients;
  /** K9 at the unlock: the factor used, when the key ring lists another factor key for it. */
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
  /** K3: the recipients of this.ring whose tag failed under the active key. */
  private tagFlags: FlaggedRecipients;
  /** K9: factors used in this session whose listed factor key is not the one they derive. */
  private readonly mismatched: Set<string>;
  /** The device's tag over "no unlock key" under the active key: what Lock now sends, made while a key is held. */
  private lockedTag: string | null = null;
  private lastActivityWrite = Number.NEGATIVE_INFINITY;
  private readonly store: DeviceStore | null;
  private readonly signInId: string | null;
  private readonly now: () => number;
  private readonly idleLockMs: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly listeners = new Set<(event: LockEvent) => void>();
  private readonly factors = new Set<FreshFactorImpl>();

  constructor(parts: SessionParts) {
    this.mailboxId = parts.ring.mailboxId;
    this.ring = parts.ring;
    this.keys = parts.keys;
    this.binding = parts.binding;
    this.store = parts.store;
    this.signInId = parts.signInId;
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

  /** K3's flags for `ring` and the factors K9 flagged, as long as the ring still lists them. */
  private flaggedIn(ring: Ring, tagFlags: FlaggedRecipients = this.tagFlags): FlaggedRecipients {
    const k9 = ring.wraps.filter((w) => this.mismatched.has(w.id)).map((w) => w.id);
    return k9.length === 0 ? tagFlags : flaggedOf(tagFlags.devices, [...tagFlags.factors, ...k9]);
  }

  /** K9 for a factor just used: its derived factor key against the one the ring lists. */
  private noteFactorMatch(factorId: string, matches: boolean | null): void {
    if (matches === false) this.mismatched.add(factorId);
    else if (matches === true) this.mismatched.delete(factorId);
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
    store.update(this.mailboxId, d.deviceId, { lastActiveAt: now }).then(
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
        ? { unlockKey: null, tag: this.lockedTag, tagKeyId: this.ring.active.keyId, seal: null }
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
    return this.store.update(this.mailboxId, device.deviceId, { unlockKey: null, unlockPublic: null }).then((current) => {
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

  // ---- The kept device (K5 to K7) ----

  /** Binds this session to its kept device: its proofs are signed with the device's key, and it locks by the device's setting. */
  async bindDevice(record: KeptDevice): Promise<void> {
    const signingKey = fromBase64url(record.signingPublic)!; // pragma: allowlist secret (a public key)
    this.attachDevice(record, await bindingTag(this.binding, { kind: "device", deviceId: record.deviceId, label: record.label, signingKey, unlockKey: null }));
  }

  /** bindDevice with the device's tag over "no unlock key" (under the active key) made already. */
  attachDevice(record: KeptDevice, lockedTag: string): void {
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
    const current = await this.store!.update(this.mailboxId, d.deviceId, change).catch(storageFailure);
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

  async keepThisDevice(options: { label: string; lockAfter?: LockAfter }, freshFactor: FreshFactor): Promise<PendingChange<RegisterDeviceRequest>> {
    this.unlockedKeys();
    const store = this.store;
    if (store === null) throw new StorageUnavailable("this browser was unlocked as a shared computer: it keeps nothing");
    if (this.keptDevice !== null) throw new TypeError("this browser is a kept device of this mailbox already");
    if (this.ring.sessions !== "required") throw new TypeError("upgrade the mailbox before keeping a device (upgradeRequest)");
    if (!deviceLabelOk(options.label)) throw new InvalidDeviceLabel();
    const lockAfter = options.lockAfter ?? "sign-out";
    if (!LOCK_SETTINGS.includes(lockAfter)) throw new TypeError("an unknown lock setting");
    const active = this.wrappableActive(freshFactor);
    const deviceId = newId("dev");
    const signing = await generateSigningKey();
    const unlock = lockAfter === "right-away" ? null : await generateUnlockKey();
    const seal = unlock === null ? null : await sealKey(active, { mailboxId: this.mailboxId }, { kind: "device", deviceId, publicKey: unlock.publicKey });
    const tag = await bindingTag(this.binding, { kind: "device", deviceId, label: options.label, signingKey: signing.publicKey, unlockKey: unlock?.publicKey ?? null }); // pragma: allowlist secret (public keys and test doubles, not secrets)
    const keyId = this.ring.active.keyId;
    const request: RegisterDeviceRequest = {
      device: { id: deviceId, label: options.label, signingKey: base64url(signing.publicKey), unlockKey: unlock === null ? null : base64url(unlock.publicKey), tag, tagKeyId: keyId },
      seal,
    };
    return pendingChange(request, async () => {
      const record: KeptDevice = {
        mailboxId: this.mailboxId,
        deviceId,
        label: options.label,
        signingKey: signing.privateKey, // pragma: allowlist secret (a non-extractable CryptoKey reference)
        unlockKey: unlock?.privateKey ?? null,
        signingPublic: request.device.signingKey,
        unlockPublic: request.device.unlockKey,
        lastKeyId: keyId,
        lockAfter,
        lastActiveAt: this.now(),
        signInId: this.signInId,
      };
      await store.put(record).catch(storageFailure);
      this.ring.devices = [...(this.ring.devices ?? []), { ...request.device, createdAt: new Date(this.now()).toISOString(), createdBy: "", lastSeenAt: null }];
      if (seal !== null) this.ring.seals = [...this.ring.seals, { keyId, to: { kind: "device", id: deviceId }, sealed: seal }];
      await this.bindDevice(record);
    });
  }

  async rekeyThisDevice(freshFactor: FreshFactor): Promise<PendingChange<UpdateDeviceRequest>> {
    this.unlockedKeys();
    const d = this.requireDevice();
    if (d.lockAfter === "right-away") throw new TypeError("a device locked right away keeps no unlock key");
    const active = this.wrappableActive(freshFactor);
    const unlock = await generateUnlockKey();
    const seal = await sealKey(active, { mailboxId: this.mailboxId }, { kind: "device", deviceId: d.deviceId, publicKey: unlock.publicKey });
    const signingKey = fromBase64url(d.signingPublic)!; // pragma: allowlist secret (a public key)
    const tag = await bindingTag(this.binding, { kind: "device", deviceId: d.deviceId, label: d.label, signingKey, unlockKey: unlock.publicKey });
    const keyId = this.ring.active.keyId;
    const request: UpdateDeviceRequest = { unlockKey: base64url(unlock.publicKey), tag, tagKeyId: keyId, seal };
    return pendingChange(request, async () => {
      await this.changeDevice({ unlockKey: unlock.privateKey, unlockPublic: request.unlockKey, lastKeyId: keyId, lastActiveAt: this.now(), signInId: this.signInId });
      this.ring.seals = [...this.ring.seals.filter((s) => !(s.to.kind === "device" && s.to.id === d.deviceId)), { keyId, to: { kind: "device", id: d.deviceId }, sealed: seal }];
      if (this.keys !== null) this.arm();
    });
  }

  async setLockAfter(lockAfter: LockAfter): Promise<{ updateDevice: UpdateDeviceRequest | null; needsRekey: boolean }> {
    this.unlockedKeys();
    if (!LOCK_SETTINGS.includes(lockAfter)) throw new TypeError("an unknown lock setting");
    const d = this.requireDevice();
    const drops = lockAfter === "right-away" && d.unlockKey !== null;
    const updateDevice: UpdateDeviceRequest | null = drops ? { unlockKey: null, tag: this.lockedTag!, tagKeyId: this.ring.active.keyId, seal: null } : null;
    const current = await this.changeDevice({ lockAfter, lastActiveAt: this.now(), ...(drops ? { unlockKey: null, unlockPublic: null } : {}) });
    this.arm();
    return { updateDevice, needsRekey: lockAfter !== "right-away" && current.unlockKey === null };
  }

  async forget(): Promise<void> {
    const d = this.keptDevice;
    await this.lockFor("removed", { forgotten: true });
    this.keptDevice = null;
    this.lockedTag = null;
    if (d !== null && this.store !== null) await this.store.delete(this.mailboxId, d.deviceId).catch(storageFailure);
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

  async sessionProof(challenge: ChallengeView): Promise<OpenSessionRequest> {
    const key = this.activeKey();
    if (typeof challenge !== "object" || challenge === null || challenge.purpose !== "session" || typeof challenge.id !== "string" || !CHALLENGE_ID.test(challenge.id)) {
      throw new TypeError("not a session challenge");
    }
    // Mail seals a session challenge to its active key: another key means another browser rotated it.
    if (challenge.keyId !== this.ring.active.keyId) throw new MailboxChanged();
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
    const device = this.keptDevice;
    if (device !== null) {
      const nonce = fromBase64url(challenge.nonce);
      if (nonce === null || nonce.length !== 32) throw new InvalidChallenge("the challenge's nonce is malformed");
      request.device = { id: device.deviceId, signature: await signDeviceProof(device.signingKey, { mailboxId: this.mailboxId, deviceId: device.deviceId, challengeId: challenge.id, nonce }) };
    }
    return request;
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
    const ff = freshFactorFor(this.mailboxId, opened, active?.wrappable ?? null, this.now);
    this.factors.add(ff);
    return ff;
  }

  /** A newer view of the same active key: K3 again (flagging what fails), then its wraps, seals and devices are this session's. */
  async refresh(view: MailboxView): Promise<void> {
    const keys = this.unlockedKeys();
    const ring = readRing(view);
    if (ring.mailboxId !== this.mailboxId) throw new TypeError("a view of another mailbox");
    if (ring.active.keyId !== this.ring.active.keyId || ring.keys.some((k) => !keys.has(k.keyId))) throw new MailboxChanged();
    this.tagFlags = await checkTags(ring, this.binding);
    this.ring = ring;
  }

  // ---- Removing a device: the rotation (device-v1 B7, M18; plan.md F6) ----

  async removeDevice(view: MailboxView, deviceId: string, freshFactor: FreshFactor): Promise<PendingChange<RemoveDeviceRequest>> {
    const keys = this.unlockedKeys();
    const ring = readRing(view);
    if (ring.mailboxId !== this.mailboxId) throw new TypeError("a view of another mailbox");
    if (ring.sessions !== "required") throw new TypeError("upgrade the mailbox before removing a device");
    // The view must be of this session's key ring; one of a newer key means another browser rotated first.
    if (ring.active.keyId !== this.ring.active.keyId || ring.keys.some((k) => !keys.has(k.keyId))) throw new MailboxChanged();
    const devices = ring.devices ?? [];
    if (!devices.some((d) => d.id === deviceId)) throw new MailboxChanged("the view does not list that device");
    const active = this.wrappableActive(freshFactor);
    const used = freshFactorOf(freshFactor);
    // K9 for the factor that proves this, against the view.
    const usedWrap = ring.wraps.find((w) => w.id === used.factorId);
    if (usedWrap !== undefined) this.noteFactorMatch(used.factorId, listedKeyMatches(usedWrap, used.use(this.mailboxId).factorPublic));
    // K3: the view's tags under the active key, before anything is sealed. A flagged recipient is never
    // sealed to, so while one is there the only rotation is the removal of that one flagged device.
    const flagged = this.flaggedIn(ring, await checkTags(ring, this.binding));
    const inTheWay = flaggedOf(
      flagged.devices.filter((id) => id !== deviceId),
      flagged.factors,
    );
    if (inTheWay.devices.length > 0 || inTheWay.factors.length > 0) throw new FlaggedRecipient(undefined, inTheWay);
    const remaining = devices.filter((d) => d.id !== deviceId);
    const factors = ring.wraps.filter((w) => w.factorKey !== null);
    // M5′, D28: the new key must reach a recovery factor.
    if (!factors.some((w) => w.kind === "recovery")) throw new NoRecoveryFactor();

    const next = await generateMailboxKey();
    const mailboxId = this.mailboxId;
    const successorSeal = await sealKey(active, { mailboxId }, { kind: "successor", publicKey: next.publicKey.publicKey });
    const nextBinding = await bindingKey(next.privateKey, { mailboxId });
    const seals: Rotation["seals"] = [];
    const tags: Rotation["tags"] = [];
    const deviceTags = new Map<string, string>();
    const factorTags = new Map<string, string>();
    for (const d of remaining) {
      const recipient = deviceRecipient(d)!; // checkTags proved it well-formed
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
    const request: RemoveDeviceRequest = {
      deviceId,
      rotation: { from: ring.active.keyId, publicKey: base64url(next.publicKey.publicKey), successorSeal, seals, tags },
    };
    // K8: the rotation proves itself before it is sent. The new key opens the successor seal to the old
    // key, and the factor just used opens the new key's seal for it; mail that arrives after a rotation
    // whose seals do not open would be readable only in this page.
    try {
      const old = await openKeySeal({ kind: "successor", key: next.privateKey }, { mailboxId, sealedKeyId: ring.active.keyId }, successorSeal);
      const own = seals.find((x) => x.to.kind === "factor" && x.to.id === used.factorId);
      if (own === undefined) throw new RotationUnproven("the factor just used receives no seal of the new key");
      const back = await openKeySeal({ kind: "factor", key: used.use(mailboxId).factorKey }, { mailboxId, sealedKeyId: next.publicKey.keyId }, own.sealed);
      if (old.keyId !== ring.active.keyId || back.keyId !== next.publicKey.keyId) throw new RotationUnproven();
    } catch (e) {
      throw e instanceof RotationUnproven ? e : new RotationUnproven();
    }
    const ff = used;
    return pendingChange(request, async () => {
      // Mail applied M18. This session moves to the new key: a decrypt-only copy (K1′), the old keys kept.
      const decryptOnly = await decryptOnlyCopy(mailboxId, next.privateKey);
      const newKeyId = next.publicKey.keyId;
      const at = new Date(this.now()).toISOString();
      const newActive = { keyId: newKeyId, publicKey: new Uint8Array(next.publicKey.publicKey), retiredAt: null, successor: null };
      const retired = { ...ring.active, retiredAt: at, successor: { keyId: newKeyId, sealed: successorSeal } };
      this.ring = {
        ...ring,
        keys: [...ring.keys.filter((k) => k.keyId !== ring.active.keyId), retired, newActive],
        active: newActive,
        devices: remaining.map((d) => ({ ...d, tag: deviceTags.get(d.id)!, tagKeyId: newKeyId })),
        wraps: ring.wraps.map((w) => (factorTags.has(w.id) ? { ...w, tag: factorTags.get(w.id)!, tagKeyId: newKeyId } : w)),
        seals: seals.map((x) => ({ keyId: newKeyId, to: x.to, sealed: x.sealed })),
      };
      if (this.keys !== null) this.keys = new Map([[newKeyId, decryptOnly], ...this.keys]);
      this.binding = nextBinding;
      // Every recipient left was checked above and is tagged under the new key by this browser.
      this.tagFlags = NONE_FLAGGED;
      this.mismatched.clear();
      // The FreshFactor's 2 minutes go on with the new key, so a second removal needs no new prompt.
      ff.retarget(next.privateKey);
      const d = this.keptDevice;
      if (d !== null && d.deviceId === deviceId) {
        // This device removed itself (K7): it keeps nothing; the session goes on as a shared computer's.
        this.keptDevice = null;
        this.lockedTag = null;
        if (this.store !== null) await this.store.delete(mailboxId, deviceId).catch(storageFailure);
      } else if (d !== null) {
        // This device accepts the new key; its tag at Mail is under it now, and so is the one Lock now sends.
        await this.bindDevice(await this.changeDevice({ lastKeyId: newKeyId }));
      }
      if (this.keys !== null) this.arm();
    });
  }

  // ---- The upgrade (device-v1 B5, M20 as amended on 2026-10-19; plan.md F5) ----

  async upgradeRequest(factors: readonly FreshFactor[]): Promise<PendingChange<UpgradeRequest>> {
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
    const request: UpgradeRequest = {
      factors: await Promise.all(
        used.map(async ({ ff, material }) => ({
          id: ff.factorId,
          factorKey: base64url(material.factorPublic),
          tag: await factorTag(this.binding, ff.facts, material.factorPublic),
          tagKeyId: keyId,
        })),
      ),
    };
    return pendingChange(request, async () => {
      this.ring.sessions = "required";
      for (const f of request.factors) this.keyFactorLocally(f.id, f.factorKey, f.tag, keyId);
    });
  }

  private keyFactorLocally(factorId: string, factorKey: string, tag: string, tagKeyId: string): void {
    this.ring.wraps = this.ring.wraps.map((w) => (w.id === factorId ? { ...w, factorKey, tag, tagKeyId } : w)); // pragma: allowlist secret (public values)
  }

  // ---- Wraps (contracts/mail-client-v1.md: a fresh factor for each, K1′) ----

  async addPasskey(passkey: PasskeyOptions, freshFactor: FreshFactor): Promise<WrapInput> {
    this.unlockedKeys();
    // A flagged factor is removed first (removeWrap, with a proof from another factor).
    if (this.flagged.factors.length > 0) throw new FlaggedRecipient(undefined, { factors: this.flagged.factors });
    const wrappable = this.wrappableActive(freshFactor);
    const wrap = await makePasskeyWrap(this.mailboxId, wrappable, passkey, this.ring.sessions === "required" ? this.binding : null);
    this.ring.wraps.push(ringWrapOf(wrap));
    return wrap;
  }

  async replaceRecoveryKey(freshFactor: FreshFactor): Promise<{ recoveryKey: string; wrap: WrapInput }> {
    this.unlockedKeys();
    // A flagged passkey is removed first. A flagged recovery factor is what this replaces: Mail keeps the
    // only recovery factor until another one is there (M5′), so it could not be removed first.
    const inTheWay = this.flagged.factors.filter((id) => this.ring.wraps.find((w) => w.id === id)?.kind !== "recovery");
    if (inTheWay.length > 0) throw new FlaggedRecipient(undefined, { factors: inTheWay });
    const wrappable = this.wrappableActive(freshFactor);
    const made = await makeRecoveryWrap(this.mailboxId, wrappable, this.ring.sessions === "required" ? this.binding : null);
    this.ring.wraps.push(ringWrapOf(made.wrap));
    return made;
  }
}

// ---- Unlocking with a factor ----

/** The kept device of this browser for the mailbox, read safely: a store that fails is a browser that keeps nothing. */
export async function keptDeviceOf(store: DeviceStore | null, mailboxId: string): Promise<KeptDevice | null> {
  if (store === null) return null;
  try {
    return await store.get(mailboxId);
  } catch {
    return null;
  }
}

async function unlockWithFactor(view: MailboxView, factor: ReAuth, options?: UnlockOptions): Promise<UnlockedMailbox> {
  const ring = readRing(view);
  const now = options?.now ?? Date.now;
  const store = options?.store ?? null;
  const idleLockMs = idleLockMsOf(options);
  // This browser's kept device, if any. K7 first: one the view no longer lists is forgotten, and the
  // browser unlocks as a new one. A view without devices at all (a Worker without spec 002) binds none.
  let record = await keptDeviceOf(store, ring.mailboxId);
  if (record !== null && ring.devices !== null && !ring.devices.some((d) => d.id === record!.deviceId)) {
    await store!.delete(ring.mailboxId, record.deviceId).catch(() => undefined);
    record = null;
  }
  if (record !== null && ring.devices === null) record = null;
  if (record !== null && ring.devices!.find((d) => d.id === record!.deviceId)!.signingKey !== record.signingPublic) {
    throw new KeySubstitutionDetected("Mail lists this device with another signing key");
  }
  const opened = await openFactor(ring, factor);
  // The factor opened a real key (its wrap names it, and unwrap checked it). A key ring that does not list that key lies.
  if (!ring.keys.some((k) => k.keyId === opened.wrap.keyId)) throw new KeySubstitutionDetected("the factor's key is not in the key ring");
  const active = await activeOfFactor(ring, opened);
  if (active === null) throw new StaleFactor();
  // K2′ (a)/(b): the factor's own wrap is its anchor; on a kept device, so is the key it last accepted (no rollback).
  const keys = await trustChain(ring, active.key, record === null ? [opened.wrap.keyId] : [opened.wrap.keyId, record.lastKeyId]);
  const binding = await bindingOf(ring, active.key);
  // K3: a recipient whose tag fails is flagged; the unlock goes on (the key itself passed K2′).
  const flagged = await checkTags(ring, binding);
  const freshFactor = freshFactorFor(ring.mailboxId, opened, active.wrappable, now);
  // K9: a factor whose listed factor key is not the one it derives is flagged too; its wrap stays its anchor.
  const mismatched = opened.listedKeyMatches === false ? [opened.wrap.id] : [];
  const session = new Session({ ring, keys, binding, store, signInId: options?.signInId ?? null, now, freshFactor, idleLockMs, flagged, mismatched });
  if (record !== null) {
    const current = await store!.update(ring.mailboxId, record.deviceId, { lastKeyId: ring.active.keyId, lastActiveAt: now() }).catch(() => null);
    if (current !== null) await session.bindDevice(current);
  }
  return session;
}

/** The FreshFactor of a factor just used (K1′): its own key, and the active key wrappable when it reaches it. */
function freshFactorFor(mailboxId: string, opened: OpenedFactor, active: MailboxPrivateKey | null, now: () => number): FreshFactorImpl {
  return new FreshFactorImpl(mailboxId, opened.wrap, { factorKey: opened.factorKey, factorPublic: factorPublicKey(opened.factorKey), active }, now);
}

/** A wrap this browser made, as the session's ring lists it. */
function ringWrapOf(wrap: WrapInput): RingWrap {
  return { id: wrap.id, keyId: wrap.keyId, kind: wrap.kind, credentialId: wrap.credentialId, label: wrap.label, wrapped: wrap.wrapped, factorKey: wrap.factorKey ?? null, tag: wrap.tag ?? null, tagKeyId: wrap.tagKeyId ?? null }; // pragma: allowlist secret (field names and public values, not secrets)
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
