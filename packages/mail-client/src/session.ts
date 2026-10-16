/**
 * Unlocking, and the unlocked mailbox (contracts/mail-client-v1.md
 * "Unlocking", "Reading", "Drafts and sending", as amended by spec 002;
 * contracts/device-v1.md Part C).
 *
 * A session holds EVERY key the key ring's chain reaches (G40), each a
 * non-extractable, decrypt-only CryptoKey inside mail-crypto's handle, by
 * keyId; the active key's public half; its binding key (A5); and the public
 * facts it needs to use a factor again. It is accepted only after K2′ (the
 * active key leads back to a key this browser trusts) and K3 (every tag in the
 * ring verifies). After a factor, it offers that factor's FreshFactor for 2
 * minutes (K1′); nothing else in it can be wrapped or sealed again.
 */
import {
  DecryptionFailed,
  factorPublicKey,
  fingerprint,
  keyIdOf,
  newId,
  openChallenge,
  openDraft,
  openHeader,
  openBody as openSealedBody,
  sealDraft as sealDraftBlock,
  signDeviceProof,
  type BindingKey,
  type MailboxPrivateKey,
  type MailboxPublicKey,
} from "@proprietor/mail-crypto";
import { base64url, fromBase64url } from "./bytes";
import { InvalidChallenge, KeySubstitutionDetected, MailboxChanged, MailboxLocked, StaleFactor, UndecryptableBody } from "./errors";
import { activeOfFactor, makePasskeyWrap, makeRecoveryWrap, openFactor, type OpenedFactor } from "./factors";
import { FreshFactorImpl, freshFactorOf } from "./fresh-factor";
import { bindingOf, checkAdvertisedKey, checkTags, readRing, trustChain, type Ring, type RingWrap } from "./keyring";
import { parseMail } from "./mime";
import type {
  ChallengeView,
  DeviceInfo,
  DeviceStore,
  DraftInput,
  DraftRecord,
  FreshFactor,
  KeptDevice,
  MailBody,
  MailboxView,
  MessageItem,
  OpenedDraft,
  OpenedMessage,
  OpenSessionRequest,
  PasskeyOptions,
  PasskeyPrompt,
  ReAuth,
  SaveDraftRequest,
  UnlockedMailbox,
  UnlockOptions,
  WrapInput,
} from "./types";

export const DEFAULT_IDLE_LOCK_MS = 15 * 60_000;
export { RECOVERY_LABEL } from "./factors";

const CHALLENGE_ID = /^chl_[0-9a-hjkmnp-tv-z]{26}$/;

/** The mailbox's active key, as advertised (domain-model G7: checked against every key opened for it). */
export function activeKeyOf(view: Pick<MailboxView, "keys" | "wraps" | "id">): MailboxPublicKey {
  const { active } = readRing(view as MailboxView);
  return { keyId: active.keyId, publicKey: active.publicKey };
}

function idleLockMsOf(options?: UnlockOptions): number {
  const ms = options?.idleLockMs ?? DEFAULT_IDLE_LOCK_MS;
  if (typeof ms !== "number" || Number.isNaN(ms) || ms <= 0) throw new TypeError("idleLockMs is a positive number of milliseconds, or Infinity");
  return ms;
}

/** Everything a session is made of; built by the unlock paths after K2′ and K3. */
export interface SessionParts {
  ring: Ring;
  keys: Map<string, MailboxPrivateKey>;
  binding: BindingKey;
  device: KeptDevice | null;
  store: DeviceStore | null;
  signInId: string | null;
  now: () => number;
  freshFactor: FreshFactorImpl | null;
  idleLockMs: number;
}

export class Session implements UnlockedMailbox {
  readonly mailboxId: string;
  readonly freshFactor: FreshFactor | null;
  private keys: Map<string, MailboxPrivateKey> | null;
  private binding: BindingKey;
  /** The key ring as this session knows it: the view it was unlocked or refreshed with, and what it committed since. */
  private ring: Ring;
  private keptDevice: KeptDevice | null;
  private readonly store: DeviceStore | null;
  private readonly signInId: string | null;
  private readonly now: () => number;
  private readonly idleLockMs: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly listeners = new Set<() => void>();
  private readonly factors = new Set<FreshFactorImpl>();

  constructor(parts: SessionParts) {
    this.mailboxId = parts.ring.mailboxId;
    this.ring = parts.ring;
    this.keys = parts.keys;
    this.binding = parts.binding;
    this.keptDevice = parts.device;
    this.store = parts.store;
    this.signInId = parts.signInId;
    this.now = parts.now;
    this.idleLockMs = parts.idleLockMs;
    this.freshFactor = parts.freshFactor;
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

  get device(): DeviceInfo | null {
    const d = this.keptDevice;
    return d === null ? null : Object.freeze({ id: d.deviceId, label: d.label, lockAfter: d.lockAfter, keepsUnlocked: d.unlockKey !== null });
  }

  private arm(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = Number.isFinite(this.idleLockMs) ? setTimeout(() => this.lock(), this.idleLockMs) : null;
  }

  /** The keys, after proving the session is unlocked; every method starts here and counts as activity. */
  private unlockedKeys(): Map<string, MailboxPrivateKey> {
    if (this.keys === null) throw new MailboxLocked();
    this.arm();
    return this.keys;
  }

  private activeKey(): MailboxPrivateKey {
    return this.unlockedKeys().get(this.ring.active.keyId)!;
  }

  touch(): void {
    this.unlockedKeys();
  }

  lock(): void {
    if (this.keys === null) return;
    this.keys = null;
    for (const ff of this.factors) ff.dispose();
    this.factors.clear();
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = null;
    for (const listener of [...this.listeners]) listener();
  }

  onLock(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
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
    if (challenge.keyId !== this.active.keyId) throw new MailboxChanged();
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
    const active = await activeOfFactor(this.ring, opened);
    if (active !== null) await checkAdvertisedKey(active.wrappable, this.ring.active);
    const ff = freshFactorFor(this.mailboxId, opened, active?.wrappable ?? null, this.now);
    this.factors.add(ff);
    return ff;
  }

  /** A newer view of the same active key: K3 again, then its wraps, seals and devices are this session's. */
  async refresh(view: MailboxView): Promise<void> {
    this.unlockedKeys();
    const ring = readRing(view);
    if (ring.mailboxId !== this.mailboxId) throw new TypeError("a view of another mailbox");
    if (ring.active.keyId !== this.active.keyId) throw new MailboxChanged();
    if (ring.keys.some((k) => !this.unlockedKeys().has(k.keyId))) throw new MailboxChanged();
    await checkTags(ring, this.binding);
    this.ring = ring;
  }

  // ---- Wraps (contracts/mail-client-v1.md: a fresh unlock for each) ----

  private async wrappableActive(reauth: ReAuth): Promise<MailboxPrivateKey> {
    const ff = freshFactorOf(await this.reauthenticate(reauth));
    try {
      const { active } = ff.use(this.mailboxId);
      if (active === null) throw new StaleFactor();
      return active;
    } finally {
      ff.dispose();
    }
  }

  async addPasskey(passkey: PasskeyOptions, reauth: ReAuth): Promise<WrapInput> {
    this.unlockedKeys();
    const wrappable = await this.wrappableActive(reauth);
    const wrap = await makePasskeyWrap(this.mailboxId, wrappable, passkey, this.ring.sessions === "required" ? this.binding : null);
    this.ring.wraps.push(ringWrapOf(wrap));
    return wrap;
  }

  async replaceRecoveryKey(reauth: ReAuth): Promise<{ recoveryKey: string; wrap: WrapInput }> {
    this.unlockedKeys();
    const wrappable = await this.wrappableActive(reauth);
    const made = await makeRecoveryWrap(this.mailboxId, wrappable, this.ring.sessions === "required" ? this.binding : null);
    this.ring.wraps.push(ringWrapOf(made.wrap));
    return made;
  }
}

// ---- Unlocking with a factor ----

async function unlockWithFactor(view: MailboxView, factor: ReAuth, options?: UnlockOptions): Promise<UnlockedMailbox> {
  const ring = readRing(view);
  const now = options?.now ?? Date.now;
  const store = options?.store ?? null;
  const idleLockMs = idleLockMsOf(options);
  const opened = await openFactor(ring, factor);
  // The factor opened a real key (its wrap names it, and unwrap checked it). A key ring that does not list that key lies.
  if (!ring.keys.some((k) => k.keyId === opened.wrap.keyId)) throw new KeySubstitutionDetected("the factor's key is not in the key ring");
  const active = await activeOfFactor(ring, opened);
  if (active === null) throw new StaleFactor();
  // K2′ (a)/(b): the factor's own wrap is its anchor.
  const keys = await trustChain(ring, active.key, [opened.wrap.keyId]);
  const binding = await bindingOf(ring, active.key);
  await checkTags(ring, binding);
  const freshFactor = freshFactorFor(ring.mailboxId, opened, active.wrappable, now);
  return new Session({ ring, keys, binding, device: null, store, signInId: options?.signInId ?? null, now, freshFactor, idleLockMs });
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
