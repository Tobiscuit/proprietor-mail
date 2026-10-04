/**
 * Unlocking, and the unlocked mailbox (contracts/mail-client-v1.md
 * "Unlocking", "Reading", "Drafts and sending"; domain-model K1, K2).
 *
 * A session holds the private key as a decrypt-only, non-extractable
 * CryptoKey inside mail-crypto's handle, the advertised public key it was
 * checked against, and the wraps it may re-authenticate with. Wrapping the
 * key again (a new passkey, a new recovery key) opens a wrappable copy from
 * a wrap for that one operation and drops it after.
 */
import {
  DecryptionFailed,
  fingerprint,
  keyIdOf,
  newId,
  newRecoveryKey,
  openDraft,
  openHeader,
  openBody as openSealedBody,
  parseRecoveryKey,
  publicKeyMatches,
  RecoveryKeyTypo as CryptoRecoveryKeyTypo,
  sealDraft as sealDraftBlock,
  unwrapPrivateKey,
  wrapPrivateKey,
  type MailboxPrivateKey,
  type MailboxPublicKey,
} from "@proprietor/mail-crypto";
import { fromBase64url } from "./bytes";
import {
  KeySubstitutionDetected,
  MailboxLocked,
  NoActiveKey,
  NoMatchingWrap,
  RecoveryKeyTypo,
  UndecryptableBody,
  WrongRecoveryKey,
} from "./errors";
import { parseMail } from "./mime";
import { assertPasskeyPrf, createPasskeyWithPrf } from "./passkeys";
import type {
  DraftInput,
  DraftRecord,
  MailBody,
  MailboxView,
  MessageItem,
  OpenedDraft,
  OpenedMessage,
  PasskeyOptions,
  PasskeyPrompt,
  ReAuth,
  SaveDraftRequest,
  UnlockedMailbox,
  UnlockOptions,
  WrapInput,
} from "./types";

export const DEFAULT_IDLE_LOCK_MS = 15 * 60_000;
export const RECOVERY_LABEL = "Recovery key";

/** A wrap as the session keeps it: what unwrapPrivateKey needs plus the credential. */
export interface SessionWrap {
  id: string;
  keyId: string;
  kind: "passkey-prf" | "recovery";
  credentialId: string | null;
  wrapped: string;
}

/** The mailbox's active key, as advertised (domain-model G7: checked against every unwrap). */
export function activeKeyOf(view: Pick<MailboxView, "keys">): MailboxPublicKey {
  const active = view.keys.find((k) => k.retiredAt === null);
  if (!active) throw new NoActiveKey();
  const publicKey = fromBase64url(active.publicKey);
  if (publicKey === null || publicKey.length !== 32) throw new NoActiveKey("the advertised public key is malformed");
  return { keyId: active.keyId, publicKey };
}

/** K2: the unwrapped key's public half must equal the advertised public key, or nothing proceeds. */
export async function checkAdvertisedKey(priv: MailboxPrivateKey, pub: MailboxPublicKey): Promise<void> {
  if (!(await publicKeyMatches(priv, pub))) throw new KeySubstitutionDetected();
}

function wrapsFor(wraps: SessionWrap[], keyId: string, kind: SessionWrap["kind"]): SessionWrap[] {
  return wraps.filter((w) => w.kind === kind && w.keyId === keyId);
}

async function unwrapWithPasskey(
  mailboxId: string,
  pub: MailboxPublicKey,
  wraps: SessionWrap[],
  prompt: PasskeyPrompt,
  wrappable: boolean,
): Promise<MailboxPrivateKey> {
  const candidates = wrapsFor(wraps, pub.keyId, "passkey-prf").filter((w) => w.credentialId !== null);
  if (candidates.length === 0) throw new NoMatchingWrap("the mailbox has no passkey for its active key");
  const { wrap, secret } = await assertPasskeyPrf(prompt, mailboxId, candidates);
  try {
    return await unwrapPrivateKey(wrap, { mailboxId, secret }, { wrappable });
  } catch (e) {
    if (e instanceof DecryptionFailed) throw new NoMatchingWrap("the passkey's wrap did not open");
    throw e;
  } finally {
    secret.fill(0);
  }
}

async function unwrapWithRecoveryKey(
  mailboxId: string,
  pub: MailboxPublicKey,
  wraps: SessionWrap[],
  display: string,
  wrappable: boolean,
): Promise<MailboxPrivateKey> {
  let secret: Uint8Array; // pragma: allowlist secret (a variable or type name, not a value)
  try {
    secret = parseRecoveryKey(display); // pragma: allowlist secret (a variable or type name, not a value)
  } catch (e) {
    if (e instanceof CryptoRecoveryKeyTypo) throw new RecoveryKeyTypo();
    throw e;
  }
  try {
    for (const wrap of wrapsFor(wraps, pub.keyId, "recovery")) {
      try {
        return await unwrapPrivateKey(wrap, { mailboxId, secret }, { wrappable });
      } catch (e) {
        if (!(e instanceof DecryptionFailed)) throw e;
      }
    }
    throw new WrongRecoveryKey();
  } finally {
    secret.fill(0);
  }
}

/** A fresh, checked, wrappable key for the one operation that wraps it again (K1). */
async function reauthenticate(mailboxId: string, pub: MailboxPublicKey, wraps: SessionWrap[], reauth: ReAuth): Promise<MailboxPrivateKey> {
  const priv =
    "passkey" in reauth
      ? await unwrapWithPasskey(mailboxId, pub, wraps, reauth.passkey, true)
      : await unwrapWithRecoveryKey(mailboxId, pub, wraps, reauth.recoveryKey, true);
  await checkAdvertisedKey(priv, pub);
  return priv;
}

export async function unlockWithPasskey(mailbox: MailboxView, passkey: PasskeyPrompt, options?: UnlockOptions): Promise<UnlockedMailbox> {
  const pub = activeKeyOf(mailbox);
  const priv = await unwrapWithPasskey(mailbox.id, pub, mailbox.wraps, passkey, false);
  await checkAdvertisedKey(priv, pub);
  return new Session(mailbox.id, priv, pub, mailbox.wraps, options);
}

export async function unlockWithRecoveryKey(mailbox: MailboxView, recoveryKey: string, options?: UnlockOptions): Promise<UnlockedMailbox> {
  const pub = activeKeyOf(mailbox);
  const priv = await unwrapWithRecoveryKey(mailbox.id, pub, mailbox.wraps, recoveryKey, false);
  await checkAdvertisedKey(priv, pub);
  return new Session(mailbox.id, priv, pub, mailbox.wraps, options);
}

/** A passkey wrap for the key, as `MailService.addWrap` / `enroll` take it. */
export async function makePasskeyWrap(mailboxId: string, priv: MailboxPrivateKey, passkey: PasskeyOptions): Promise<WrapInput> {
  const wrapId = newId("wrp");
  const { credentialId, secret } = await createPasskeyWithPrf(passkey, mailboxId, wrapId);
  try {
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId, kind: "passkey-prf", secret });
    return { ...wrap, credentialId, label: passkey.label };
  } finally {
    secret.fill(0);
  }
}

/** A recovery wrap for the key and the display form to show once. */
export async function makeRecoveryWrap(mailboxId: string, priv: MailboxPrivateKey): Promise<{ recoveryKey: string; wrap: WrapInput }> {
  const { secret, display } = newRecoveryKey();
  try {
    const wrap = await wrapPrivateKey(priv, { mailboxId, wrapId: newId("wrp"), kind: "recovery", secret });
    return { recoveryKey: display, wrap: { ...wrap, credentialId: null, label: RECOVERY_LABEL } };
  } finally {
    secret.fill(0);
  }
}

function idleLockMsOf(options?: UnlockOptions): number {
  const ms = options?.idleLockMs ?? DEFAULT_IDLE_LOCK_MS;
  if (typeof ms !== "number" || Number.isNaN(ms) || ms <= 0) throw new TypeError("idleLockMs is a positive number of milliseconds, or Infinity");
  return ms;
}

export class Session implements UnlockedMailbox {
  readonly mailboxId: string;
  readonly keyId: string;
  readonly fingerprint: string;
  private priv: MailboxPrivateKey | null;
  private readonly pub: MailboxPublicKey;
  private readonly wraps: SessionWrap[];
  private readonly idleLockMs: number;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private readonly listeners = new Set<() => void>();

  constructor(mailboxId: string, priv: MailboxPrivateKey, pub: MailboxPublicKey, wraps: SessionWrap[], options?: UnlockOptions) {
    this.mailboxId = mailboxId;
    this.keyId = pub.keyId;
    this.fingerprint = fingerprint(pub.keyId);
    this.priv = priv;
    this.pub = pub;
    this.wraps = wraps.map((w) => ({ id: w.id, keyId: w.keyId, kind: w.kind, credentialId: w.credentialId, wrapped: w.wrapped })); // pragma: allowlist secret (a variable or type name, not a value)
    this.idleLockMs = idleLockMsOf(options);
    this.arm();
  }

  get locked(): boolean {
    return this.priv === null;
  }

  private arm(): void {
    if (this.timer !== null) clearTimeout(this.timer);
    this.timer = Number.isFinite(this.idleLockMs) ? setTimeout(() => this.lock(), this.idleLockMs) : null;
  }

  /** The key, after proving the session is unlocked; every method starts here and counts as activity. */
  private key(): MailboxPrivateKey {
    if (this.priv === null) throw new MailboxLocked();
    this.arm();
    return this.priv;
  }

  touch(): void {
    this.key();
  }

  lock(): void {
    if (this.priv === null) return;
    this.priv = null;
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

  async openMessages(items: MessageItem[]): Promise<OpenedMessage[]> {
    const priv = this.key();
    return Promise.all(
      items.map(async (item): Promise<OpenedMessage> => {
        const { keyId: _keyId, keyEnvelope: _env, header: _h, ...rest } = item;
        try {
          const header = await openHeader(priv, { mailboxId: this.mailboxId, messageId: item.id }, item);
          return { ...rest, header, undecryptable: false };
        } catch {
          return { ...rest, header: null, undecryptable: true };
        }
      }),
    );
  }

  async openBody(item: MessageItem, sealedBody: Uint8Array): Promise<MailBody> {
    const priv = this.key();
    let raw: Uint8Array;
    try {
      raw = await openSealedBody(priv, { mailboxId: this.mailboxId, messageId: item.id }, { keyEnvelope: item.keyEnvelope, body: sealedBody });
    } catch {
      throw new UndecryptableBody();
    }
    return parseMail(raw);
  }

  async sealDraft(draftId: string | null, draft: DraftInput): Promise<SaveDraftRequest> {
    this.key();
    const id = draftId ?? newId("drf");
    const sealed = await sealDraftBlock(
      this.pub,
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
        updatedAt: new Date().toISOString(),
      },
    );
    return { id, keyId: sealed.keyId, keyEnvelope: sealed.keyEnvelope, sealed: sealed.sealed };
  }

  async openDrafts(records: DraftRecord[]): Promise<OpenedDraft[]> {
    const priv = this.key();
    return Promise.all(
      records.map(async (record): Promise<OpenedDraft> => {
        try {
          const draft = await openDraft(priv, { mailboxId: this.mailboxId, draftId: record.id }, record);
          return { id: record.id, updatedAt: record.updatedAt, draft, undecryptable: false };
        } catch {
          return { id: record.id, updatedAt: record.updatedAt, draft: null, undecryptable: true };
        }
      }),
    );
  }

  async addPasskey(passkey: PasskeyOptions, reauth: ReAuth): Promise<WrapInput> {
    this.key();
    const wrappable = await reauthenticate(this.mailboxId, this.pub, this.wraps, reauth);
    const wrap = await makePasskeyWrap(this.mailboxId, wrappable, passkey);
    this.wraps.push(wrap);
    return wrap;
  }

  async replaceRecoveryKey(reauth: ReAuth): Promise<{ recoveryKey: string; wrap: WrapInput }> {
    this.key();
    const wrappable = await reauthenticate(this.mailboxId, this.pub, this.wraps, reauth);
    const made = await makeRecoveryWrap(this.mailboxId, wrappable);
    this.wraps.push(made.wrap);
    return made;
  }
}

/** The keyId of a base64url public key, for callers that only have the view. */
export async function keyIdOfView(publicKey: string): Promise<string | null> {
  const bytes = fromBase64url(publicKey);
  return bytes === null || bytes.length !== 32 ? null : keyIdOf(bytes);
}
