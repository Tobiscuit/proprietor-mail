/**
 * @proprietor/mail-client — the browser half of the inbox.
 *
 * The API of contracts/mail-client-v1.md, implemented by slice S6a on the
 * signatures the stub published (slice S0c). Everything in the owner's
 * browser that touches a mailbox key, a message key, a recovery key or
 * hostile message content lives here, in the published repository, so that
 * the code that keeps the zero-access promise can be read and checked.
 *
 * Rules (the contract, "Rules for the whole package"): no network; runs
 * under the dashboard's policy with Trusted Types enforced; nothing
 * persists; keys stay non-extractable and decrypt-only; errors are typed.
 */
export type {
  Address,
  Auth,
  BodyAttachment,
  ChallengeRequest,
  ChallengeView,
  ComposeInput,
  DeviceInfo,
  DeviceInput,
  DeviceStore,
  DeviceView,
  Draft,
  DraftInput,
  DraftRecord,
  Enrollment,
  EnrollRequest,
  FactorProof,
  FlaggedRecipients,
  Folder,
  FreshFactor,
  KeptDevice,
  KeptDeviceChange,
  KeyView,
  LockAfter,
  LockEvent,
  LockReason,
  LockResult,
  MailBody,
  MailboxView,
  MessageHeader,
  MessageItem,
  OpenedDraft,
  OpenedMessage,
  OpenSessionRequest,
  OpenSessionResult,
  PasskeyOptions,
  PasskeyPrompt,
  PendingChange,
  ProtectionTexts,
  ReAuth,
  RecipientRef,
  RegisterDeviceRequest,
  RemoveDeviceRequest,
  RenderedBody,
  ResumeOptions,
  ResumeResult,
  Rotation,
  SaveDraftRequest,
  SealView,
  SendRequest,
  Thread,
  TrustedHtml,
  UnlockedMailbox,
  UnlockOptions,
  UpdateDeviceRequest,
  UpgradeRequest,
  WrapInput,
  WrapView,
} from "./types";

export {
  DeviceRemoved,
  EnrollmentDiscarded,
  FactorExpired,
  FlaggedRecipient,
  InvalidChallenge,
  InvalidDeviceLabel,
  InvalidSendForm,
  KeySubstitutionDetected,
  MailboxChanged,
  MailboxLocked,
  MailboxNotProvisioned,
  MailClientError,
  MissingFactors,
  NoActiveKey,
  NoMatchingWrap,
  NoRecoveryFactor,
  NotImplemented,
  PasskeyCancelled,
  PrfUnavailable,
  RecoveryKeyTypo,
  RecoveryNotConfirmed,
  RotationUnproven,
  StaleFactor,
  StorageUnavailable,
  UndecryptableBody,
  UnsafeFrame,
  UnsupportedBrowser,
  WrongRecoveryKey,
} from "./errors";

export { canKeepDevices, DEVICE_DATABASE, indexedDbDeviceStore, KEPT_DEVICE_FIELDS, memoryDeviceStore } from "./device-store";

export { startEnrollment } from "./enrollment";
export { DEFAULT_IDLE_LOCK_MS, LOCK_AFTER_MS, unlockWithPasskey, unlockWithRecoveryKey } from "./session";
export { FRESH_FACTOR_MS } from "./fresh-factor";
export { resumeDevice } from "./resume";
export { pageNonce, POLICY_NAME, renderBody, showInFrame } from "./render";
export { threadsOf } from "./threads";
export { searchMessages } from "./search";
export { forwardOf, parseAddressList, replyTo } from "./compose";
export { decodeSendForm, encodeSendForm, SEND_LIMITS } from "./send-form";
export { PROTECTION } from "./protection";

import { x25519Supported } from "@proprietor/mail-crypto";

/** True since slice S6a replaced the stubs. Screens may show "coming soon" while false. */
export const IMPLEMENTED: boolean = true;

/**
 * What this browser can do before any prompt: "prf" when WebAuthn is there
 * and the browser knows the PRF extension, "no-prf" when WebAuthn exists
 * without it, "unknown" when there is no WebAuthn or no X25519 at all (then
 * startEnrollment would throw UnsupportedBrowser). Whether a given
 * authenticator supports PRF is only known after create().
 */
export async function passkeySupport(): Promise<"prf" | "no-prf" | "unknown"> {
  const g = globalThis as {
    PublicKeyCredential?: { getClientCapabilities?: () => Promise<Record<string, boolean>> };
    navigator?: { credentials?: unknown };
  };
  if (!g.navigator?.credentials || !g.PublicKeyCredential || !(await x25519Supported())) return "unknown";
  const capabilities = g.PublicKeyCredential.getClientCapabilities;
  if (typeof capabilities === "function") {
    try {
      const caps = await capabilities.call(g.PublicKeyCredential);
      if (caps["extension:prf"] === true) return "prf";
      if (caps["extension:prf"] === false) return "no-prf";
    } catch {
      // fall through: the capability query itself is optional
    }
  }
  return "unknown";
}
