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
  BodyAttachment,
  ComposeInput,
  Draft,
  DraftInput,
  DraftRecord,
  Enrollment,
  EnrollRequest,
  Folder,
  KeyView,
  MailBody,
  MailboxView,
  MessageHeader,
  MessageItem,
  OpenedDraft,
  OpenedMessage,
  PasskeyOptions,
  PasskeyPrompt,
  ProtectionTexts,
  ReAuth,
  RenderedBody,
  SaveDraftRequest,
  SendRequest,
  Thread,
  TrustedHtml,
  UnlockedMailbox,
  UnlockOptions,
  WrapInput,
  WrapView,
} from "./types";

export {
  EnrollmentDiscarded,
  InvalidSendForm,
  KeySubstitutionDetected,
  MailboxLocked,
  MailboxNotProvisioned,
  MailClientError,
  NoActiveKey,
  NoMatchingWrap,
  NotImplemented,
  PasskeyCancelled,
  PrfUnavailable,
  RecoveryKeyTypo,
  RecoveryNotConfirmed,
  UndecryptableBody,
  UnsafeFrame,
  UnsupportedBrowser,
  WrongRecoveryKey,
} from "./errors";

export { startEnrollment } from "./enrollment";
export { DEFAULT_IDLE_LOCK_MS, unlockWithPasskey, unlockWithRecoveryKey } from "./session";
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
