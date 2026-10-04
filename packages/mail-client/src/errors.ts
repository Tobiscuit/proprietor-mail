/**
 * Every error this package throws (contracts/mail-client-v1.md, rule 5): a
 * MailClientError subclass with a stable `name`, set explicitly so that a
 * minifier cannot change it. Messages never carry mail content, an address or
 * key material; screens branch on `name` and show their own wording.
 */
export class MailClientError extends Error {
  constructor(message: string, name = "MailClientError") {
    super(message);
    this.name = name;
  }
}

/** The stub's marker; nothing throws it any more (IMPLEMENTED is true). */
export class NotImplemented extends MailClientError {
  constructor(message = "not implemented") {
    super(message, "NotImplemented");
  }
}
/** No native X25519 with wrapKey/unwrapKey in this browser's Web Crypto, or no WebAuthn (mail-crypto has no fallback). */
export class UnsupportedBrowser extends MailClientError {
  constructor(message = "this browser lacks an API the inbox needs") {
    super(message, "UnsupportedBrowser");
  }
}
/** The authenticator or browser returned no PRF output. */
export class PrfUnavailable extends MailClientError {
  constructor(message = "this passkey cannot derive a key (no PRF)") {
    super(message, "PrfUnavailable");
  }
}
/** The person dismissed the passkey prompt. */
export class PasskeyCancelled extends MailClientError {
  constructor(message = "the passkey prompt was dismissed") {
    super(message, "PasskeyCancelled");
  }
}
/** The passkey used has no wrap in this mailbox. */
export class NoMatchingWrap extends MailClientError {
  constructor(message = "no wrap of this mailbox opens with that passkey") {
    super(message, "NoMatchingWrap");
  }
}
/** Domain-model G7: the unwrapped key does not match the advertised public key. Stop everything. */
export class KeySubstitutionDetected extends MailClientError {
  constructor(message = "the mailbox's advertised public key is not the key this device holds") {
    super(message, "KeySubstitutionDetected");
  }
}
/** The recovery key's checksum does not match: a typo, caught before any decryption. */
export class RecoveryKeyTypo extends MailClientError {
  constructor(message = "that recovery key has a typo") {
    super(message, "RecoveryKeyTypo");
  }
}
/** The recovery key parses but opens no recovery wrap of this mailbox. */
export class WrongRecoveryKey extends MailClientError {
  constructor(message = "that recovery key does not open this mailbox") {
    super(message, "WrongRecoveryKey");
  }
}
/** Used after lock(). */
export class MailboxLocked extends MailClientError {
  constructor(message = "the mailbox is locked") {
    super(message, "MailboxLocked");
  }
}
/** A body could not be decrypted (never shown as an empty message). */
export class UndecryptableBody extends MailClientError {
  constructor(message = "this message could not be decrypted") {
    super(message, "UndecryptableBody");
  }
}

// ---- Added by S6a (the contract lets the package add exports) ----

/** startEnrollment on a mailbox that is not `provisioned`. */
export class MailboxNotProvisioned extends MailClientError {
  constructor(message = "only a provisioned mailbox can be set up") {
    super(message, "MailboxNotProvisioned");
  }
}
/** The mailbox advertises no key without a retiredAt. */
export class NoActiveKey extends MailClientError {
  constructor(message = "the mailbox has no active key") {
    super(message, "NoActiveKey");
  }
}
/** Enrollment.request() before confirmRecovery() succeeded, or after discard(). */
export class RecoveryNotConfirmed extends MailClientError {
  constructor(message = "the recovery key has not been proven saved") {
    super(message, "RecoveryNotConfirmed");
  }
}
/** The enrollment was discarded; nothing of it can be used. */
export class EnrollmentDiscarded extends MailClientError {
  constructor(message = "this enrollment was discarded") {
    super(message, "EnrollmentDiscarded");
  }
}
/** showInFrame on a frame whose sandbox is missing or too permissive (spec D3). */
export class UnsafeFrame extends MailClientError {
  constructor(message = "the frame's sandbox is missing or grants more than popups") {
    super(message, "UnsafeFrame");
  }
}
/** encodeSendForm / decodeSendForm: a limit or a shape the Worker would refuse. */
export class InvalidSendForm extends MailClientError {
  constructor(message = "the message cannot be sent as it is") {
    super(message, "InvalidSendForm");
  }
}
