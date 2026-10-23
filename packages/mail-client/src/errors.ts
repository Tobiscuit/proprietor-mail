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

// ---- Added by slice D1 (spec 002: kept devices, contracts/device-v1.md Part C) ----

/** K7: this browser's kept device was removed from the mailbox; its record and keys are gone. */
export class DeviceRemoved extends MailClientError {
  constructor(message = "this device was removed from the mailbox") {
    super(message, "DeviceRemoved");
  }
}
/** D31: this browser cannot keep non-extractable P-256 keys (a private window, or storage refused): it acts as a shared computer. */
export class StorageUnavailable extends MailClientError {
  constructor(message = "this browser cannot keep the inbox unlocked") {
    super(message, "StorageUnavailable");
  }
}
/** A FreshFactor used after its 2 minutes, or after dispose(): use the passkey or the recovery key again. */
export class FactorExpired extends MailClientError {
  constructor(message = "that unlock is no longer fresh") {
    super(message, "FactorExpired");
  }
}
/** The mailbox's key ring changed since this unlock (another browser rotated the key): fetch the mailbox again and unlock or resume. */
export class MailboxChanged extends MailClientError {
  constructor(message = "the mailbox changed since it was unlocked") {
    super(message, "MailboxChanged");
  }
}
/**
 * A refusal: a passkey that opens only an older key and has no
 * seal of the current one, so it reaches no key Mail seals to now (the key
 * ring is missing that factor's seal). Unlock with another factor. Since the
 * upgrade names every factor (B5 as amended on 2026-10-19), a factor is never
 * left without its key, and there is no repair flow.
 */
export class StaleFactor extends MailClientError {
  constructor(message = "this passkey only opens an older mailbox key") {
    super(message, "StaleFactor");
  }
}
/** M5′ / D28: the request would leave no recovery factor able to reach the mailbox key (an upgrade or a rotation needs one). */
export class NoRecoveryFactor extends MailClientError {
  constructor(message = "the recovery key must be part of this change") {
    super(message, "NoRecoveryFactor");
  }
}
/** A device name the Worker would refuse: 1 to 40 characters on one line. */
export class InvalidDeviceLabel extends MailClientError {
  constructor(message = "a device name has 1 to 40 characters on one line") {
    super(message, "InvalidDeviceLabel");
  }
}
/** K4: what Mail sent as a challenge does not open as one; nothing was answered. */
export class InvalidChallenge extends MailClientError {
  constructor(message = "that challenge could not be answered") {
    super(message, "InvalidChallenge");
  }
}

// ---- Added by D1's round 2 (contracts/device-v1.md Part C as amended on 2026-10-19) ----

/**
 * K3, K9: the change would seal the mailbox key to a flagged recipient, or add a factor while a flagged
 * one is there. `flagged` names the recipients in the way: remove them first (removeDevice for a
 * device, removeWrap with a proof from another factor for a factor), then try again.
 */
export class FlaggedRecipient extends MailClientError {
  readonly flagged: { readonly devices: readonly string[]; readonly factors: readonly string[] };
  constructor(message = "remove the flagged device or factor first", flagged: { devices?: readonly string[]; factors?: readonly string[] } = {}) {
    super(message, "FlaggedRecipient");
    this.flagged = Object.freeze({ devices: Object.freeze([...(flagged.devices ?? [])]), factors: Object.freeze([...(flagged.factors ?? [])]) });
  }
}

/**
 * K8: the rotation this browser made did not prove itself: its successor seal did not open with the new
 * key, or the new key's seal for the factor just used did not open with that factor's key (or there is
 * none). Nothing was sent and nothing changed here; mail that arrived after such a rotation would have
 * opened only in this page. Try again; if it fails again, use another browser.
 */
export class RotationUnproven extends MailClientError {
  constructor(message = "the key change could not be checked in this browser, so it was not made") {
    super(message, "RotationUnproven");
  }
}

/**
 * B5, M20 as amended on 2026-10-19: the upgrade names every factor of the mailbox, each just used, and
 * these were not among them. Use each (the screen asks for it by its label), or remove one the owner no
 * longer has (removeWrap, which needs no proof while sessions are optional), then ask again.
 */
export class MissingFactors extends MailClientError {
  readonly missing: readonly { readonly id: string; readonly kind: "passkey-prf" | "recovery"; readonly label: string }[];
  constructor(message = "every passkey and the recovery key must be used for the upgrade", missing: readonly { id: string; kind: "passkey-prf" | "recovery"; label: string }[] = []) {
    super(message, "MissingFactors");
    this.missing = Object.freeze(missing.map((m) => Object.freeze({ id: m.id, kind: m.kind, label: m.label })));
  }
}

// ---- Added by round 3 (contracts/device-v1.md Part C, K13) ----

/**
 * K13: a rotation is due (an email code revoked devices, B7a), and it comes before any other change.
 * Finish it first: removeDevices with no devices (or with every flagged one), with this FreshFactor.
 */
export class RotationDue extends MailClientError {
  constructor(message = "finish removing the revoked devices first") {
    super(message, "RotationDue");
  }
}
