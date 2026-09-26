export class NotImplemented extends Error {
  constructor(what: string) {
    super(`@platform-mail/crypto: ${what} is not implemented yet (slice S1)`);
    this.name = "NotImplemented";
  }
}

/** An authentication tag did not verify, or a blob is malformed. Never an empty result. */
export class DecryptionFailed extends Error {
  constructor(message = "this could not be decrypted") {
    super(message);
    this.name = "DecryptionFailed";
  }
}

/** A recovery key whose checksum does not match: a typo, caught before any decryption. */
export class RecoveryKeyTypo extends Error {
  constructor(message = "that recovery key has a typo") {
    super(message);
    this.name = "RecoveryKeyTypo";
  }
}
