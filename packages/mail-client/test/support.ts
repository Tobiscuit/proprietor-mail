// Test support: a WebAuthn `credentials` double with the PRF extension, fixtures and byte helpers.
// The double stands in for navigator.credentials where no authenticator exists (Node, and browsers
// without a PRF-capable virtual authenticator). Its PRF is HMAC-SHA256 under a per-credential key,
// which is what a real authenticator's hmac-secret does, so the same input gives the same output.
import { Buffer } from "node:buffer";
import { keyIdOf, sealMessage, type MessageHeader } from "@proprietor/mail-crypto";
import type { EnrollRequest, MailboxView, MessageItem, OpenedMessage, PasskeyOptions, WrapView } from "../src/index";

export const b64url = (bytes: Uint8Array | ArrayBuffer): string => Buffer.from(bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : bytes).toString("base64url");
export const fromB64url = (s: string): Uint8Array<ArrayBuffer> => new Uint8Array(Buffer.from(s, "base64url"));
export const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);

export interface DoubleOptions {
  /** `false`: the authenticator reports `prf.enabled: false`. Default true. */
  prf?: boolean;
  /** `false`: PRF is enabled at creation but results come only from get(). Default true. */
  prfAtCreate?: boolean;
  /** The prompt is dismissed. */
  cancel?: boolean;
  /** Which of the allowed credentials the person "uses" in get(): index into allowCredentials. */
  pick?: number;
  /** get() answers with a credential the mailbox does not know. */
  strangerInGet?: boolean;
}

interface Stored {
  rawId: Uint8Array<ArrayBuffer>;
  rpId: string;
  prfKey: CryptoKey;
}

export class CredentialsDouble {
  readonly created: PublicKeyCredentialCreationOptions[] = [];
  readonly got: PublicKeyCredentialRequestOptions[] = [];
  private readonly stored: Stored[] = [];

  constructor(public options: DoubleOptions = {}) {}

  /** base64url of the last created credential's rawId: what a wrap's `credentialId` must be. */
  lastCredentialId(): string {
    return b64url(this.stored.at(-1)!.rawId);
  }

  private async prfKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  }

  private async prf(stored: Stored, input: BufferSource): Promise<ArrayBuffer> {
    return crypto.subtle.sign("HMAC", stored.prfKey, input);
  }

  private cancelled(): never {
    throw new DOMException("The operation either timed out or was not allowed.", "NotAllowedError");
  }

  async create(options?: CredentialCreationOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) throw new TypeError("publicKey options are required");
    this.created.push(pk);
    if (this.options.cancel) this.cancelled();
    const stored: Stored = { rawId: crypto.getRandomValues(new Uint8Array(16)), rpId: pk.rp.id ?? "", prfKey: await this.prfKey() };
    this.stored.push(stored);
    const eval_ = pk.extensions?.prf?.eval;
    const prf: AuthenticationExtensionsPRFOutputs =
      this.options.prf === false
        ? { enabled: false }
        : eval_ && this.options.prfAtCreate !== false
          ? { enabled: true, results: { first: await this.prf(stored, eval_.first) } }
          : { enabled: true };
    return credential(stored.rawId, { prf });
  }

  async get(options?: CredentialRequestOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) throw new TypeError("publicKey options are required");
    this.got.push(pk);
    if (this.options.cancel) this.cancelled();
    const allowed = pk.allowCredentials ?? [];
    if (allowed.length === 0) throw new DOMException("no allowed credentials", "NotAllowedError");
    if (this.options.strangerInGet) {
      const stranger: Stored = { rawId: crypto.getRandomValues(new Uint8Array(16)), rpId: pk.rpId ?? "", prfKey: await this.prfKey() };
      return credential(stranger.rawId, { prf: {} });
    }
    const chosen = allowed[this.options.pick ?? 0]!;
    const id = b64url(bufferBytes(chosen.id));
    const stored = this.stored.find((s) => b64url(s.rawId) === id);
    if (!stored) throw new DOMException("unknown credential", "NotAllowedError");
    if (stored.rpId !== pk.rpId) throw new DOMException("rpId mismatch", "SecurityError");
    const byCredential = pk.extensions?.prf?.evalByCredential?.[id]; // pragma: allowlist secret (a variable or type name, not a value)
    const prf: AuthenticationExtensionsPRFOutputs =
      this.options.prf === false || !byCredential ? {} : { results: { first: await this.prf(stored, byCredential.first) } };
    return credential(stored.rawId, { prf });
  }
}

function bufferBytes(source: BufferSource): Uint8Array {
  return source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
}

function credential(rawId: Uint8Array<ArrayBuffer>, extensions: AuthenticationExtensionsClientOutputs): Credential {
  const c = {
    id: b64url(rawId),
    rawId: rawId.buffer.slice(0),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {},
    getClientExtensionResults: () => extensions,
  };
  return c as unknown as Credential;
}

export function passkeyOptions(credentials: CredentialsDouble, overrides: Partial<PasskeyOptions> = {}): PasskeyOptions { // pragma: allowlist secret (a variable or type name, not a value)
  return {
    rpId: "example.com",
    rpName: "Example",
    userName: "Mail key — hello@example.com",
    userDisplayName: "hello@example.com",
    label: "Laptop passkey",
    credentials,
    ...overrides,
  };
}

/** A MailboxView as `MailService.mailbox()` would answer after `enroll(request)`. */
export function mailboxAfterEnroll(mailboxId: string, request: EnrollRequest, overrides: Partial<MailboxView> = {}): MailboxView {
  const now = "2026-10-04T10:00:00.000Z";
  const keyId = request.wraps[0]!.keyId;
  const wraps: WrapView[] = request.wraps.map((w) => ({ ...w, createdAt: now, createdBy: "acc_owner" }));
  return {
    id: mailboxId,
    address: "hello@example.com",
    addresses: ["hello@example.com", "team@example.com"],
    status: "active",
    displayName: "Example",
    keys: [{ keyId, publicKey: request.publicKey, createdAt: now, createdBy: "acc_owner", retiredAt: null }],
    wraps,
    ...overrides,
  };
}

export async function publicKeyOf(request: EnrollRequest) {
  const publicKey = fromB64url(request.publicKey);
  return { keyId: await keyIdOf(publicKey), publicKey };
}

export const sampleHeader: MessageHeader = {
  v: 1,
  direction: "in",
  envelopeFrom: "bounce@x.example",
  envelopeTo: "hello@example.com",
  from: { name: "Ana Ruiz", address: "ana@example.com" },
  to: [{ name: "", address: "hello@example.com" }],
  cc: [],
  bcc: [],
  replyTo: [],
  subject: "Kitchen remodel quote",
  date: "2026-09-26T15:04:05.000Z",
  messageId: "abc@example.com",
  inReplyTo: null,
  references: [],
  snippet: "Hi — we'd like a quote for…",
  attachments: [],
};

export const sampleRaw = utf8(
  [
    "From: Ana Ruiz <ana@example.com>",
    "To: hello@example.com",
    "Subject: Kitchen remodel quote",
    "Date: Sat, 26 Sep 2026 15:04:05 +0000",
    "Message-ID: <abc@example.com>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Hi — we'd like a quote for the kitchen.",
    "",
  ].join("\r\n"),
);

/** A 1x1 red PNG. */
export const PNG_1x1 = fromB64url("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg");

export const multipartRaw = utf8(
  [
    "From: Ana Ruiz <ana@example.com>",
    "To: hello@example.com",
    "Subject: Plans",
    "Date: Sat, 26 Sep 2026 15:04:05 +0000",
    "Message-ID: <plans@example.com>",
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="outer"',
    "",
    "--outer",
    'Content-Type: multipart/related; boundary="inner"',
    "",
    "--inner",
    "Content-Type: text/html; charset=utf-8",
    "",
    '<p class="x">Plans <img src="cid:logo@example.com"></p>',
    "--inner",
    "Content-Type: image/png",
    "Content-ID: <logo@example.com>",
    "Content-Disposition: inline; filename=logo.png",
    "Content-Transfer-Encoding: base64",
    "",
    Buffer.from(PNG_1x1).toString("base64"),
    "--inner--",
    "--outer",
    "Content-Type: application/pdf; name=plan.pdf",
    "Content-Disposition: attachment; filename=plan.pdf",
    "Content-Transfer-Encoding: base64",
    "",
    "JVBERi0xLjQKJcTl8uXrp/Og0MTGCg==",
    "--outer--",
    "",
  ].join("\r\n"),
);

/** Seals a message for the mailbox as the Worker would, as a MessageItem. */
export async function sealedItem(
  pub: { keyId: string; publicKey: Uint8Array },
  mailboxId: string,
  messageId: string,
  header: MessageHeader = sampleHeader,
  raw: Uint8Array = sampleRaw,
  overrides: Partial<MessageItem> = {},
): Promise<{ item: MessageItem; body: Uint8Array }> {
  const sealed = await sealMessage(pub, { mailboxId, messageId }, header, raw);
  return {
    item: {
      id: messageId,
      folder: "inbox",
      direction: header.direction,
      receivedAt: "2026-09-26T15:04:06.000Z",
      size: raw.length,
      seen: false,
      flagged: false,
      keyId: sealed.keyId,
      keyEnvelope: sealed.keyEnvelope,
      header: sealed.header,
      ...overrides,
    },
    body: sealed.body,
  };
}

let counter = 0;
/** An opened message for the pure helpers (threads, search, compose). */
export function opened(header: Partial<MessageHeader> & { subject: string }, overrides: Partial<OpenedMessage> = {}): OpenedMessage {
  counter += 1;
  return {
    id: `msg_${String(counter).padStart(26, "0")}`,
    folder: "inbox",
    direction: header.direction ?? "in",
    receivedAt: `2026-09-26T15:${String(counter % 60).padStart(2, "0")}:00.000Z`,
    size: 1000,
    seen: false,
    flagged: false,
    header: { ...sampleHeader, messageId: `m${counter}@example.com`, ...header },
    undecryptable: false,
    ...overrides,
  };
}
