import type { MailboxPublicKey, MessageHeader, SealedMessage } from "@proprietor/mail-crypto";
import type { BuildOptions, BuiltMessage, ComposedMessage, RawSendRequest } from "@proprietor/mail-outbound";
import type { Clock, IdSource, MailboxPorts, MimeBuilder, NewMailSignal, RawMailer, Sealer } from "../../src/ports";
import { base64urlFromBytes } from "./capability-tokens";
import { testId } from "./ids";

const utf8 = (s: string) => new TextEncoder().encode(s);

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** An ordered record of what the ports and the constructed email saw, for ordering assertions. */
export type Trace = string[];

/**
 * Seals with REAL AES-256-GCM under a fresh key that is thrown away at once,
 * so whatever reaches storage is ciphertext, exactly as with envelope v1. It
 * keeps the plaintext header and raw bytes it was handed in TEST memory, so a
 * test can check what the Worker built. The key envelope is 80 random bytes:
 * the real one is S1's (HPKE), and the Worker only stores it.
 */
export class FakeSealer implements Sealer {
  readonly sealed: { pub: MailboxPublicKey; ids: { mailboxId: string; messageId: string }; header: MessageHeader; raw: Uint8Array }[] = [];
  failNext = false;
  constructor(private readonly trace: Trace) {}

  async seal(pub: MailboxPublicKey, ids: { mailboxId: string; messageId: string }, header: MessageHeader, raw: Uint8Array): Promise<SealedMessage> {
    this.trace.push("seal");
    if (this.failNext) {
      this.failNext = false;
      throw new Error("fake sealer failure");
    }
    this.sealed.push({ pub, ids, header, raw: raw.slice() });
    const key = (await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"])) as CryptoKey;
    const ivHeader = crypto.getRandomValues(new Uint8Array(12));
    const ivBody = crypto.getRandomValues(new Uint8Array(12));
    const headerCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivHeader }, key, utf8(JSON.stringify(header))));
    const bodyCt = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivBody }, key, raw));
    return {
      keyId: pub.keyId,
      keyEnvelope: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(80))),
      header: base64urlFromBytes(concat(new Uint8Array([1]), ivHeader, headerCt)),
      body: concat(utf8("PMB1"), ivBody, bodyCt),
    };
  }

  /** The contract's keyId: lowercase hex of the first 16 bytes of SHA-256(public key). */
  async keyIdOf(publicKey: Uint8Array): Promise<string> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
    return [...digest.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
}

/** A plain-text RFC 5322 message; records what it was asked to build. */
export class FakeMime implements MimeBuilder {
  readonly built: { msg: ComposedMessage; opts: BuildOptions }[] = [];
  failWith: Error | undefined;

  build(msg: ComposedMessage, opts: BuildOptions): BuiltMessage {
    if (this.failWith !== undefined) throw this.failWith;
    this.built.push({ msg, opts });
    const fmt = (a: { name?: string; address: string }) => (a.name ? `"${a.name}" <${a.address}>` : `<${a.address}>`);
    const messageId = `${testId("msg").slice(4)}@${opts.messageIdDomain}`;
    const lines = [
      `From: ${fmt(msg.from)}`,
      `To: ${msg.to.map(fmt).join(", ")}`,
      ...(msg.cc && msg.cc.length > 0 ? [`Cc: ${msg.cc.map(fmt).join(", ")}`] : []),
      `Subject: ${msg.subject}`,
      `Date: ${(opts.now ?? new Date()).toUTCString()}`,
      `Message-ID: <${messageId}>`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "",
      msg.text,
    ];
    const recipients = [...new Set([...msg.to, ...(msg.cc ?? []), ...(msg.bcc ?? [])].map((a) => a.address.toLowerCase()))];
    return { raw: utf8(lines.join("\r\n")), messageId, recipients };
  }
}

export class FakeMailer implements RawMailer {
  readonly sent: RawSendRequest[] = [];
  failWith: Error | undefined;
  constructor(private readonly trace: Trace) {}

  async send(req: RawSendRequest): Promise<{ providerMessageId: string }> {
    this.trace.push("ses");
    if (this.failWith !== undefined) throw this.failWith;
    this.sent.push(req);
    return { providerMessageId: `ses-${this.sent.length}` };
  }
}

export class FakeSignal implements NewMailSignal {
  readonly events: { businessId: string; mailboxId: string; unread: number }[] = [];
  failWith: Error | undefined;
  async unread(event: { businessId: string; mailboxId: string; unread: number }): Promise<void> {
    if (this.failWith !== undefined) throw this.failWith;
    this.events.push({ ...event });
  }
}

export class FakeClock implements Clock {
  constructor(public current = new Date("2026-09-26T12:00:00.000Z")) {}
  now(): Date {
    return new Date(this.current.getTime());
  }
  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
}

export class FakeIds implements IdSource {
  messageId(): string {
    return testId("msg");
  }
}

export interface FakePorts extends MailboxPorts {
  sealer: FakeSealer;
  mime: FakeMime;
  mailer: FakeMailer;
  signal: FakeSignal;
  clock: FakeClock;
  trace: Trace;
}

export function fakePorts(): FakePorts {
  const trace: Trace = [];
  return {
    trace,
    sealer: new FakeSealer(trace),
    ids: new FakeIds(),
    mime: new FakeMime(),
    mailer: new FakeMailer(trace),
    signal: new FakeSignal(),
    clock: new FakeClock(),
  };
}
