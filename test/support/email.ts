import type { Trace } from "./fakes";

/**
 * A ForwardableEmailMessage as Email Routing hands one to `email()`: envelope
 * `from`/`to`, the header block, the raw bytes as a stream, and the three
 * actions. It records what the Worker did with it.
 */
export interface TestEmail {
  message: ForwardableEmailMessage;
  rejects: string[];
  forwards: { rcptTo: string }[];
}

export function crlf(lines: string[]): Uint8Array {
  return new TextEncoder().encode(lines.join("\r\n"));
}

export function sampleMessage(opts: { to: string; subject?: string; body?: string; from?: string } ): Uint8Array {
  return crlf([
    `From: ${opts.from ?? '"Ana Ruiz" <ana@example.com>'}`,
    `To: <${opts.to}>`,
    `Subject: ${opts.subject ?? "Kitchen remodel quote"}`,
    "Date: Sat, 26 Sep 2026 15:04:05 +0000",
    `Message-ID: <${crypto.randomUUID()}@example.com>`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    opts.body ?? "Hi, we'd like a quote.",
  ]);
}

export function incomingEmail(
  raw: Uint8Array,
  envelope: { from?: string; to: string; rawSize?: number; forwardFails?: boolean; headers?: [string, string][] },
  trace?: Trace,
): TestEmail {
  const rejects: string[] = [];
  const forwards: { rcptTo: string }[] = [];
  let delivered = false;
  // highWaterMark 0: pulled only when the Worker actually reads, so "read"
  // lands in the trace at the moment it happens.
  const stream = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (!delivered) {
          trace?.push("read");
          delivered = true;
          controller.enqueue(raw);
        } else {
          controller.close();
        }
      },
    },
    { highWaterMark: 0 },
  );
  const headers = new Headers(envelope.headers ?? [["subject", "(set by the test)"]]);
  const message = {
    from: envelope.from ?? "bounce@example.com",
    to: envelope.to,
    headers,
    raw: stream,
    rawSize: envelope.rawSize ?? raw.byteLength,
    setReject(reason: string) {
      trace?.push("reject");
      rejects.push(reason);
    },
    async forward(rcptTo: string) {
      trace?.push("forward");
      if (envelope.forwardFails) throw new Error("destination address is not verified");
      forwards.push({ rcptTo });
      return { messageId: `${crypto.randomUUID()}@forward.test` };
    },
    async reply() {
      throw new Error("the Mail Worker never replies");
    },
  };
  return { message: message as unknown as ForwardableEmailMessage, rejects, forwards };
}

