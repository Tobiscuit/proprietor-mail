/**
 * An in-memory SQS queue behind a `fetch`, speaking the AWS JSON protocol as
 * the SQS API reference documents it (checked 2026-09-29): `POST /` on
 * `sqs.<region>.amazonaws.com`, `X-Amz-Target: AmazonSQS.<Action>`,
 * `Content-Type: application/x-amz-json-1.0`, ReceiveMessage answering
 * `{ Messages: [...] }` (or `{}` when the queue is empty), DeleteMessageBatch
 * answering `{ Successful, Failed }` with HTTP 200 even for a partial failure.
 *
 * It records every request so tests can check what would have left the
 * machine, and it can be told to fail deletes or to answer an error.
 */

export const TEST_QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/example-mail-events";

export interface QueuedMessage {
  messageId: string;
  receiptHandle: string;
  body: string;
  /** How many times ReceiveMessage handed it out. */
  receives: number;
  /** Handed out and neither deleted nor released: hidden, as SQS hides a message for its visibility timeout. */
  inFlight: boolean;
}

export interface SqsRequest {
  url: string;
  target: string | null;
  contentType: string | null;
  authorization: string | null;
  amzDate: string | null;
  body: Record<string, unknown>;
}

export interface FakeSqs {
  fetch: typeof fetch;
  requests: SqsRequest[];
  /** What is on the queue right now (visible or not). */
  messages: QueuedMessage[];
  enqueue(body: unknown): QueuedMessage;
  /** Message ids whose next delete answers a Failed entry (one failure each, then it succeeds). */
  failDeleteOnce: Set<string>;
  /** Message ids whose deletes always fail. */
  failDeleteAlways: Set<string>;
  /** When set, every request gets this answer instead. */
  answerWith: (() => Response) | null;
  /** The visibility timeout passing: every in-flight message can be received again. */
  releaseInFlight(): void;
  received(): SqsRequest[];
  deleted(): SqsRequest[];
}

let counter = 0;

export function fakeSqs(): FakeSqs {
  const messages: QueuedMessage[] = [];
  const requests: SqsRequest[] = [];
  const failDeleteOnce = new Set<string>();
  const failDeleteAlways = new Set<string>();
  const state: { answerWith: (() => Response) | null } = { answerWith: null };
  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/x-amz-json-1.0" } });

  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    // Decoded by hand: workerd warns on `.text()` for a body typed application/x-amz-json-1.0.
    const text = new TextDecoder().decode(await request.clone().arrayBuffer());
    const body = (text === "" ? {} : JSON.parse(text)) as Record<string, unknown>;
    const target = request.headers.get("x-amz-target");
    requests.push({
      url: request.url,
      target,
      contentType: request.headers.get("content-type"),
      authorization: request.headers.get("authorization"),
      amzDate: request.headers.get("x-amz-date"),
      body,
    });
    if (state.answerWith !== null) return state.answerWith();
    if (body.QueueUrl !== TEST_QUEUE_URL) {
      return json({ __type: "com.amazonaws.sqs#QueueDoesNotExist", message: "The specified queue does not exist." }, 400);
    }
    if (target === "AmazonSQS.ReceiveMessage") {
      const max = typeof body.MaxNumberOfMessages === "number" ? body.MaxNumberOfMessages : 1;
      const batch = messages.filter((m) => !m.inFlight).slice(0, max);
      for (const m of batch) {
        m.receives += 1;
        m.inFlight = true;
      }
      if (batch.length === 0) return json({});
      return json({
        Messages: batch.map((m) => ({
          MessageId: m.messageId,
          ReceiptHandle: m.receiptHandle,
          MD5OfBody: "00000000000000000000000000000000",
          Body: m.body,
          Attributes: { ApproximateReceiveCount: String(m.receives), SentTimestamp: "1790000000000" },
        })),
      });
    }
    if (target === "AmazonSQS.DeleteMessageBatch") {
      const entries = body.Entries as { Id: string; ReceiptHandle: string }[];
      const Successful: { Id: string }[] = [];
      const Failed: { Id: string; Code: string; Message: string; SenderFault: boolean }[] = [];
      for (const entry of entries) {
        const at = messages.findIndex((m) => m.receiptHandle === entry.ReceiptHandle);
        const message = messages[at];
        if (message === undefined) {
          Failed.push({ Id: entry.Id, Code: "ReceiptHandleIsInvalid", Message: "The input receipt handle is invalid.", SenderFault: true });
          continue;
        }
        if (failDeleteAlways.has(message.messageId) || failDeleteOnce.delete(message.messageId)) {
          Failed.push({ Id: entry.Id, Code: "InternalError", Message: "An internal error occurred.", SenderFault: false });
          continue;
        }
        messages.splice(at, 1);
        Successful.push({ Id: entry.Id });
      }
      return json({ Successful, Failed });
    }
    return json({ __type: "com.amazonaws.sqs#UnsupportedOperation", message: "Unsupported operation." }, 400);
  }) as typeof fetch;

  return {
    fetch: impl,
    requests,
    messages,
    failDeleteOnce,
    failDeleteAlways,
    get answerWith() {
      return state.answerWith;
    },
    set answerWith(value) {
      state.answerWith = value;
    },
    enqueue(body: unknown) {
      counter += 1;
      const message: QueuedMessage = {
        messageId: crypto.randomUUID(),
        receiptHandle: `AQEB-example-receipt-${counter}-${crypto.randomUUID().replace(/-/g, "")}`,
        body: typeof body === "string" ? body : JSON.stringify(body),
        receives: 0,
        inFlight: false,
      };
      messages.push(message);
      return message;
    },
    releaseInFlight() {
      for (const m of messages) m.inFlight = false;
    },
    received: () => requests.filter((r) => r.target === "AmazonSQS.ReceiveMessage"),
    deleted: () => requests.filter((r) => r.target === "AmazonSQS.DeleteMessageBatch"),
  };
}
