import { AwsClient } from "aws4fetch";

/**
 * The two SQS calls the deliverability feed makes (plan.md §13), over the AWS
 * JSON protocol as the SQS API reference documents it (ReceiveMessage,
 * DeleteMessageBatch; checked 2026-09-29): a POST to `/` on
 * `sqs.<region>.amazonaws.com`, `X-Amz-Target: AmazonSQS.<Action>`,
 * `Content-Type: application/x-amz-json-1.0`, the queue URL in the body,
 * SigV4 with signing name `sqs`. aws4fetch signs; the injectable fetch sends,
 * so tests see exactly what would leave the machine. It never retries on its
 * own: a receive is safe to repeat and a delete is repeated by the caller.
 *
 * Errors carry the HTTP status and the error code only. SQS's explanation
 * text, the queue URL (it names the AWS account) and the message bodies (they
 * carry recipients and subjects, spec D8) never go into an error or a log.
 */

export interface SqsQueueCredentials {
  /** `https://sqs.<region>.amazonaws.com/<account id>/<queue name>`: the region is read from it. */
  queueUrl: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** Only for temporary (STS) credentials. */
  sessionToken?: string;
}

export interface QueueMessage {
  messageId: string;
  receiptHandle: string;
  body: string;
}

export interface DeleteEntry {
  /** Distinct within the batch: letters, digits, `-` and `_`, at most 80 characters. */
  id: string;
  receiptHandle: string;
}

export interface DeleteOutcome {
  deleted: string[];
  failed: { id: string; code: string; senderFault: boolean }[];
}

export interface SqsQueueClient {
  readonly region: string;
  /** Up to `max` (1–10) messages, waiting up to `waitSeconds` (0–20; more than 0 is a long poll) for one. */
  receive(opts: { max: number; waitSeconds: number }): Promise<QueueMessage[]>;
  /** 1–10 entries. A partial failure is an ordinary answer, not a throw. */
  deleteBatch(entries: DeleteEntry[]): Promise<DeleteOutcome>;
}

/** SQS refused or failed. `retryable` for throttling, 5xx and anything that never answered. */
export class SqsRequestFailed extends Error {
  constructor(
    readonly action: "ReceiveMessage" | "DeleteMessageBatch",
    readonly status: number,
    readonly code: string,
    readonly retryable: boolean,
  ) {
    super(`SQS ${action} failed: HTTP ${status} ${code}`);
    this.name = "SqsRequestFailed";
  }
}

/** A standard SQS queue URL in a commercial region; the account id and queue name are checked for shape only. */
const QUEUE_URL = /^https:\/\/sqs\.([a-z]{2}(?:-[a-z]+)+-\d{1,2})\.amazonaws\.com\/\d{12}\/[A-Za-z0-9_-]{1,80}$/;
/** A batch entry id (DeleteMessageBatchRequestEntry.Id): letters, digits, `-` and `_`, at most 80 characters. */
export const BATCH_ID = /^[A-Za-z0-9_-]{1,80}$/;
const DEFAULT_TIMEOUT_MS = 15_000;
/** ReceiveMessage: MaxNumberOfMessages 1–10, WaitTimeSeconds 0–20; DeleteMessageBatch: at most 10 entries. */
const MAX_BATCH = 10;
const MAX_WAIT_SECONDS = 20;

/** Error codes SQS returns for throttling (RequestThrottled on every action; the older name for older SDKs). */
const THROTTLING = new Set(["RequestThrottled", "ThrottlingException", "Throttling"]);

export function sqsQueueClient(creds: SqsQueueCredentials, opts?: { fetch?: typeof fetch; timeoutMs?: number }): SqsQueueClient {
  const match = QUEUE_URL.exec(creds.queueUrl);
  if (match === null) throw new TypeError("sqsQueueClient: queueUrl must be an SQS queue URL (https://sqs.<region>.amazonaws.com/<account>/<queue>)");
  const region = match[1]!;
  const endpoint = `https://sqs.${region}.amazonaws.com/`;
  const aws = new AwsClient({
    accessKeyId: creds.accessKeyId, // pragma: allowlist secret (a field name, not a value)
    secretAccessKey: creds.secretAccessKey, // pragma: allowlist secret (a field name, not a value)
    sessionToken: creds.sessionToken, // pragma: allowlist secret (a field name, not a value)
    region,
    service: "sqs",
    retries: 0,
  });
  const send: typeof fetch = opts?.fetch ?? ((input, init) => fetch(input, init));
  const timeoutMs = opts?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  async function call(action: "ReceiveMessage" | "DeleteMessageBatch", input: Record<string, unknown>): Promise<Record<string, unknown>> {
    const body = JSON.stringify({ QueueUrl: creds.queueUrl, ...input });
    const signed = await aws.sign(endpoint, {
      method: "POST",
      headers: { "content-type": "application/x-amz-json-1.0", "x-amz-target": `AmazonSQS.${action}` },
      body,
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      let answer: Response;
      let text: string;
      try {
        answer = await send(signed.url, { method: signed.method, headers: signed.headers, body, signal: controller.signal });
        // Decoded by hand: workerd warns on `.text()` for a body typed application/x-amz-json-1.0.
        text = new TextDecoder().decode(await answer.arrayBuffer());
      } catch {
        // Nothing answered: whether SQS saw the request is unknown, and both
        // calls are safe to repeat, so a retry is right.
        throw new SqsRequestFailed(action, 0, controller.signal.aborted ? "Timeout" : "NetworkError", true);
      }
      const parsed = parseJson(text);
      if (!answer.ok) throw new SqsRequestFailed(action, answer.status, errorCode(answer, parsed), retryable(answer.status, errorCode(answer, parsed)));
      if (parsed === undefined) throw new SqsRequestFailed(action, answer.status, "MalformedResponse", false);
      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    region,
    async receive({ max, waitSeconds }) {
      if (!Number.isInteger(max) || max < 1 || max > MAX_BATCH) throw new RangeError(`receive: max must be 1 to ${MAX_BATCH}`);
      if (!Number.isInteger(waitSeconds) || waitSeconds < 0 || waitSeconds > MAX_WAIT_SECONDS) {
        throw new RangeError(`receive: waitSeconds must be 0 to ${MAX_WAIT_SECONDS}`);
      }
      const answer = await call("ReceiveMessage", { MaxNumberOfMessages: max, WaitTimeSeconds: waitSeconds });
      // An empty queue answers no Messages member at all.
      if (answer.Messages === undefined) return [];
      if (!Array.isArray(answer.Messages)) throw new SqsRequestFailed("ReceiveMessage", 200, "MalformedResponse", false);
      return answer.Messages.map((m: unknown) => {
        const message = m as Record<string, unknown>;
        if (typeof message.MessageId !== "string" || typeof message.ReceiptHandle !== "string" || typeof message.Body !== "string") {
          throw new SqsRequestFailed("ReceiveMessage", 200, "MalformedResponse", false);
        }
        return { messageId: message.MessageId, receiptHandle: message.ReceiptHandle, body: message.Body };
      });
    },
    async deleteBatch(entries) {
      if (entries.length < 1 || entries.length > MAX_BATCH) throw new RangeError(`deleteBatch: 1 to ${MAX_BATCH} entries`);
      if (entries.some((e) => !BATCH_ID.test(e.id)) || new Set(entries.map((e) => e.id)).size !== entries.length) {
        throw new RangeError("deleteBatch: entry ids must be distinct and of the SQS batch id form");
      }
      const answer = await call("DeleteMessageBatch", { Entries: entries.map((e) => ({ Id: e.id, ReceiptHandle: e.receiptHandle })) });
      const successful = Array.isArray(answer.Successful) ? (answer.Successful as Record<string, unknown>[]) : [];
      const failed = Array.isArray(answer.Failed) ? (answer.Failed as Record<string, unknown>[]) : [];
      return {
        deleted: successful.map((s) => String(s.Id)),
        failed: failed.map((f) => ({ id: String(f.Id), code: typeof f.Code === "string" ? f.Code : "UnknownError", senderFault: f.SenderFault === true })),
      };
    },
  };
}

function retryable(status: number, code: string): boolean {
  return status === 429 || status >= 500 || THROTTLING.has(code);
}

/**
 * The error's code: `__type` in the body is `com.amazonaws.sqs#<Code>` (the
 * JSON protocol's shape); `x-amzn-query-error` carries the query protocol's
 * name with `;Sender` or `;Receiver` appended. The part after `#` (or the whole
 * value, when there is no `#`) is the code; nothing else of either is kept.
 */
function errorCode(answer: Response, body: Record<string, unknown> | undefined): string {
  const type = typeof body?.__type === "string" ? body.__type : (answer.headers.get("x-amzn-query-error")?.split(";")[0] ?? "");
  const code = type.slice(type.indexOf("#") + 1).trim();
  return /^[A-Za-z0-9_.-]{1,128}$/.test(code) ? code : "UnknownError";
}

function parseJson(text: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
  } catch {
    return undefined;
  }
}
