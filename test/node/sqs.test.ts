import { Buffer } from "node:buffer";
import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SqsRequestFailed, sqsQueueClient } from "../../src/deliverability/sqs";

/*
 * What the requests must look like, from the SQS API reference (ReceiveMessage,
 * DeleteMessageBatch; checked 2026-09-29): the AWS JSON protocol is a POST to
 * `/` on `sqs.<region>.amazonaws.com` with `X-Amz-Target: AmazonSQS.<Action>`,
 * `Content-Type: application/x-amz-json-1.0`, the QueueUrl inside the body,
 * SigV4 with signing name `sqs`. An error answers `{ "__type": "com.amazonaws.sqs#<Code>",
 * "message": … }` with an `x-amzn-query-error` header; DeleteMessageBatch
 * answers HTTP 200 with `Failed` entries for a partial failure.
 */

const QUEUE_URL = "https://sqs.us-east-1.amazonaws.com/123456789012/example-mail-events";
const CREDS = {
  queueUrl: QUEUE_URL,
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "test-secret-not-a-real-key", // pragma: allowlist secret (fake)
};

type Captured = { request: Request; init: RequestInit | undefined; body: string };

function fakeFetch(answer: () => Response | Promise<Response>) {
  const calls: Captured[] = [];
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    calls.push({ request, init, body: await request.clone().text() });
    return answer();
  }) as typeof fetch;
  return { impl, calls };
}

const sqsAnswer = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/x-amz-json-1.0", ...headers } });

/** SigV4, written out from the AWS General Reference, independent of aws4fetch. */
function expectedAuthorization(creds: { accessKeyId: string; secretAccessKey: string }, region: string, amzDate: string, body: string, signed: [string, string][]) {
  const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
  const hmac = (key: Buffer | string, s: string) => createHmac("sha256", key).update(s, "utf8").digest();
  const date = amzDate.slice(0, 8);
  const headers = [...signed].sort(([a], [b]) => (a < b ? -1 : 1));
  const canonicalRequest = ["POST", "/", "", headers.map(([k, v]) => `${k}:${v}\n`).join(""), headers.map(([k]) => k).join(";"), sha256(body)].join("\n");
  const scope = `${date}/${region}/sqs/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
  let key: Buffer = hmac(`AWS4${creds.secretAccessKey}`, date);
  for (const part of [region, "sqs", "aws4_request"]) key = hmac(key, part);
  const signature = createHmac("sha256", key).update(stringToSign, "utf8").digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${headers.map(([k]) => k).join(";")}, Signature=${signature}`;
}

describe("sqsQueueClient: the signed requests", () => {
  it("ReceiveMessage is the documented JSON-protocol call, SigV4-signed for sqs in the queue's region", async () => {
    const { impl, calls } = fakeFetch(() =>
      sqsAnswer(200, {
        Messages: [
          { MessageId: "219f8380-5770-4cc2-8c3e-5c715e145f5e", ReceiptHandle: "AQEB-example", MD5OfBody: "fafb00f5732ab283681e124bf8747ed1", Body: '{"eventType":"Bounce"}' },
        ],
      }),
    );
    const client = sqsQueueClient(CREDS, { fetch: impl });
    expect(client.region).toBe("us-east-1");
    const messages = await client.receive({ max: 10, waitSeconds: 2 });
    expect(messages).toEqual([{ messageId: "219f8380-5770-4cc2-8c3e-5c715e145f5e", receiptHandle: "AQEB-example", body: '{"eventType":"Bounce"}' }]);

    expect(calls).toHaveLength(1);
    const { request, init, body } = calls[0]!;
    expect(request.method).toBe("POST");
    expect(request.url).toBe("https://sqs.us-east-1.amazonaws.com/");
    expect(request.headers.get("content-type")).toBe("application/x-amz-json-1.0");
    expect(request.headers.get("x-amz-target")).toBe("AmazonSQS.ReceiveMessage");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(body)).toEqual({ QueueUrl: QUEUE_URL, MaxNumberOfMessages: 10, WaitTimeSeconds: 2 });

    const amzDate = request.headers.get("x-amz-date")!;
    expect(amzDate).toMatch(/^\d{8}T\d{6}Z$/);
    expect(request.headers.get("authorization")).toBe(
      expectedAuthorization(CREDS, "us-east-1", amzDate, body, [
        ["host", "sqs.us-east-1.amazonaws.com"],
        ["x-amz-date", amzDate],
        ["x-amz-target", "AmazonSQS.ReceiveMessage"],
      ]),
    );
    expect(request.headers.has("x-amz-security-token")).toBe(false);
  });

  it("DeleteMessageBatch carries the entries by id and receipt handle, and reports each outcome", async () => {
    const { impl, calls } = fakeFetch(() =>
      sqsAnswer(200, {
        Successful: [{ Id: "m1" }],
        Failed: [{ Id: "m2", Code: "InternalError", Message: "An internal error occurred.", SenderFault: false }],
      }),
    );
    const client = sqsQueueClient(CREDS, { fetch: impl });
    const outcome = await client.deleteBatch([
      { id: "m1", receiptHandle: "AQEB-one" },
      { id: "m2", receiptHandle: "AQEB-two" },
    ]);
    expect(outcome).toEqual({ deleted: ["m1"], failed: [{ id: "m2", code: "InternalError", senderFault: false }] });
    const { request, body } = calls[0]!;
    expect(request.headers.get("x-amz-target")).toBe("AmazonSQS.DeleteMessageBatch");
    expect(JSON.parse(body)).toEqual({
      QueueUrl: QUEUE_URL,
      Entries: [
        { Id: "m1", ReceiptHandle: "AQEB-one" },
        { Id: "m2", ReceiptHandle: "AQEB-two" },
      ],
    });
    const amzDate = request.headers.get("x-amz-date")!;
    expect(request.headers.get("authorization")).toBe(
      expectedAuthorization(CREDS, "us-east-1", amzDate, body, [
        ["host", "sqs.us-east-1.amazonaws.com"],
        ["x-amz-date", amzDate],
        ["x-amz-target", "AmazonSQS.DeleteMessageBatch"],
      ]),
    );
  });

  it("signs the session token of temporary credentials, and takes the region from the queue URL", async () => {
    const creds = { ...CREDS, queueUrl: "https://sqs.eu-west-2.amazonaws.com/123456789012/example-mail-events", sessionToken: "test-session-token" }; // pragma: allowlist secret (fake)
    const { impl, calls } = fakeFetch(() => sqsAnswer(200, {}));
    await sqsQueueClient(creds, { fetch: impl }).receive({ max: 1, waitSeconds: 0 });
    const { request, body } = calls[0]!;
    expect(request.url).toBe("https://sqs.eu-west-2.amazonaws.com/");
    expect(request.headers.get("x-amz-security-token")).toBe("test-session-token");
    const amzDate = request.headers.get("x-amz-date")!;
    expect(request.headers.get("authorization")).toBe(
      expectedAuthorization(creds, "eu-west-2", amzDate, body, [
        ["host", "sqs.eu-west-2.amazonaws.com"],
        ["x-amz-date", amzDate],
        ["x-amz-security-token", "test-session-token"],
        ["x-amz-target", "AmazonSQS.ReceiveMessage"],
      ]),
    );
  });

  it("an empty queue answers no Messages member: that is an empty list, not an error", async () => {
    const { impl } = fakeFetch(() => sqsAnswer(200, {}));
    expect(await sqsQueueClient(CREDS, { fetch: impl }).receive({ max: 10, waitSeconds: 2 })).toEqual([]);
  });

  it("refuses a queue URL that is not an SQS queue URL, before any request", () => {
    for (const queueUrl of [
      "https://example.com/123456789012/queue",
      "http://sqs.us-east-1.amazonaws.com/123456789012/queue",
      "https://sqs.us-east-1.amazonaws.com/queue",
      "https://sqs.us-east-1.amazonaws.com/123456789012/",
      "",
    ]) {
      expect(() => sqsQueueClient({ ...CREDS, queueUrl })).toThrow(TypeError);
    }
  });

  it("refuses more than ten entries, or none, before any request (the SQS batch limit)", async () => {
    const { impl, calls } = fakeFetch(() => sqsAnswer(200, {}));
    const client = sqsQueueClient(CREDS, { fetch: impl });
    await expect(client.deleteBatch([])).rejects.toThrow(RangeError);
    await expect(client.deleteBatch(Array.from({ length: 11 }, (_, i) => ({ id: `m${i}`, receiptHandle: "h" })))).rejects.toThrow(RangeError);
    await expect(client.receive({ max: 11, waitSeconds: 0 })).rejects.toThrow(RangeError);
    await expect(client.receive({ max: 1, waitSeconds: 21 })).rejects.toThrow(RangeError);
    expect(calls).toEqual([]);
  });
});

describe("sqsQueueClient: when SQS says no", () => {
  it("an SQS error becomes SqsRequestFailed with the status and the code from __type, and no text from the answer", async () => {
    const { impl } = fakeFetch(() =>
      sqsAnswer(
        400,
        { __type: "com.amazonaws.sqs#QueueDoesNotExist", message: "The specified queue does not exist for this wsdl version." },
        { "x-amzn-query-error": "AWS.SimpleQueueService.NonExistentQueue;Sender" },
      ),
    );
    const err = await sqsQueueClient(CREDS, { fetch: impl })
      .receive({ max: 10, waitSeconds: 2 })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SqsRequestFailed);
    expect(err).toMatchObject({ name: "SqsRequestFailed", status: 400, code: "QueueDoesNotExist", retryable: false });
    expect((err as Error).message).not.toContain("wsdl");
    expect((err as Error).message).not.toContain("123456789012");
  });

  it("throttling and 5xx are retryable; a network failure or timeout is status 0", async () => {
    const throttled = fakeFetch(() => sqsAnswer(400, { __type: "com.amazonaws.sqs#RequestThrottled", message: "slow down" }));
    await expect(sqsQueueClient(CREDS, { fetch: throttled.impl }).receive({ max: 1, waitSeconds: 0 })).rejects.toMatchObject({ code: "RequestThrottled", retryable: true });

    const down = fakeFetch(() => new Response("<html>bad gateway</html>", { status: 502 }));
    await expect(sqsQueueClient(CREDS, { fetch: down.impl }).receive({ max: 1, waitSeconds: 0 })).rejects.toMatchObject({ status: 502, code: "UnknownError", retryable: true });

    const unreachable = (async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch;
    await expect(sqsQueueClient(CREDS, { fetch: unreachable }).receive({ max: 1, waitSeconds: 0 })).rejects.toMatchObject({ status: 0, code: "NetworkError", retryable: true });

    const slow = ((_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      })) as typeof fetch;
    await expect(sqsQueueClient(CREDS, { fetch: slow, timeoutMs: 20 }).receive({ max: 1, waitSeconds: 0 })).rejects.toMatchObject({ status: 0, code: "Timeout", retryable: true });
  });

  it("a 200 that is not the documented shape is a failure, not an empty queue", async () => {
    const { impl } = fakeFetch(() => new Response("not json", { status: 200 }));
    await expect(sqsQueueClient(CREDS, { fetch: impl }).receive({ max: 1, waitSeconds: 0 })).rejects.toMatchObject({ status: 200, code: "MalformedResponse" });
    const odd = fakeFetch(() => sqsAnswer(200, { Messages: [{ MessageId: "x" }] }));
    await expect(sqsQueueClient(CREDS, { fetch: odd.impl }).receive({ max: 1, waitSeconds: 0 })).rejects.toMatchObject({ status: 200, code: "MalformedResponse" });
  });
});
