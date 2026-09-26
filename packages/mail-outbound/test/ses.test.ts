import { Buffer } from "node:buffer";
import { createHash, createHmac } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  InvalidMessage,
  LIMITS,
  SendRejected,
  buildMime,
  sesRawMailer,
  type RawSendRequest,
  type SesCredentials,
} from "../src/index";
import { MIXED, goldenOptions } from "./fixtures";

/*
 * What the request must look like, from the SES API v2 reference
 * (https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html,
 * checked 2026-09-26) and the service's Smithy model
 * (github.com/aws/api-models-aws, models/sesv2/service/2019-09-27):
 *   - POST /v2/email/outbound-emails on the "email" endpoint prefix,
 *     Content-type: application/json, protocol aws.protocols#restJson1;
 *   - SigV4 with signing name "ses" (aws.auth#sigv4 { name: "ses" });
 *   - Content.Raw.Data is a blob, which restJson1 carries as a base64 string
 *     (API_RawMessage: "needs to be base64-encoded if you are accessing Amazon
 *     SES directly through the HTTPS interface");
 *   - FromEmailAddress, Destination, ConfigurationSetName and TenantName are
 *     top-level members; only Content is required.
 */

const CREDS: SesCredentials = {
  accessKeyId: "AKIDEXAMPLE",
  secretAccessKey: "test-secret-not-a-real-key", // pragma: allowlist secret (fake)
  region: "us-east-1",
};

function sesAnswer(status: number, body: unknown, headers: Record<string, string> = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return new Response(text, { status, headers: { "content-type": "application/json", ...headers } });
}

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

function request(overrides: Partial<RawSendRequest> = {}): RawSendRequest {
  const built = buildMime(MIXED, goldenOptions());
  return {
    raw: built.raw,
    fromAddress: "hello@operator.example",
    recipients: [...built.recipients, "bcc-only@example.com"],
    configurationSet: "send-operator-mail",
    tenantName: "client-operator",
    ...overrides,
  };
}

/** SigV4, written out from the AWS General Reference, independent of aws4fetch. */
function expectedAuthorization(creds: SesCredentials, amzDate: string, body: string, signed: [string, string][]) {
  const sha256 = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
  const hmac = (key: Buffer | string, s: string) => createHmac("sha256", key).update(s, "utf8").digest();
  const date = amzDate.slice(0, 8);
  const headers = [...signed].sort(([a], [b]) => (a < b ? -1 : 1));
  const canonicalRequest = [
    "POST",
    "/v2/email/outbound-emails",
    "",
    headers.map(([k, v]) => `${k}:${v}\n`).join(""),
    headers.map(([k]) => k).join(";"),
    sha256(body),
  ].join("\n");
  const scope = `${date}/${creds.region}/ses/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
  let key: Buffer = hmac(`AWS4${creds.secretAccessKey}`, date);
  for (const part of [creds.region, "ses", "aws4_request"]) key = hmac(key, part);
  const signature = createHmac("sha256", key).update(stringToSign, "utf8").digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${headers.map(([k]) => k).join(";")}, Signature=${signature}`;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sesRawMailer: the signed request", () => {
  it("is exactly the documented SendEmail call with raw content", async () => {
    const { impl, calls } = fakeFetch(() => sesAnswer(200, { MessageId: "0100019a-example-000000" }));
    const req = request();
    const result = await sesRawMailer(CREDS, { fetch: impl }).send(req);

    expect(result).toEqual({ providerMessageId: "0100019a-example-000000" });
    expect(calls).toHaveLength(1);
    const { request: sent, init, body } = calls[0]!;
    expect(sent.method).toBe("POST");
    expect(sent.url).toBe("https://email.us-east-1.amazonaws.com/v2/email/outbound-emails");
    expect(sent.headers.get("content-type")).toBe("application/json");
    expect(init?.signal).toBeInstanceOf(AbortSignal);

    expect(JSON.parse(body)).toEqual({
      FromEmailAddress: "hello@operator.example",
      // with raw content the Destination is the SMTP envelope only; SES takes
      // the headers from the message (see the README for why BccAddresses)
      Destination: { BccAddresses: req.recipients },
      Content: { Raw: { Data: Buffer.from(req.raw).toString("base64") } },
      ConfigurationSetName: "send-operator-mail",
      TenantName: "client-operator",
    });

    const amzDate = sent.headers.get("x-amz-date")!;
    expect(amzDate).toMatch(/^\d{8}T\d{6}Z$/);
    expect(Math.abs(Date.parse(amzDate.replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, "$1-$2-$3T$4:$5:$6Z")) - Date.now())).toBeLessThan(60_000);
    expect(sent.headers.get("authorization")).toBe(
      expectedAuthorization(CREDS, amzDate, body, [
        ["host", "email.us-east-1.amazonaws.com"],
        ["x-amz-date", amzDate],
      ]),
    );
    expect(sent.headers.has("x-amz-security-token")).toBe(false);
  });

  it("signs the session token of temporary credentials", async () => {
    const creds = { ...CREDS, region: "eu-west-2", sessionToken: "test-session-token" }; // pragma: allowlist secret (fake)
    const { impl, calls } = fakeFetch(() => sesAnswer(200, { MessageId: "m" }));
    await sesRawMailer(creds, { fetch: impl }).send(request());
    const { request: sent, body } = calls[0]!;
    expect(sent.url).toBe("https://email.eu-west-2.amazonaws.com/v2/email/outbound-emails");
    expect(sent.headers.get("x-amz-security-token")).toBe("test-session-token");
    const amzDate = sent.headers.get("x-amz-date")!;
    expect(sent.headers.get("authorization")).toBe(
      expectedAuthorization(creds, amzDate, body, [
        ["host", "email.eu-west-2.amazonaws.com"],
        ["x-amz-date", amzDate],
        ["x-amz-security-token", "test-session-token"],
      ]),
    );
  });

  it("leaves TenantName out until the tenant exists", async () => {
    const { impl, calls } = fakeFetch(() => sesAnswer(200, { MessageId: "m" }));
    const { tenantName: _omit, ...withoutTenant } = request();
    await sesRawMailer(CREDS, { fetch: impl }).send(withoutTenant);
    expect(JSON.parse(calls[0]!.body)).not.toHaveProperty("TenantName");
  });

  it("uses the global fetch when none is injected", async () => {
    const { impl, calls } = fakeFetch(() => sesAnswer(200, { MessageId: "global" }));
    vi.stubGlobal("fetch", impl);
    await expect(sesRawMailer(CREDS).send(request())).resolves.toEqual({ providerMessageId: "global" });
    expect(calls).toHaveLength(1);
  });

  it("does not retry on its own: one failed call is one request", async () => {
    const { impl, calls } = fakeFetch(() => sesAnswer(503, { message: "try later" }, { "x-amzn-errortype": "ServiceUnavailable" }));
    await expect(sesRawMailer(CREDS, { fetch: impl }).send(request())).rejects.toBeInstanceOf(SendRejected);
    expect(calls).toHaveLength(1);
  });
});

describe("sesRawMailer: failures", () => {
  async function rejection(response: () => Response | Promise<Response>): Promise<SendRejected> {
    const { impl } = fakeFetch(response);
    const err = await sesRawMailer(CREDS, { fetch: impl }).send(request()).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(SendRejected);
    return err as SendRejected;
  }

  // restJson1: the error type comes from X-Amzn-Errortype, else the body's
  // __type, else its code, sanitized by dropping anything after ':' and before
  // '#' (Smithy, aws-restjson1-protocol "Operation error serialization").
  // Codes and statuses: API_SendEmail "Errors" and CommonErrors; throttling is
  // TooManyRequestsException (429) and ThrottlingException (400) —
  // "exceeding sending limits results in a ThrottlingException error"
  // (SES developer guide, manage-sending-quotas-errors).
  it.each([
    [429, { "x-amzn-errortype": "TooManyRequestsException:http://internal.amazon.com/coral/com.amazonaws.sesv2/" }, { message: "Too many requests" }, "TooManyRequestsException", true],
    [400, { "x-amzn-errortype": "ThrottlingException" }, { message: "Maximum sending rate exceeded." }, "ThrottlingException", true],
    [400, {}, { __type: "com.amazonaws.sesv2#ThrottlingException", message: "Daily message quota exceeded." }, "ThrottlingException", true],
    [500, { "x-amzn-errortype": "InternalFailure" }, { message: "internal" }, "InternalFailure", true],
    [503, {}, "<html>Service Unavailable</html>", "UnknownError", true],
    [400, { "x-amzn-errortype": "MessageRejected" }, { message: "Email address is not verified." }, "MessageRejected", false],
    [400, {}, { code: "AccountSuspendedException", message: "suspended" }, "AccountSuspendedException", false],
    [400, { "x-amzn-errortype": "SendingPausedException" }, { message: "paused" }, "SendingPausedException", false],
    [400, { "x-amzn-errortype": "MailFromDomainNotVerifiedException" }, {}, "MailFromDomainNotVerifiedException", false],
    [400, { "x-amzn-errortype": "BadRequestException" }, { message: "bad" }, "BadRequestException", false],
    [403, { "x-amzn-errortype": "AccessDeniedException" }, { Message: "not authorized" }, "AccessDeniedException", false],
    [404, { "x-amzn-errortype": "NotFoundException" }, { message: "no such configuration set" }, "NotFoundException", false],
  ] as const)("HTTP %i %j → %s", async (status, headers, body, code, retryable) => {
    const err = await rejection(() => sesAnswer(status, body, headers));
    expect(err.status).toBe(status);
    expect(err.code).toBe(code);
    expect(err.retryable).toBe(retryable);
    expect(err.name).toBe("SendRejected");
  });

  it("keeps SES's explanation but never the addresses in it", async () => {
    const err = await rejection(() =>
      sesAnswer(
        400,
        { message: "Email address is not verified. The following identities failed the check in region US-EAST-1: ana@example.com, Hello@Operator.dev" },
        { "x-amzn-errortype": "MessageRejected" },
      ),
    );
    expect(err.message).toContain("MessageRejected");
    expect(err.message).toContain("Email address is not verified.");
    expect(err.message).not.toMatch(/ana@example\.com|operator\.dev/i);
  });

  it("treats a 200 without a MessageId as a failure nobody should retry", async () => {
    const err = await rejection(() => sesAnswer(200, {}));
    expect(err.code).toBe("MalformedResponse");
    expect(err.retryable).toBe(false);
  });

  it("gives up after timeoutMs and does not call it retryable (SES may have accepted it)", async () => {
    const hanging = (async (_input: RequestInfo | URL, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason));
      })) as typeof fetch;
    const started = Date.now();
    const err = await sesRawMailer(CREDS, { fetch: hanging, timeoutMs: 50 }).send(request()).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SendRejected);
    expect(err).toMatchObject({ status: 0, code: "Timeout", retryable: false });
    expect(Date.now() - started).toBeLessThan(5000);
  });

  it("reports a network failure as not retryable", async () => {
    const broken = (async () => {
      throw new TypeError("fetch failed");
    }) as typeof fetch;
    const err = await sesRawMailer(CREDS, { fetch: broken }).send(request()).catch((e: unknown) => e);
    expect(err).toMatchObject({ name: "SendRejected", status: 0, code: "NetworkError", retryable: false });
  });
});

describe("sesRawMailer: refuses before calling SES", () => {
  const many = (n: number) => Array.from({ length: n }, (_, i) => `r${i}@example.com`);

  it.each([
    ["no recipients", { recipients: [] }],
    ["too many recipients", { recipients: many(LIMITS.maxRecipients + 1) }],
    ["an invalid recipient", { recipients: ["ana@example.com\r\nX: y"] }],
    ["an invalid from address", { fromAddress: "Mailbox <hello@operator.example>" }],
    ["an empty message", { raw: new Uint8Array(0) }],
    ["an oversized message", { raw: new Uint8Array(LIMITS.maxRawBytes + 1) }],
    ["no configuration set", { configurationSet: "" }],
    ["an invalid tenant name", { tenantName: "client operator" }],
  ] as const)("%s", async (_what, overrides) => {
    const { impl, calls } = fakeFetch(() => sesAnswer(200, { MessageId: "m" }));
    await expect(sesRawMailer(CREDS, { fetch: impl }).send(request(overrides as Partial<RawSendRequest>))).rejects.toBeInstanceOf(
      InvalidMessage,
    );
    expect(calls).toHaveLength(0);
  });

  it("refuses a region that is not a region", () => {
    expect(() => sesRawMailer({ ...CREDS, region: "us-east-1.evil.example" })).toThrow(TypeError);
  });
});

describe("LIMITS against SES's own quotas", () => {
  // https://docs.aws.amazon.com/ses/latest/dg/quotas.html (checked 2026-09-26):
  // "Using the SES v2 API or SMTP - Maximum message size (including
  // attachments): 40 MB per message (after base64 encoding)" and "Maximum
  // number of recipients per message: 50".
  it("keeps the raw size under 40 MB after base64, read as the smaller decimal megabytes", () => {
    const base64Bytes = Math.ceil(LIMITS.maxRawBytes / 3) * 4;
    expect(base64Bytes).toBe(13_981_016);
    expect(base64Bytes).toBeLessThanOrEqual(40 * 1000 * 1000);
  });

  it("allows no more recipients than SES does", () => {
    expect(LIMITS.maxRecipients).toBeLessThanOrEqual(50);
  });

  it("sends the largest message buildMime allows as one request body SES accepts", async () => {
    const { impl, calls } = fakeFetch(() => sesAnswer(200, { MessageId: "m" }));
    const raw = new Uint8Array(LIMITS.maxRawBytes).fill(0x41);
    await sesRawMailer(CREDS, { fetch: impl }).send(request({ raw }));
    const data = (JSON.parse(calls[0]!.body) as { Content: { Raw: { Data: string } } }).Content.Raw.Data;
    expect(data.length).toBe(13_981_016);
  });
});
