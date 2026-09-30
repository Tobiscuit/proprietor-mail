# @proprietor/mail-outbound

Turns a composed message into an RFC 5322 / MIME message (`buildMime`) and
sends it through Amazon SES API v2 `SendEmail` as raw content
(`sesRawMailer`). No bindings and no Node APIs: `fetch`, Web Crypto and
`TextEncoder` only, so the same code runs in a Worker and in Node.

```ts
const built = buildMime(msg, { messageIdDomain: "example.com" });
// built.raw: the exact bytes SES receives and the Sent copy seals
// built.recipients: to + cc + bcc, lower-cased, de-duplicated (the envelope)
const mailer = sesRawMailer({ accessKeyId, secretAccessKey, region: "us-east-1" });
const { providerMessageId } = await mailer.send({
  raw: built.raw,
  fromAddress: "hello@example.com",
  recipients: built.recipients,
  configurationSet: "send-example-mail",
  tenantName: "client-example", // omit until the SES tenant exists
});
```

From the repository root:

```
npm ci && npm test -w @proprietor/mail-outbound && npm run typecheck -w @proprietor/mail-outbound
```

## What the message looks like

| Input | Structure |
|---|---|
| text only | `text/plain` |
| text + html | `multipart/alternative` [text, html] |
| any attachment | `multipart/mixed` [body, attachment…] |
| inline attachment with a Content-ID, and html | the html becomes `multipart/related; type="text/html"` [html, inline…] |

- 7-bit ASCII and CRLF throughout; every line within 76 characters (998 at
  most, only for an address or id that cannot be broken).
- Bodies are quoted-printable, or base64 when that is shorter (mostly
  non-Latin text). Attachments are base64.
- Display names and subjects that are not short printable ASCII go out as
  RFC 2047 B-encoded words of whole characters; filenames as RFC 2231.
- No `Bcc` header, ever: bcc exists only in `recipients`.
- `Date` is UTC; `Message-ID` is `<32 hex chars @ messageIdDomain>` from
  `crypto.getRandomValues`.
- `InvalidMessage` (naming the field, never its value, because callers log
  it) for CR, LF or NUL in any header input, an address outside a strict
  ASCII addr-spec, a malformed id, media type or Content-ID, no recipients,
  more than `LIMITS.maxRecipients`, or more than `LIMITS.maxRawBytes`.

## SES facts this package rests on (checked 2026-09-26)

| Fact | Source |
|---|---|
| `POST https://email.{region}.amazonaws.com/v2/email/outbound-emails`, JSON; SigV4 signing name `ses` (the host prefix is `email`) | [API_SendEmail](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_SendEmail.html); SES v2 Smithy model (`aws.auth#sigv4 {name: "ses"}`, `endpointPrefix: "email"`, `aws.protocols#restJson1`) |
| Raw content is `"Content": {"Raw": {"Data": "<base64 of the whole message>"}}` | [API_RawMessage](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_RawMessage.html) ("needs to be base64-encoded if you are accessing Amazon SES directly through the HTTPS interface"); `RawMessageData` is a blob in the model |
| Only `Content` is required. `Destination` is optional; with raw content it is the SMTP envelope, and the headers come from the message | API_SendEmail; [send-email-raw](https://docs.aws.amazon.com/ses/latest/dg/send-email-raw.html): "the addresses you specify in the Source and Destinations parameters define the envelope sender and recipients" |
| `TenantName`: string, min length 1, "up to 64 alphanumeric characters … hyphens (-) and underscores (_)"; the send succeeds only if every referenced identity and configuration set is associated with the SES tenant | API_SendEmail; model `TenantName` |
| `EmailTags`: a list of `{ Name, Value }`, each "ASCII letters (a–z, A–Z), numbers (0–9), underscores (_), or dashes (-)", at most 256 characters; SES publishes them back as `mail.tags` in every event for the message (`tags` on `RawSendRequest`; checked 2026-09-29) | [API_MessageTag](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_MessageTag.html); [event contents](https://docs.aws.amazon.com/ses/latest/dg/event-publishing-retrieving-sns-contents.html) |
| Max message size: 40 MB after base64 for the v2 API (10 MB for v1); max 50 recipients across To, CC and BCC | [quotas](https://docs.aws.amazon.com/ses/latest/dg/quotas.html) |
| Lines at most 1,000 characters; local parts 7-bit ASCII only (no SMTPUTF8), IDN domains as punycode | API_RawMessage; [API_Destination](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_Destination.html) |
| Errors: the type is in `x-amzn-errortype` (else the body's `__type` or `code`), sanitized by dropping what follows `:` and what precedes `#`; the message is in the body's `message` | Smithy `aws-restjson1-protocol`, "Operation error serialization"; a fake-key call to the real endpoint answered `403`, `x-amzn-errortype: UnrecognizedClientException`, `{"message": "…"}` |
| Throttling is `TooManyRequestsException` (429) and `ThrottlingException` (400, for "Maximum sending rate exceeded" and "Daily message quota exceeded"); `InternalFailure` 500 and `ServiceUnavailable` 503. No SES v2 error carries Smithy's `@retryable` trait | API_SendEmail "Errors"; [CommonErrors](https://docs.aws.amazon.com/ses/latest/APIReference-V2/CommonErrors.html); [manage-sending-quotas-errors](https://docs.aws.amazon.com/ses/latest/dg/manage-sending-quotas-errors.html) |
| **SES overwrites `Message-ID` and `Date`** on every message it accepts | [header-fields](https://docs.aws.amazon.com/ses/latest/dg/header-fields.html): "If you provide a Message-ID header, Amazon SES overrides the header with its own value" |

## IAM for the client-mail principal (for the infrastructure step)

**A raw send through the v2 API needs `ses:SendEmail` only.** The
[Service Authorization Reference for SES v2](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sesv2.html)
has a `SendEmail` action with resource types `identity` (required),
`configuration-set` and `template`, and condition keys that include
`ses:FromAddress`, `ses:Recipients`, `ses:TenantName` and `ses:ApiVersion`.
It has no `SendRawEmail` action: `ses:SendRawEmail` belongs to the v1 API and
to the SMTP interface ("The SES SMTP interface uses SES API version 2 of
ses:SendRawEmail",
[control-user-access](https://docs.aws.amazon.com/ses/latest/dg/control-user-access.html)).

Two consequences for the policy sketched in `plan.md` §6:

- `ses:SendRawEmail` can be dropped (this package never uses SMTP).
- An SES tenant is not one of `SendEmail`'s resource types, so
  `arn:aws:ses:…:tenant/*` in `Resource` neither grants nor restricts
  anything for this action. An SES tenant's ARN is
  `arn:${Partition}:ses:${Region}:${Account}:tenant/${TenantName}/${TenantId}`;
  to pin the SES tenant, use the condition key. `StringEquals` on a key the request
  does not carry fails closed, so add `ses:TenantName` together with the
  SES tenant, when sends start carrying `TenantName`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "SendOnlyAsClientMailboxes",
    "Effect": "Allow",
    "Action": "ses:SendEmail",
    "Resource": [
      "arn:aws:ses:us-east-1:123456789012:identity/example.com",
      "arn:aws:ses:us-east-1:123456789012:configuration-set/send-example-mail"
    ],
    "Condition": {
      "StringEquals": {
        "ses:FromAddress": "hello@example.com",
        "ses:TenantName": "client-example",
        "ses:ApiVersion": "2"
      }
    }
  }]
}
```

Check it in the IAM policy simulator before attaching it, as `plan.md` §6
says. Not verified from the docs: whether `ses:FromAddress` is read from
`FromEmailAddress` or from the raw message's `From` header. This package
makes the question moot: `fromAddress` is, by contract, the `From` header's
address.

## Decisions a reviewer should check

- **Destination is `{ BccAddresses: recipients }`.** With raw content the
  split into To/Cc/Bcc is meaningless (SES documents `Destination` as the
  envelope), so every recipient goes in the one field that could never be
  turned into a visible header, even by a future SES change.
- **No automatic retries, and no fallback without the configuration set.**
  aws4fetch's `fetch` retries 5xx and 429 up to 10 times; this package signs
  with it and sends once. A retry after a 5xx or a timeout can deliver twice,
  and the caller holds the idempotency key (M7). A contact form's sender
  may drop the configuration set on failure so that a visitor's enquiry is
  not lost; here the configuration set carries the SES tenant's
  suppression list and Mail's own event feed, and the sender is a person who
  sees the error, so a failure stays a failure.
- **`retryable` is true only for throttling and 5xx.** A timeout
  (`code: "Timeout"`) and a network failure (`"NetworkError"`) have
  `status: 0` and are not retryable: SES may already have accepted the
  message. A 2xx without a `MessageId` is `"MalformedResponse"`, not
  retryable, for the same reason. The default timeout is 15 s (`timeoutMs`).
- **Error messages keep SES's explanation but replace addresses with
  `[address]`**, since they end up in logs and logs carry no addresses (D8).

## For the Worker (S2)

- `BuiltMessage.messageId` is the Message-ID the **Sent copy** carries. SES
  replaces it on the wire, so recipients see SES's id, and their replies
  thread on that id (`In-Reply-To`). Store `providerMessageId` with the
  sent message to thread replies. Not verified: the domain SES puts after the
  `@` outside us-east-1 (the docs' us-east-1 example is
  `<{MessageId}@email.amazonses.com>`).
- postal-mime 3.0.1 reads a quoted-printable text part inside a multipart
  with one extra trailing `"\n"`: it keeps the CRLF that RFC 2046 §5.1.1
  attaches to the next delimiter. Python's `email` parser reads the same
  bytes exactly. Harmless when displaying; worth knowing before comparing
  text.

## Tests

| File | What |
|---|---|
| `test/encoding.test.ts` | codecs: RFC 4648 vectors, RFC 2045 QP rules, RFC 2047 words, RFC 2231, folding, date |
| `test/mime.golden.test.ts` | byte-for-byte golden files for the three shapes; the goldens were written line by line, independently of the builder |
| `test/mime.roundtrip.test.ts` | every message parses back through postal-mime to the same fields: the goldens, awkward cases, 300 generated messages |
| `test/mime.rules.test.ts` | CRLF, 7-bit, line lengths, no Bcc, recipients, limits, header injection, malformed input |
| `test/ses.test.ts` | the signed request against the API reference, with SigV4 recomputed independently; error mapping; timeout; validation before sending |
| `test/runtime.test.ts` | no Node built-ins in `src/`; exact version pins |
| `test/ses.live.test.ts` | live, **mailbox simulator only**; skipped unless the variables below are set |

The live test sends each shape to `success@simulator.amazonses.com` and one
message each to the bounce and complaint simulators, and refuses in code any
recipient outside `@simulator.amazonses.com`. It needs
`SES_TEST_ACCESS_KEY_ID`, `SES_TEST_SECRET_ACCESS_KEY`, `SES_TEST_FROM` and
`SES_TEST_CONFIGURATION_SET` (optional: `SES_TEST_SESSION_TOKEN`,
`SES_TEST_REGION`, `SES_TEST_TENANT`), put into the environment of the one
command from your secret store. Run it only with a principal that sends
client mail, never with a credential whose SES events feed another
application's data.
