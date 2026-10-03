/**
 * SES event records as SES publishes them to SNS (raw delivery puts the record
 * itself in the SQS message body): the documented shapes from "Contents of
 * event data that Amazon SES publishes to Amazon SNS" and its examples page
 * (checked 2026-09-29), with example.com addresses and AWS's placeholder
 * account 123456789012.
 *
 * Every record carries the `mail` object with `commonHeaders` and
 * `destination` — the content the feed must never store or log — and the
 * `mailbox` message tag that Mail puts on every send (plan.md §13, G22).
 */

export interface EventOptions {
  /** The `mailbox` tag's value; `null` leaves the tag out (an unroutable event). */
  mailboxId: string | null;
  recipients?: string[];
  /** The mail object's timestamp; the event's own timestamp is one minute later unless given. */
  sentAt?: string;
  at?: string;
  subject?: string;
  from?: string;
  configurationSet?: string;
}

const SENT_AT = "2026-09-29T10:00:00.000Z";
const AT = "2026-09-29T10:01:00.000Z";

function mailObject(o: EventOptions) {
  const recipients = o.recipients ?? ["recipient@example.com"];
  const from = o.from ?? "hello@example.com";
  const subject = o.subject ?? "Your quote";
  return {
    timestamp: o.sentAt ?? SENT_AT,
    source: from,
    sourceArn: "arn:aws:ses:us-east-1:123456789012:identity/example.com",
    sendingAccountId: "123456789012",
    messageId: "0100019a0b1c2d3e-4f5a6b7c-8d9e-4f0a-b1c2-d3e4f5a6b7c8-000000",
    destination: recipients,
    headersTruncated: false,
    headers: [
      { name: "From", value: from },
      { name: "To", value: recipients.join(", ") },
      { name: "Subject", value: subject },
      { name: "MIME-Version", value: "1.0" },
      { name: "Content-Type", value: 'multipart/alternative; boundary="----=_Part_example"' },
    ],
    commonHeaders: {
      from: [from],
      to: recipients,
      messageId: "0100019a0b1c2d3e-4f5a6b7c-8d9e-4f0a-b1c2-d3e4f5a6b7c8-000000",
      subject,
    },
    tags: {
      "ses:configuration-set": [o.configurationSet ?? "send-example-mail"],
      "ses:source-ip": ["192.0.2.0"],
      "ses:from-domain": ["example.com"],
      "ses:caller-identity": ["send-example-mail"],
      ...(o.mailboxId === null ? {} : { mailbox: [o.mailboxId] }),
    },
  };
}

export function bounceEvent(o: EventOptions & { bounceType?: "Permanent" | "Transient" | "Undetermined"; bounceSubType?: string }) {
  const recipients = o.recipients ?? ["recipient@example.com"];
  const bounceType = o.bounceType ?? "Permanent";
  return {
    eventType: "Bounce",
    bounce: {
      bounceType,
      bounceSubType: o.bounceSubType ?? (bounceType === "Permanent" ? "General" : bounceType === "Transient" ? "MailboxFull" : "Undetermined"),
      bouncedRecipients: recipients.map((emailAddress) => ({
        emailAddress,
        action: "failed",
        status: bounceType === "Permanent" ? "5.1.1" : "4.2.2",
        diagnosticCode: bounceType === "Permanent" ? "smtp; 550 5.1.1 user unknown" : "smtp; 452 4.2.2 mailbox full",
      })),
      timestamp: o.at ?? AT,
      feedbackId: "0100019a0b1c2d3e-feedback-bounce-example-000000",
      reportingMTA: "dsn; mta.example.net",
    },
    mail: mailObject(o),
  };
}

export function complaintEvent(o: EventOptions & { complaintFeedbackType?: string }) {
  const recipients = o.recipients ?? ["recipient@example.com"];
  return {
    eventType: "Complaint",
    complaint: {
      complainedRecipients: recipients.map((emailAddress) => ({ emailAddress })),
      timestamp: o.at ?? AT,
      feedbackId: "0100019a0b1c2d3e-feedback-complaint-example-000000",
      userAgent: "ExampleCorp Feedback Loop (V0.01)",
      complaintFeedbackType: o.complaintFeedbackType ?? "abuse",
      arrivalDate: o.at ?? AT,
    },
    mail: mailObject(o),
  };
}

export function deliveryDelayEvent(o: EventOptions) {
  const recipients = o.recipients ?? ["recipient@example.com"];
  return {
    eventType: "DeliveryDelay",
    mail: mailObject(o),
    deliveryDelay: {
      timestamp: o.at ?? AT,
      delayType: "TransientCommunicationFailure",
      expirationTime: "2026-09-30T10:01:00.000Z",
      delayedRecipients: recipients.map((emailAddress) => ({
        emailAddress,
        status: "4.4.1",
        diagnosticCode: "smtp; 421 4.4.1 Unable to connect to remote host",
      })),
    },
  };
}

export function rejectEvent(o: EventOptions) {
  return { eventType: "Reject", mail: mailObject(o), reject: { reason: "Bad content" } };
}

export function renderingFailureEvent(o: EventOptions) {
  return {
    eventType: "Rendering Failure",
    mail: mailObject(o),
    failure: { errorMessage: "Attribute 'attributeName' is not present in the rendering data.", templateName: "MyTemplate" },
  };
}

/** An event type Mail does not subscribe to (plan.md §13); if one arrives, it changes nothing and is discarded. */
export function deliveryEvent(o: EventOptions) {
  const recipients = o.recipients ?? ["recipient@example.com"];
  return {
    eventType: "Delivery",
    mail: mailObject(o),
    delivery: {
      timestamp: o.at ?? AT,
      processingTimeMillis: 11893,
      recipients,
      smtpResponse: "250 2.6.0 Message received",
      remoteMtaIp: "192.0.2.1",
      reportingMTA: "a8-70.smtp-out.amazonses.com",
    },
  };
}

/** The SNS envelope a subscription WITHOUT raw message delivery would wrap the record in. */
export function snsEnvelope(record: unknown) {
  return {
    Type: "Notification",
    MessageId: "22b80b92-fdea-4c2c-8f9d-bdfb0c7bf324",
    TopicArn: "arn:aws:sns:us-east-1:123456789012:example-mail-events",
    Message: JSON.stringify(record),
    Timestamp: AT,
    SignatureVersion: "1",
    Signature: "EXAMPLE",
    SigningCertURL: "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-example.pem",
    UnsubscribeURL: "https://sns.us-east-1.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-east-1:123456789012:example-mail-events:example",
  };
}
