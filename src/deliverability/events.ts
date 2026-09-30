import { normalizeAddress } from "../directory/directory";
import * as v from "../mailbox/validate";

/**
 * Reads one SES event record (plan.md §13) as SES publishes it: the shapes in
 * "Contents of event data that Amazon SES publishes to Amazon SNS" (checked
 * 2026-09-29). With raw message delivery the SQS body IS the record; without
 * it the body is an SNS envelope whose `Message` is the record, and that is
 * unwrapped too.
 *
 * What comes out is the least the feed needs: the mailbox the send named in
 * its `mailbox` tag (G22: routing is by that tag alone, never by an address in
 * the record), the kind of event, and, for the two kinds a mailbox stores,
 * the recipients and the event's time. Subjects, headers and the mail
 * object's addresses are read by nothing here and go nowhere.
 */

export type ParsedEvent =
  | { kind: "bounce"; bounceType: "Permanent" | "Transient" | "Undetermined"; recipients: string[]; at: string }
  | { kind: "complaint"; recipients: string[]; at: string }
  | { kind: "delay" | "reject" | "rendering-failure" | "other" };

export interface EventRecord {
  /** null: no `mailbox` tag, or one that is not a mailbox id. */
  mailboxId: string | null;
  event: ParsedEvent;
}

export type ParseOutcome = { ok: true; record: EventRecord } | { ok: false; reason: "not-json" | "not-an-event" | "no-recipients" };

/** The mailbox id form (contracts/envelope-v1.md, "Identifiers"), as the tag carries it. */
const MAILBOX_ID = /^mbx_[0-9abcdefghjkmnpqrstvwxyz]{26}$/;

const KINDS: Record<string, ParsedEvent["kind"]> = {
  Bounce: "bounce",
  Complaint: "complaint",
  DeliveryDelay: "delay",
  Reject: "reject",
  "Rendering Failure": "rendering-failure",
};

export function parseEventRecord(body: string): ParseOutcome {
  let record = asObject(parseJson(body));
  if (record === undefined) return { ok: false, reason: "not-json" };
  // An SNS envelope (a subscription without raw message delivery).
  if (record.Type === "Notification" && typeof record.Message === "string") {
    record = asObject(parseJson(record.Message));
    if (record === undefined) return { ok: false, reason: "not-json" };
  }
  const type = typeof record.eventType === "string" ? record.eventType : typeof record.notificationType === "string" ? record.notificationType : null;
  const mail = asObject(record.mail);
  if (type === null || mail === undefined) return { ok: false, reason: "not-an-event" };

  const mailboxId = mailboxTag(mail);
  const kind = KINDS[type] ?? "other";
  if (kind === "bounce") {
    const bounce = asObject(record.bounce) ?? {};
    const bounceType = bounce.bounceType === "Permanent" || bounce.bounceType === "Transient" ? bounce.bounceType : "Undetermined";
    const recipients = addressesOf(bounce.bouncedRecipients);
    if (recipients.length === 0) return { ok: false, reason: "no-recipients" };
    return { ok: true, record: { mailboxId, event: { kind, bounceType, recipients, at: timeOf(bounce.timestamp, mail.timestamp) } } };
  }
  if (kind === "complaint") {
    const complaint = asObject(record.complaint) ?? {};
    const recipients = addressesOf(complaint.complainedRecipients);
    if (recipients.length === 0) return { ok: false, reason: "no-recipients" };
    return { ok: true, record: { mailboxId, event: { kind, recipients, at: timeOf(complaint.timestamp, mail.timestamp) } } };
  }
  return { ok: true, record: { mailboxId, event: { kind } } };
}

/** `mail.tags.mailbox` is a list of values (SES publishes every tag as a list); the first is the mailbox. */
function mailboxTag(mail: Record<string, unknown>): string | null {
  const tags = asObject(mail.tags);
  const values = tags?.mailbox;
  const value = Array.isArray(values) ? values[0] : values;
  return typeof value === "string" && MAILBOX_ID.test(value) ? value : null;
}

/**
 * `emailAddress` of each recipient object, in the Directory's form. Anything
 * the Mailbox would not accept as an address (the same check as a send's
 * recipients) is dropped here, so a record never bounces between the feed
 * and a Mailbox that refuses it.
 */
function addressesOf(list: unknown): string[] {
  if (!Array.isArray(list)) return [];
  const out = new Set<string>();
  for (const item of list) {
    const raw = asObject(item)?.emailAddress;
    if (typeof raw !== "string") continue;
    // A DSN's Final-Recipient can arrive as "rfc822; user@example.com" or in angle brackets.
    const bare = normalizeAddress(raw.replace(/^rfc822;\s*/i, "").replace(/^.*<([^>]+)>.*$/, "$1"));
    try {
      out.add(v.address(bare, "recipient"));
    } catch {
      // not an address: dropped
    }
  }
  return [...out];
}

/** The event's own time, else the send's, else now; always ISO 8601 with milliseconds. */
function timeOf(...candidates: unknown[]): string {
  for (const c of candidates) {
    if (typeof c !== "string") continue;
    const ms = Date.parse(c);
    if (!Number.isNaN(ms)) return new Date(ms).toISOString();
  }
  return new Date().toISOString();
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
}
