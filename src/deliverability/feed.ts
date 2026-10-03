import { getAgentByName } from "agents";
import { Directory, type DirectoryEntry } from "../directory/directory";
import type { Env } from "../env";
import { type LogValue, logAlert, logEvent } from "../log";
import type { Mailbox } from "../mailbox/mailbox";
import { type ParsedEvent, parseEventRecord } from "./events";
import { BATCH_ID, type DeleteEntry, type QueueMessage, SqsRequestFailed, type SqsQueueClient, sqsQueueClient } from "./sqs";

/**
 * The deliverability feed (plan.md §13; domain-model M11, M12, G22): every
 * five minutes the Worker's cron reads Mail's own SQS queue, where SES puts
 * the bounce, complaint, reject, delay and rendering-failure events of Mail's
 * configuration sets; routes each by the `mailbox` tag the send carried;
 * hands a permanent bounce or a complaint to that Mailbox, which keeps a
 * keyed hash of each recipient; and deletes what it has dealt with.
 *
 * At least once: SQS may hand a message out twice, and a message whose
 * delete failed comes back after its visibility timeout. Recording is an
 * upsert, so a second time changes nothing. A message the Mailbox could not
 * record is NOT deleted, so SQS delivers it again and, after enough failures,
 * moves it to the dead-letter queue for the operator.
 *
 * Nothing from an event is logged: not a recipient, not a subject, not a
 * header. The one log line per run carries counts; an alert carries a fixed
 * reason and at most a mailbox id.
 */

/** ReceiveMessage's ceiling per call, and DeleteMessageBatch's. */
export const FEED_BATCH = 10;
/** Rounds per cron run: 200 events every five minutes is far above any mailbox's volume; the queue holds the rest. */
export const FEED_ROUNDS_MAX = 20;
/**
 * A long poll (more than 0) asks every SQS server, so an empty answer means an
 * empty queue; a short poll samples a subset and can miss messages that are
 * there. Two seconds bounds what an empty queue costs a run.
 */
export const FEED_WAIT_SECONDS = 2;

export interface FeedSummary {
  cron: string | null;
  rounds: number;
  received: number;
  bouncesPermanent: number;
  bouncesTransient: number;
  complaints: number;
  delays: number;
  rejects: number;
  renderingFailures: number;
  /** Event types Mail does not subscribe to (plan.md §13); discarded unread. */
  other: number;
  unreadable: number;
  unroutable: number;
  recorded: number;
  notRecorded: number;
  deleted: number;
  notDeleted: number;
}

/** What a Mailbox stores: a permanent bounce or a complaint, its recipients, and when. */
export interface DeliveryEvent {
  kind: "bounce" | "complaint";
  recipients: string[];
  at: string;
}

/** The one Mailbox method this feed calls, typed from the class as MailService's stub is (src/service.ts). */
type DeliveryRecorder = Pick<Mailbox, "recordDeliveryEvent">;

const REQUIRED = ["MAIL_EVENTS_QUEUE_URL", "SES_ACCESS_KEY_ID", "SES_SECRET_ACCESS_KEY"] as const;

/** The cron's entry: an unconfigured feed is an operator alert, not a failed run, because the secret is set after the first deploy (plan.md §15). */
export async function runDeliverabilityFeed(env: Env, cron: string): Promise<void> {
  const missing = REQUIRED.filter((name) => typeof env[name] !== "string" || env[name] === "");
  if (missing.length > 0) {
    logAlert("events-feed-not-configured", { cron, missing: missing.join(",") });
    return;
  }
  await pollDeliverabilityFeed(env, { cron });
}

export async function pollDeliverabilityFeed(env: Env, opts: { fetch?: typeof fetch; cron?: string } = {}): Promise<FeedSummary> {
  const client = sqsQueueClient(
    { queueUrl: env.MAIL_EVENTS_QUEUE_URL, accessKeyId: env.SES_ACCESS_KEY_ID, secretAccessKey: env.SES_SECRET_ACCESS_KEY },
    opts.fetch === undefined ? undefined : { fetch: opts.fetch },
  );
  const run = new FeedRun(env, client, opts.cron ?? null);
  try {
    await run.drain();
  } finally {
    logEvent("deliverability-feed", run.summary as unknown as Record<string, LogValue>);
  }
  return run.summary;
}

class FeedRun {
  readonly summary: FeedSummary;
  private readonly directory: Directory;
  private readonly entries = new Map<string, DirectoryEntry | null>();

  constructor(
    private readonly env: Env,
    private readonly client: SqsQueueClient,
    cron: string | null,
  ) {
    this.directory = new Directory(env.DIRECTORY);
    this.summary = {
      cron,
      rounds: 0,
      received: 0,
      bouncesPermanent: 0,
      bouncesTransient: 0,
      complaints: 0,
      delays: 0,
      rejects: 0,
      renderingFailures: 0,
      other: 0,
      unreadable: 0,
      unroutable: 0,
      recorded: 0,
      notRecorded: 0,
      deleted: 0,
      notDeleted: 0,
    };
  }

  async drain(): Promise<void> {
    for (let round = 0; round < FEED_ROUNDS_MAX; round++) {
      let messages: QueueMessage[];
      try {
        messages = await this.client.receive({ max: FEED_BATCH, waitSeconds: FEED_WAIT_SECONDS });
      } catch (err) {
        if (err instanceof SqsRequestFailed) {
          logAlert("events-feed-receive-failed", { status: err.status, code: err.code, retryable: err.retryable });
          throw new Error("the deliverability feed could not receive events");
        }
        throw err;
      }
      this.summary.rounds += 1;
      if (messages.length === 0) return;
      this.summary.received += messages.length;
      const done: QueueMessage[] = [];
      for (const message of messages) {
        if (await this.handle(message)) done.push(message);
      }
      await this.deleteAll(done);
    }
  }

  /** True when the message is dealt with and may be deleted. */
  private async handle(message: QueueMessage): Promise<boolean> {
    const parsed = parseEventRecord(message.body);
    if (!parsed.ok) {
      this.summary.unreadable += 1;
      logAlert("delivery-event-unreadable", { reason: parsed.reason });
      return true;
    }
    const { mailboxId, event } = parsed.record;
    this.count(event);
    if (mailboxId === null) {
      this.summary.unroutable += 1;
      logAlert("delivery-event-unroutable", { reason: "no-mailbox-tag", eventKind: event.kind });
      return true;
    }
    const entry = await this.entry(mailboxId);
    if (entry === null || entry.status === "closed") {
      this.summary.unroutable += 1;
      logAlert("delivery-event-unroutable", { reason: "unknown-mailbox", eventKind: event.kind, mailbox: mailboxId });
      return true;
    }
    const stored = event.kind === "complaint" ? event : event.kind === "bounce" && event.bounceType === "Permanent" ? event : null;
    // Transient bounces, delays, rejects, rendering failures: counted, nothing stored (plan.md §13).
    if (stored === null) return true;

    const recorder = await this.recorder(entry.id);
    const answer = await recorder.recordDeliveryEvent(entry, { kind: stored.kind, recipients: stored.recipients, at: stored.at });
    if (answer.ok) {
      this.summary.recorded += 1;
      return true;
    }
    this.summary.notRecorded += 1;
    logAlert("delivery-event-not-recorded", { mailbox: entry.id, eventKind: stored.kind, result: answer.error.name });
    return false;
  }

  private count(event: ParsedEvent): void {
    const s = this.summary;
    if (event.kind === "bounce") {
      if (event.bounceType === "Permanent") s.bouncesPermanent += 1;
      else s.bouncesTransient += 1;
    } else if (event.kind === "complaint") s.complaints += 1;
    else if (event.kind === "delay") s.delays += 1;
    else if (event.kind === "reject") s.rejects += 1;
    else if (event.kind === "rendering-failure") s.renderingFailures += 1;
    else s.other += 1;
  }

  private async entry(mailboxId: string): Promise<DirectoryEntry | null> {
    let entry = this.entries.get(mailboxId);
    if (entry === undefined) {
      entry = await this.directory.byId(mailboxId);
      this.entries.set(mailboxId, entry);
    }
    return entry;
  }

  private async recorder(mailboxId: string): Promise<DeliveryRecorder> {
    // getAgentByName, not namespace.get: it starts the Agent's lifecycle first (src/service.ts).
    return (await getAgentByName(this.env.Mailbox, mailboxId)) as unknown as DeliveryRecorder;
  }

  /**
   * One DeleteMessageBatch for the round, then one more for whatever it
   * reported as failed. What still fails stays on the queue: SQS hands it out
   * again after the visibility timeout, and recording it again changes nothing.
   */
  private async deleteAll(messages: QueueMessage[]): Promise<void> {
    if (messages.length === 0) return;
    let entries: DeleteEntry[] = messages.map((m, i) => ({ id: BATCH_ID.test(m.messageId) ? m.messageId : `m${i}`, receiptHandle: m.receiptHandle }));
    for (let attempt = 0; attempt < 2 && entries.length > 0; attempt++) {
      let deleted: Set<string>;
      try {
        deleted = new Set((await this.client.deleteBatch(entries)).deleted);
      } catch (err) {
        if (!(err instanceof SqsRequestFailed)) throw err;
        logAlert("events-feed-delete-failed", { status: err.status, code: err.code, retryable: err.retryable });
        break;
      }
      this.summary.deleted += deleted.size;
      entries = entries.filter((e) => !deleted.has(e.id));
    }
    if (entries.length > 0) {
      this.summary.notDeleted += entries.length;
      logAlert("delivery-events-not-deleted", { count: entries.length });
    }
  }
}
