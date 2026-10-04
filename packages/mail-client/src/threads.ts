/**
 * Threads (contracts/mail-client-v1.md "Reading"): Message-ID, In-Reply-To
 * and References link messages; a message whose client dropped those
 * headers but whose subject says it is a reply or forward joins the thread
 * with that subject (the subject-normalisation fallback agentic-inbox uses;
 * written here). One message that arrived for two of the mailbox's
 * addresses (domain-model G13) is one message in its thread, and the thread
 * lists both addresses.
 */
import type { Address, MessageHeader } from "@proprietor/mail-crypto";
import type { OpenedMessage, Thread } from "./types";

const REPLY_PREFIX = /^\s*(?:(?:re|fwd?|fw|aw|wg|sv|vs|tr|rif|antw|r)\s*(?:\[\d+\])?\s*:\s*)+/i;

/** The subject without its reply/forward prefixes. */
export function baseSubject(subject: string): string {
  return subject.replace(REPLY_PREFIX, "").replace(/\s+/g, " ").trim();
}

function hasReplyPrefix(subject: string): boolean {
  return REPLY_PREFIX.test(subject);
}

function normalizedId(id: string | null | undefined): string | null {
  if (typeof id !== "string") return null;
  const bare = id.trim().replace(/^<|>$/g, "").trim();
  return bare.length === 0 ? null : bare.toLowerCase();
}

function byTime(a: OpenedMessage, b: OpenedMessage): number {
  return a.receivedAt < b.receivedAt ? -1 : a.receivedAt > b.receivedAt ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

class UnionFind {
  private readonly parent = new Map<string, string>();
  find(x: string): string {
    let root = x;
    while (this.parent.has(root) && this.parent.get(root) !== root) root = this.parent.get(root)!;
    // path compression
    let cur = x;
    while (this.parent.has(cur) && this.parent.get(cur) !== root) {
      const next = this.parent.get(cur)!;
      this.parent.set(cur, root);
      cur = next;
    }
    if (!this.parent.has(root)) this.parent.set(root, root);
    return root;
  }
  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(rb, ra);
  }
}

interface Entry {
  node: string;
  message: OpenedMessage;
  header: MessageHeader;
  /** Every address the merged copies arrived for, in order of arrival. */
  envelopeTo: string[];
}

export function threadsOf(messages: OpenedMessage[]): Thread[] {
  const sorted = [...messages].sort(byTime);
  const threads: Thread[] = [];
  const entries: Entry[] = [];
  const byMessageId = new Map<string, Entry>();

  for (const message of sorted) {
    if (message.header === null) {
      threads.push({ id: message.id, subject: "", messages: [message], envelopeTo: [], latestAt: message.receivedAt, unread: message.seen ? 0 : 1, participants: [] });
      continue;
    }
    const header = message.header;
    const mid = normalizedId(header.messageId);
    const existing = mid === null ? undefined : byMessageId.get(mid);
    if (existing) {
      // G13: the same message, arrived for another of the mailbox's addresses.
      if (header.envelopeTo !== null && !existing.envelopeTo.includes(header.envelopeTo)) existing.envelopeTo.push(header.envelopeTo);
      if (message.seen && !existing.message.seen) existing.message = { ...existing.message, seen: true };
      if (message.flagged && !existing.message.flagged) existing.message = { ...existing.message, flagged: true };
      continue;
    }
    const entry: Entry = {
      node: mid === null ? `msg:${message.id}` : `mid:${mid}`,
      message,
      header,
      envelopeTo: header.envelopeTo === null ? [] : [header.envelopeTo],
    };
    entries.push(entry);
    if (mid !== null) byMessageId.set(mid, entry);
  }

  const uf = new UnionFind();
  const linked = new Set<Entry>();
  for (const entry of entries) {
    uf.find(entry.node);
    const parents = [normalizedId(entry.header.inReplyTo), ...entry.header.references.map((r) => normalizedId(r))].filter((p): p is string => p !== null);
    for (const parent of parents) uf.union(`mid:${parent}`, entry.node);
    if (parents.length > 0) linked.add(entry);
  }

  // Subject fallback: a reply/forward by its own subject, with no thread headers, joins the oldest
  // thread whose subject (without prefixes) is the same.
  const firstBySubject = new Map<string, Entry>();
  for (const entry of entries) {
    const key = baseSubject(entry.header.subject).toLowerCase();
    if (key.length === 0) continue;
    if (!firstBySubject.has(key)) firstBySubject.set(key, entry);
  }
  for (const entry of entries) {
    if (linked.has(entry) || !hasReplyPrefix(entry.header.subject)) continue;
    const first = firstBySubject.get(baseSubject(entry.header.subject).toLowerCase());
    if (first && first !== entry) uf.union(first.node, entry.node);
  }

  const groups = new Map<string, Entry[]>();
  for (const entry of entries) {
    const root = uf.find(entry.node);
    const group = groups.get(root);
    if (group) group.push(entry);
    else groups.set(root, [entry]);
  }

  for (const group of groups.values()) {
    group.sort((a, b) => byTime(a.message, b.message));
    const oldest = group[0]!;
    const envelopeTo: string[] = [];
    const participants: Address[] = [];
    const seenAddresses = new Set<string>();
    let latestAt = oldest.message.receivedAt;
    let unread = 0;
    for (const entry of group) {
      for (const address of entry.envelopeTo) if (!envelopeTo.includes(address)) envelopeTo.push(address);
      const h = entry.header;
      for (const a of [...(h.from ? [h.from] : []), ...h.to, ...h.cc, ...h.replyTo]) {
        const key = a.address.toLowerCase();
        if (key.length === 0 || seenAddresses.has(key)) continue;
        seenAddresses.add(key);
        participants.push(a);
      }
      if (entry.message.receivedAt > latestAt) latestAt = entry.message.receivedAt;
      if (!entry.message.seen) unread += 1;
    }
    threads.push({
      id: oldest.message.id,
      subject: baseSubject(oldest.header.subject),
      messages: group.map((e) => e.message),
      envelopeTo,
      latestAt,
      unread,
      participants,
    });
  }

  return threads.sort((a, b) => (a.latestAt > b.latestAt ? -1 : a.latestAt < b.latestAt ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}
