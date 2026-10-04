// threadsOf (contracts/mail-client-v1.md "Reading"): Message-ID, In-Reply-To and References link
// messages; a subject-only fallback catches replies whose client dropped the headers; one message
// that arrived for two of the mailbox's addresses is merged, and the thread lists both (G13).
import { describe, expect, test } from "vitest";
import { threadsOf } from "../src/index";
import { opened } from "./support";

describe("threadsOf", () => {
  test("links by In-Reply-To and References, oldest first inside a thread, newest thread first", () => {
    const root = opened({ subject: "Kitchen", messageId: "k1@example.com" }, { receivedAt: "2026-09-01T10:00:00.000Z" });
    const reply = opened({ subject: "Re: Kitchen", messageId: "k2@example.com", inReplyTo: "k1@example.com", references: ["k1@example.com"] }, { receivedAt: "2026-09-02T10:00:00.000Z" });
    const other = opened({ subject: "Bathroom", messageId: "b1@example.com" }, { receivedAt: "2026-09-03T10:00:00.000Z" });
    // References only, pointing at the root (the reply's own Message-ID unknown to us).
    const grandchild = opened({ subject: "Re: Kitchen", messageId: "k3@example.com", inReplyTo: "lost@example.com", references: ["k1@example.com", "lost@example.com"] }, { receivedAt: "2026-09-04T10:00:00.000Z" });
    const threads = threadsOf([reply, other, grandchild, root]);
    expect(threads.map((t) => t.subject)).toEqual(["Kitchen", "Bathroom"]);
    expect(threads[0]!.messages.map((m) => m.header!.messageId)).toEqual(["k1@example.com", "k2@example.com", "k3@example.com"]);
    expect(threads[0]!.latestAt).toBe("2026-09-04T10:00:00.000Z");
    expect(threads[0]!.id).toBe(root.id);
    expect(threads[1]!.messages.map((m) => m.id)).toEqual([other.id]);
  });

  test("a reply that arrived before the message it answers still threads with it", () => {
    const late = opened({ subject: "Quote", messageId: "q1@example.com" }, { receivedAt: "2026-09-02T10:00:00.000Z" });
    const early = opened({ subject: "Re: Quote", messageId: "q2@example.com", inReplyTo: "q1@example.com" }, { receivedAt: "2026-09-01T10:00:00.000Z" });
    const [thread] = threadsOf([late, early]);
    expect(thread!.messages.map((m) => m.id)).toEqual([early.id, late.id]);
  });

  test("merges the two arrivals of one Message-ID and lists both envelopeTo addresses (G13)", () => {
    const first = opened({ subject: "Hi both", messageId: "dup@example.com", envelopeTo: "hello@example.com" }, { receivedAt: "2026-09-01T10:00:00.000Z", seen: true });
    const second = opened({ subject: "Hi both", messageId: "dup@example.com", envelopeTo: "team@example.com" }, { receivedAt: "2026-09-01T10:00:01.000Z" });
    const threads = threadsOf([second, first]);
    expect(threads.length).toBe(1);
    expect(threads[0]!.messages.length).toBe(1);
    expect(threads[0]!.messages[0]!.id).toBe(first.id);
    expect(threads[0]!.envelopeTo).toEqual(["hello@example.com", "team@example.com"]);
    expect(threads[0]!.unread).toBe(0);
  });

  test("subject fallback: a 'Re:' without headers joins the thread with that subject; a fresh message with the same subject does not", () => {
    const root = opened({ subject: "Invoice 42", messageId: "i1@example.com" }, { receivedAt: "2026-09-01T10:00:00.000Z" });
    const lostHeaders = opened({ subject: "RE: Invoice 42", messageId: "i2@example.com" }, { receivedAt: "2026-09-02T10:00:00.000Z" });
    const unrelated = opened({ subject: "Invoice 42", messageId: "i3@example.com" }, { receivedAt: "2026-09-03T10:00:00.000Z" });
    const fwd = opened({ subject: "Fwd: Re: Invoice 42", messageId: "i4@example.com" }, { receivedAt: "2026-09-04T10:00:00.000Z" });
    const threads = threadsOf([root, lostHeaders, unrelated, fwd]);
    const byRoot = threads.find((t) => t.messages.some((m) => m.id === root.id))!;
    expect(byRoot.messages.map((m) => m.id)).toEqual([root.id, lostHeaders.id, fwd.id]);
    expect(threads.find((t) => t.messages.some((m) => m.id === unrelated.id))!.messages.length).toBe(1);
  });

  test("subject, unread and participants", () => {
    const root = opened(
      { subject: "Re: Fwd: AW: Plans", messageId: "p1@example.com", from: { name: "Ana", address: "Ana@example.com" }, to: [{ name: "", address: "hello@example.com" }], cc: [{ name: "Bo", address: "bo@example.org" }] },
      { receivedAt: "2026-09-01T10:00:00.000Z" },
    );
    const reply = opened(
      { subject: "Re: Plans", messageId: "p2@example.com", inReplyTo: "p1@example.com", from: { name: "Ana Ruiz", address: "ana@example.com" }, to: [{ name: "", address: "hello@example.com" }], cc: [] },
      { receivedAt: "2026-09-02T10:00:00.000Z", seen: true },
    );
    const [thread] = threadsOf([root, reply]);
    expect(thread!.subject).toBe("Plans");
    expect(thread!.unread).toBe(1);
    expect(thread!.participants.map((p) => p.address.toLowerCase())).toEqual(["ana@example.com", "hello@example.com", "bo@example.org"]);
  });

  test("messages without a Message-ID or that could not be decrypted are threads of their own", () => {
    const noId = opened({ subject: "no id", messageId: null });
    const noId2 = opened({ subject: "no id", messageId: null });
    const broken = opened({ subject: "" }, { header: null, undecryptable: true });
    const threads = threadsOf([noId, noId2, broken]);
    expect(threads.length).toBe(3);
    const brokenThread = threads.find((t) => t.messages[0]!.id === broken.id)!;
    expect(brokenThread).toMatchObject({ subject: "", envelopeTo: [], participants: [], unread: 1 });
  });

  test("the input is not mutated and an empty list gives no threads", () => {
    const a = opened({ subject: "A", messageId: "a@example.com" });
    const list = [a];
    threadsOf(list);
    expect(list).toEqual([a]);
    expect(threadsOf([])).toEqual([]);
  });
});
