// encodeSendForm / decodeSendForm (contracts/mail-client-v1.md "Drafts and sending", spec D22):
// the browser builds FormData (a JSON part plus one File per attachment); the server side of the
// send route checks the limits and returns exactly what MailService.send takes.
import { describe, expect, test } from "vitest";
import { LIMITS } from "@proprietor/mail-outbound";
import { decodeSendForm, encodeSendForm, InvalidSendForm, SEND_LIMITS, type ComposeInput } from "../src/index";

const compose: ComposeInput = {
  from: "team@example.com",
  to: [{ name: "Ana Ruiz", address: "ana@example.com" }],
  cc: [{ name: "", address: "bo@example.org" }],
  bcc: [],
  subject: "Re: Kitchen remodel",
  text: "Soon.",
  inReplyTo: "k1@example.com",
  references: ["k0@example.com", "k1@example.com"],
  attachments: [new File([new Uint8Array([1, 2, 3])], "plan.pdf", { type: "application/pdf" }), new File(["hi"], "note.txt", { type: "text/plain" })],
};

describe("SEND_LIMITS", () => {
  test("mirror the Worker's limits, so a refusal happens before the upload", () => {
    expect(SEND_LIMITS.maxRecipients).toBe(LIMITS.maxRecipients);
    expect(SEND_LIMITS.maxRawBytes).toBe(LIMITS.maxRawBytes);
    expect(SEND_LIMITS.maxFormBytes).toBe(25 * 1024 * 1024); // D22
  });
});

describe("encodeSendForm → decodeSendForm", () => {
  test("round-trips to exactly MailService.send's request, attachments as bytes", async () => {
    const form = encodeSendForm(compose, { idempotencyKey: "idem-1", draftId: "drf_0000000000000000000000draf" });
    expect([...form.keys()]).toEqual(["request", "attachment", "attachment"]);
    expect(form.getAll("attachment").every((f) => f instanceof File)).toBe(true);
    const request = await decodeSendForm(form);
    expect(request).toEqual({
      idempotencyKey: "idem-1",
      from: "team@example.com",
      to: compose.to,
      cc: compose.cc,
      bcc: [],
      subject: "Re: Kitchen remodel",
      text: "Soon.",
      inReplyTo: "k1@example.com",
      references: compose.references,
      attachments: [
        { filename: "plan.pdf", mimeType: "application/pdf", content: new Uint8Array([1, 2, 3]) },
        { filename: "note.txt", mimeType: "text/plain", content: new TextEncoder().encode("hi") },
      ],
      draftId: "drf_0000000000000000000000draf",
    });
    expect(request.attachments[0]!.content).toBeInstanceOf(Uint8Array);
  });

  test("optional fields are left out, not sent as null", async () => {
    const request = await decodeSendForm(encodeSendForm({ ...compose, from: undefined, inReplyTo: null, attachments: [] }, { idempotencyKey: "idem-2" }));
    expect("from" in request).toBe(false);
    expect("inReplyTo" in request).toBe(false);
    expect("draftId" in request).toBe(false);
    expect(request.attachments).toEqual([]);
  });

  test("an attachment without a type gets application/octet-stream", async () => {
    const request = await decodeSendForm(encodeSendForm({ ...compose, attachments: [new File([new Uint8Array(4)], "blob")] }, { idempotencyKey: "idem-3" }));
    expect(request.attachments[0]).toMatchObject({ filename: "blob", mimeType: "application/octet-stream" });
  });

  test("the browser side refuses what the Worker would refuse, before any upload", () => {
    const many = Array.from({ length: SEND_LIMITS.maxRecipients + 1 }, (_, i) => ({ name: "", address: `u${i}@example.com` }));
    expect(() => encodeSendForm({ ...compose, to: many }, { idempotencyKey: "k" })).toThrow(InvalidSendForm);
    expect(() => encodeSendForm({ ...compose, to: [] }, { idempotencyKey: "k" })).toThrow(InvalidSendForm);
    expect(() => encodeSendForm({ ...compose, subject: "a\nb" }, { idempotencyKey: "k" })).toThrow(InvalidSendForm);
    expect(() => encodeSendForm({ ...compose, subject: "x".repeat(999) }, { idempotencyKey: "k" })).toThrow(InvalidSendForm);
    expect(() => encodeSendForm(compose, { idempotencyKey: "has space" })).toThrow(InvalidSendForm);
    expect(() => encodeSendForm({ ...compose, to: [{ name: "x", address: "not-an-address" }] }, { idempotencyKey: "k" })).toThrow(InvalidSendForm);
    const big = new File([new Uint8Array(SEND_LIMITS.maxRawBytes + 1)], "big.bin");
    expect(() => encodeSendForm({ ...compose, attachments: [big] }, { idempotencyKey: "k" })).toThrow(InvalidSendForm);
  });

  test("the server side checks the same limits on a form it did not build", async () => {
    const malformed = new FormData();
    await expect(decodeSendForm(malformed)).rejects.toBeInstanceOf(InvalidSendForm);
    malformed.set("request", "not json");
    await expect(decodeSendForm(malformed)).rejects.toBeInstanceOf(InvalidSendForm);

    const base = () => {
      const form = encodeSendForm(compose, { idempotencyKey: "idem-4" });
      return { form, request: JSON.parse(form.get("request") as string) as Record<string, unknown> };
    };

    const tooMany = base();
    tooMany.request.to = Array.from({ length: SEND_LIMITS.maxRecipients + 1 }, (_, i) => ({ name: "", address: `u${i}@example.com` }));
    tooMany.form.set("request", JSON.stringify(tooMany.request));
    await expect(decodeSendForm(tooMany.form)).rejects.toBeInstanceOf(InvalidSendForm);

    const extraFile = base();
    extraFile.form.append("attachment", new File(["x"], "extra.txt"));
    await expect(decodeSendForm(extraFile.form)).rejects.toBeInstanceOf(InvalidSendForm);

    const notAFile = base();
    notAFile.form.append("attachment", "a string, not a File");
    await expect(decodeSendForm(notAFile.form)).rejects.toBeInstanceOf(InvalidSendForm);

    const wrongShape = base();
    wrongShape.request.text = 42;
    wrongShape.form.set("request", JSON.stringify(wrongShape.request));
    await expect(decodeSendForm(wrongShape.form)).rejects.toBeInstanceOf(InvalidSendForm);

    const tooBig = base();
    tooBig.form.set("attachment", new File([new Uint8Array(SEND_LIMITS.maxRawBytes + 1)], "big.bin"), "big.bin");
    await expect(decodeSendForm(tooBig.form)).rejects.toBeInstanceOf(InvalidSendForm);

    const badDraft = base();
    badDraft.request.draftId = "msg_notadraft";
    badDraft.form.set("request", JSON.stringify(badDraft.request));
    await expect(decodeSendForm(badDraft.form)).rejects.toBeInstanceOf(InvalidSendForm);
  });

  test("the mail session rides inside the request (device-v1 B1, D29): encodeSendForm takes it, decodeSendForm returns it", async () => {
    const session = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
    const request = await decodeSendForm(encodeSendForm(compose, { idempotencyKey: "idem-s", session }));
    expect(request.session).toBe(session);
    expect(JSON.parse(encodeSendForm(compose, { idempotencyKey: "idem-s", session }).get("request") as string).session).toBe(session);
  });

  test("no session: no field; a session that is not 32 bytes of base64url is refused, on both sides", async () => {
    const without = await decodeSendForm(encodeSendForm(compose, { idempotencyKey: "idem-n" }));
    expect("session" in without).toBe(false);
    for (const bad of ["", "short", "A".repeat(43) + "=", Buffer.from(new Uint8Array(31)).toString("base64url"), "x".repeat(44)]) {
      expect(() => encodeSendForm(compose, { idempotencyKey: "k", session: bad }), bad).toThrow(InvalidSendForm);
      const form = encodeSendForm(compose, { idempotencyKey: "k" });
      const r = JSON.parse(form.get("request") as string) as Record<string, unknown>;
      r.session = bad;
      form.set("request", JSON.stringify(r));
      await expect(decodeSendForm(form), bad).rejects.toBeInstanceOf(InvalidSendForm);
    }
  });
});
