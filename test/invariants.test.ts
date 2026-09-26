import { genericObservability } from "agents/observability";
import { createExecutionContext, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import worker from "../src/index";
import type { Mailbox } from "../src/mailbox/mailbox";
import { base64urlFromBytes } from "./support/capability-tokens";
import { type CapturedConsole, captureConsole } from "./support/console";
import { crlf, incomingEmail } from "./support/email";
import { testId } from "./support/ids";
import {
  capFor,
  newKeyPair,
  passkeyWrap,
  provisionMailbox,
  recoveryWrap,
  type TestMailbox,
} from "./support/mailbox";
import { refusalOf, valueOf } from "./support/results";
import {
  byteString,
  captureDiagnostics,
  directoryHaystacks,
  formsOf,
  type Haystack,
  mailboxHaystacks,
  r2Haystacks,
  search,
} from "./support/scan";

const mail = () => exports.MailService;
const utf8 = (s: string) => new TextEncoder().encode(s);
const b64 = (s: string) => btoa(byteString(utf8(s)));
const qp = (s: string) => [...utf8(s)].map((b) => (b >= 33 && b <= 126 && b !== 61 ? String.fromCharCode(b) : `=${b.toString(16).toUpperCase().padStart(2, "0")}`)).join("");

function markers() {
  const tag = crypto.randomUUID().slice(0, 8);
  return {
    subject: `Zürich-subject-${tag}`,
    senderName: `Åsa-sender-${tag}`,
    senderAddress: `sender-${tag}@example.com`,
    body: `Grüße-body-${tag}`,
    attachment: `Straße-plan-${tag}.pdf`,
    sentSubject: `Köln-sent-subject-${tag}`,
    sentBody: `Señor-sent-body-${tag}`,
    sentRecipientName: `Zoë-recipient-${tag}`,
    sentRecipientAddress: `recipient-${tag}@example.org`,
    sentAttachment: `Café-quote-${tag}.pdf`,
  };
}

/** One arriving message carrying the markers in the encodings real mail uses. */
function markedMessage(m: ReturnType<typeof markers>, to: string): Uint8Array {
  return crlf([
    `From: =?UTF-8?B?${b64(m.senderName)}?= <${m.senderAddress}>`,
    `To: <${to}>`,
    `Subject: =?UTF-8?Q?${qp(m.subject)}?=`,
    "Date: Sat, 26 Sep 2026 15:04:05 +0000",
    `Message-ID: <${crypto.randomUUID()}@example.com>`,
    "MIME-Version: 1.0",
    'Content-Type: multipart/mixed; boundary="mark"',
    "",
    "--mark",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    `Hello, ${qp(m.body)}`,
    "--mark",
    "Content-Type: application/pdf",
    `Content-Disposition: attachment; filename*=UTF-8''${encodeURIComponent(m.attachment)}`,
    "Content-Transfer-Encoding: base64",
    "",
    b64(`%PDF ${m.body}`),
    "--mark--",
    "",
  ]);
}

async function everything(mb: TestMailbox, captured: CapturedConsole, diagnostics: Haystack[]): Promise<Haystack[]> {
  return [
    ...(await mailboxHaystacks(mb.stub)),
    ...(await directoryHaystacks()),
    ...(await r2Haystacks()),
    ...captured.lines.map((text, i) => ({ where: `console line ${i}`, text: byteString(utf8(text)) })),
    ...diagnostics,
  ];
}

let captured: CapturedConsole;
let diagnostics: ReturnType<typeof captureDiagnostics>;
beforeEach(() => {
  captured = captureConsole();
  diagnostics = captureDiagnostics();
});
afterEach(() => {
  diagnostics.stop();
  captured.restore();
});

describe("the scanner finds what it claims to (so the invariant tests cannot pass by accident)", () => {
  it("finds a target plain, in base64 at every alignment, quoted-printable with soft breaks, and hex", () => {
    const probe = "Zürich-subject-probe";
    for (const prefix of ["", "a", "ab"]) {
      const stream = utf8(`${prefix}${probe}tail`);
      expect(search([{ where: "b64", text: btoa(byteString(stream)) }], { probe }).length).toBeGreaterThan(0);
    }
    const softBroken = qp(probe).replace(/(.{7})/, "$1=\r\n");
    expect(search([{ where: "qp", text: softBroken }], { probe })).toEqual([{ target: "probe", form: "quoted-printable", where: "qp" }]);
    expect(search([{ where: "plain", text: byteString(utf8(`x${probe}y`)) }], { probe })[0]?.form).toBe("plain");
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    expect(search([{ where: "hex", text: hex }], { bytes })[0]?.form).toBe("hex");
    expect(formsOf(probe).map((f) => f.form)).toContain("base64url@2");
  });

  it("catches the Agents SDK's default observability, which would publish the subject (why Mailbox turns it off)", async () => {
    const mb = await provisionMailbox();
    const m = markers();
    await runInDurableObject(mb.stub, (instance: Mailbox) => {
      (instance as unknown as { observability: unknown }).observability = genericObservability;
    });
    // Email Routing hands over header values as they arrived: RFC 2047-encoded.
    const email = incomingEmail(markedMessage(m, mb.address), { to: mb.address, headers: [["subject", `=?UTF-8?Q?${qp(m.subject)}?=`]] });
    await worker.email!(email.message, env, createExecutionContext());
    const findings = search(diagnostics.messages, { subject: m.subject });
    expect(findings).toContainEqual({ target: "subject", form: "quoted-printable", where: "diagnostics agents:email" });
  });
});

describe("M1: no plaintext at rest, and none in a log", () => {
  it("after an arrival and a send, no subject, name, address, body or attachment name is anywhere in any form", async () => {
    const mb = await provisionMailbox();
    const m = markers();

    const email = incomingEmail(markedMessage(m, mb.address), {
      to: mb.address,
      from: m.senderAddress,
      headers: [
        ["subject", `=?UTF-8?Q?${qp(m.subject)}?=`],
        ["from", `=?UTF-8?B?${b64(m.senderName)}?= <${m.senderAddress}>`],
      ],
    });
    await worker.email!(email.message, env, createExecutionContext());
    expect(email.rejects).toEqual([]);
    // The fakes did see the plaintext: the markers really went through the Worker.
    expect(mb.ports.sealer.sealed[0]!.header.subject).toBe(m.subject);
    expect(mb.ports.sealer.sealed[0]!.header.attachments[0]!.filename).toBe(m.attachment);

    const sent = await mail().send(await capFor(mb), {
      idempotencyKey: "m1-send",
      to: [{ name: m.sentRecipientName, address: m.sentRecipientAddress }],
      subject: m.sentSubject,
      text: `Dear ${m.sentRecipientName}, ${m.sentBody}`,
      attachments: [{ filename: m.sentAttachment, mimeType: "application/pdf", content: utf8(`%PDF ${m.sentBody}`) }],
    });
    expect(sent.ok).toBe(true);
    expect(mb.ports.mailer.sent[0]!.recipients).toEqual([m.sentRecipientAddress]);

    // Reading paths log too: exercise them before scanning.
    const cap = await capFor(mb);
    const { items } = valueOf(await mail().list(cap, { folder: "inbox" }));
    await new Response(valueOf(await mail().body(await capFor(mb), items[0]!.id))).arrayBuffer();
    valueOf(await mail().mailbox(await capFor(mb)));
    valueOf(await mail().audit(await capFor(mb), {}));

    const haystacks = await everything(mb, captured, diagnostics.messages);
    expect(haystacks.some((h) => h.where.startsWith("mailbox sqlite messages"))).toBe(true);
    expect(haystacks.some((h) => h.where.startsWith("r2 mbx/"))).toBe(true);
    expect(haystacks.some((h) => h.where.startsWith("console"))).toBe(true);
    expect(search(haystacks, m)).toEqual([]);
  });

  it("keeps even a message the parser gave up on out of every log and table", async () => {
    const mb = await provisionMailbox();
    const m = markers();
    const raw = crlf([`X-Filler: ${"a".repeat(300 * 1024)}`, `Subject: ${m.subject}`, "", m.body]);
    await worker.email!(incomingEmail(raw, { to: mb.address, headers: [["subject", `=?UTF-8?Q?${qp(m.subject)}?=`]] }).message, env, createExecutionContext());
    expect(search(await everything(mb, captured, diagnostics.messages), m)).toEqual([]);
  });
});

describe("M3: the server holds no private key while the assistant is off", () => {
  it("after enrolment, arrivals and a send, no table, object or log holds the private key in any form", async () => {
    const mb = await provisionMailbox({ status: "provisioned" });
    const key = await newKeyPair();
    valueOf(
      await mail().enroll(await capFor(mb), {
        publicKey: base64urlFromBytes(key.publicKey),
        wraps: [recoveryWrap(key.keyId), passkeyWrap(key.keyId)],
      }),
    );
    const m = markers();
    await worker.email!(incomingEmail(markedMessage(m, mb.address), { to: mb.address }).message, env, createExecutionContext());
    valueOf(await mail().send(await capFor(mb), { idempotencyKey: "m3", to: [{ address: "a@example.com" }], subject: "s", text: "t" }));

    const haystacks = await everything(mb, captured, diagnostics.messages);
    expect(search(haystacks, { privateBytes: key.privateKey })).toEqual([]);
    // The public key IS stored, as it must be; the scan would see it.
    expect(search(haystacks, { publicKey: key.publicKey }).length).toBeGreaterThan(0);
    expect(valueOf(await mail().mailbox(await capFor(mb))).policy.assistant).toBe("off");
  });

  it("no method accepts a private key, under any field name", async () => {
    const mb = await provisionMailbox();
    const priv = base64urlFromBytes((await newKeyPair()).privateKey);
    const fresh = await provisionMailbox({ status: "provisioned" });
    const k = await newKeyPair();
    const calls: [string, () => Promise<Parameters<typeof refusalOf>[0]>][] = [
      ["enroll", async () => mail().enroll(await capFor(fresh), { publicKey: base64urlFromBytes(k.publicKey), wraps: [recoveryWrap(k.keyId)], privateKey: priv })],
      ["enroll wrap", async () => mail().enroll(await capFor(fresh), { publicKey: base64urlFromBytes(k.publicKey), wraps: [recoveryWrap(k.keyId, { privateKey: priv })] })],
      ["addWrap", async () => mail().addWrap(await capFor(mb), passkeyWrap(mb.key!.keyId, { privateKey: priv }))],
      ["saveDraft", async () => mail().saveDraft(await capFor(mb), { id: testId("drf"), keyId: mb.key!.keyId, keyEnvelope: base64urlFromBytes(new Uint8Array(80)), sealed: "AAAA", privateKey: priv })],
      ["setPolicy", async () => mail().setPolicy(await capFor(mb), { assistant: "off", privateKey: priv })],
      ["send", async () => mail().send(await capFor(mb), { idempotencyKey: "k", to: [{ address: "a@b.test" }], subject: "s", text: "t", privateKey: priv })],
      ["update", async () => mail().update(await capFor(mb), testId("msg"), { seen: true, privateKey: priv })],
      ["list", async () => mail().list(await capFor(mb), { folder: "inbox", privateKey: priv })],
    ];
    for (const [name, call] of calls) {
      expect([name, refusalOf(await call()).name]).toEqual([name, "InvalidRequest"]);
    }
    expect(valueOf(await mail().mailbox(await capFor(fresh))).keys).toEqual([]);
  });
});
