import type { Draft, MessageHeader } from "../src/index";
import { Buffer } from "node:buffer";
import { utf8 } from "./reference";

/** RFC 2047 B-encoded words of at most 45 UTF-8 bytes each, folded with CRLF SP. */
function encodedWords(text: string): string {
  const words: string[] = [];
  let chunk = "";
  for (const ch of text) {
    if (Buffer.byteLength(chunk + ch) > 45) {
      words.push(chunk);
      chunk = "";
    }
    chunk += ch;
  }
  words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w).toString("base64")}?=`).join("\r\n ");
}

/** The contract's own MessageHeader example. */
export const smallHeader: MessageHeader = {
  v: 1,
  direction: "in",
  envelopeFrom: "bounce@x.example",
  from: { name: "Ana Ruiz", address: "ana@example.com" },
  to: [{ name: "", address: "hello@operator.example" }],
  cc: [],
  bcc: [],
  replyTo: [],
  subject: "Kitchen remodel quote",
  date: "2026-09-26T15:04:05.000Z",
  messageId: "abc@example.com",
  inReplyTo: null,
  references: [],
  snippet: "Hi — we'd like a quote for…",
  attachments: [],
};

export const smallRaw = utf8(
  [
    "Return-Path: <bounce@x.example>",
    "From: Ana Ruiz <ana@example.com>",
    "To: hello@operator.example",
    "Subject: Kitchen remodel quote",
    "Date: Sat, 26 Sep 2026 15:04:05 +0000",
    "Message-ID: <abc@example.com>",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    "Hi — we'd like a quote for the kitchen.",
    "",
  ].join("\r\n"),
);

const unicodeSubject = "Cotización: baño — ¿podemos vernos el 3/10? 見積もり 🛁";

/** Non-ASCII subject, names and filename, with an attachment. */
export const unicodeHeader: MessageHeader = {
  v: 1,
  direction: "in",
  envelopeFrom: "bounces+x@mail.example.com",
  from: { name: "José Nguyễn 🛠", address: "jose@example.com" },
  to: [{ name: "Example Tile Co", address: "hello@client.example" }],
  cc: [{ name: "Zoë Ångström", address: "zoe@example.org" }],
  bcc: [],
  replyTo: [{ name: "", address: "jose+replies@example.com" }],
  subject: unicodeSubject,
  date: "2026-09-26T15:04:05.000Z",
  messageId: "20260926150405.1234@mail.example.com",
  inReplyTo: "prev@example.com",
  references: ["first@example.com", "prev@example.com"],
  snippet: "Hola, adjunto el plano del baño. ¿Pueden darme un precio? Gracias.",
  attachments: [{ filename: "plano-baño.pdf", mimeType: "application/pdf", size: 22, inline: false }],
};

export const unicodeRaw = utf8(
  [
    "From: =?UTF-8?Q?Jos=C3=A9_Nguy=E1=BB=85n_=F0=9F=9B=A0?= <jose@example.com>",
    "To: \"Example Tile Co\" <hello@client.example>",
    `Subject: ${encodedWords(unicodeSubject)}`,
    "Message-ID: <20260926150405.1234@mail.example.com>",
    "MIME-Version: 1.0",
    "Content-Type: multipart/mixed; boundary=\"b1\"",
    "",
    "--b1",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 8bit",
    "",
    "Hola, adjunto el plano del baño. ¿Pueden darme un precio? Gracias.",
    "--b1",
    "Content-Type: application/pdf; name=\"=?UTF-8?Q?plano-ba=C3=B1o.pdf?=\"",
    "Content-Disposition: attachment",
    "Content-Transfer-Encoding: base64",
    "",
    "JVBERi0xLjQKJcTl8uXrp/Og0MTGCg==",
    "--b1--",
    "",
  ].join("\r\n"),
);

export const draft: Draft = {
  v: 1,
  to: [{ name: "José Nguyễn", address: "jose@example.com" }],
  cc: [],
  bcc: [{ name: "", address: "archive@example.org" }],
  subject: "Re: Cotización — baño",
  text: "Hola José,\n\nGracias por el plano. Le enviamos el precio mañana.\n\n— Alex",
  inReplyTo: "20260926150405.1234@mail.example.com",
  references: ["first@example.com", "prev@example.com", "20260926150405.1234@mail.example.com"],
  updatedAt: "2026-09-26T15:04:05.000Z",
};
