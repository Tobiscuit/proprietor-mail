import type { BuildOptions, ComposedMessage } from "../src/index";

export const NOW = new Date("2026-09-26T15:04:05Z");

/**
 * Deterministic stand-in for crypto.getRandomValues: bytes 00, 01, 02, ... across calls.
 * buildMime draws the Message-ID first (16 bytes) and then one boundary per
 * multipart, outermost first (12 bytes each), so the goldens can name them.
 */
export function counterRandom(start = 0): (length: number) => Uint8Array {
  let next = start;
  return (length) => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = next++ & 0xff;
    return out;
  };
}

export function goldenOptions(): BuildOptions {
  return { messageIdDomain: "example.com", now: NOW, random: counterRandom() };
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** Shape 1: text only. Non-ASCII names and subject, threading headers, a Bcc. */
export const TEXT_ONLY: ComposedMessage = {
  from: { name: "Renée Durand", address: "hello@example.com" },
  to: [{ name: "Ana Pérez", address: "ana@example.com" }, { address: "bo@example.org" }],
  cc: [{ name: "O'Brien, Pat", address: "pat@example.net" }],
  bcc: [{ name: "Hidden Person", address: "hidden-bcc@example.com" }],
  replyTo: [{ name: "Renée Durand", address: "hello@example.com" }],
  subject: "Your bathroom quote — tile options, grout colours and prices",
  text: "Hi Ana,\n\nThe tile options are below = pick one.\nPrice: 1 200 €, trailing space here \n",
  inReplyTo: "CAF=abc123@mail.example.com",
  references: ["root.1@mail.example.com", "CAF=abc123@mail.example.com"],
};

/** Shape 2: multipart/alternative. A long ASCII subject that folds, an HTML line that needs soft breaks. */
export const ALTERNATIVE: ComposedMessage = {
  from: { name: "Example", address: "hello@example.com" },
  to: [{ address: "ana@example.com" }],
  subject: "Your appointment on Monday, 28 September 2026 at 09:30 has been confirmed by our team",
  text: "Your appointment is confirmed.\n",
  html:
    '<p style="margin:0;font-family:Georgia,serif">Your appointment is <strong>confirmed</strong>.' +
    " See you on Monday, 28 September 2026 at 09:30.</p>\n",
};

export const PNG_SIGNATURE = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
export const TINY_PDF = new Uint8Array([
  ...utf8("%PDF-1.7\n%"),
  0xe2, 0xe3, 0xcf, 0xd3,
  ...utf8("\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"),
]);

/** Shape 3: multipart/mixed with an inline image (Content-ID, multipart/related) and two attachments. */
export const MIXED: ComposedMessage = {
  from: { address: "hello@example.com" },
  to: [{ name: "Ana", address: "ana@example.com" }],
  subject: "Invoice 2026-041",
  text: "Your invoice is attached.\n",
  html: '<p>Your invoice is attached.</p><img src="cid:logo.0001@example.com" alt="Example">\n',
  attachments: [
    { filename: "logo.png", mimeType: "image/png", content: PNG_SIGNATURE, inline: true, contentId: "logo.0001@example.com" },
    { filename: "Factura señor Pérez — septiembre 2026.pdf", mimeType: "application/pdf", content: TINY_PDF },
    { filename: "notes.txt", mimeType: "text/plain", content: utf8("plain text attachment\n") },
  ],
};
