/**
 * Search over decrypted headers (contracts/mail-client-v1.md "Reading"):
 * case- and accent-insensitive; every word of the query must match somewhere
 * in the subject, snippet, names and addresses, attachment names or the
 * address the message arrived for. Decryption happens elsewhere: this only
 * reads what openMessages already opened.
 */
import type { OpenedMessage } from "./types";

/** Lower case without diacritics: "Cotización" and "cotizacion" are the same word. */
export function fold(text: string): string {
  return text.normalize("NFD").replace(/\p{M}+/gu, "").toLowerCase();
}

function haystack(message: OpenedMessage): string {
  const h = message.header!;
  const people = [...(h.from ? [h.from] : []), ...h.to, ...h.cc, ...h.replyTo].flatMap((a) => [a.name, a.address]);
  return fold([h.subject, h.snippet, ...people, ...h.attachments.map((a) => a.filename), h.envelopeTo ?? ""].join("\n"));
}

export function searchMessages(messages: OpenedMessage[], query: string): OpenedMessage[] {
  const words = fold(String(query)).split(/\s+/).filter((w) => w.length > 0);
  if (words.length === 0) return messages;
  return messages.filter((m) => {
    if (m.header === null) return false;
    const text = haystack(m);
    return words.every((w) => text.includes(w));
  });
}
