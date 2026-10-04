/**
 * The decrypted raw message, parsed with postal-mime into what the screens
 * show: text, HTML, attachments. The HTML is NOT safe yet; renderBody
 * sanitises it for the one frame.
 */
import PostalMime from "postal-mime";
import { utf8 } from "./bytes";
import type { BodyAttachment, MailBody } from "./types";

/** postal-mime invents an HTML part from text (and text from HTML) when only one exists; the raw headers say which parts are real. */
function declaresPart(raw: Uint8Array, subtype: "html" | "plain"): boolean {
  // Header lines are ASCII; a Latin-1 view keeps byte offsets and never throws.
  let text = "";
  const step = 0x8000;
  for (let i = 0; i < raw.length; i += step) text += String.fromCharCode.apply(null, raw.subarray(i, i + step) as unknown as number[]);
  return new RegExp(`^content-type:\\s*text/${subtype}\\b`, "im").test(text);
}

function contentBytes(content: ArrayBuffer | Uint8Array | string): Uint8Array {
  if (content instanceof Uint8Array) return content;
  if (content instanceof ArrayBuffer) return new Uint8Array(content);
  return utf8(String(content));
}

export async function parseMail(raw: Uint8Array): Promise<MailBody> {
  const email = await PostalMime.parse(raw);
  const attachments: BodyAttachment[] = email.attachments.map((a) => {
    const content = contentBytes(a.content);
    const contentId = a.contentId ? a.contentId.replace(/^<|>$/g, "") : null;
    return {
      filename: a.filename ?? (contentId !== null ? "inline" : "attachment"),
      mimeType: a.mimeType || "application/octet-stream",
      size: content.byteLength,
      contentId,
      inline: a.disposition === "inline" || a.related === true,
      content,
    };
  });
  return {
    raw,
    text: email.text ?? null,
    html: email.html !== undefined && declaresPart(raw, "html") ? email.html : null,
    attachments,
  };
}
