/**
 * The Message-ID recipients actually see on mail sent through SES. SES
 * replaces the Message-ID (and Date) of a raw message with its own:
 * `<{MessageId}@email.amazonses.com>` in us-east-1 (slice S3, verified there).
 * Other regions are believed to use `<{MessageId}@{region}.amazonses.com>`;
 * that form is NOT verified, and only us-east-1 is used (plan.md §6).
 *
 * The Sent copy's sealed header carries this id, so that the browser threads
 * a recipient's reply onto the message that was sent; the sealed body stays
 * exactly the bytes handed to SES.
 */
export function sesMessageId(providerMessageId: string, region: string): string {
  const domain = region === "us-east-1" ? "email.amazonses.com" : `${region}.amazonses.com`;
  return `${providerMessageId}@${domain}`;
}
