/**
 * The promise, as data (contracts/mail-client-v1.md; spec 001 §2 Option A and
 * §4; spec 002 §5). A test compares these texts with
 * specs/001-inbox-module/spec.md and specs/002-device-sessions/spec.md, so the
 * dashboard never shows wording the specs do not have. `{operator}` is the
 * name of the business that runs the platform; the screen fills it in.
 */
import type { ProtectionTexts } from "./types";

const OPTION_A =
  "Mail in your inbox is stored encrypted with a key that only your own devices " +
  "hold. {operator}'s servers never have that key, so the stored mail is " +
  "unreadable without it — to {operator}, to anyone who obtains a copy of the " +
  "database, and to anyone who asks {operator} for it. " +
  "Two honest limits: like every email service, the platform's software handles " +
  "each message in readable form for the moment it arrives and the moment you " +
  "send one, and does not keep it that way. And the inbox runs in your browser " +
  "from code {operator} serves, so a changed version of that code could read " +
  "what you read.";

/** Spec 002 §5: shown under "How your mail is protected" whenever the mailbox has kept devices. */
const DEVICES =
  "A device you keep unlocked opens your mail without your security key, until " +
  "it locks or you remove it. Anyone who has it while it is unlocked can read " +
  "your mail, as with any mail app. Its own screen lock and disk encryption " +
  "protect it when you are away. If a device is lost, remove it from another " +
  "device or with your recovery key. It stops working at once, and new mail uses " +
  "a new key it never gets. If you lose every device, every security key and " +
  "your recovery key, nobody can open your mail, not even {operator}.";

export const PROTECTION: ProtectionTexts = Object.freeze({
  optionA(operator: string): string {
    return OPTION_A.replaceAll("{operator}", String(operator));
  },
  devices(operator: string): string {
    return DEVICES.replaceAll("{operator}", String(operator));
  },
  metadata: Object.freeze([
    {
      what: "That a message arrived, when, how large, for which mailbox",
      where: "Mailbox storage (plaintext columns)",
      why: "Sorting, quotas, the unread count",
    },
    { what: "Folder, read and starred flags", where: "Mailbox storage", why: "Set by the owner's own actions" },
    {
      what: "Envelope sender and recipient of arriving mail",
      where: "Cloudflare's Email Routing, in transit (whether its activity log shows them is unverified)",
      why: "That is how SMTP delivery works",
    },
    { what: "The full message, in transit, for the moment of arrival", where: "Mail Worker memory", why: "Encryption happens there, immediately" },
    {
      what: "Recipients and subject of mail the owner sends, and the full message for the moment of sending",
      where:
        "Mail Worker memory, and the dashboard Worker's memory (its server action passes the composed message on); " +
        "SES delivery events include `commonHeaders` with the subject (AWS event-publishing examples, checked 2026-09-26)",
      why: "SES needs the message to send it; SES reports what it delivered",
    },
    { what: "That a new message arrived (a count, never content)", where: "The per-business dashboard Agent, for Web Push", why: "So the phone can buzz" },
    {
      what: "Which devices and recovery keys exist (labels and times, not the secrets)",
      where: "Mailbox key ring",
      why: "So the owner can manage devices",
    },
    // Spec 002 §5 adds these rows.
    {
      what: "Which devices are kept, their names, their public keys, the sealed copies of the mailbox key made for them, and when each last opened a session",
      where: "Mailbox key ring",
      why: "So the owner can see and remove them, and so Mail can refuse a removed one",
    },
    {
      what: "When an inbox session opened and ended, and from which kept device",
      where: "Mailbox storage",
      why: "Sessions last an hour; a removed device's sessions end with it",
    },
    {
      what: "Each factor's public key",
      where: "Mailbox key ring",
      why: "So a new key can reach a factor that is not present, and so Mail can check a factor without its secret",
    },
  ]),
});
