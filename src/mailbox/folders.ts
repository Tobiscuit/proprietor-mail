// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
//     https://opensource.org/licenses/Apache-2.0
//
// Modified by Operator, 2026-09: adapted from agentic-inbox's shared/folders.ts.
// The drafts folder's id is `drafts` (plan.md §3), the six system folders are
// seeded by the Mailbox schema and are fixed (domain-model M8), and the
// display-name helpers and tool descriptions were dropped (the UI is elsewhere).

/**
 * Canonical folder ID constants: the single source of truth for folder ids in
 * the Mail Worker, so no magic strings are scattered around.
 */
export const Folders = {
  INBOX: "inbox",
  SENT: "sent",
  DRAFTS: "drafts",
  ARCHIVE: "archive",
  TRASH: "trash",
  SPAM: "spam",
} as const;

export type FolderId = (typeof Folders)[keyof typeof Folders];

/** Seeded in this order; each always exists and cannot be renamed or deleted (M8). */
export const SYSTEM_FOLDERS: readonly { id: FolderId; name: string }[] = [
  { id: Folders.INBOX, name: "Inbox" },
  { id: Folders.SENT, name: "Sent" },
  { id: Folders.DRAFTS, name: "Drafts" },
  { id: Folders.ARCHIVE, name: "Archive" },
  { id: Folders.TRASH, name: "Trash" },
  { id: Folders.SPAM, name: "Spam" },
];
