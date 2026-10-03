/**
 * The plaintexts inside the blocks: MessageHeader and Draft as UTF-8 JSON
 * (contracts/envelope-v1.md "MessageHeader", "Draft").
 */
import { fromUtf8, utf8 } from "./bytes";
import { DecryptionFailed } from "./errors";
import type { Draft, MessageHeader } from "./index";

export const HEADER_JSON_MAX_BYTES = 64 * 1024;
const REFERENCES_KEPT = 20;

const HEADER_KEYS = [
  "v", "direction", "envelopeFrom", "envelopeTo", "from", "to", "cc", "bcc", "replyTo", "subject",
  "date", "messageId", "inReplyTo", "references", "snippet", "attachments",
] as const satisfies readonly (keyof MessageHeader)[];

const DRAFT_KEYS = [
  "v", "to", "cc", "bcc", "subject", "text", "inReplyTo", "references", "updatedAt",
] as const satisfies readonly (keyof Draft)[];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasEveryKey(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return keys.every((k) => Object.hasOwn(value, k) && value[k] !== undefined);
}

function assertShape(value: unknown, keys: readonly string[], what: string): asserts value is Record<string, unknown> {
  if (!isRecord(value) || value.v !== 1 || !hasEveryKey(value, keys)) {
    throw new TypeError(`a ${what} v1 has every one of these keys: ${keys.join(", ")}`);
  }
}

/**
 * UTF-8 JSON of a MessageHeader, at most 64 KiB. If it would be larger, the
 * contract's rule applies: `references` keeps its last 20 entries, then
 * `snippet` is shortened (by whole code points, only as far as needed). A
 * header still too large after both is refused: the contract names nothing
 * else to drop.
 */
export function serializeHeader(header: MessageHeader): Uint8Array<ArrayBuffer> {
  assertShape(header, HEADER_KEYS, "MessageHeader");
  if (header.direction !== "in" && header.direction !== "out") throw new TypeError('direction is "in" or "out"');
  let json = utf8(JSON.stringify(header));
  if (json.length <= HEADER_JSON_MAX_BYTES) return json;

  const trimmed: MessageHeader = { ...header, references: header.references.slice(-REFERENCES_KEPT) };
  json = utf8(JSON.stringify(trimmed));
  if (json.length <= HEADER_JSON_MAX_BYTES) return json;

  // The longest snippet prefix that fits: binary search over code points.
  const chars = Array.from(trimmed.snippet);
  const withSnippet = (n: number) => utf8(JSON.stringify({ ...trimmed, snippet: chars.slice(0, n).join("") }));
  let lo = 0;
  let hi = chars.length;
  if (withSnippet(0).length > HEADER_JSON_MAX_BYTES) {
    throw new RangeError("MessageHeader JSON is over 64 KiB even with 20 references and an empty snippet");
  }
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    if (withSnippet(mid).length <= HEADER_JSON_MAX_BYTES) lo = mid;
    else hi = mid - 1;
  }
  return withSnippet(lo);
}

export function serializeDraft(draft: Draft): Uint8Array<ArrayBuffer> {
  assertShape(draft, DRAFT_KEYS, "Draft");
  return utf8(JSON.stringify(draft));
}

function parse(bytes: Uint8Array, keys: readonly string[]): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(fromUtf8(bytes));
  } catch {
    throw new DecryptionFailed("the decrypted block is not valid JSON");
  }
  // Unknown keys are kept and ignored (forward compatibility inside v1).
  if (!isRecord(value) || value.v !== 1 || !hasEveryKey(value, keys)) {
    throw new DecryptionFailed("the decrypted block is not a v1 plaintext");
  }
  return value;
}

export function parseHeader(bytes: Uint8Array): MessageHeader {
  return parse(bytes, HEADER_KEYS) as unknown as MessageHeader;
}

export function parseDraft(bytes: Uint8Array): Draft {
  return parse(bytes, DRAFT_KEYS) as unknown as Draft;
}
