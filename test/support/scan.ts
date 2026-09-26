import { subscribe, unsubscribe } from "node:diagnostics_channel";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import type { Mailbox } from "../../src/mailbox/mailbox";

/**
 * The M1 / M3 scanner: every place the Worker can leave something behind,
 * searched for a secret in every form it could take.
 *
 * Places: every table of the Mailbox's SQLite (the Agents SDK's own tables
 * included), its key-value storage, every table of the Directory, every R2
 * object, the captured console, and the Agents SDK's diagnostics channels
 * (which Tail Workers receive).
 *
 * Forms: the plain bytes, base64 and base64url at each of the three byte
 * alignments, quoted-printable (soft line breaks ignored), and lower-case hex.
 */

const utf8 = (s: string) => new TextEncoder().encode(s);

/** A byte string: one char per byte, so text and binary haystacks compare alike. */
export function byteString(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return out;
}

function base64(bytes: Uint8Array): string {
  return btoa(byteString(bytes)).replace(/=+$/, "");
}

function quotedPrintable(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b >= 33 && b <= 126 && b !== 61 ? String.fromCharCode(b) : `=${b.toString(16).toUpperCase().padStart(2, "0")}`;
  }
  return out;
}

export interface Form {
  form: string;
  needle: string;
}

export function formsOf(target: string | Uint8Array): Form[] {
  const bytes = typeof target === "string" ? utf8(target) : target;
  const forms: Form[] = [{ form: "plain", needle: byteString(bytes) }];
  for (let offset = 0; offset < 3; offset++) {
    const whole = bytes.subarray(offset, offset + 3 * Math.floor((bytes.length - offset) / 3));
    if (whole.length < 6) continue;
    const b64 = base64(whole);
    forms.push({ form: `base64@${offset}`, needle: b64 });
    forms.push({ form: `base64url@${offset}`, needle: b64.replace(/\+/g, "-").replace(/\//g, "_") });
  }
  forms.push({ form: "quoted-printable", needle: quotedPrintable(bytes) });
  forms.push({ form: "hex", needle: [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("") });
  return forms;
}

export interface Haystack {
  where: string;
  text: string;
}

export interface Finding {
  target: string;
  form: string;
  where: string;
}

export function search(haystacks: Haystack[], targets: Record<string, string | Uint8Array>): Finding[] {
  const findings: Finding[] = [];
  for (const h of haystacks) {
    const withoutSoftBreaks = h.text.replace(/=\r?\n/g, "");
    for (const [name, target] of Object.entries(targets)) {
      for (const { form, needle } of formsOf(target)) {
        const haystack = form === "quoted-printable" ? withoutSoftBreaks : h.text;
        if (haystack.includes(needle)) findings.push({ target: name, form, where: h.where });
      }
    }
  }
  return findings;
}

function valueText(value: unknown): string {
  if (value instanceof ArrayBuffer) return byteString(new Uint8Array(value));
  if (ArrayBuffer.isView(value)) return byteString(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
  if (typeof value === "string") return byteString(utf8(value));
  return byteString(utf8(JSON.stringify(value) ?? String(value)));
}

/** Everything the Mailbox's Durable Object holds: SQLite (all tables) and its key-value storage. */
export async function mailboxHaystacks(stub: DurableObjectStub<Mailbox>): Promise<Haystack[]> {
  return runInDurableObject(stub, async (_instance, state) => {
    const out: Haystack[] = [];
    const tables = state.storage.sql
      .exec("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'")
      .toArray()
      .map((r) => String(r.name));
    for (const table of tables) {
      for (const row of state.storage.sql.exec(`SELECT * FROM "${table}"`).toArray()) {
        out.push({ where: `mailbox sqlite ${table}`, text: Object.values(row).map(valueText).join("\u0000") });
      }
    }
    for (const [key, value] of await state.storage.list()) {
      out.push({ where: `mailbox kv ${key}`, text: `${key}\u0000${valueText(value)}` });
    }
    return out;
  });
}

export async function directoryHaystacks(): Promise<Haystack[]> {
  const out: Haystack[] = [];
  const { results: tables } = await env.DIRECTORY.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'",
  ).all<{ name: string }>();
  for (const { name } of tables) {
    const { results } = await env.DIRECTORY.prepare(`SELECT * FROM "${name}"`).all();
    for (const row of results) out.push({ where: `directory ${name}`, text: Object.values(row).map(valueText).join("\u0000") });
  }
  return out;
}

export async function r2Haystacks(): Promise<Haystack[]> {
  const out: Haystack[] = [];
  let cursor: string | undefined;
  do {
    const page = await env.MAIL.list(cursor === undefined ? {} : { cursor });
    for (const object of page.objects) {
      const body = await env.MAIL.get(object.key);
      out.push({ where: `r2 ${object.key}`, text: `${object.key}\u0000${byteString(new Uint8Array(await body!.arrayBuffer()))}` });
    }
    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor !== undefined);
  return out;
}

/** The Agents SDK's diagnostics channels (agents 0.24.0, observability/diagnostics). */
const CHANNELS = [
  "agents:state",
  "agents:rpc",
  "agents:message",
  "agents:chat",
  "agents:transcript",
  "agents:fiber",
  "agents:task",
  "agents:stream",
  "agents:agent_tool",
  "agents:schedule",
  "agents:lifecycle",
  "agents:workflow",
  "agents:mcp",
  "agents:email",
  "agents:channel",
];

export function captureDiagnostics(): { messages: Haystack[]; stop(): void } {
  const messages: Haystack[] = [];
  const handlers = CHANNELS.map((name) => {
    const handler = (message: unknown) => messages.push({ where: `diagnostics ${name}`, text: valueText(message) });
    subscribe(name, handler);
    return [name, handler] as const;
  });
  return {
    messages,
    stop() {
      for (const [name, handler] of handlers) unsubscribe(name, handler);
    },
  };
}
