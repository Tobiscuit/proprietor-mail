/**
 * Captures every console line, from any request context in this isolate (the
 * test, the Worker's entrypoints and its Durable Objects share it).
 *
 * Plain function replacement rather than `vi.spyOn`: a vitest spy called from
 * another request context (a MailService call through `exports`) makes workerd
 * report that request as hung.
 */
const METHODS = ["log", "info", "warn", "error", "debug"] as const;

export interface CapturedConsole {
  lines: string[];
  restore(): void;
}

export function captureConsole(opts: { passThrough?: boolean } = {}): CapturedConsole {
  const lines: string[] = [];
  const originals = METHODS.map((m) => [m, console[m]] as const);
  for (const [method, original] of originals) {
    console[method] = (...args: unknown[]) => {
      lines.push(args.map((a) => (typeof a === "string" ? a : a instanceof Error ? `${a.name}: ${a.message}\n${a.stack ?? ""}` : safeJson(a))).join(" "));
      if (opts.passThrough) original.apply(console, args);
    };
  }
  return {
    lines,
    restore() {
      for (const [method, original] of originals) console[method] = original;
    },
  };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
