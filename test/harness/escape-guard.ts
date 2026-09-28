import type { Plugin } from "vite";
import type { Reporter, TestCase, TestModule, TestRunEndReason } from "vitest/node";

/**
 * THE ESCAPE GUARD: `npm test` fails when workerd reports an exception that
 * escaped (an RPC method that threw, or an invocation cancelled as "hung"),
 * unless the test that caused it declared it.
 *
 * Why it reads the terminal. When a Workers RPC method throws, workerd itself
 * prints `uncaught exception; source = Uncaught (in promise); stack = …` for
 * the callee, and for an entrypoint also `uncaught exception; exception = …
 * your Worker's code had hung and would never generate a response`. Nothing
 * inside the isolate sees these: an `unhandledrejection` listener in the test
 * isolate stays silent for them (it does fire for a plain unhandled
 * rejection), so vitest's own unhandled-error policy (on by default, off only
 * with `dangerouslyIgnoreUnhandledErrors`) never hears of them, and neither
 * would a listener of ours. @cloudflare/vitest-pool-workers 0.22.0 gives no
 * hook either: its miniflare (5.20260815.0-alpha) has no `handleRuntimeStdio`
 * any more, and the pool sets miniflare's shared `handleStructuredLogs` itself
 * (user options only reach the runner worker), writing every message to this
 * process's stdout or stderr. So the guard reads those two streams.
 *
 * How a test declares an escape: `expectEmailThrow` (test/support/escapes.ts)
 * records it in the test's `task.meta`, which reaches this process with the
 * test's result. It is the only declaration there is, for the one handler
 * that throws on purpose: `email()` failing a delivery (plan.md §5). A
 * declaration names text that appears in the escaped error's first line and
 * how many lines workerd prints for it; the verdict matches each escape line
 * to a declaration by that text and demands the exact count, so a declaration
 * cannot excuse anything else, and a declared escape that stops appearing
 * (for instance because the pool stopped printing) fails the run too. A
 * "hung" cancellation can never be declared.
 */

export const ESCAPE_MARKER = "uncaught exception;";
export const HUNG_TEXT = "had hung and would never generate a response";
/** The one kind of declaration the guard accepts. */
export const EMAIL_THROW = "email() throws on purpose (plan.md §5)";

export interface DeclaredEscape {
  kind: typeof EMAIL_THROW;
  /** Why this escape is expected, in words: which failure, in which delivery mode. */
  reason: string;
  /** Text in the escaped error's first line: the test's own marker, or the fixed text of the failure it injects. */
  error: string;
  /** How many escape lines workerd prints for it: one for each RPC hop the throw crosses. */
  lines: number;
}

export interface Declaration extends DeclaredEscape {
  /** The declaring test: module and full name. */
  test: string;
}

/** One escape line as workerd printed it: its first line, and the stack lines under it (for the report). */
export interface Escape {
  line: string;
  detail: string[];
}

export interface Verdict {
  escapes: number;
  /** Escape lines that no declaration covers. */
  undeclared: Escape[];
  /** Declarations whose count of lines was not exactly met. */
  unmet: { declaration: Declaration; seen: number }[];
  /** Declarations the guard does not accept (another kind, or without a reason). */
  invalid: { declaration: unknown; test: string; problem: string }[];
  declared: { declaration: Declaration; seen: number }[];
}

const ANSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;

/**
 * The escape lines in one chunk of terminal output. The pool writes one
 * message per write, but vitest's TTY renderer may join several into one
 * chunk, so every line is looked at.
 */
export function escapesIn(chunk: string): Escape[] {
  const found: Escape[] = [];
  for (const raw of chunk.split("\n")) {
    const line = raw.replace(ANSI, "").replace(/\r$/, "");
    if (line.startsWith(ESCAPE_MARKER)) found.push({ line, detail: [] });
    else if (found.length > 0 && line.trim() !== "") found.at(-1)!.detail.push(line);
  }
  return found;
}

export function isHung(escape: Escape): boolean {
  return escape.line.includes(HUNG_TEXT);
}

/** The accepted declarations of one test, and what is wrong with the others. */
export function readDeclarations(test: string, meta: unknown): { valid: Declaration[]; invalid: Verdict["invalid"] } {
  const valid: Declaration[] = [];
  const invalid: Verdict["invalid"] = [];
  const escapes = (meta as { escapes?: unknown } | undefined)?.escapes;
  if (escapes === undefined) return { valid, invalid };
  if (!Array.isArray(escapes)) return { valid, invalid: [{ declaration: escapes, test, problem: "escapes is not a list" }] };
  for (const d of escapes as Partial<DeclaredEscape>[]) {
    const problem =
      d?.kind !== EMAIL_THROW
        ? `the only declaration allowed is "${EMAIL_THROW}"`
        : typeof d.reason !== "string" || d.reason.trim().length < 10
          ? "a declaration needs a reason"
          : typeof d.error !== "string" || d.error.length < 8
            ? "a declaration needs the error text it expects (8 characters or more)"
            : !Number.isInteger(d.lines) || (d.lines as number) < 1
              ? "a declaration needs how many lines it expects"
              : null;
    if (problem === null) valid.push({ ...(d as DeclaredEscape), test });
    else invalid.push({ declaration: d, test, problem });
  }
  return { valid, invalid };
}

export function verdict(escapes: Escape[], declarations: Declaration[], invalid: Verdict["invalid"] = []): Verdict {
  const seen = new Map<Declaration, number>(declarations.map((d) => [d, 0]));
  const undeclared: Escape[] = [];
  for (const escape of escapes) {
    // A "hung" cancellation is never declared: it is the runtime's own verdict on an invocation.
    const owner = isHung(escape)
      ? undefined
      : declarations.find((d) => escape.line.includes(d.error) && (seen.get(d) ?? 0) < d.lines);
    if (owner === undefined) undeclared.push(escape);
    else seen.set(owner, (seen.get(owner) ?? 0) + 1);
  }
  const counted = declarations.map((declaration) => ({ declaration, seen: seen.get(declaration) ?? 0 }));
  return {
    escapes: escapes.length,
    undeclared,
    unmet: counted.filter((c) => c.seen !== c.declaration.lines),
    invalid,
    declared: counted,
  };
}

export function failed(v: Verdict): boolean {
  return v.undeclared.length > 0 || v.unmet.length > 0 || v.invalid.length > 0;
}

export function report(v: Verdict): string {
  const declaredLines = v.declared.reduce((n, d) => n + d.seen, 0);
  if (!failed(v)) {
    return `escape guard: ${v.escapes} escaped exception line(s) from workerd, ${declaredLines} declared by ${v.declared.length} test(s) (${EMAIL_THROW}); none undeclared\n`;
  }
  const out = [
    "",
    "escape guard: FAILED. workerd reported exceptions that escaped an RPC hop, and no test declared them.",
    "  A refusal must be answered as a value (contracts/mail-service-v1.md); only email() may throw, on purpose (plan.md §5),",
    "  and a test that makes it throw declares it with expectEmailThrow (test/support/escapes.ts).",
  ];
  if (v.undeclared.length > 0) {
    out.push("", `  ${v.undeclared.length} undeclared escape line(s):`);
    v.undeclared.forEach((e, i) => {
      out.push(`   ${i + 1}) ${e.line}`);
      for (const d of e.detail.slice(0, 6)) out.push(`        ${d.trim()}`);
    });
  }
  if (v.unmet.length > 0) {
    out.push("", "  declared escapes that did not print exactly as declared (a guard that cannot see workerd would pass everything):");
    for (const { declaration, seen } of v.unmet) {
      out.push(`   - ${declaration.test}: expected ${declaration.lines} line(s) containing "${declaration.error}", saw ${seen}`);
    }
  }
  if (v.invalid.length > 0) {
    out.push("", "  declarations the guard does not accept:");
    for (const { test, problem } of v.invalid) out.push(`   - ${test}: ${problem}`);
  }
  out.push("");
  return `${out.join("\n")}\n`;
}

/**
 * The reporter half: collects declarations from each finished test and, at
 * the end of the run, judges every escape line seen. A failure sets the exit
 * code (vitest never lowers it) and prints the report.
 */
export class EscapeGuardReporter implements Reporter {
  readonly escapes: Escape[] = [];
  readonly declarations: Declaration[] = [];
  readonly invalid: Verdict["invalid"] = [];

  /** Each run is judged on its own lines (watch mode reruns). */
  onTestRunStart(): void {
    this.escapes.length = 0;
    this.declarations.length = 0;
    this.invalid.length = 0;
  }

  observe(chunk: unknown): void {
    const text = typeof chunk === "string" ? chunk : chunk instanceof Uint8Array ? new TextDecoder().decode(chunk) : "";
    if (text.includes(ESCAPE_MARKER)) this.escapes.push(...escapesIn(text));
  }

  onTestCaseResult(testCase: TestCase): void {
    const name = `${testCase.module.moduleId.replace(`${process.cwd()}/`, "")} > ${testCase.fullName}`;
    const { valid, invalid } = readDeclarations(name, testCase.meta());
    this.declarations.push(...valid);
    this.invalid.push(...invalid);
  }

  async onTestRunEnd(_modules: ReadonlyArray<TestModule>, _errors: ReadonlyArray<unknown>, reason: TestRunEndReason): Promise<void> {
    if (reason === "interrupted") return;
    // workerd's stdout is a pipe, and vitest's TTY renderer buffers what it
    // intercepts: give both a moment to deliver the last lines.
    await new Promise((resolve) => setTimeout(resolve, 300));
    const v = verdict(this.escapes, this.declarations, this.invalid);
    process.stderr.write(report(v));
    if (failed(v)) process.exitCode = 1;
  }
}

let installed: EscapeGuardReporter | undefined;

/**
 * The plugin half. `configureVitest` runs before vitest creates its reporters
 * and after the command line is read, so the guard is added whatever
 * `--reporter` says, and it wraps stdout and stderr before anything else does
 * (vitest's TTY renderer then forwards through the wrapper).
 */
export function escapeGuard(): Plugin {
  return {
    name: "proprietor-mail:escape-guard",
    configureVitest({ vitest }) {
      // A config restart (watch mode) builds new reporters: add the same guard again; the streams stay wrapped once.
      if (installed !== undefined) {
        vitest.config.reporters.push(installed);
        return;
      }
      const guard = new EscapeGuardReporter();
      installed = guard;
      for (const stream of [process.stdout, process.stderr]) {
        const write = stream.write.bind(stream) as (...args: unknown[]) => boolean;
        stream.write = ((chunk: unknown, ...rest: unknown[]) => {
          guard.observe(chunk);
          return write(chunk, ...rest);
        }) as typeof stream.write;
      }
      vitest.config.reporters.push(guard);
    },
  };
}
