import { describe, expect, it } from "vitest";
import {
  type Declaration,
  EMAIL_THROW,
  type Escape,
  EscapeGuardReporter,
  escapesIn,
  failed,
  readDeclarations,
  report,
  verdict,
} from "../harness/escape-guard";

// The escape guard's judgement, on the lines workerd really prints (copied
// from a run of this suite before refusals became values).
const UNCAUGHT_REFUSAL = [
  "uncaught exception; source = Uncaught (in promise); stack = NotFound: not found",
  "    at Mailbox.ensureIdentity (src/mailbox/mailbox.ts:773:68)",
  "",
].join("\n");
const HUNG = [
  "uncaught exception; exception = workerd/io/io-context.c++:1593: failed: jsg.Error: The Workers runtime canceled this request because it detected that your Worker's code had hung and would never generate a response. Refer to: https://developers.cloudflare.com/workers/observability/errors/",
  "stack: node_modules/@cloudflare/workerd-linux-64/bin/workerd@3566148",
  "",
].join("\n");
const R2_DOWN = [
  "uncaught exception; source = Uncaught (in promise); stack = Error: R2 is unavailable",
  "    at R2Bucket.failing.put (test/inbound.test.ts:40:13)",
  "",
].join("\n");

function declaration(over: Partial<Declaration> = {}): Declaration {
  return { kind: EMAIL_THROW, reason: "store mode: the R2 put failed", error: "R2 is unavailable", lines: 1, test: "t", ...over };
}

const lines = (...chunks: string[]): Escape[] => chunks.flatMap(escapesIn);

describe("escape guard: reading the terminal", () => {
  it("finds workerd's escape lines, with their stack, and nothing else", () => {
    expect(escapesIn(`stdout | test/a.test.ts > x\n${UNCAUGHT_REFUSAL}`)).toEqual([
      { line: "uncaught exception; source = Uncaught (in promise); stack = NotFound: not found", detail: ["    at Mailbox.ensureIdentity (src/mailbox/mailbox.ts:773:68)"] },
    ]);
    expect(escapesIn("  uncaught exception; indented, so quoted by someone, not printed by workerd\n")).toEqual([]);
  });

  it("finds each of several messages joined into one chunk, through colour codes", () => {
    const joined = `\u001b[2K${UNCAUGHT_REFUSAL}\u001b[31m${HUNG}\u001b[39m${R2_DOWN}`;
    expect(escapesIn(joined).map((e) => e.line.slice(0, 40))).toEqual([
      "uncaught exception; source = Uncaught (i",
      "uncaught exception; exception = workerd/",
      "uncaught exception; source = Uncaught (i",
    ]);
  });
});

describe("escape guard: the verdict", () => {
  it("passes a run with no escapes", () => {
    expect(failed(verdict([], []))).toBe(false);
  });

  it("fails on an undeclared uncaught exception, and on a hung cancellation", () => {
    expect(verdict(lines(UNCAUGHT_REFUSAL), []).undeclared).toHaveLength(1);
    expect(verdict(lines(HUNG), []).undeclared).toHaveLength(1);
    expect(failed(verdict(lines(UNCAUGHT_REFUSAL), []))).toBe(true);
  });

  it("accepts exactly the declared lines", () => {
    const v = verdict(lines(R2_DOWN), [declaration()]);
    expect(failed(v)).toBe(false);
    expect(v.declared).toEqual([{ declaration: declaration(), seen: 1 }]);
  });

  it("never lets a declaration excuse a hung cancellation, whatever its text", () => {
    const v = verdict(lines(HUNG), [declaration({ error: "had hung and would never" })]);
    expect(v.undeclared).toHaveLength(1);
    expect(v.unmet).toEqual([{ declaration: declaration({ error: "had hung and would never" }), seen: 0 }]);
  });

  it("fails when a declared escape prints more lines than declared: the extra one is undeclared", () => {
    const v = verdict(lines(R2_DOWN, R2_DOWN), [declaration()]);
    expect(v.undeclared).toHaveLength(1);
    expect(failed(v)).toBe(true);
  });

  it("fails when a declared escape prints fewer lines, or none: a guard that cannot see workerd must not pass", () => {
    expect(verdict([], [declaration()]).unmet).toEqual([{ declaration: declaration(), seen: 0 }]);
    expect(failed(verdict(lines(R2_DOWN), [declaration({ lines: 2 })]))).toBe(true);
  });

  it("does not let a declaration excuse a line without its text", () => {
    const v = verdict(lines(UNCAUGHT_REFUSAL), [declaration()]);
    expect(v.undeclared.map((e) => e.line)).toEqual(["uncaught exception; source = Uncaught (in promise); stack = NotFound: not found"]);
  });
});

describe("escape guard: declarations", () => {
  it("accepts the one kind, with a reason, the error text and a line count", () => {
    const meta = { escapes: [{ kind: EMAIL_THROW, reason: "store mode: the R2 put failed", error: "R2 is unavailable", lines: 1 }] };
    expect(readDeclarations("t", meta)).toEqual({ valid: [declaration()], invalid: [] });
    expect(readDeclarations("t", {})).toEqual({ valid: [], invalid: [] });
  });

  it("refuses any other kind, and a declaration without a reason, an error text or a count", () => {
    const base = { kind: EMAIL_THROW, reason: "store mode: the R2 put failed", error: "R2 is unavailable", lines: 1 };
    for (const bad of [
      { ...base, kind: "a refusal, just this once" },
      { ...base, reason: "" },
      { ...base, error: "" },
      { ...base, lines: 0 },
    ]) {
      expect(readDeclarations("t", { escapes: [bad] }).invalid).toHaveLength(1);
    }
    expect(failed(verdict([], [], readDeclarations("t", { escapes: [{ ...base, kind: "other" }] }).invalid))).toBe(true);
  });

  it("reports what failed, one escape per entry, and says nothing is wrong when nothing is", () => {
    const text = report(verdict(lines(UNCAUGHT_REFUSAL, HUNG), [declaration()]));
    expect(text).toContain("escape guard: FAILED");
    expect(text).toContain("2 undeclared escape line(s)");
    expect(text).toContain('expected 1 line(s) containing "R2 is unavailable", saw 0');
    // Indented, so the report itself never reads as an escape.
    expect(escapesIn(text)).toEqual([]);
    expect(report(verdict(lines(R2_DOWN), [declaration()]))).toMatch(/^escape guard: 1 escaped exception line\(s\) from workerd, 1 declared by 1 test\(s\)/);
  });
});

describe("escape guard: the reporter", () => {
  it("collects escape lines from what is written, and starts each run afresh", () => {
    const guard = new EscapeGuardReporter();
    guard.observe(new TextEncoder().encode(R2_DOWN));
    guard.observe(`vitest's own output\n${HUNG}`);
    guard.observe(42);
    expect(guard.escapes.map((e) => e.line.slice(0, 40))).toEqual([
      "uncaught exception; source = Uncaught (i",
      "uncaught exception; exception = workerd/",
    ]);
    guard.onTestRunStart();
    expect(guard.escapes).toEqual([]);
    expect(guard.declarations).toEqual([]);
  });
});
