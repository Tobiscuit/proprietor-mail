import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

// S2a: the harness itself. Each binding is the real local simulation, and the
// Worker has no HTTP surface.
describe("harness", () => {
  it("answers 404 to every HTTP request: no public surface", async () => {
    for (const path of ["/", "/api/v1/mailboxes", "/cdn-cgi/anything", "/mcp"]) {
      const res = await exports.default.fetch(new Request(`https://proprietor-mail.test${path}`));
      expect(res.status).toBe(404);
      await res.body?.cancel();
    }
  });

  it("has a real D1 with the Directory migration applied", async () => {
    const { results } = await env.DIRECTORY.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'mailboxes'",
    ).all<{ name: string }>();
    expect(results.map((r) => r.name)).toEqual(["mailboxes"]);
  });

  it("has a real R2 bucket", async () => {
    await env.MAIL.put("harness/probe", new Uint8Array([1, 2, 3]));
    const obj = await env.MAIL.get("harness/probe");
    expect(new Uint8Array(await obj!.arrayBuffer())).toEqual(new Uint8Array([1, 2, 3]));
    await env.MAIL.delete("harness/probe");
  });

  it("binds the Mailbox Durable Object namespace", () => {
    expect(typeof env.Mailbox.idFromName).toBe("function");
  });
});
