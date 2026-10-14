import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

import tool, { ACTIONS, type AdminBinding } from "../../scripts/mail-admin/index";

const fake = (): AdminBinding & { [K in keyof AdminBinding]: ReturnType<typeof vi.fn> } => ({
  suspend: vi.fn(async () => ({ ok: true, value: { status: "suspended" } })),
  resume: vi.fn(async () => ({ ok: true, value: { status: "active" } })),
  setDelivery: vi.fn(async () => ({ ok: false, error: { name: "NotFound", message: "no such mailbox" } })),
});

const post = (path: string, body: string) => new Request(`http://127.0.0.1:8798/${path}`, { method: "POST", body });

describe("the operator's MailAdmin tool (tasks.md S8)", () => {
  it("passes each action's JSON to the same-named MailAdmin method and answers its result as it came", async () => {
    const admin = fake();
    const input = { mailboxId: "mbx_1", operator: "op", delivery: "store-and-forward", forwardTo: "owner@example.com" };
    const response = await tool.fetch(post("setDelivery", JSON.stringify(input)), { ADMIN: admin });
    expect(admin.setDelivery).toHaveBeenCalledWith(input);
    expect(await response.json()).toEqual({ ok: false, error: { name: "NotFound", message: "no such mailbox" } });
    await tool.fetch(post("suspend", JSON.stringify({ mailboxId: "mbx_1", operator: "op" })), { ADMIN: admin });
    expect(admin.suspend).toHaveBeenCalledOnce();
  });

  it("calls nothing for an unknown action, a GET, or a body that is not a JSON object", async () => {
    const admin = fake();
    expect((await tool.fetch(post("close", "{}"), { ADMIN: admin })).status).toBe(404);
    expect((await tool.fetch(new Request("http://127.0.0.1:8798/suspend"), { ADMIN: admin })).status).toBe(404);
    expect((await tool.fetch(post("resume", "not json"), { ADMIN: admin })).status).toBe(400);
    expect((await tool.fetch(post("resume", "42"), { ADMIN: admin })).status).toBe(400);
    for (const name of ACTIONS) expect(admin[name]).not.toHaveBeenCalled();
  });

  it("is never deployed: it binds MailAdmin remotely, and nothing else", () => {
    const raw = readFileSync(path.resolve(import.meta.dirname, "../../scripts/mail-admin/wrangler.jsonc"), "utf8").replace(/^\s*\/\/.*$/gm, "");
    const config = JSON.parse(raw) as { services: unknown[]; workers_dev: boolean; routes?: unknown };
    expect(config.services).toEqual([{ binding: "ADMIN", service: "proprietor-mail", entrypoint: "MailAdmin", remote: true }]);
    expect(config.workers_dev).toBe(false);
    expect(config.routes).toBeUndefined();
  });
});
