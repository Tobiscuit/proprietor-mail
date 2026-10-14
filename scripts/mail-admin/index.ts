/**
 * The operator's MailAdmin tool (tasks.md S8). Local only:
 *
 *   npx wrangler dev -c scripts/mail-admin/wrangler.jsonc --ip 127.0.0.1 --port 8798
 *
 * then one POST per action, a JSON body as MailAdmin takes it:
 *
 *   curl -s localhost:8798/setDelivery -d '{"mailboxId":"mbx_…","operator":"you","delivery":"store-and-forward","forwardTo":"you@example.com"}'
 *   curl -s localhost:8798/suspend -d '{"mailboxId":"mbx_…","operator":"you"}'
 *   curl -s localhost:8798/resume -d '{"mailboxId":"mbx_…","operator":"you"}'
 *
 * It answers MailAdmin's MailResult as it came: refusals are values
 * (contracts/mail-service-v1.md). Every change is written to the mailbox's
 * audit log, which the owner reads.
 */

export interface AdminBinding {
  suspend(input: { mailboxId: string; operator: string }): Promise<unknown>;
  resume(input: { mailboxId: string; operator: string }): Promise<unknown>;
  setDelivery(input: { mailboxId: string; operator: string; delivery: string; forwardTo?: string | null }): Promise<unknown>;
}

export const ACTIONS = ["suspend", "resume", "setDelivery"] as const;
type Action = (typeof ACTIONS)[number];

const isAction = (name: string): name is Action => (ACTIONS as readonly string[]).includes(name);

export default {
  async fetch(request: Request, env: { ADMIN: AdminBinding }): Promise<Response> {
    const action = new URL(request.url).pathname.slice(1);
    if (request.method !== "POST" || !isAction(action)) {
      return Response.json({ ok: false, error: `POST /${ACTIONS.join(", /")} with a JSON body` }, { status: 404 });
    }
    let input: unknown;
    try {
      input = await request.json();
    } catch {
      return Response.json({ ok: false, error: "the body must be JSON" }, { status: 400 });
    }
    if (typeof input !== "object" || input === null) {
      return Response.json({ ok: false, error: "the body must be a JSON object" }, { status: 400 });
    }
    // MailAdmin checks its own input and answers a refusal as a value.
    switch (action) {
      case "suspend":
        return Response.json(await env.ADMIN.suspend(input as Parameters<AdminBinding["suspend"]>[0]));
      case "resume":
        return Response.json(await env.ADMIN.resume(input as Parameters<AdminBinding["resume"]>[0]));
      case "setDelivery":
        return Response.json(await env.ADMIN.setDelivery(input as Parameters<AdminBinding["setDelivery"]>[0]));
    }
  },
};
