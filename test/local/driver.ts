import * as mailCrypto from "@platform-mail/crypto";
import type { MailError } from "../../src/errors";
import type { MailService } from "../../src/service";
import { base64urlFromBytes, canonicalClaims, canonicalHeader, randomJti, signToken, bytesFromBase64url } from "../support/capability-tokens";
import { testId } from "../support/ids";
import { TEST_KEY_B64URL, TEST_KID } from "../support/test-keys";

/**
 * The dashboard's part in a LOCAL end-to-end run (test/README.md), nothing
 * more: it mints capabilities with the public TEST key (the one in
 * contracts/capability-v1.vectors.json) and calls MailService over a real
 * service binding, as spec 007's server actions will.
 *
 *   POST /enroll?tenant=…&mbx=…   the owner's setup: a key pair and a recovery wrap
 *   GET  /list?tenant=…&mbx=…     what MailService returns: ids, sizes, ciphertext
 *   GET  /open?tenant=…&mbx=…     the browser's part: decrypt the newest message
 *   GET  /refuse?tenant=…&mbx=…   an expired capability: the refusal, as the value it arrives as
 *
 * Mail answers with MailResult values (contracts/mail-service-v1.md); a
 * refusal is shown as `{ refused: { name, message, … } }` with status 409.
 *
 * With S1 merged the key pair is S1's and /open decrypts with the private key
 * this process keeps in memory. Before S1, enrolment uses a Web Crypto X25519
 * key and a wrap-shaped placeholder, and nothing can be opened (nor sealed).
 */
interface Env {
  MAIL: Service<MailService>;
}

const privateKeys = new Map<string, mailCrypto.MailboxPrivateKey>();

async function capability(tenant: string, mbx: string): Promise<string> {
  const claims = canonicalClaims({ sub: "acc_local_owner", tenant, mbx, role: "owner", iat: Math.floor(Date.now() / 1000), jti: randomJti() });
  return signToken(canonicalHeader(TEST_KID), claims, bytesFromBase64url(TEST_KEY_B64URL));
}

async function enrolment(mbx: string) {
  if (mailCrypto.IMPLEMENTED) {
    const { publicKey, privateKey } = await mailCrypto.generateMailboxKey();
    privateKeys.set(mbx, privateKey);
    const recovery = mailCrypto.newRecoveryKey();
    const wrap = await mailCrypto.wrapPrivateKey(privateKey, { mailboxId: mbx, wrapId: mailCrypto.newId("wrp"), kind: "recovery", secret: recovery.secret }); // pragma: allowlist secret (S1's parameter name)
    return { publicKey: base64urlFromBytes(publicKey.publicKey), wraps: [{ ...wrap, label: "Recovery key (local run)" }] };
  }
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKey = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  const keyId = [...digest.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const wrapped = new Uint8Array(61);
  wrapped[0] = 1;
  return {
    publicKey: base64urlFromBytes(publicKey),
    wraps: [{ id: testId("wrp"), keyId, kind: "recovery", label: "Placeholder (S1 not merged)", wrapped: base64urlFromBytes(wrapped) }],
  };
}

/** A refusal from Mail, shown as the dashboard would branch on it: the error's name and fields, never an exception. */
function refusal(error: MailError): Response {
  return Response.json({ refused: error }, { status: 409 });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const tenant = url.searchParams.get("tenant") ?? "";
    const mbx = url.searchParams.get("mbx") ?? "";
    try {
      if (url.pathname === "/enroll" && request.method === "POST") {
        const enrolled = await env.MAIL.enroll(await capability(tenant, mbx), await enrolment(mbx));
        return enrolled.ok ? Response.json(enrolled.value) : refusal(enrolled.error);
      }
      if (url.pathname === "/list") {
        const page = await env.MAIL.list(await capability(tenant, mbx), { folder: url.searchParams.get("folder") ?? "inbox" });
        if (!page.ok) return refusal(page.error);
        return Response.json(page.value.items.map((i) => ({ id: i.id, folder: i.folder, size: i.size, receivedAt: i.receivedAt, keyId: i.keyId, sealedHeaderChars: i.header.length })));
      }
      if (url.pathname === "/open") {
        const ownerKey = privateKeys.get(mbx);
        if (ownerKey === undefined) return Response.json({ error: "no private key in this process (S1 not merged, or not enrolled here)" }, { status: 409 });
        const page = await env.MAIL.list(await capability(tenant, mbx), { folder: "inbox" });
        if (!page.ok) return refusal(page.error);
        const [item] = page.value.items;
        if (item === undefined) return Response.json({ error: "inbox is empty" }, { status: 404 });
        const ids = { mailboxId: mbx, messageId: item.id };
        const header = await mailCrypto.openHeader(ownerKey, ids, item);
        // The body arrives as the value of an ok answer: a ReadableStream inside the result.
        const body = await env.MAIL.body(await capability(tenant, mbx), item.id);
        if (!body.ok) return refusal(body.error);
        const sealed = new Uint8Array(await new Response(body.value).arrayBuffer());
        const raw = await mailCrypto.openBody(ownerKey, ids, { keyEnvelope: item.keyEnvelope, body: sealed });
        return Response.json({ id: item.id, subject: header.subject, from: header.from, snippet: header.snippet, rawBytes: raw.byteLength });
      }
      if (url.pathname === "/refuse") {
        // A refusal across two processes: an expired capability comes back as a value, name and reason intact.
        const expired = canonicalClaims({ sub: "acc_local_owner", tenant, mbx, role: "owner", iat: Math.floor(Date.now() / 1000) - 120, jti: randomJti() });
        const answer = await env.MAIL.list(await signToken(canonicalHeader(TEST_KID), expired, bytesFromBase64url(TEST_KEY_B64URL)), { folder: "inbox" });
        return Response.json(answer);
      }
      return new Response("not found", { status: 404 });
    } catch (err) {
      // Only the binding or the runtime failing lands here; Mail itself answers with values.
      return Response.json({ bindingFailed: (err as Error).name }, { status: 502 });
    }
  },
};
