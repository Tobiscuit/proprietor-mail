import * as mailCrypto from "@platform-mail/crypto";
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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const tenant = url.searchParams.get("tenant") ?? "";
    const mbx = url.searchParams.get("mbx") ?? "";
    try {
      if (url.pathname === "/enroll" && request.method === "POST") {
        return Response.json(await env.MAIL.enroll(await capability(tenant, mbx), await enrolment(mbx)));
      }
      if (url.pathname === "/list") {
        const page = await env.MAIL.list(await capability(tenant, mbx), { folder: url.searchParams.get("folder") ?? "inbox" });
        return Response.json(page.items.map((i) => ({ id: i.id, folder: i.folder, size: i.size, receivedAt: i.receivedAt, keyId: i.keyId, sealedHeaderChars: i.header.length })));
      }
      if (url.pathname === "/open") {
        const ownerKey = privateKeys.get(mbx);
        if (ownerKey === undefined) return Response.json({ error: "no private key in this process (S1 not merged, or not enrolled here)" }, { status: 409 });
        const [item] = (await env.MAIL.list(await capability(tenant, mbx), { folder: "inbox" })).items;
        if (item === undefined) return Response.json({ error: "inbox is empty" }, { status: 404 });
        const ids = { mailboxId: mbx, messageId: item.id };
        const header = await mailCrypto.openHeader(ownerKey, ids, item);
        const sealed = new Uint8Array(await new Response(await env.MAIL.body(await capability(tenant, mbx), item.id)).arrayBuffer());
        const raw = await mailCrypto.openBody(ownerKey, ids, { keyEnvelope: item.keyEnvelope, body: sealed });
        return Response.json({ id: item.id, subject: header.subject, from: header.from, snippet: header.snippet, rawBytes: raw.byteLength });
      }
      return new Response("not found", { status: 404 });
    } catch (err) {
      const e = err as Error & { reason?: string };
      return Response.json({ error: e.name, message: e.message, reason: e.reason ?? null }, { status: 500 });
    }
  },
};
