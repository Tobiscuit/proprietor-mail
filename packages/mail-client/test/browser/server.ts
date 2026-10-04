// A test server: the harness page under the dashboard's exact policy (plan.md §1, round 2) with
// Trusted Types enforced, the bundled harness as its one nonce-stamped module script, and a
// remote image that counts how often anything fetched it (it must stay at zero).
import { randomBytes } from "node:crypto";
import { createServer, type Server } from "node:http";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

export const POLICY_NAME = "proprietor-mail#srcdoc";

/** The dashboard's policy as its maintainers committed to it, plus what this page needs to exist at all. */
export function policyFor(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'nonce-${nonce}'`,
    "img-src 'self' data: blob:",
    "connect-src 'self'",
    "frame-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'",
    "require-trusted-types-for 'script'",
    `trusted-types ${POLICY_NAME}`,
  ].join("; ");
}

export interface TestServer {
  origin: string;
  host: string;
  nonce: string;
  remoteImageHits(): number;
  close(): Promise<void>;
}

const PNG_1x1 = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==", "base64");

async function bundleHarness(): Promise<string> {
  const entry = resolve(dirname(fileURLToPath(import.meta.url)), "harness.ts");
  const result = await build({
    entryPoints: [entry],
    bundle: true,
    format: "esm",
    platform: "browser",
    target: "es2022",
    write: false,
    sourcemap: false,
    logLevel: "silent",
  });
  return result.outputFiles[0]!.text;
}

export async function startTestServer(): Promise<TestServer> {
  const nonce = randomBytes(16).toString("base64");
  const script = await bundleHarness();
  let hits = 0;
  const page =
    `<!DOCTYPE html><html><head><meta charset="utf-8"><title>mail-client harness</title></head><body>` +
    // A server-rendered element with a nonce attribute: not a script, so pageNonce() must ignore it.
    `<div id="decoy" nonce="not-the-nonce"></div><p id="status">loading</p>` +
    `<script type="module" nonce="${nonce}" src="/harness.js"></script></body></html>`;
  const server: Server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "content-security-policy": policyFor(nonce), "cache-control": "no-store" });
      res.end(page);
    } else if (url.pathname === "/harness.js") {
      res.writeHead(200, { "content-type": "text/javascript; charset=utf-8", "cache-control": "no-store" });
      res.end(script);
    } else if (url.pathname === "/remote.png") {
      hits += 1;
      res.writeHead(200, { "content-type": "image/png", "cache-control": "no-store" });
      res.end(PNG_1x1);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("no port");
  // WebAuthn needs a secure context, and the RP ID must be the page's host: http://localhost is one.
  const host = "localhost";
  return {
    origin: `http://${host}:${address.port}`,
    host,
    nonce,
    remoteImageHits: () => hits,
    close: () => new Promise<void>((ok, fail) => server.close((e) => (e ? fail(e) : ok()))),
  };
}
