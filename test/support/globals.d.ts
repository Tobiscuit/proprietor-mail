// Types `exports` from "cloudflare:workers" in tests: the loopback bindings to
// this Worker's own entrypoints, which call them through real RPC.
declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import("../../src/index");
    durableNamespaces: "Mailbox";
  }
}
