# platform-mail

The platform's **Inbox module**: one mailbox per business, read inside the one
dashboard, with client mail that the operator cannot read at rest.

- Inbound: Cloudflare Email Routing → this Worker's `email()` handler →
  `routeAgentEmail` → one `Mailbox` Durable Object per mailbox, which encrypts
  every arriving message to the mailbox's public key before storing it.
- Reading: the dashboard (spec 007, in the SEO-engine repo) calls this
  Worker's `MailService` entrypoint over a service binding with a short-lived
  signed capability; ciphertext comes back and is decrypted in the owner's
  browser.
- Outbound: Amazon SES (raw MIME), one SES tenant per business.

Start with `specs/001-inbox-module/spec.md` (what and why, and the decisions
that belong to the maintainer), then `domain-model.md`, `plan.md` and `tasks.md`.
The two contracts other repositories implement are in `contracts/`.

Parts of this repository are adapted from
[cloudflare/agentic-inbox](https://github.com/cloudflare/agentic-inbox)
under the Apache License 2.0; see `NOTICE` and `LICENSES/Apache-2.0.txt`.

## Layout

    specs/001-inbox-module/   spec, domain model, plan, tasks
    contracts/                capability v1 (dashboard ↔ Mail), envelope v1 (Worker ↔ browser)
    packages/mail-crypto/     envelope v1 + key wrapping; runs in the browser and the Worker
    packages/mail-outbound/   MIME builder + SES v2 raw sender
    src/, test/, migrations/  the Mail Worker (slice S2)
