# @proprietor/mail-client

The browser half of the inbox, exactly as `contracts/mail-client-v1.md`
describes it: the key ceremony, unlock, opening sealed mail, threads and
search over decrypted headers, the one sandboxed frame, drafts sealed before
they are saved, and the send form. Framework-free; the dashboard's inbox
screens call it and never hold a key, parse MIME or write message HTML.

Everything that touches a mailbox key, a message key, a recovery key or
hostile message content lives here, in the published repository, so that
the code that keeps the zero-access promise can be read and checked (spec
D2, D10).

## Rules the package keeps, and how

| Rule | How |
| --- | --- |
| No network | Nothing here fetches. A test scans the source and every runtime dependency's shipped JavaScript for `fetch`, sockets, beacons, workers and dynamic imports. |
| Runs under the dashboard's policy | No `eval`, `Function`, string timers, WebAssembly or DOM sink except the frame's `srcdoc`, set through the one Trusted Types policy. The same scan guards this. The browser tests serve a page with the dashboard's exact policy and Trusted Types **enforced**. |
| Nothing persists | No storage API is used; the scan refuses `localStorage`, `sessionStorage`, IndexedDB, the Cache API and cookies. |
| Keys stay non-extractable and decrypt-only | The private key is opened from its wrap by Web Crypto's `unwrapKey` as a non-extractable key (D21, K1). Wrapping it again (`addPasskey`, `replaceRecoveryKey`) opens a *wrappable* copy from a wrap for that one operation, with a fresh prompt or the recovery key, and drops it after. |
| Errors are typed | Every error is a `MailClientError` subclass with a stable `name`; messages carry no content, address or key. |

## Enrollment and unlock

- `startEnrollment(mailbox, passkey)` makes the key pair (`generateKey`,
  never exported), the passkey wrap and the recovery wrap. The passkey's
  PRF output comes from `create()` when the authenticator gives it there, or
  from one `get()` when it only reports `prf.enabled`; without PRF,
  `PrfUnavailable`, and `startEnrollment(mailbox, null)` offers a
  recovery-key-only setup. The recovery key is shown once; `request()`
  refuses until `confirmRecovery()` matched the characters at four random
  positions of the 55 symbols.
- `unlockWithPasskey` is one `get()` over the active key's passkey wraps,
  each with its own PRF input; the credential used selects the wrap.
  `unlockWithRecoveryKey` tries the recovery wraps.
- **At every unlock the unwrapped key's public half is compared with the
  mailbox's advertised public key** (`checkAdvertisedKey` in
  `src/session.ts`); a mismatch is `KeySubstitutionDetected` and nothing
  proceeds (G7, K2).
- The unlocked mailbox locks after `idleLockMs` (15 minutes) without
  `touch()`, every method counts as activity, and `lock()` is immediate.

WebAuthn sits behind the `credentials` port (`PasskeyOptions.credentials`),
so everything above is tested in Node with a double whose PRF is an HMAC; the
browser tests run the same flows through Chromium's virtual authenticator
with `hasPrf` and, elsewhere, through the double injected into the page.

The RP ID is whatever the dashboard passes as `rpId`: its exact host (D5).
Nothing here names a host.

## Reading

- `openMessages` opens each header; a failure is `{ header: null,
  undecryptable: true }` and never fails the batch.
- `openBody` decrypts the body object and parses it with postal-mime into
  `raw`, `text`, `html` and `attachments` (bytes, `contentId` without angle
  brackets, `inline`). `html` is set only when the message has a `text/html`
  part; `text` is null when it has no `text/plain` part (the screens quote
  the snippet then, as `replyTo` does).
- `threadsOf` links by Message-ID, In-Reply-To and References, and a message
  with none of those whose subject says `Re:`/`Fwd:` joins the oldest thread
  with that subject. The two arrivals of one message (two of the mailbox's
  addresses, G13) are one message, and the thread's `envelopeTo` lists both.
- `searchMessages` folds case and accents; every word must match in the
  subject, snippet, names, addresses, attachment names or `envelopeTo`.

## The one frame

`renderBody(body, { nonce })` returns a complete document for `srcdoc` and
`showInFrame(frame, rendered)` assigns it. What happens in between:

1. DOMPurify sanitises the HTML into a detached document with the html
   profile only (no SVG, no MathML), `WHOLE_DOCUMENT`, and a forbid-list for
   scripts, frames, objects, forms and form controls, `<link>`, `<meta>`,
   `<base>`, media and `<template>`. Links keep `http:`, `https:` and
   `mailto:` only and get `target="_blank" rel="noopener noreferrer"`.
2. **No remote content** (G17, D19): `src`, `srcset`, `background`,
   `poster` and CSS `url()` values that are not a `data:` raster image are
   removed and counted in `remoteImagesBlocked`; `@import` and
   `image-set()` too. `cid:` images become `data:` URLs of the message's
   own PNG, JPEG, GIF or WebP attachments (never SVG), counted in
   `inlineImages`.
3. **Styles** (G18): each `<style>` is scrubbed (no `@import`, no `url()`
   but `data:` raster images, no `expression()`, `behavior` or
   `-moz-binding`, and no `<`, so it cannot close its element) and emitted
   with the page's nonce. Inline `style` attributes are scrubbed the same way
   and moved into that nonce-stamped sheet as class rules
   (`.pm-inline-N`), because the inherited policy's `style-src-attr` would
   refuse them in place.
4. Plain-text mail is escaped into a `<pre class="plain">` that keeps its
   line breaks.
5. The document becomes a `TrustedHTML` through the package's one policy,
   **`proprietor-mail#srcdoc`**.

`showInFrame` refuses a frame whose `sandbox` attribute is missing or carries
any token other than `allow-popups` and `allow-popups-to-escape-sandbox` (an
empty `sandbox` is accepted: it is the strictest), sets
`referrerpolicy="no-referrer"`, and assigns `srcdoc`. It also refuses
anything that is not a live `RenderedBody` from `renderBody`.

`pageNonce()` returns the `.nonce` property of the page's own script
element, read at run time; it never reads an attribute from server-rendered
HTML.

### The Trusted Types policy, precisely

The policy accepts a string only while `renderBody` runs, and only the exact
string `renderBody` hands it: twice per render. Under enforcement
`DOMParser.parseFromString` is a sink too, so DOMPurify receives this
policy (its `TRUSTED_TYPES_POLICY` option) and passes the message's HTML
through it once, into its *detached* parse document, where nothing runs; the
second string is the finished document, the only `TrustedHTML` that ever
reaches a live sink. Outside a render, and for any other string, `createHTML`
throws; `createScriptURL` always throws. DOMPurify never creates its default
`dompurify` policy, so the dashboard's `trusted-types` allowlist needs this
one name. The browser tests record every `securitypolicyviolation` and
expect none for Trusted Types, scripts, images, frames or connections.

Two things the dashboard's maintainers should expect in CSP reports, both
harmless: the detached parse document inherits the page's policy, so a
message's own `<style>` elements, `style` attributes and `<base>` are
reported as refused (`style-src-elem`/`style-src-attr` "inline",
`base-uri`) before the sanitiser removes or rewrites them.

## Drafts and sending

- `sealDraft` and `openDrafts` use envelope v1 draft blocks; `sealDraft(null,
  …)` makes a new `drf_` id.
- `replyTo` / `forwardOf` build the compose input: `Re:`/`Fwd:` once, the
  quoted block (`> `), `inReplyTo` and the last 20 `references`, and `from`
  = the address the message arrived at when it is one of the mailbox's, else
  one it was addressed to, else the primary. Reply-all leaves the mailbox's
  own addresses out. `parseAddressList` reads what the owner typed and lists
  what is not an address.
- `encodeSendForm` builds `FormData` for `POST /inbox/send`: a `request`
  JSON part and one `attachment` `File` part per attachment, in order.
  `decodeSendForm` runs on the route's server side and returns exactly what
  `MailService.send` takes. Both check `SEND_LIMITS`, which mirror the
  Worker's (50 recipients, 10 MiB of content; a test keeps them equal) plus
  the route's 25 MB cap (D22); a refusal is `InvalidSendForm`.

## The promise, as data

`PROTECTION.optionA(operator)` and `PROTECTION.metadata` are the spec's
Option A text and the §4 table; `test/protection.test.ts` reads them back
from `specs/001-inbox-module/spec.md`.

## Tests

- `npm test -w @proprietor/mail-client`: Node, 86 tests, no browser.
- `npm run test:browsers -w @proprietor/mail-client`: Playwright drives
  Chromium, Firefox and WebKit against a page served with the dashboard's
  policy and Trusted Types enforced (`test/browser/server.ts` has the exact
  header). Needs `npx playwright install --with-deps`. `MAIL_CLIENT_BROWSERS`
  narrows the list; a browser that cannot launch fails, it never skips.
- Mutation checks for the audit: removing `checkAdvertisedKey`'s throw fails
  the G7 tests in `test/unlock.test.ts` and `test/browser`; removing the
  sandbox check in `showInFrame` fails the refusal test; removing the nonce
  check in `renderBody` fails the "refuses a missing nonce" test.

## Vendoring

The dashboard vendors `src/` with `VERSION` and `SHA256SUMS`, as it does
for `@proprietor/mail-crypto`; `src/` imports only relative files,
`@proprietor/mail-crypto`, `dompurify` and `postal-mime`.
