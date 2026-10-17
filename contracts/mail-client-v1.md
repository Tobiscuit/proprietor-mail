# Contract: `@proprietor/mail-client`, version 1

**Implemented by** `packages/mail-client` in this repository (slice S6a).
**Used by** the dashboard's inbox route group (a separate application; slice
S6b there), which vendors the package's `src/` with `VERSION` and
`SHA256SUMS`, the same way it vendors `@proprietor/mail-crypto`.
**Status:** API fixed 2026-09-28 by the architect and agreed with the
dashboard's maintainers as the module boundary (`specs/001-inbox-module/plan.md`
§14). The TypeScript in `packages/mail-client/src/index.ts` is the
authoritative signature; this file says what each part must do. A builder who
finds evidence that a signature is wrong proposes the change to the architect,
who changes this file and the stub together.

## Why this package exists

Everything in the owner's browser that touches a mailbox key, a message key, a
recovery key, or hostile message content lives here, in the published
repository, so that the code that keeps the zero-access promise can be read
and checked (spec D2, D10). The dashboard's screens call it; they never
handle a key, never parse MIME and never write message HTML themselves.

## Rules for the whole package

1. **No network.** The package makes no request. The screens move ciphertext
   between the server actions or the body route and this package.
2. **Runs under the dashboard's policy.** It must work under the dashboard's
   exact Content Security Policy (`plan.md` §1) with Trusted Types ENFORCED:
   no `eval`, no `new Function`, no WebAssembly, no string-to-code, no DOM
   sink except the frame's `srcdoc`, set through the one Trusted Types
   policy below. The same scan that guards `mail-crypto` guards this package
   and every runtime dependency.
3. **Nothing persists.** No `localStorage`, `sessionStorage`, IndexedDB, Cache
   API or cookies. Decrypted content and keys live in memory only, for as
   long as the page holds an unlocked mailbox.
4. **Keys stay non-extractable and decrypt-only.** An unlocked mailbox holds
   the private key as a non-extractable `CryptoKey` WITHOUT its raw scalar
   (domain-model K1). Wrapping the key again (another passkey, a new recovery
   key) needs a fresh unlock for that one operation.
5. **Errors are typed.** Every error this package throws is a
   `MailClientError` subclass with a stable `name`. Messages never contain
   mail content, addresses or key material.

## Enrollment (setting up a `provisioned` mailbox)

`startEnrollment(mailbox, passkey)` generates the mailbox key pair in the
browser and makes the wraps:

- **Passkey wrap** (when `passkey` is given): `navigator.credentials.create()`
  with `rp.id = passkey.rpId` (the dashboard's exact host, D5), a random
  16-byte `user.id`, `authenticatorSelection` `{ residentKey: "preferred",
  userVerification: "required" }`, `attestation: "none"`, algorithms ES256,
  EdDSA and RS256, and the PRF extension evaluated with
  `prfInput(mailboxId, wrapId)` from `mail-crypto`. If the authenticator
  returns PRF results at creation, they wrap the key. If it only reports
  `prf.enabled: true`, one `get()` for that credential evaluates the PRF (a
  second prompt). If PRF is not enabled, the call throws `PrfUnavailable`, and
  the screen may offer a recovery-key-only setup with a clear warning by
  calling `startEnrollment(mailbox, null)`.
- The challenge is random bytes made in the browser. No server verifies the
  attestation or any assertion, on purpose: this passkey authenticates
  nothing. It only derives the key that wraps the mailbox key, and the PRF
  output is released only after user verification on the authenticator.
- **Recovery wrap**, always: `newRecoveryKey()` from `mail-crypto`.

The returned `Enrollment` shows the recovery key once and asks for proof that
it was saved: the characters at four random positions of the 55-character
display form. `request()` refuses until `confirmRecovery()` succeeded, then
returns exactly what `MailService.enroll` takes. `unlocked()` turns the new
key into a decrypt-only `UnlockedMailbox` without another prompt; `discard()`
drops everything.

## Unlocking

- `unlockWithPasskey(mailbox, passkey)`: one `get()` with `rpId`,
  `allowCredentials` = the credential ids of the mailbox's passkey wraps,
  `userVerification: "required"`, and the PRF `evalByCredential` map from each
  credential id to that wrap's `prfInput`. The credential the person used
  selects the wrap.
- `unlockWithRecoveryKey(mailbox, display)`: parses the display form
  (`RecoveryKeyTypo` on a checksum mismatch) and tries the recovery wraps
  (`WrongRecoveryKey` when none opens).
- Both then check that the unwrapped key's public half equals the mailbox's
  advertised active public key. A mismatch throws `KeySubstitutionDetected`,
  and the screen must stop and show the key-substitution warning
  (domain-model G7).
- The unlocked mailbox locks itself after `idleLockMs` (default 15 minutes)
  without `touch()`, and on `lock()`. A locked mailbox throws `MailboxLocked`
  from every method.

## Reading

- `openMessages(items)` opens each list item's header. An item that fails to
  decrypt comes back with `undecryptable: true` and `header: null`; it never
  fails the batch, and the screen shows "this message could not be
  decrypted", never an empty message.
- `openBody(item, sealedBody)` decrypts the R2 object the body route streamed
  and parses the MIME (postal-mime) into text, HTML and attachments.
- `threadsOf(messages)` groups by Message-ID, In-Reply-To and References, with
  the subject-normalisation fallback adapted from agentic-inbox. It merges
  duplicates: one message addressed to two of the mailbox's addresses arrives
  twice (domain-model G13), and the merged message lists both
  `envelopeTo` values.
- `searchMessages(messages, query)` searches decrypted headers, snippets and
  attachment names, case- and accent-insensitively; every word must match.

## Rendering a body (spec D3, domain-model G17 and G18)

`renderBody(body, { nonce })` returns the HTML for the one sandboxed frame,
and `showInFrame(frame, rendered)` puts it there:

- The HTML goes through DOMPurify. Scripts, frames, objects, forms, form
  controls, `<link>`, `<meta>`, `<base>` and event-handler attributes never
  survive. Links keep `http:`, `https:` and `mailto:` targets only, and open
  in a new tab with `rel="noopener noreferrer"`.
- **No remote content, ever** (G17): remote `src`, `srcset`, `background` and
  CSS `url()` values are removed and counted in `remoteImagesBlocked`. The
  page's policy would block them anyway. Inline images (`cid:`) become
  `data:` URLs of the message's own raster-image attachments (PNG, JPEG, GIF,
  WebP; never SVG). Not `blob:` URLs: a `blob:` URL the page creates is not
  expected to load inside the frame's opaque origin (File API, blob URL
  storage keys), and the page's policy allows `data:` images.
- **Styles** (G18): the frame inherits the page's policy, which drops a
  `<style>` element without the page's nonce. After the CSS is sanitised (no
  `@import`, no `url()` other than the `data:` images above), each `<style>`
  element gets the nonce passed in `opts.nonce`. The screen reads that nonce
  with `pageNonce()`, which returns the `.nonce` property of the page's own
  script element, and never from HTML the server rendered. Plain-text mail is
  escaped and shown with its line breaks kept.
- `showInFrame` refuses a frame whose `sandbox` attribute is missing or grants
  `allow-scripts`, `allow-same-origin`, `allow-forms` or any top-navigation
  permission. The only tokens it accepts are `allow-popups` and
  `allow-popups-to-escape-sandbox`, so that a link can open in a new tab. It
  sets `referrerpolicy="no-referrer"` and assigns `srcdoc` a `TrustedHTML`
  from the policy named **`proprietor-mail#srcdoc`**. That policy is created
  once, is private to the package, and its `createHTML` accepts only HTML that
  `renderBody` produced. DOMPurify parses through a Trusted Types sink as
  well: the package hands DOMPurify its own policy (`TRUSTED_TYPES_POLICY`),
  so the dashboard's allowlist needs this one name and not DOMPurify's
  default `dompurify` policy. The browser tests prove it under enforcement.
- `dispose()` drops the rendered HTML and the decoded attachments.

## Drafts and sending

- `sealDraft` and `openDrafts` use envelope v1 draft blocks; the server only
  ever stores the sealed form.
- `replyTo(message, body, mailbox, mode)` and `forwardOf(...)` build the
  compose input: `Re:`/`Fwd:` once, the quoted block, `inReplyTo` and
  `references`, and a `from` among the mailbox's own addresses (the address
  the original arrived at when it is one of them, else the primary).
  Reply-all leaves out the mailbox's own addresses.
- `encodeSendForm(compose, opts)` builds the `FormData` the send server
  action receives (a JSON part plus one `File` per attachment).
  `decodeSendForm(form)` runs on the server side of that action, checks the
  limits and returns exactly the request `MailService.send` takes. Both are
  pure and run in browsers and in Workers.

## The promise, as data

`PROTECTION` holds the owner-facing texts for Option A (spec §2) and the
metadata list (spec §4), with `{operator}` left for the screen to fill. A test
compares them with `spec.md`, so the dashboard never shows wording the spec
does not have.

## Tests this contract requires

- Real browsers (Playwright: Chromium, Firefox and WebKit), with a test page
  that sends the dashboard's exact CSP header and ENFORCES Trusted Types.
- Chromium's virtual authenticator with PRF for enrollment and unlock. A
  browser without a PRF-capable virtual authenticator runs the same flows
  through an injected `credentials` double.
- The frame: no script runs inside it, including through markup that
  DOMPurify has historically mishandled; remote images never load;
  nonce-stamped styles apply; `cid:` images render as `data:` URLs; the inherited
  `frame-ancestors 'none'` does not stop the frame from rendering.
- Mutation checks are part of the audit: the tests must fail when the
  public-key check, the sandbox check or the nonce check is removed.

## Amended 2026-10-16 (spec 002): kept devices

`specs/002-device-sessions/` and `contracts/device-v1.md` change two rules of
this contract and add an API. **First draft by the architect**; the
mail-client builder (slice D1) fixes the exact signatures here before the
dashboard's builder starts, and the architect reviews them.

**Rule 3, as amended: nothing persists except a kept device.** A browser the
owner said is theirs keeps one record per mailbox in IndexedDB, exactly as
device-v1 Part C K5 lists: the device id and label, two non-extractable
P-256 private keys and their public forms, the keyId it last accepted, its
lock setting, its last activity time, and the sign-in id it was unlocked
under. Never a mailbox key, a factor secret, a mail session token or
decrypted content. No `localStorage`, `sessionStorage`, Cache API or cookies,
as before. A shared computer keeps nothing.

**Rule 4, as amended (K1′).** An unlocked session holds every key
non-extractable and decrypt-only. A key is opened extractable only for one
sealing or wrapping step just after a factor was used (a FreshFactor, at most
2 minutes), and is dropped after. On a kept device the unlock key opens the
device's seal, and other code on the dashboard's origin could ask Web Crypto
for an extractable copy. That is a limit of the platform, stated in the
spec's threat model.

**What the API must offer** (`specs/002-device-sessions/plan.md` §5 lists
it): a kept-device store (IndexedDB, and a memory one for tests) and the check
that a browser can keep keys; `resumeDevice` (unlocked with no prompt, locked
with a reason, or removed and wiped); sessions that hold every key the chain
reaches, check K2′ and K3 at every unlock, and offer a FreshFactor after a
factor; `reauthenticate`; `sessionProof`; keep, rekey, lock now, set the lock
setting, forget, and remove a device with its rotation, each as a request and
a `commit()`; the upgrade; `setFactorKey`; `addPasskey` and
`replaceRecoveryKey` with factor keys; enrollment with factor keys and a
device; the send form's `session`; `PROTECTION.devices`; the errors
`DeviceRemoved`, `StorageUnavailable`, `FactorExpired`.

**Tests this amendment requires:** the D1 acceptance tests in
`specs/002-device-sessions/tasks.md`, in Node and in Chromium, Firefox and
WebKit under the dashboard's exact policy with Trusted Types enforced.
