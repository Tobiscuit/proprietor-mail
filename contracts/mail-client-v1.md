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
non-extractable and decrypt-only. A key is opened extractable only for the
steps that seal or wrap it again in the one flow the person just started with
a factor (a FreshFactor, at most 2 minutes), and is dropped when that flow
ends or the 2 minutes pass. On a kept device the unlock key opens the
device's seal, and other code on the dashboard's origin could ask Web Crypto
for an extractable copy. That is a limit of the platform, stated in the
spec's threat model.

### The API (fixed by slice D1, 2026-10-17; round 2, 2026-10-19)

`packages/mail-client/src/index.ts` and `src/types.ts` are authoritative; this
is what each part does. Request types mirror device-v1 Part B field for field
(base64url without padding, exact lengths, no other field), so the dashboard
passes them to `MailService` unchanged.

Round 2 follows device-v1 Part C as amended on 2026-10-19: K3 flags a
recipient whose tag fails instead of stopping (`flagged`, `FlaggedRecipient`),
K8 (`RotationUnproven`) and K9 are new, and the upgrade takes every factor
(`MissingFactors`); `setFactorKey` is gone.

**The kept-device store (K5, rule 3 as amended).**

```ts
indexedDbDeviceStore(): DeviceStore
memoryDeviceStore(): DeviceStore
canKeepDevices(store: DeviceStore): Promise<boolean>
const KEPT_DEVICE_FIELDS: readonly ["mailboxId", "deviceId", "label", "signingKey", "unlockKey",
  "signingPublic", "unlockPublic", "lastKeyId", "lockAfter", "lastActiveAt", "signInId"]
const DEVICE_DATABASE: { name: "proprietor-mail"; version: 1; store: "kept-devices" }
interface DeviceStore {
  get(mailboxId: string): Promise<KeptDevice | null>;
  put(record: KeptDevice): Promise<void>;
  update(mailboxId: string, deviceId: string, change: KeptDeviceChange): Promise<KeptDevice | null>;
  delete(mailboxId: string, deviceId?: string): Promise<void>;
}
type LockAfter = "right-away" | "15-minutes" | "1-hour" | "sign-out";
const LOCK_AFTER_MS: Readonly<Record<LockAfter, number>>   // 0, 15 min, 1 h, Infinity
```

- `indexedDbDeviceStore()` is the browser's store: one database for the
  package, one record per mailbox (keyed by `mailboxId`), writes with
  "strict" durability; IndexedDB's own failures are `StorageUnavailable`.
  `memoryDeviceStore()` is the same contract in memory, cloning on every read
  and write as IndexedDB does, for Node tests. Every `put` and `update` is
  checked against K5: a record with any other field, or whose keys are not
  non-extractable P-256 keys of their kind (ECDSA `sign`, ECDH `deriveBits`),
  is a `TypeError` and nothing is written. `update` and `delete` name the
  device they are for, so a page that is behind never brings back a key
  another page deleted.
- `canKeepDevices(store)` writes a probe record under a fresh, random mailbox
  id, reads it back, signs and derives with the keys it got, compares them
  with the originals, and deletes it. False, never an exception, where a
  CryptoKey cannot be kept (D31): then the screen unlocks as a shared
  computer and says why.

**Coming back (F2, F3, F10).**

```ts
resumeDevice(view: MailboxView, options: { store: DeviceStore; signInId: string | null;
  now?: () => number; idleLockMs?: number }): Promise<ResumeResult>
type ResumeResult =
  | { state: "none" }
  | { state: "unlocked"; mailbox: UnlockedMailbox }
  | { state: "locked"; reason: LockReason; device: DeviceInfo }
  | { state: "removed" };
type LockReason = "right-away" | "idle" | "signed-out" | "locked" | "no-seal";
interface DeviceInfo { id: string; label: string; lockAfter: LockAfter; keepsUnlocked: boolean }
```

- Call it on every load before asking for anything. It checks the lock
  setting first (K6: a lock that fell due deletes the unlock key before
  anything else), then K7 (a device the view no longer lists is wiped:
  `removed`, show "This device was removed"), then opens the device's seal of
  the active key, walks K2′ back to the key the device last accepted (a
  rollback is `KeySubstitutionDetected`), and checks every tag (K3: a
  recipient whose tag fails is flagged in `mailbox.flagged`; the inbox
  opens).
  `unlocked` needs no prompt; `locked` needs a factor; `no-seal` also covers a
  view from a Mail Worker without spec 002 (the record is kept for later).

**Unlocking with a factor, and the FreshFactor (K1′, K2′, K3).**

```ts
unlockWithPasskey(view: MailboxView, passkey: PasskeyPrompt, options?: UnlockOptions): Promise<UnlockedMailbox>
unlockWithRecoveryKey(view: MailboxView, recoveryKey: string, options?: UnlockOptions): Promise<UnlockedMailbox>
interface UnlockOptions { idleLockMs?: number; store?: DeviceStore; signInId?: string | null; now?: () => number }
interface FreshFactor {
  readonly factorId: string; readonly kind: "passkey-prf" | "recovery";
  readonly expiresAt: number; readonly expired: boolean;
  answer(challenge: ChallengeView): Promise<FactorProof>;
  dispose(): void;
}
const FRESH_FACTOR_MS = 120000
```

- A factor opens its envelope v1 wrap and derives its factor key from the
  same secret, which is zeroed then. The active key comes from that wrap or
  from the factor's seal, and is accepted only along the successor seals back
  to the factor's own key (and, on a kept device, to the key it last
  accepted). Every tag is checked: a device or factor whose tag fails is
  flagged (K3), and so is the factor just used when the factor key it
  derives is not the one the view lists for it (K9); the unlock goes on.
  Only a failure of the key itself (K2, K2′) is `KeySubstitutionDetected`.
  With `store`, a kept device of this
  mailbox is bound to the session (one the view no longer lists is
  forgotten). Without it nothing is kept: a shared computer.
- `unlocked.freshFactor` is that factor's FreshFactor, for 2 minutes on the
  injected clock: `answer(challenge)` opens only a `purpose: "factor"`
  challenge for this factor and gives `auth.factorProof`; it also lends the
  wrappable copy of the active key to the steps below. Expired or disposed,
  every use is `FactorExpired`. Locking disposes it.

**The unlocked mailbox: what spec 002 adds or changes.**

```ts
interface UnlockedMailbox {
  readonly keyId: string;                    // the active key; changes when this browser commits a rotation
  readonly keyIds: readonly string[];        // every key held, the active one first (G40)
  readonly device: DeviceInfo | null;
  readonly freshFactor: FreshFactor | null;  // null after resumeDevice and enrollment
  readonly flagged: FlaggedRecipients;       // K3, K9: recipients never sealed to; frozen, empty when all is well
  sessionProof(challenge: ChallengeView): Promise<OpenSessionRequest>;
  reauthenticate(reauth: ReAuth): Promise<FreshFactor>;
  refresh(view: MailboxView): Promise<void>;
  keepThisDevice(options: { label: string; lockAfter?: LockAfter }, freshFactor: FreshFactor): Promise<PendingChange<RegisterDeviceRequest>>;
  rekeyThisDevice(freshFactor: FreshFactor): Promise<PendingChange<UpdateDeviceRequest>>;
  setLockAfter(lockAfter: LockAfter): Promise<{ updateDevice: UpdateDeviceRequest | null; needsRekey: boolean }>;
  removeDevice(view: MailboxView, deviceId: string, freshFactor: FreshFactor): Promise<PendingChange<RemoveDeviceRequest>>;
  upgradeRequest(factors: readonly FreshFactor[]): Promise<PendingChange<UpgradeRequest>>;
  addPasskey(passkey: PasskeyOptions, freshFactor: FreshFactor): Promise<WrapInput>;
  replaceRecoveryKey(freshFactor: FreshFactor): Promise<{ recoveryKey: string; wrap: WrapInput }>;
  lock(): Promise<LockResult>;
  forget(): Promise<void>;
  onLock(listener: (event: LockEvent) => void): () => void;
  // openMessages, openBody, sealDraft, openDrafts, touch: as before
}
interface FlaggedRecipients { readonly devices: readonly string[]; readonly factors: readonly string[] }
interface PendingChange<T> { readonly request: T; commit(): Promise<void> }
interface LockResult { readonly updateDevice: UpdateDeviceRequest | null }
interface LockEvent { readonly reason: "lock" | "idle" | "removed"; readonly updateDevice: UpdateDeviceRequest | null }
```

- Every `PendingChange` is the request for Mail and a `commit()` for after
  Mail answered `ok: true`; nothing in the browser changes before.
- `sessionProof(challenge)` answers a session challenge with the active key,
  plus the device's signature on a kept device: `openSession`'s request. A
  challenge for another key is `MailboxChanged`; bytes that do not open as a
  challenge are `InvalidChallenge` (K4).
- `flagged` lists, by id, the devices and factors this browser does not
  trust: a tag that fails under the active key (K3), or a factor used in this
  session whose listed factor key is not the one it derives (K9). The screens
  show them as recipients no holder of the key added, and offer Remove:
  `removeDevice` for a device, `removeWrap` with a proof from another factor
  for a factor (for a recovery factor, `replaceRecoveryKey` first, since Mail
  keeps the only recovery factor, M5′).
- `reauthenticate(reauth)` is one prompt or the recovery key, for a sensitive
  setting, and checks K9 for that factor; `refresh(view)` checks K3 on a
  newer view of the same key, flagging what fails, and adopts its wraps,
  seals and devices (another key: `MailboxChanged`).
- `keepThisDevice` (F1) makes the two P-256 key pairs, seals the active key
  to the unlock key, tags the device; its request goes to `registerDevice`
  with the session and a factor proof, and `commit()` stores the record and
  binds the session. `rekeyThisDevice` (F4) does the same for a new unlock key
  after a lock; its request goes to `updateDevice` with the device's session.
  `setLockAfter` changes the setting at once; to "right-away" it drops the
  unlock key and answers the `updateDevice` request; back to a timed setting
  it answers `needsRekey`.
- `removeDevice(view, deviceId, freshFactor)` (F6) checks every tag in the
  view (K3) and K9 for the factor that proves it. While a recipient other
  than the device being removed is flagged, it refuses with
  `FlaggedRecipient`, whose `flagged` names the ones in the way: the new key
  would have to be sealed to them, so removing a flagged device is the only
  rotation while one is there (two flagged devices: neither removal can be
  made under B7, see the note below). Otherwise it makes the new key, the
  successor seal, a seal to every remaining device unlock key and factor key,
  and a tag for every remaining recipient, naming exactly them (B7). Then K8:
  it opens the successor seal with the new key and the new key's seal for the
  factor just used with that factor's key, and refuses with
  `RotationUnproven` (nothing sent, nothing changed) unless both give back
  the keys they name. It refuses with `NoRecoveryFactor` when no recovery
  factor with a key would receive the new key (M5′), and with
  `MailboxChanged` on a view of another key. `commit()` moves the session to
  the new key (decrypt-only; the old keys stay), re-binds this device under
  it, or wipes it when it removed itself (then its mail session ended: open a
  new one), and clears `flagged`. The FreshFactor's 2 minutes go on with the
  new key.
- `upgradeRequest(freshFactors)` (F5, D26, B5 and M20 as amended) gives every
  factor of the mailbox its factor key and tag in one request: each must be
  among the FreshFactors, used just now, or it is `MissingFactors`, whose
  `missing` names each one left out (`id`, `kind`, `label`) so the screen can
  ask for it. A factor the owner no longer has is removed first (`removeWrap`
  needs no proof while sessions are optional).
- `addPasskey(passkey, freshFactor)` (F8) and `replaceRecoveryKey(freshFactor)`
  (F7) wrap the FreshFactor's active key; once sessions are required the wrap
  also carries its factor key, `tag` and `tagKeyId`. Each Mail call takes a
  factor proof from the same FreshFactor, or from another factor when this
  one is flagged (its proof cannot answer: Mail seals its challenge to the
  listed key). While a factor is flagged, `addPasskey` refuses with
  `FlaggedRecipient` (remove it first), and so does `replaceRecoveryKey`
  unless every flagged factor is a recovery factor, which this replaces.
- `lock()` is Lock now: every key is dropped at once; on a kept device it also
  deletes the unlock key and answers the `updateDevice` request that clears it
  at Mail (send it with the session while one is live, then forget the
  token). A kept device locks itself by its setting while the page is open
  (15 minutes or 1 hour without use; never on idle for "sign-out"), and when
  another page of the browser locked or forgot it; listeners get the same
  request. `forget()` is K7, after `DeviceRevoked`: the record is deleted and
  every key dropped. Operations on a device another page forgot are
  `DeviceRemoved`.

**Enrollment (F12).**

```ts
startEnrollment(mailbox: Pick<MailboxView, "id" | "address" | "status">, passkey: PasskeyOptions | null,
  options?: { keep?: { store: DeviceStore; label: string; lockAfter?: LockAfter; signInId?: string | null }; now?: () => number }): Promise<Enrollment>
interface Enrollment { /* as before */ commit(): Promise<void> }
```

- Every wrap carries `factorKey`, `tag` and `tagKeyId` (the new key), so the
  mailbox requires sessions from the start (B5). With `keep`, `request()`
  carries `device: { device, seal }`, and after Mail accepted it `commit()`
  keeps the device; `unlocked()` then returns its session (before `commit()`
  it is a `TypeError`). Without `keep`, `commit()` does nothing.

**The send form (D29).** `encodeSendForm(compose, { idempotencyKey, draftId?,
session? })` puts the mail session into the request part, and
`decodeSendForm(form)` returns it as `request.session`; a token that is not
base64url of 32 bytes is `InvalidSendForm`. The send route passes it on
unchanged.

**The promise.** `PROTECTION.devices(operator)` is spec 002 §5's "Devices you
keep unlocked." text; `PROTECTION.metadata` is spec 001 §4's rows followed by
the three rows spec 002 §5 adds.

**Errors added** (each a `MailClientError` with a stable `name`):
`DeviceRemoved` (K7: this device was removed and is wiped),
`StorageUnavailable` (this browser cannot keep keys, or its storage failed),
`FactorExpired` (a FreshFactor past its 2 minutes, or disposed),
`MailboxChanged` (the key ring changed since this unlock: fetch the view
again, then resume or unlock), `StaleFactor` (a refusal: a security key that
opens only an older key and has no seal of the active one; unlock with
another factor), `NoRecoveryFactor` (a rotation the recovery key would not
reach), `InvalidDeviceLabel` (not 1 to 40 characters on one line),
`InvalidChallenge` (K4: nothing was answered). Round 2 adds
`FlaggedRecipient` (with `flagged`: remove those first), `RotationUnproven`
(K8: the rotation's own seals did not open, so it was not made) and
`MissingFactors` (with `missing`: the upgrade needs every factor).
`KeySubstitutionDetected` now also covers every K2′ failure; a failing tag
(K3) flags its recipient instead.

**Note for the architect (two flagged devices).** B7 requires a rotation to
seal and tag every remaining device, so while two devices are flagged,
removing either would seal the new key to the other: both removals are
refused with `FlaggedRecipient`, and nothing in the browser gets past it. A
removal of several devices in one rotation (or a rotation that may leave a
flagged device out, which Mail then deletes) would; it needs a change to B7.

**Shapes.** `MailboxView` gains `sessions`, `devices` and `seals`, `KeyView`
gains `successor`, and `WrapView` gains `factorKey`, `tag` and `tagKeyId`,
each optional so that a view from a Mail Worker without spec 002 reads as a
mailbox whose sessions are optional. Part B's shapes are exported as types:
`Auth`, `FactorProof`, `ChallengeRequest`, `ChallengeView`,
`OpenSessionRequest`, `OpenSessionResult`, `DeviceInput`,
`RegisterDeviceRequest`, `UpdateDeviceRequest`, `RecipientRef`, `Rotation`,
`RemoveDeviceRequest`, `UpgradeRequest`, `DeviceView`, `SealView`, and
`FlaggedRecipients`; `WrapInput` gains the optional factor fields,
`EnrollRequest` gains `device`, `SendRequest` gains `session`.
`SetFactorKeyRequest` is gone with `setFactorKey` (round 2).

**Breaking changes** to S6a's exports: `addPasskey` and `replaceRecoveryKey`
take a `FreshFactor` (they took a `ReAuth`: call `reauthenticate` first);
`lock()` answers a `Promise<LockResult>` (keys still drop at once); `onLock`
listeners receive a `LockEvent`; `keyId` and `fingerprint` follow a committed
rotation; `unlockWithPasskey` and `unlockWithRecoveryKey` try a factor's
wraps of every key, so a ring that does not list the key a factor opens is
`KeySubstitutionDetected` (it was `NoMatchingWrap` or `WrongRecoveryKey`); a
new enrollment's wraps carry factor keys, so a new mailbox requires sessions.

**Tests this amendment requires:** the D1 acceptance tests in
`specs/002-device-sessions/tasks.md`, in Node and in Chromium, Firefox and
WebKit under the dashboard's exact policy with Trusted Types enforced.
