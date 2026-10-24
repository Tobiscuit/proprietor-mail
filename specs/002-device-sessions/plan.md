# Plan — unlock once per device, with revocation

**Spec:** `spec.md` · **Domain model:** `domain-model.md` · **Tasks:** `tasks.md` ·
**Contract:** `../../contracts/device-v1.md`, `../../contracts/action-descriptor-v1.md`

**Round 3 (2026-10-22):** §10 is what changes for D34–D43: the migration's
new columns, every flow that changes, and the two new flows (F13 revoke with
an email code, F14 finish a rotation). A flow below that changes says so in
its first line.

## 1. The shape

```
  owner's browser                                dashboard (separate app)          Mail Worker
  ─────────────────────────────────────────      ─────────────────────────         ──────────────────────────
  mail-client                                    inbox route group                 MailService ─▶ Mailbox (DO)
   ├─ kept-device store (IndexedDB, per mailbox)   server actions + body route       key ring: keys (+ successor
   │    signing key  ECDSA P-256, non-extractable    relay `auth` unchanged,           seals), factors (wraps +
   │    unlock key   ECDH P-256, non-extractable     never store or log it             factor keys), devices,
   │    lastKeyId, lockAfter, lastActiveAt,        send route (the shell's):          seals of the active key
   │    signInId                                     passes request.session on       challenges, mail sessions,
   ├─ lock engine (K6)                                                                 sessions: optional|required
   └─ session: every key the chain reaches,
      non-extractable; a FreshFactor for 2 min
      after a factor, for one sealing step
```

The mailbox key never leaves Web Crypto as bytes, and never touches the
browser's storage. A kept device holds only the key that opens **its seal**,
and that seal stays at Mail. Mail holds public keys, seals, tags, hashes of
challenge answers and of session tokens. It holds nothing that opens a key.

## 2. Data model: Mailbox migration `0003_devices`

*(Round 3 adds to 0003 before it has run anywhere: §10.1.)*

```sql
ALTER TABLE policy    ADD COLUMN sessions TEXT NOT NULL DEFAULT 'optional' CHECK (sessions IN ('optional','required'));
ALTER TABLE keys      ADD COLUMN successor_key_id TEXT;            -- set when the key is retired
ALTER TABLE keys      ADD COLUMN successor_seal   TEXT;            -- this key sealed to its successor (109 bytes)
ALTER TABLE key_wraps ADD COLUMN factor_key  BLOB;                 -- X25519 public key, 32 bytes (contract A2)
ALTER TABLE key_wraps ADD COLUMN tag         TEXT;                 -- binding tag (A5)
ALTER TABLE key_wraps ADD COLUMN tag_key_id  TEXT;                 -- the key the tag is made under
CREATE TABLE devices (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, label TEXT NOT NULL,
  signing_key BLOB NOT NULL,            -- P-256, 65 bytes
  unlock_key  BLOB,                     -- P-256, 65 bytes; NULL while locked or for "right away"
  tag TEXT NOT NULL, tag_key_id TEXT NOT NULL,
  created_at TEXT NOT NULL, created_by TEXT NOT NULL, last_seen_at TEXT);
CREATE TABLE key_seals (
  key_id TEXT NOT NULL REFERENCES keys(key_id),
  to_kind TEXT NOT NULL CHECK (to_kind IN ('device','factor')), to_id TEXT NOT NULL,
  sealed TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
  PRIMARY KEY (key_id, to_kind, to_id));
CREATE TABLE challenges (
  id TEXT PRIMARY KEY, purpose TEXT NOT NULL CHECK (purpose IN ('session','factor')),
  target_id TEXT NOT NULL, answer_hash TEXT NOT NULL, nonce TEXT NOT NULL, account_id TEXT NOT NULL,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT,
  refused_at TEXT);                     -- set when a refusal of it as used or expired is first audited
CREATE INDEX challenges_by_expiry ON challenges(expires_at);
CREATE TABLE mail_sessions (
  token_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL, device_id TEXT,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE INDEX mail_sessions_by_device ON mail_sessions(device_id);
CREATE INDEX mail_sessions_by_expiry ON mail_sessions(expires_at);
```

The answer is kept only as its SHA-256; the nonce is kept as it is, because
Mail sends it with the challenge for the device to sign and it opens nothing.

It runs inside `transactionSync` on the Mailbox's first wake after the deploy,
like 0001 and 0002. Existing rows are untouched, and `sessions` starts
`optional`, so every existing behavior and test holds. The Directory (D1) does
not change.

## 3. The flows

Arrows are the dashboard's server actions (or its body route) calling
`MailService`; the dashboard relays and never interprets. `T` is a mail
session token. `FF` is a FreshFactor: what the browser holds for two minutes
after a factor was used, namely the factor's own key (A2) and a wrappable copy
of the active key, for one sealing or wrapping step.

### F1 — First unlock in a new browser, "this device is mine" (sessions required)

*(Changed in round 3: §10.2.)*

```
browser                                                       Mail
  mailbox() ─────────────────────────────────────────────────▶ view (keys+successors, wraps+factor keys,
                                                                devices, seals)            [no session]
  owner: "This device is mine" + passkey / recovery key
  unlock with the factor → session (K2′ via the factor's wrap and the chain; K3 tags) + FF
  challenge({purpose:"session"}) ─────────────────────────────▶ sealed to the active key
  open it (K4) → openSession({challengeId, answer}) ──────────▶ T (no device yet)
  challenge({purpose:"factor", factorId}) ────────────────────▶ sealed to the factor key
  keepThisDevice(...) with FF: two P-256 key pairs; the active key sealed to the unlock key; tag
  registerDevice({device, seal}, {session:T, factorProof}) ───▶ checks (M17), stores, T is now this device's
  commit: IndexedDB record (lastKeyId = active keyId); FF disposed
```

One prompt in all. With the recovery key only, the same steps run.

### F2 — A kept, unlocked device loads the inbox

*(Changed in round 3: §10.2.)*

```
  mailbox() → view
  resume: record found; lock checks (K6: lockAfter vs lastActiveAt, signInId) pass;
          the device is in view.devices (else K7: wipe, "This device was removed")
          open its seal with the unlock key → active key (non-extractable)
          K2′: if active ≠ lastKeyId, walk the successor seals back to lastKeyId; else K2
          K3: every tag; retired keys through the chain
  challenge(session) → sign A7 + answer → openSession({challengeId, answer, device:{id, signature}}) → T
```

No prompt. The session is renewed the same way before it expires, or on
`SessionRequired`.

### F3 — Lock

- **Lock now, an idle timer, or a sign-in id that changed:** delete the unlock
  key from IndexedDB, keeping the identity, `lastKeyId` and the setting. Drop
  the session's keys. If `T` is still live, first call
  `updateDevice({unlockKey: null, tag, seal: null}, {session: T})`, with the
  tag made under the active key before the key is dropped.
- **A lock that fell due while the page was closed:** found by `resume`, which
  deletes the unlock key before anything else. Mail is not told; the stale
  unlock key it holds opens nothing, and the next unlock replaces it.

### F4 — Unlock after a lock

*(Changed in round 3: §10.2.)*

Factor → session + FF → `challenge(session)` → `openSession` with the device's
signature and the key proof → `T` → new unlock key, seal and tag →
`updateDevice(…, {session: T})` → commit. `updateDevice` needs a device
session, not a factor proof: the person has just used a factor, and a device
that is locked cannot open a session (D27).

### F5 — The upgrade (an existing mailbox, sessions optional)

*(Changed in round 3: §10.2.)*

```
  unlock with the recovery key (and the passkey, if it was the one just used) → session + FF(s)
  challenge(session) → openSession → T                          (works while sessions are optional)
  upgradeRequest([FF recovery, FF passkey?]) → factor keys (A2) + tags under the active key
  upgrade({factors}, {session:T}) ─────────────────────────────▶ M20; sessions = required
  then F1 from "challenge({purpose:"factor"…})" to keep this browser
```

If the owner unlocked with the passkey, the screen asks for the recovery
key once before the upgrade. "Not now" leaves the mailbox exactly as today.

### F6 — Remove a device (rotation)

*(Changed in round 3: §10.2.)*

```
  ReAuth: passkey / recovery key → FF
  mailbox() → fresh view
  challenge({purpose:"factor", factorId: FF.factorId}) → factorProof
  removeDevice(view, deviceId, FF):
     K3: check the tag of every remaining recipient under the active key
     new key pair (generateKey, wrappable)
     successorSeal = seal(active key → new public key)            (A4, "successor")
     seals: the new key to every remaining device's unlock key and every factor key
     tags: every remaining device and factor, under the new key
  removeDevice({deviceId, rotation:{from, publicKey, successorSeal, seals, tags}},
               {session:T, factorProof}) ────────────────────────▶ M18 in one transaction
  commit: the session holds the new key (drafts seal to it); this device wiped if it removed itself
```

The other kept devices find their seal of the new key at their next load
(F2), and walk back to the key they knew. Their sessions ended, so they open
new ones. The removed device finds itself missing from the view, or gets
`DeviceRevoked`, and wipes (F10). Mail seals the next arrival to the new key.

### F7 — Replace the recovery key

*(Changed in round 3: §10.2.)*

ReAuth → FF. The new recovery key, its envelope v1 wrap of the active key,
its factor key (A2) and tag → `addWrap(…, {session, factorProof})`, with
a second challenge answered by the same FF →
`removeWrap(old, {session, factorProof})`. M5′ holds throughout: the new one
is added before the old one goes.

### F8 — Add a passkey (a second authenticator)

*(Changed in round 3: §10.2.)*

ReAuth → FF → create the passkey with PRF (one more prompt, on the new
authenticator) → its envelope v1 wrap of the active key, and its factor key
from the same PRF output, with tag → `addWrap(…, {session, factorProof})`. It
gets the current key by its wrap and every older key through the chain (R8).

### F9 — (removed 2026-10-19: the upgrade takes every factor, D26)

### F10 — A removed device's next contact

*(Changed in round 3: §10.2.)*

`resume` finds the device missing from `mailbox()`, or a call answers
`DeviceRevoked`. The browser deletes the record, drops every key and shows
"This device was removed. Unlock with your passkey or recovery key to
use it again." Unlocking again makes it a new device.

### F11 — A shared computer

*(Changed in round 3: §10.2.)*

Factor → session → `challenge(session)` → `openSession` (key proof only) →
`T`. Nothing is written to IndexedDB. The page locks after 15 minutes without
use, and everything is gone with the page.

### F12 — Enrollment of a new mailbox

*(Changed in round 3: §10.2.)*

`startEnrollment` makes the key pair, the passkey wrap and its factor key and
tag, the recovery wrap and its factor key and tag, and (for "this device is
mine") the device with its seal and tag. Recovery confirmed → `enroll({
publicKey, wraps, device})` → sessions required from the start → commit the
device → `challenge` / `openSession` → `T`.

## 4. `MailService`, in short

The contract's §B3 is the table. Inside the Worker:

- `CallContext` gains `auth: { session: string | null; factorProof: … | null }`,
  filled by `MailService` from the method's last argument (for `send`, from
  `request.session`).
- The Mailbox's `enter(ctx, need)` gets a second parameter:
  `"bootstrap" | "session" | "device-session" | "factor"`. One table,
  `SESSION_NEEDS`, maps every MailService method to its need. A fitness test
  walks `MailService`'s methods and fails on any that is missing from the
  table.
- Session and proof checking lives in one module of the Worker (for example
  `src/mailbox/sessions.ts`). It uses `@proprietor/mail-crypto`'s `sealChallenge` and `verifyDeviceProof`
  (`packages/mail-crypto/src/proofs.ts`), through a new `proofs` port, so
  that tests can inject a clock and, where useful, fakes.
- Rotation (`removeDevice`) is one `transactionSync`: every check first,
  then every write. A failure throws inside the transaction, so nothing is
  written.

## 5. `mail-client`, in short

The final signatures are the mail-client builder's, written into
`contracts/mail-client-v1.md` (amended) and reviewed by the architect before
the dashboard builder starts. What they must offer:

- **Store:** `indexedDbDeviceStore()`, `memoryDeviceStore()` (tests), and
  `canKeepDevices(store)`, the check that this browser keeps non-extractable
  P-256 keys across a reload (D31).
- **Load:** `resumeDevice(view, {store, signInId, now})` → `unlocked` (no
  prompt) | `locked` (with why) | `removed` (wiped).
- **Factors:** `unlockWithPasskey` and `unlockWithRecoveryKey` keep their
  names. The session they return holds every key the chain reaches (G40) and
  offers the FF of the factor just used. `reauthenticate(reauth)` gives an FF
  for a sensitive setting. An FF answers factor challenges and expires after
  2 minutes.
- **Sessions:** `sessionProof(challenge)` (key proof, plus the device's
  signature on a kept device).
- **Devices:** `keepThisDevice`, `rekeyThisDevice`, `lockNow`,
  `setLockAfter`, `forget` (K7), and `removeDevice(view, id, FF)`. Each returns
  the request to send and a `commit()` for after Mail accepted it.
- **Factors:** `addPasskey(passkey, FF)` and `replaceRecoveryKey(FF)` (now with
  factor keys), `upgradeRequest(FFs)` (every factor of the mailbox).
- **Enrollment:** `startEnrollment(mailbox, passkey, {keep?})`; `request()`
  includes factor keys, tags and the device.
- **Send form:** `encodeSendForm(compose, {…, session})`, and `decodeSendForm`
  returns `session` inside the request.
- **PROTECTION:** gains `devices(operator)` and the new metadata rows (spec
  §5), compared with the spec by its test.
- **Errors:** `DeviceRemoved` (wiped), `StorageUnavailable` (cannot keep
  keys), `FactorExpired` (the FF is past its 2 minutes), and the existing
  `KeySubstitutionDetected` for K2′ and K3 failures.

## 6. The dashboard's inbox

Inside `app/(modules)/inbox/**` and `lib/strings/inbox.ts`, with its tests:

- **Actions:** every device-bound action takes `auth` from the client and
  passes it as Mail's last argument. New actions: `challenge`, `openSession`,
  `upgrade`, `registerDevice`, `updateDevice`, `removeDevice`.
  The body route reads the token from a request header
  (`x-proprietor-mail-session-token`: Cloudflare redacts a header's value in
  Workers Logs and tails only when its name contains `auth`, `key`, `secret`,
  `token` or `jwt`). New types and error names live in the inbox's
  `_lib` until the shell folds them into `lib/mail.ts` (an ask, below).
- **MailboxProvider:** `resumeDevice` on mount; a mail session opened and
  renewed in memory; `SessionRequired` opens a new session once;
  `DeviceRevoked` wipes and shows the notice; the lock engine's timers; Lock
  now.
- **Gate:** the question on the unlock screen ("This device is mine" / "This
  is a shared computer"), so one prompt does everything; the upgrade offer for
  an existing mailbox; the "removed" notice; "this browser can't keep your
  inbox unlocked" (D31).
- **Settings:** This device (name, lock after, Lock now, Remove this device);
  Your devices (list, last opened, Remove); Passkeys (list,
  Add, Remove); Recovery key (Replace). Every one of them except the lock
  setting asks for a factor first.
- **Vendored packages:** `mail-client` and `mail-crypto` repacked from the
  integration commit, with `SHA256SUMS` and `VERSION` (its test proves them).
- **The fake Mail Worker** (`test/render/fake-mail`) implements the new
  methods with the real `sealChallenge` and `verifyDeviceProof`, enough for the
  flows to run in Chromium.

### What the dashboard's shell is asked for (not in the inbox's lane)

1. **A per-sign-in id** (D30): a value from the shell's session that is the
   same for one sign-in and new after the next, passed to the inbox's layout.
   For example, a hash of the sign-in assertion's issue time and subject.
   Until it exists, "when I sign out" is labeled "until I lock it".
2. **Fold the new types into `lib/mail.ts`:** `MailRpc`'s new methods, the
   `auth` argument, the three error names. The inbox carries them locally in
   the meantime.
3. Nothing else. The send route needs no change, because the session rides
   inside the send request (D29).

## 7. Testing

- **mail-crypto:** device-v1 vectors (written by its builder, A9) and the
  negative cases. Round trips for both KEMs. Domain separation (K4: a message
  key envelope, a wrap and a key seal never open as a challenge). Tag
  sensitivity to every field. `sealChallenge` and `verifyDeviceProof` against
  the vectors. The runtime scan still passes.
- **mail-client (Node):** resume in every lock state; K2′ accepts a real chain
  and refuses a key sealed by someone who never held the old key, and a
  rollback; K3 refuses a tag that fails; rotation requests name exactly the
  remaining recipients; an FF expires; nothing persisted beyond K5's list (a
  test reads the stored record).
- **mail-client (browsers):** Chromium and Firefox here, WebKit in CI. A kept
  device survives a reload (a new page, the same profile); its keys are
  non-extractable P-256; no X25519 key ever reaches IndexedDB; the storage
  check fails cleanly where keys cannot be kept; everything under the
  dashboard's policy with Trusted Types enforced.
- **Mail Worker (workerd):** migration on an existing mailbox, with legacy
  behavior unchanged (the whole existing suite, untouched). Challenges (used
  once, expiry, consumed when wrong, the limit of 20). Sessions (expiry,
  account, device). Every M13–M21 and M5′. The fitness test of `SESSION_NEEDS`.
  M1's marker scan, extended to tokens and answers (never stored in the
  clear). The escape guard.
- **Integration (architect):** the mail-client's halves against the Worker's,
  with the real crypto on both sides: F1, F2, F5, F6 and F10 run end to end
  in workerd with mail-crypto in the test as the browser.
- **Dashboard:** unit (rules: still no storage API in the route group, since
  the store is mail-client's; the rpc names), render (each gate), and the
  Chromium flow with a virtual authenticator with PRF: F1, F2, lock and
  reload, F5 on a legacy fake mailbox, recovery-only F1 in a second context,
  F6 from it, and F10 in the first.
- **Mutation checks** (the audit): drop K2′'s chain walk, drop K3's tag
  check, drop the session check on one method, drop the factor proof on
  `removeDevice`, drop the wipe on `DeviceRevoked`. Each must fail a test.

## 8. Rollout and rollback

1. Mail Worker deploy. 0003 runs on each Mailbox's next wake; `sessions` is
   `optional`; nothing behaves differently.
2. Dashboard deploy, with the new inbox and the vendored packages.
3. The operator upgrades their mailbox from the inbox (F5).

Before step 3, either side rolls back freely. After it, an older dashboard is
refused by Mail until it is rolled forward. After the **first device
removal**, rolling back either side locks the inbox until it is rolled
forward: the new active key is reachable only through seals, which an older
Mail Worker does not serve and an older dashboard cannot open. Nothing is
lost: an older Mail Worker skips 0003 and seals arriving mail to the active
key. The first removal is the point of no return for both.

Step 3, the upgrade, in order: in a browser where the passkey does PRF, the passkey first, then the
recovery key (spec §7).

## 9. Who owns what

| Files | Owner |
|---|---|
| `specs/002-device-sessions/**`, `contracts/device-v1.md`, the pointer in `contracts/mail-service-v1.md`, the first draft of the mail-client amendment | architect |
| `packages/mail-crypto/src/index.ts` id prefixes `dev` and `chl` | architect (in the spec commit) |
| `packages/mail-crypto/**` except `src/proofs.ts` and `test/proofs.test.ts`; `packages/mail-client/**`; `contracts/device-v1.vectors.json`; the mail-client amendment's final API | builder **D1** (crypto and client) |
| `packages/mail-crypto/src/proofs.ts`, `test/proofs.test.ts`, and one line in `src/index.ts` (its re-export, directly under `export { x25519Supported } from "./keys";`); `src/**`, `test/**`, `wrangler.jsonc`, `vitest.config.ts`, the root `package.json` | builder **D2** (Mail Worker) |
| the dashboard's `app/(modules)/inbox/**`, `lib/strings/inbox.ts`, `test/{unit,render,screens}/inbox*`, `test/render/fake-mail/**`, `test/render/mail-fixture.ts`, `vendor/**` and the lockfile entries for the two vendored packages | builder **D3** (dashboard inbox), after D1 and D2 |

## 10. Round 3 (2026-10-22): what changes for D34–D43

### 10.1 Migration `0003_devices`, added to before it ever ran

No Mailbox outside the tests has run 0003 (spec 002 is not deployed), so it is
edited in place rather than followed by a 0004. The Worker's builder writes
the exact statements; what they must hold:

```sql
-- factors: the signing key and the admission (A2b, A11); removed ones move to removed_factors (M24)
ALTER TABLE key_wraps ADD COLUMN signing_key        BLOB;   -- 65 bytes
ALTER TABLE key_wraps ADD COLUMN admission_by       TEXT;
ALTER TABLE key_wraps ADD COLUMN admission_sig      TEXT;
ALTER TABLE key_wraps ADD COLUMN admission_self_sig TEXT;
CREATE TABLE removed_factors (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, credential_id TEXT, label TEXT NOT NULL,
  factor_key BLOB NOT NULL, signing_key BLOB NOT NULL,
  admission_by TEXT NOT NULL, admission_sig TEXT NOT NULL, admission_self_sig TEXT NOT NULL,
  created_at TEXT NOT NULL, created_by TEXT NOT NULL, removed_at TEXT NOT NULL, removed_by TEXT NOT NULL);
-- keys: the transition beside the successor seal
ALTER TABLE keys ADD COLUMN successor_signed_by TEXT;
ALTER TABLE keys ADD COLUMN successor_sig       TEXT;
-- devices (in its CREATE TABLE): the admission and the unlock key's signature
--   admission_by TEXT NOT NULL, admission_sig TEXT NOT NULL, unlock_sig TEXT  (NULL exactly when unlock_key is)
-- challenges (in its CREATE TABLE): two more purposes, and the descriptor
--   purpose CHECK (purpose IN ('session','factor','key','email')), answer_hash NULL for 'email',
--   kind TEXT, descriptor TEXT, action_digest TEXT   (NULL for 'session')
CREATE INDEX challenges_by_digest ON challenges(action_digest);
-- the rotation that is due after an email-code revocation (M22, M23)
CREATE TABLE rotation_due (one INTEGER PRIMARY KEY CHECK (one = 1),
  since TEXT NOT NULL, by_account TEXT NOT NULL, devices TEXT NOT NULL);   -- devices: JSON array of ids
```

### 10.2 The flows, as they change

**F1, first unlock and keep (sessions required).** One prompt; the
FreshFactor answers both factor challenges.

```
  mailbox() → view
  factor → unlock: K2″ from the factor (transitions signed by factors connected to it), K3′, K9 → FF
  challenge({purpose:"session"}) → C_s, sealed to the active key
  challenge({purpose:"factor", factorId, action:{kind:"open-session", request: digest({challengeId: C_s.id})}}) → C_f
  K4/K12: build C_f's descriptor from our own request; equal bytes; open with its digest → factor answer
  openSession({challengeId: C_s.id, answer, factorProof}) ────────────────▶ T (no device yet)
  keepThisDevice(…, FF): two P-256 pairs; the active key sealed to the unlock key; tag;
                         unlockSignature (the device); admission (the FF's factor signs it)
  challenge({purpose:"factor", factorId, action:{kind:"register-device", device:{id, label}, request: digest({device, seal})}})
  registerDevice({device, seal}, {session:T, factorProof}) ───────────────▶ M25 checks; T is now this device's
  commit: record {mailboxId, accountId, …, lastKeyId, trustRoot: the factor's signing key}
```

**F2, a kept device loads.**

```
  resumeDevice(view, {store, accountId, signInId}):
    the record for (mailbox, account); none → "none" (another account's is never read: K10)
    K6: "sign-out" locks when signInId differs from the record's, a null after a non-null included (D34)
    K7: not in view.devices → this account's record wiped → "removed"
    the seal → the active key; K2″ from lastKeyId, each step signed by a factor connected to trustRoot; K3′
    K11: lastKeyId written only if the record still holds the walk's start; else resume once more
  challenge(session) → openSession({challengeId, answer, device:{id, signature}}) → T
  view.rotationDue → the banner "Finish removing" (F14)
```

**F4, unlock after a lock.** As before, and the new unlock key carries its
signature; `trustRoot` becomes the factor just used.

**F5, the upgrade.** `upgradeRequest(FFs)` gives every factor its factor key,
signing key, admission (A11's cycle) and tag. Then `challenge({purpose:"key",
action:{kind:"upgrade", request: digest({factors})}})`, opened with the
mailbox key and its own digest, and `upgrade(request, {session:T, keyProof})`.

**F6, remove devices (with the rotation).**

```
  ReAuth → FF; mailbox() → a fresh view
  ids = the devices chosen, plus every flagged device (D40)
  removeDevices(view, ids, FF): K3′ for every remaining recipient; new key; successor seal;
                                seals; tags; the transition, signed by FF's factor (K12); K8
  challenge({purpose:"factor", factorId: FF's, action:{kind:"remove-devices", deviceIds: ids, request: digest({deviceIds, rotation})}})
  removeDevices({deviceIds: ids, rotation}, {session:T, factorProof}) ───▶ M18′ in one transaction
```

**F7 and F8, a new recovery key or another passkey.** The new factor's
admission is signed by the FreshFactor's factor and by the new factor itself
(its own signing key, from the new secret). Descriptors of kind `add-factor`
and `remove-factor`. The removed factor's record moves to `removed_factors`.

**F10, a removed device.** Only the signed-in account's record is wiped. On
`Forbidden` (another account's device) nothing is wiped (K10).

**F11, a shared computer.** Factor → unlock → `openSession` with a key proof
and a factor proof of kind `open-session` → `T`. After 60 minutes the session
cannot be renewed without a factor, so the page asks again (D38).

**F12, enrollment.** The factors' admissions follow A11's cycle; the device
is admitted by one of them and signs its unlock key.

### F13 — Revoke a device with an email code (new, D35)

```
  any browser where the owner is signed in: unlocked, locked or new (no session needed)
  mailbox() → view → "Lost a device?" → the owner picks kept devices
  challenge({purpose:"email", action:{kind:"revoke-device", deviceIds}}) → {id, descriptor, expiresAt}
  page → dashboard: requestActionCodeAction(descriptor)
           → {ok:true, codeId, sentTo}    "We sent a code to …"
           → {ok:false, reason}           "not-allowed": offer the passkey way (F6); "too-many", "not-sent": say so
  the owner types the code → the inbox's server action, in ONE action:
           confirmActionCodeHere(codeId, code) → {attestation} | {refused}
           mint the capability with confirmation = attestation, unchanged
           MailService.revokeDevices(cap, {deviceIds}) ──────────────────────▶ B7a: the devices go; rotationDue
         (the attestation never reaches the browser)
  the page: "Removed. To finish, confirm with your passkey" → F14 now, or later on any device
```

### F14 — Finish a rotation that is due (new, D35)

```
  any browser that holds a FreshFactor while view.rotationDue is set (K13):
  after an unlock with a factor, or "Finish removing" → ReAuth
  removeDevices(view, flagged devices (often none), FF) → as F6, deviceIds may be empty
  Mail: the new key; rotationDue cleared; every other session ends
```

### 10.3 `MailService` and the Worker

- `SESSION_NEEDS` gains `revokeDevices: "email-confirmation"` (no session,
  `owner`, the capability's `confirmation`), and `removeDevices` replaces
  `removeDevice`. The fitness test still walks every method.
- One module holds the confirmations: issuing a descriptor with
  `challenge`, checking a factor or key proof against the digest of the
  call's own request, and checking an email attestation (B7a). Request
  digests and descriptors come from `@proprietor/mail-crypto` (one RFC 8785
  serializer, one reader), never from a second implementation in the Worker.
- The capability verifier reads the `confirmation` claim strictly, and hands
  it to `revokeDevices` only.
- Signatures (A11) are checked with mail-crypto's verifiers before the
  transaction writes anything.

### 10.4 `mail-client`

What the API must add (the builder fixes the exact signatures in
`contracts/mail-client-v1.md`, and the architect reviews them before the
dashboard's slice):

- the store keyed by mailbox and account (database version 2; the version 1
  store is dropped, since no record exists outside tests); `accountId` in
  `resumeDevice`, in the unlock options, and in enrollment's `keep`;
  `trustRoot` in the record;
- the factor graph and K2″ and K3′, everywhere K2′ and K3 ran;
- `FreshFactor.answer` taking the request it confirms, so it answers only
  that action (K4, K12); helpers that build each kind's action and request
  digest, from mail-crypto;
- session proofs without a device that carry a factor proof (D38);
- `removeDevices(view, ids, freshFactor)` (several, and none while a rotation
  is due), with the transition signed; `revokeRequest(view, ids)` (the
  `email` challenge's action); `rotationDue` on the unlocked mailbox;
- the compare-and-swap of `lastKeyId` (K11);
- `Forbidden` wiping nothing; `DeviceRevoked` wiping only this account's
  record.

### 10.5 The dashboard's inbox

Stacked on the dashboard's spec 008 (its pull request with Better Auth):

- the layout reads `currentSignInId()` into `InboxShell.signInId` and
  `currentSession().accountId` into `InboxShell.accountId`;
- the new server actions; `revokeWithCode` checks the code and mints the
  capability with the attestation in one action, using the dashboard's
  `confirmActionCodeHere` (its `lib/action-codes.ts`) and
  `requestActionCodeAction` (its `app/actions/action-codes.ts`);
- the screens: "Lost a device?", the "Finish removing" banner, devices
  grouped by account, "passkey" in every word;
- the shell's Mail types (`lib/mail.ts`, the dashboard's pull request #14)
  follow B3's table.

### 10.6 Rollout, as it changes

The dashboard's spec 008 (Better Auth) goes live first, by its own runbook.
Then §8's order: the Mail Worker, the dashboard, the upgrade. Before 008's
cutover, on a sign-in through Access, the inbox's "when I sign out" reads
"Until I lock it" (D34), and where the dashboard cannot send a code the inbox
offers the passkey way; everything else works.
