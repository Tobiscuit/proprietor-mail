# 002 — Unlock once per device, with revocation

Status: written 2026-10-16. Spec only; nothing is deployed and no live
infrastructure was changed. The design was decided with the operator. This
document records those decisions with their reasons, adds the ones the
design analysis forced (§6, D24–D33), and states the threat model.

Companion documents: `domain-model.md` (the DDD pass and the gaps it found),
`plan.md` (the protocol flow by flow, the data model, the rollout),
`tasks.md` (the build slices), `../../contracts/device-v1.md` (the bytes and
the calls). It builds on `../001-inbox-module/` and amends four of its rules,
named where they change: M5, K1, K2, and mail-client rule 3.

## 1. The friction, and the goal

Today the mailbox private key lives only in the inbox page's memory. Every
page load drops it, so the owner is asked for a security key or the recovery
key **every time** they open the inbox. That is safe, and it is a daily cost.

The goal is to **unlock once per device**. A browser the owner says is theirs
keeps the inbox openable without a prompt, until it locks by the owner's own
setting, or until the owner **removes** it. A removed device is refused by
Mail at once, never receives the key that replaces the old one, and forgets
what it held the next time it reaches Mail.

Zero-access is unchanged: Mail's servers never hold a key that opens stored
mail (001 D1, M3).

## 2. Requirements

- **R1 — A kept device opens the inbox without a prompt.** It holds its own
  keys in the browser, non-extractable, made on the device when the owner says
  "this device is mine".
- **R2 — A kept device proves itself on every call.** Mail refuses any
  mailbox call that does not carry a live session opened by that device (or by
  an unlocked browser), whatever the dashboard's sign-in cookie says. Only the
  calls that show the mailbox's state before an unlock (`mailboxes`,
  `mailbox`, the unread count) and the calls that open a session are exempt. This is
  the pattern of Chrome's Device Bound Session Credentials: a key pair made on
  the device, the public half registered, short sessions renewed by a
  signature.
- **R3 — Lock settings, per device**, enforced by the browser (Mail cannot
  enforce them, and the screens say so): lock after **right away**,
  **15 minutes**, **1 hour**, or **when I sign out**. The default is "when I
  sign out", because the dashboard's sign-in lasts long. **Lock now** stays.
- **R4 — One question, asked in each browser:** "This device is mine" or
  "This is a shared computer". A shared computer keeps nothing and locks right
  away.
- **R5 — Remove a device** from Settings: from any kept device, or from a new
  browser after unlocking with the recovery key alone. Mail deletes the
  device's record and its sealed copy of the key, so its calls are refused at
  once. The mailbox key **rotates** in the same step: there is a new key pair,
  its private key is sealed to every remaining device and to every factor (the
  recovery key included), and the old keys stay so old mail opens. The removed
  device never receives the new key. The next time it reaches Mail, it wipes
  its own keys.
- **R6 — Sensitive settings still need a fresh factor**: removing a device,
  keeping a new device, adding or removing a passkey, replacing the recovery
  key. Mail checks that factor itself (D25), so a stolen device that is
  unlocked cannot do these.
- **R7 — The recovery key alone is enough**: it unlocks a new browser, makes
  that browser a kept device, removes other devices, and receives every new
  key.
- **R8 — Adding another authenticator later** (for example a platform passkey
  on a phone) gives it the current key, and through the key chain every older
  one.
- **R9 — Audit rows** for every change to devices, factors, keys and sessions.
  Ids, kinds, counts and labels only.
- **R10 — Existing mailboxes keep working unchanged** until their owner turns
  this on (§7).
- **R11 — Owner-facing words** never assume a phone, a face scan or a synced
  passkey (D33).

## 3. What the owner sees

Two kinds of things unlock a mailbox, and the screens keep them apart:

- **A device** is one browser on one computer or phone. A kept device stays
  able to open the inbox. It holds a key pair made in that browser and stored
  in that browser's profile.
- **A factor** is what a person carries: a **security key or passkey** (with
  the PRF extension, for example a USB key with its own fingerprint sensor),
  or the **recovery key**. A factor is needed only to unlock a browser for the
  first time, after it locked, and for the sensitive settings.

Flows:

1. **Unlocking in a new browser.** The screen asks "This device is mine" or
   "This is a shared computer", then for a security key, passkey or recovery
   key. If the owner chose "mine", the browser becomes a kept device in the
   same step: no second prompt.
2. **Coming back.** A kept device that has not locked opens the inbox with no
   prompt. One that locked asks for a factor, and is kept again after it.
3. **Lock settings.** Settings, "This device": lock after right away,
   15 minutes, 1 hour, or when I sign out; Lock now; Remove this device.
4. **Devices.** Settings, "Your devices": each kept device, with its name and
   when it last opened the inbox. Remove asks for a security key, passkey or
   the recovery key.
5. **A lost or stolen device.** Remove it from any other device, or from any
   browser with the recovery key. From then on Mail refuses it, and new mail
   uses a key it never gets.
6. **Security key at work, recovery key at home.** At home, the recovery key
   unlocks the browser and keeps it. At work, the security key does the same.
   From then on each browser opens with no prompt. A browser that is locked or
   new needs only whichever factor is at hand.
7. **A shared computer** keeps nothing. Its inbox locks when you leave the
   page, and after 15 minutes without use while the page is open.

## 4. Threat model

"Unlocked" means a device whose inbox opens without a prompt right now: a kept
device that has not locked, or any browser with the inbox open.

| Who | Can | Cannot |
|---|---|---|
| **Someone with a lost or stolen device that is unlocked** | Read, send and delete mail, as with any mail app, until the device is removed or locks itself. With the browser's developer tools they can also copy the mailbox key the device can open (K1′), which reads mail stored up to the removal, and only together with a copy of that stored mail. | Remove the owner's other devices, keep another device, add a factor or change the recovery key: each needs a fresh factor that Mail checks (D25). Read anything that arrives after the device is removed: the key rotates and the device never gets the new one. |
| **Someone with a lost device that is locked** | Nothing through the inbox: a locked device has deleted its unlock key, and a session needs the mailbox key. But until the browser compacts its storage, the device's files may still hold a remnant of the deleted unlock key, and that remnant, with the seal Mail holds, would open the mailbox key. **So a lost device should be removed even when it was locked.** | Anything once the device is removed: Mail refuses it, its seal is gone, and the key rotates. |
| **Someone with a copy of the browser's profile** (malware that reads the disk; the profile holds the sign-in cookie too) | Act as the device until it is removed. Its keys are software keys in the profile, not hardware-bound (D24), and a lock that is due takes effect only when the inbox's own code next loads (K6). | Act as the device after it is removed. The OS lock and disk encryption guard the profile at rest. |
| **Someone who learns a mail session token** (it passes through the dashboard for each call) | Call Mail as that browser until the token expires, at most 60 minutes. | Renew it: a new session needs the mailbox key. Use it after the device is removed or the key rotates: every other session ends then. |
| **Someone with the dashboard's sign-in cookie** from another machine | Call the dashboard as the owner. | Any mailbox call except `mailboxes`, `mailbox` and `unread` (R2). Without a session, opened with the mailbox key, Mail refuses list, read, send, delete and every setting. |
| **Whoever controls the servers** (the operator, the database, its backups) | See which devices exist, their names and public keys, and when sessions open (§5). Delete records, which locks devices out (availability, not secrecy). | Read stored mail (001 D1, unchanged). Get the mailbox key sealed to a key they control: browsers check every device and factor key against a tag only key holders can make (K3), and accept a new key only through a chain from a key they trust (K2′). Turn a key proof into a decryption: challenges are their own domain (K4). |
| **A changed version of the dashboard's code** | Read what the owner reads, as in 001 §2 (limit 2). On a kept device that is unlocked, it can do so whenever any dashboard page is open in that browser, not only the inbox: the device's keys belong to the dashboard's origin (K1′). | — this limit is unchanged in kind, and published (001 D2). |

And by design:

- **Losing every device, every factor and the recovery key loses the mail.**
  Nobody can open it, the operator included (001 D6, unchanged).
- **The server cannot enforce lock settings** (K6). A kept device that is set
  to "15 minutes" forgets its key when the inbox next loads or while it is
  open. A copy of its files taken in between still holds the unlock key.
- **A removed device's old key copy** (if someone took one, K1′) still opens
  mail stored before the removal, given that stored mail. Rotation protects
  mail from then on, not mail already stored.

## 5. The promise, amended

Option A's text (001 §2) stands as it is. The owner also sees this text,
under "How your mail is protected", whenever the mailbox has kept devices.
`{operator}` is filled in as before:

**Devices you keep unlocked.**
> A device you keep unlocked opens your mail without your security key, until
> it locks or you remove it. Anyone who has it while it is unlocked can read
> your mail, as with any mail app. Its own screen lock and disk encryption
> protect it when you are away. If a device is lost, remove it from another
> device or with your recovery key. It stops working at once, and new mail uses
> a new key it never gets. If you lose every device, every security key and
> your recovery key, nobody can open your mail, not even {operator}.

What the platform can see (001 §4) gains these rows:

| What | Where it is visible | Why it exists |
|---|---|---|
| Which devices are kept, their names, their public keys, the sealed copies of the mailbox key made for them, and when each last opened a session | Mailbox key ring | So the owner can see and remove them, and so Mail can refuse a removed one |
| When an inbox session opened and ended, and from which kept device | Mailbox storage | Sessions last an hour; a removed device's sessions end with it |
| Each factor's public key | Mailbox key ring | So a new key can reach a factor that is not present, and so Mail can check a factor without its secret |

`mail-client`'s `PROTECTION` carries both texts, and its test compares them
with this section, as it does with 001's.

## 6. Decisions

### Recorded from the operator (2026-10-16), with their reasons

| | Decision | Why |
|---|---|---|
| **O1** | A device key, non-extractable, in the browser, made on the device; it opens the inbox without a prompt and signs the device's mail sessions. | The prompt on every entry is the friction. A key the page cannot read keeps the mailbox key out of reach of anything that only reads storage. |
| **O2** | Lock after: right away / 15 minutes / 1 hour / when I sign out; default "when I sign out"; Lock now stays. One question per browser: "this device is mine" or "this is a shared computer" (shared means right away). | The sign-in is long, and a browser the owner keeps should be usable while the security key is elsewhere. |
| **O3** | Removing a device deletes its record and its wrap, refuses it at once, and rotates the key: the new key is sealed to every remaining device and to the recovery key; old keys are kept; the removed device never gets the new key; it wipes itself on its next contact; every step audited. | Revocation that only deletes a record would leave a stolen device able to read new mail with a key it already has. |
| **O4** | Zero-access unchanged. The trade is said plainly: a lost device that is unlocked reads mail until it is removed, and losing every device and the recovery key loses the mail. | The same terms any end-to-end encrypted mail app offers; hiding them would break 001 §2's rule that the promise names its limits. |
| **O5** | The first mailbox's owner unlocks with a **roaming security key** (PRF through CTAP2 `hmac-secret`, user verification on the key's own fingerprint sensor), often kept at another site. So: the security key is needed only for a browser's first unlock and after a lock. The **recovery key alone** must unlock and keep a browser. "When I sign out" keeps an unlocked browser working while the key is away. Removing a device and rotating the key must work from a browser unlocked by the recovery key alone. Adding a second authenticator later must give it the current key. Wording says "a lost or stolen device that is unlocked", never "phone". | The security key is not always at hand. Several browsers cannot use it at all: Safari on macOS and iOS do not pass PRF to external keys (§9). |

### Decided in the design (D24–D33): the operator's call, with recommendations

| # | Decision | Recommendation |
|---|---|---|
| **D24** | **What a kept device stores, and where the mailbox key lives.** WebKit (Safari, and every browser on iPhone) cannot read an X25519 key back from IndexedDB, and private windows keep no keys at all (§9). | **P-256 device keys** (ECDSA to sign, ECDH to unlock) in IndexedDB. The mailbox key is **never stored in the browser**: it is sealed to the device's unlock key, and the seal stays at Mail, so removing a device cuts it off even from old keys after a reload. A browser that fails the storage check acts as a shared computer. **The trade:** on a kept device that is unlocked, code on the dashboard's origin could take an extractable copy of the mailbox key (K1′), where today it could only use the key while the inbox is open. This is inside D2's boundary; it is said in §4. |
| **D25** | **Mail checks a fresh factor** for keeping a device, removing a device, adding or removing a passkey, and giving a factor its key. | **Yes.** Without it, someone holding an unlocked device could remove the owner's other devices and rotate to a key only they hold. Mail checks the factor by a challenge sealed to the factor's public key, derived from the factor's secret (contract A2), so Mail never holds the secret. |
| **D26** | **The one-time upgrade of an existing mailbox.** Mail cannot check an existing factor until it knows that factor's public key, and it can only learn it once, on trust. | **One upgrade, which must include the recovery key** (typed once), plus the security key if it was used for the same unlock. It is allowed only while no factor has a key. A security key left out gets its key later, the first time it is used in a browser where the recovery key is typed too (`setFactorKey`). Until the upgrade the mailbox works exactly as today. |
| **D27** | **Mail sessions.** | A session opens with a **key proof** (a challenge sealed to the active key) plus, for a kept device, its **signature**. It lasts 60 minutes and is renewed without a prompt while the device is unlocked. So a locked device cannot even send, and a cookie alone opens nothing. |
| **D28** | **Rotation on every removal**, refused unless the recovery key can receive the new key. | **Yes** (M5′). A removal from a browser where only a passkey was used still seals the new key to the recovery key's public key, so no recovery secret is needed. |
| **D29** | **How a session reaches Mail.** The capability (a claim `dsn`) would be the single cleanest place, but the dashboard mints capabilities in its shell, and its send route is the shell's. | **A last `auth` argument** on each method, and **`request.session` for `send`**, so the dashboard's send route passes it on unchanged and needs no change. A capability claim can replace both later, in a new contract version, if the shell wants it. |
| **D30** | **"When I sign out" needs a signal the inbox does not have.** The inbox cannot see when the dashboard's sign-in started. | **A per-sign-in id from the dashboard shell** (a value that is the same for one sign-in and new after the next), passed to the inbox. Until the shell provides it, the setting is labeled "until I lock it", which is what it then does. |
| **D31** | **Browsers that cannot keep keys** (private windows; any browser that fails the check). | **Treated as shared computers**, with a sentence saying why. No weaker fallback: storing the key under a key the page can read would undo D24's point. |
| **D32** | **Review of the new constructions** (the self-Diffie-Hellman binding key, HPKE export used to wrap keys, factor keys through DeriveKeyPair). | **An external cryptographic review before the first client mailbox uses this.** The operator's own mailbox can use it first, as with envelope v1. |
| **D33** | **Owner-facing words.** | "Security key or passkey" and "recovery key" for factors, "device" for a browser on a computer or phone. Never "phone" alone, "Face ID" or "fingerprint" as if every device had one. |

## 7. The existing mailbox (migration)

The first mailbox was enrolled under 001: one key, a passkey wrap and a
recovery wrap, no factor keys, `sessions: "optional"`.

- After the Mail Worker and the dashboard ship this, **everything keeps
  working as today**. Wraps are untouched, a factor still unlocks, and no
  session is needed (R10).
- The first time the owner unlocks and chooses "this device is mine", the
  inbox offers the **upgrade**. With the recovery key just typed, it happens at
  once. With the security key, the screen asks for the recovery key once. The
  upgrade gives both factors their public keys, turns sessions on for good, and
  keeps that browser.
- From then on each browser needs one unlock with either factor to be kept.
  A security key left out of the upgrade gets its public key in the first
  browser where it is used together with the recovery key.
- Nothing is re-encrypted. Old mail keeps opening with the same key until the
  first device removal rotates it; after that the old key opens old mail
  through the chain.
- **Rolling the dashboard back** to a version without sessions, after the
  upgrade, leaves the inbox refusing its calls until the dashboard is rolled
  forward. Mail data is not touched. `sessions` never returns to `"optional"`
  (M13).

## 8. Out of scope

- A rotation without a removal ("change my mailbox key").
- Approving a new device from another device (a code shown on one, typed on
  the other). Today a new browser always needs a factor.
- Mail enforcing timed locks (forgetting a device's seal after its lock time).
  It is possible, but the operator decided the browser enforces them. It is
  listed as future hardening.
- Hardware-bound device keys. DBSC's TPM binding is not available to web
  pages.
- Re-encrypting old mail to the new key after a removal.

## 9. Facts this rests on (checked 2026-10-16)

| Fact | Source |
|---|---|
| `CryptoKey` is serializable; IndexedDB stores it by structured clone, and a non-extractable key stays non-extractable | MDN (SubtleCrypto "Storing keys", CryptoKey.extractable), through context7 |
| WebKit cannot read an X25519 `CryptoKey` back from IndexedDB ("Unable to deserialize data"): its OKP serializer accepts Ed25519 only, and writes no public/private distinction | the bun project's fix of the same WebCore code (PR #33553), and an application's Safari report (cipheroom PR #13); secondary sources, consistent with each other |
| Safari private windows cannot store any `CryptoKey` in IndexedDB (no per-origin wrapping key in an ephemeral session) | an application's report (open-chat issue #9343), marked unverified on a device there too |
| PRF with an external security key: Chrome, Edge and Firefox on Windows 11; Chrome on macOS 15+; Chrome on Android over USB (not NFC); **not** Safari 18+ on macOS; **not** any browser on iOS/iPadOS ("Platform does not pass extension data to/from external keys"); Firefox 139+ | Yubico's developer guide to PRF |
| Two PRF inputs (`first`, `second`) per assertion | Yubico's developer guide (its key-rotation example) |
| DBSC: Chrome 146 on Windows (rollout from May 2026), macOS from Chrome 147; no Safari or Firefox implementation announced; keys in the TPM or Secure Enclave | Google Workspace updates (2026-05), press coverage (2026-04, 2026-10) |
| X25519 in Web Crypto: Chrome 133, Firefox 130, Safari 17 | caniuse/MDN compat data (and 001 §8, reproduced) |
| Workers Web Crypto: ECDSA sign/verify, ECDH and X25519 deriveBits, HKDF, HMAC, AES-GCM wrapKey/unwrapKey | Cloudflare Workers docs, through context7 |
| `@hpke/core` 1.9.0 exports the export-only AEAD (`ExportOnly`) and `export()` on both contexts, and takes a `CryptoKey` (or pair) as the recipient key; DHKEM(P-256) is native Web Crypto | its installed type declarations (read) |

**Not verified**, and where it gets checked:

- That Safari (macOS and iOS, a normal window) stores and reads back
  non-extractable ECDSA and ECDH P-256 keys in IndexedDB. The mail-client's
  WebKit test checks it in CI; Playwright's WebKit is not Safari, so the first
  real check is the operator's own iPhone. Until then, D31 makes a failure
  safe.
- That `@hpke/core` opens with a non-extractable **P-256** recipient key (it
  does with X25519, 001 §8). Checked by the mail-crypto builder.
- That Firefox on macOS and Linux passes PRF to external security keys. Not
  needed for the design (the recovery key covers any browser); worth knowing
  for the owner.
- That a non-extractable X25519 key may `deriveBits` with its own public key in
  every engine (A5). Checked in the browser tests.
