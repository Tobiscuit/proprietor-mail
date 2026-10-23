# 002 — Unlock once per device, with revocation

Status: written 2026-10-16. Spec only; nothing is deployed and no live
infrastructure was changed. The design was decided with the operator. This
document records those decisions with their reasons, adds the ones the
design analysis forced (§6, D24–D33), and states the threat model.

**Amended 2026-10-22 (round 3), before anything shipped.** The dashboard now
signs people in itself (its spec 008: an email code, then the phone's or
laptop's own passkey), which gives the inbox two things it lacked: a real
per-sign-in id, and email codes it can attest for one action. Round 3 also
answers the formal model's four findings (`formal/002/ir.md`, README) and the
two limits of §7a. Its decisions are D34–D43 (§6); where they change an
earlier sentence, that sentence is rewritten and the decision says so.

Companion documents: `domain-model.md` (the DDD pass and the gaps it found),
`plan.md` (the protocol flow by flow, the data model, the rollout),
`tasks.md` (the build slices), `../../contracts/device-v1.md` (the bytes and
the calls). It builds on `../001-inbox-module/` and amends four of its rules,
named where they change: M5, K1, K2, and mail-client rule 3.

## 1. The friction, and the goal

Today the mailbox private key lives only in the inbox page's memory. Every
page load drops it, so the owner is asked for a passkey or the recovery key
**every time** they open the inbox. That is safe, and it is a daily cost.

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
  "When I sign out" means the dashboard's own sign-in: a new sign-in, or none,
  locks the device (D34).
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
  its own keys. Several devices can go in one step (D40).
- **R5a — Revoke a device with an email code** (D35), from any browser where
  the owner is signed in, with no passkey or recovery key at hand (the usual
  case: the lost device *was* the phone). Mail refuses the device at once, as
  in R5. Making the new key needs a factor, so the rotation waits for the next
  unlock with a passkey or the recovery key, on any device, and the inbox asks
  for it until it is done.
- **R6 — Sensitive settings still need a fresh factor**: removing a device
  with its rotation, keeping a new device, adding or removing a passkey,
  replacing the recovery key, finishing a rotation. Mail checks that factor
  itself (D25), so a stolen device that is unlocked cannot do these. An email
  code is enough only to revoke (R5a). **Every confirmation names the one
  action it confirms** (D36): it cannot be replayed for another.
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
- **R11 — Owner-facing words** say "passkey" for the phone's or laptop's own
  passkey and "recovery key" for the typed one, and never mention hardware
  keys (D43, which replaces D33's wording).
- **R12 — A kept device belongs to the person who kept it** (D37). Another
  person signed in on the same browser profile is never shown it, never opens
  its key, and never wipes it.
- **R13 — The phone's own passkey is enough for every confirmation** (D43).
  Nothing in this spec needs a hardware key.

## 3. What the owner sees

Two kinds of things unlock a mailbox, and the screens keep them apart:

- **A device** is one browser on one computer or phone. A kept device stays
  able to open the inbox. It holds a key pair made in that browser and stored
  in that browser's profile.
- **A factor** is what a person has: their **passkey** (the phone's or
  laptop's own, opened with Face ID, a fingerprint or the device's PIN, and
  synced by iCloud Keychain or Google Password Manager; the inbox uses its PRF
  extension), or the **recovery key** they wrote down. A factor is needed only
  to unlock a browser for the first time, after it locked, and for the
  sensitive settings.

Flows:

1. **Unlocking in a new browser.** The screen asks "This device is mine" or
   "This is a shared computer", then for the passkey or the recovery key. If the owner chose "mine", the browser becomes a kept device in the
   same step: no second prompt.
2. **Coming back.** A kept device that has not locked opens the inbox with no
   prompt. One that locked asks for a factor, and is kept again after it.
3. **Lock settings.** Settings, "This device": lock after right away,
   15 minutes, 1 hour, or when I sign out; Lock now; Remove this device.
4. **Devices.** Settings, "Your devices": each kept device, with its name and
   when it last opened the inbox. Remove asks for the passkey or the recovery
   key, and can remove several at once. Another person's kept devices are
   listed apart, under their name, for the owner.
5. **A lost or stolen device.** Remove it from any other device, or from any
   browser with the recovery key. From then on Mail refuses it, and new mail
   uses a key it never gets.
6. **The phone, and a laptop.** The phone's passkey unlocks the phone's
   browser and keeps it; the laptop is kept the same way, with the passkey
   (on the laptop, or the phone held near it) or the recovery key. From then
   on each opens with no prompt. A browser that is locked or new needs
   whichever factor is at hand.
7. **A shared computer** keeps nothing. Its inbox locks when you leave the
   page, and after 15 minutes without use while the page is open. It asks for
   the passkey or the recovery key again after an hour (D38).
8. **The phone is gone, and with it the passkey.** On any browser: sign in
   with an email code, open Inbox, "Lost a device?", pick it, and type the
   code the email brings. The phone is refused at once. The inbox then shows
   "Finish removing it" on every device until someone unlocks with the
   passkey (from another device that has it) or the recovery key, which
   makes the new key in the same step (R5a, D35).
9. **Signing out.** With "when I sign out", the inbox locks itself the next
   time it loads under another sign-in or none (D34). On a preview, where the
   dashboard has no sign-in of its own, the setting reads "until I lock it",
   which is what it does there.

## 4. Threat model

"Unlocked" means a device whose inbox opens without a prompt right now: a kept
device that has not locked, or any browser with the inbox open.

| Who | Can | Cannot |
|---|---|---|
| **Someone with a lost or stolen device that is unlocked** | Read, send and delete mail, as with any mail app, until the device is removed or revoked, or locks itself. With the browser's developer tools they can also copy the mailbox key the device can open (K1′), which reads mail stored up to the rotation, and only together with a copy of that stored mail. | Remove the owner's other devices, keep another device, add a factor, change the recovery key or make a new key: each needs a fresh factor that Mail checks (D25), and browsers accept a new key or a new recipient only when a factor signed it (D39). Open a session with a copied key once the device is revoked: a session needs the device's signature or a factor too (D38). Read anything that arrives after the rotation: the device never gets the new key. |
| **Someone who controls the owner's email** (or holds the owner's phone with the mail app open) | Sign in to the dashboard with an email code, and revoke devices with another (R5a): the owner then unlocks those browsers again with the passkey or the recovery key. That is a loss of convenience, not of mail. | Open the inbox (it needs a passkey, the recovery key or a kept device), keep a device, add a factor, change the recovery key, or make the key future mail is sealed to (D35). With a stolen unlocked device as well, they read as that device until it is removed (the row above), and still cannot do any of these. |
| **Someone with a lost device that is locked** | Nothing through the inbox: a locked device has deleted its unlock key, and a session needs the mailbox key. But until the browser compacts its storage, the device's files may still hold a remnant of the deleted unlock key, and that remnant, with the seal Mail holds, would open the mailbox key. **So a lost device should be removed even when it was locked.** | Anything once the device is removed: Mail refuses it, its seal is gone, and the key rotates. |
| **Someone with a copy of the browser's profile** (malware that reads the disk; the profile holds the sign-in cookie too) | Act as the device until it is removed. Its keys are software keys in the profile, not hardware-bound (D24), and a lock that is due takes effect only when the inbox's own code next loads (K6). | Act as the device after it is removed. The OS lock and disk encryption guard the profile at rest. |
| **Someone who learns a mail session token** (it passes through the dashboard for each call) | Call Mail as that browser until the token expires, at most 60 minutes. | Renew it: a new session needs the mailbox key and the device's signature or a factor. Use it after the device is removed or revoked, or the key rotates: its sessions end then. Use a confirmation it relays for another action: each is bound to its own (D36). |
| **Someone with the dashboard's sign-in cookie** from another machine | Call the dashboard as the owner. | Any mailbox call except `mailboxes`, `mailbox` and `unread` (R2). Without a session, opened with the mailbox key, Mail refuses list, read, send, delete and every setting. |
| **Whoever controls the servers** (the operator, the database, its backups) | See which devices exist, their names and public keys, and when sessions open (§5). Delete records, which locks devices out (availability, not secrecy). | Read stored mail (001 D1, unchanged). Get the mailbox key sealed to a key they control, **even with a copy of an old key taken from a removed device**: browsers seal only to a device or factor a factor admitted, and accept a new key only through successor seals that a factor signed (D39, K2′, K3). Turn a key proof into a decryption: challenges are their own domain (K4). |
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
- **Between an email-code revocation and its rotation** (R5a), arriving mail
  is still sealed to the key the revoked device could open. The device cannot
  fetch it: Mail refuses the device, and a copied key alone opens no session
  (D38). Reading it would take a copy of that key (K1′) and a copy of Mail's
  stored mail. The first unlock with a passkey or the recovery key ends the
  window, and every device's inbox asks for it until then.
- **A factor that was removed** stays able to sign for browsers that a
  hostile server shows an old key ring (D39), and such a server can list it
  as present again, so new keys would be sealed to it. Mail refuses it at
  once, so this matters only together with whoever controls the servers, as
  a leaked recovery key already does (001 D6). *Later options:* kept devices
  remember the factors they saw removed; a signed removal; a transparency log
  of the key ring.

## 5. The promise, amended

Option A's text (001 §2) stands as it is. The owner also sees this text,
under "How your mail is protected", whenever the mailbox has kept devices.
`{operator}` is filled in as before:

**Devices you keep unlocked.**
> A device you keep unlocked opens your mail without your passkey, until
> it locks or you remove it. Anyone who has it while it is unlocked can read
> your mail, as with any mail app. Its own screen lock and disk encryption
> protect it when you are away. If a device is lost, remove it from another
> device or with your recovery key. It stops working at once, and new mail uses
> a new key it never gets. If you lose every device, your passkey and
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
| **O2** | Lock after: right away / 15 minutes / 1 hour / when I sign out; default "when I sign out"; Lock now stays. One question per browser: "this device is mine" or "this is a shared computer" (shared means right away). | The sign-in is long, and a browser the owner keeps should be usable while the passkey is not at hand. |
| **O3** | Removing a device deletes its record and its wrap, refuses it at once, and rotates the key: the new key is sealed to every remaining device and to the recovery key; old keys are kept; the removed device never gets the new key; it wipes itself on its next contact; every step audited. | Revocation that only deletes a record would leave a stolen device able to read new mail with a key it already has. |
| **O4** | Zero-access unchanged. The trade is said plainly: a lost device that is unlocked reads mail until it is removed, and losing every device and the recovery key loses the mail. | The same terms any end-to-end encrypted mail app offers; hiding them would break 001 §2's rule that the promise names its limits. |
| **O5** | *(Reworded 2026-10-22 by D43; the substance stands.)* The owner unlocks with their **passkey**, which is not always at hand. So: the passkey is needed only for a browser's first unlock and after a lock. The **recovery key alone** must unlock and keep a browser. "When I sign out" keeps an unlocked browser working while the passkey is elsewhere. Removing a device and rotating the key must work from a browser unlocked by the recovery key alone. Adding a second passkey later must give it the current key. Wording says "a lost or stolen device that is unlocked", never "phone". | The passkey is not always where the browser is, and some browsers cannot use PRF with it at all (§9). |

### Decided in the design (D24–D33): the operator's call, with recommendations

| # | Decision | Recommendation |
|---|---|---|
| **D24** | **What a kept device stores, and where the mailbox key lives.** WebKit (Safari, and every browser on iPhone) cannot read an X25519 key back from IndexedDB, and private windows keep no keys at all (§9). | **P-256 device keys** (ECDSA to sign, ECDH to unlock) in IndexedDB. The mailbox key is **never stored in the browser**: it is sealed to the device's unlock key, and the seal stays at Mail, so removing a device cuts it off even from old keys after a reload. A browser that fails the storage check acts as a shared computer. **The trade:** on a kept device that is unlocked, code on the dashboard's origin could take an extractable copy of the mailbox key (K1′), where today it could only use the key while the inbox is open. This is inside D2's boundary; it is said in §4. |
| **D25** | **Mail checks a fresh factor** for keeping a device, removing a device, adding or removing a passkey, and giving a factor its key. | **Yes.** Without it, someone holding an unlocked device could remove the owner's other devices and rotate to a key only they hold. Mail checks the factor by a challenge sealed to the factor's public key, derived from the factor's secret (contract A2), so Mail never holds the secret. |
| **D26** | **The one-time upgrade of an existing mailbox.** Mail cannot check an existing factor until it knows that factor's public key, and it can only learn it once, on trust. | **One upgrade, with every factor of the mailbox at once** (amended 2026-10-19 after an independent review): for the first mailbox, its passkey and the recovery key in one browser where the passkey does PRF. A factor the owner no longer has is removed first. Every factor then reaches every key made after it, so no factor is ever left behind. Until the upgrade the mailbox works exactly as today. (The first form took the recovery key alone, and a passkey left out stopped reaching new keys after the first device removal.) |
| **D27** | **Mail sessions.** | A session opens with a **key proof** (a challenge sealed to the active key) plus, for a kept device, its **signature**. It lasts 60 minutes and is renewed without a prompt while the device is unlocked. So a locked device cannot even send, and a cookie alone opens nothing. |
| **D28** | **Rotation on every removal**, refused unless the recovery key can receive the new key. | **Yes** (M5′). A removal from a browser where only a passkey was used still seals the new key to the recovery key's public key, so no recovery secret is needed. |
| **D29** | **How a session reaches Mail.** The capability (a claim `dsn`) would be the single cleanest place, but the dashboard mints capabilities in its shell, and its send route is the shell's. | **A last `auth` argument** on each method, and **`request.session` for `send`**, so the dashboard's send route passes it on unchanged and needs no change. A capability claim can replace both later, in a new contract version, if the shell wants it. |
| **D30** | **"When I sign out" needs a signal the inbox does not have.** The inbox cannot see when the dashboard's sign-in started. | **A per-sign-in id from the dashboard shell** (a value that is the same for one sign-in and new after the next), passed to the inbox. Until the shell provides it, the setting is labeled "until I lock it", which is what it then does. |
| **D31** | **Browsers that cannot keep keys** (private windows; any browser that fails the check). | **Treated as shared computers**, with a sentence saying why. No weaker fallback: storing the key under a key the page can read would undo D24's point. |
| **D32** | **Review of the new constructions** (the self-Diffie-Hellman binding key, HPKE export used to wrap keys, factor keys through DeriveKeyPair). | **An external cryptographic review before the first client mailbox uses this.** The operator's own mailbox can use it first, as with envelope v1. |
| **D33** | **Owner-facing words.** | *(Replaced 2026-10-22 by D43.)* Named the factors with a hardware term beside "passkey", and avoided "phone" alone, "Face ID" and "fingerprint". |

### Round 3 (2026-10-22): decided in the design, with their reasons

Better Auth on the dashboard (its spec 008) made the user flows designable,
and the formal model's findings named what had to change. Each decision is
reversible until the first device removal (§7); none is deployed.

| # | Decision | Why |
|---|---|---|
| **D34** | **"When I sign out" is the dashboard's sign-in** (D30, wired). The inbox's layout reads the shell's `currentSignInId()` (a hash of the Better Auth session id, never the id) into `InboxShell.signInId`. A kept device stores the id it was unlocked under (K5). Set to "when I sign out", it locks when the id it sees differs: a new sign-in, **or none after one**. Two nulls never lock: on a preview, where Access signs people in and there is no sign-in of the dashboard's own, the setting reads "Until I lock it", which is what it does there. | Better Auth renews a session by moving its expiry on the same session row, so the id is stable for one sign-in and new after the next; signing out deletes the row. A missing id after one was seen is treated as a sign-out, so a fault fails locked. The lock takes effect when the inbox next loads, as every setting does (K6): the sign-out page is the shell's. |
| **D35** | **An email code may only revoke; making a key needs a factor.** The dashboard sends a code to the signed-in person's email for one action Mail described, checks it, and attests it in the capability (`capability-v1.md`, `confirmation`). Mail accepts that for **`revokeDevices`** and nothing else: the devices, their seals and their sessions go at once, and a **rotation is due**. It never keeps a device, adds or removes a factor, replaces the recovery key, or rotates. The rotation is made by the next browser that holds a fresh factor (passkey or recovery key), with `removeDevices` (B7), and Mail accepts a successor key only from a call whose factor proof and transition signature come from that factor (D39). Until then the inbox asks for it on every device. | Whoever generates a successor key knows it. Someone who controls only the owner's email (or holds the owner's phone with the mail app open) could otherwise rotate to a key they know and read every later message. Revoking gives nobody a key, so the worst an email code does is make the owner unlock again. The cost is a window, stated in §4. |
| **D36** | **Every confirmation is bound to its action** (model finding 3). Mail issues an **action descriptor** (`action-descriptor-v1.md`: kind, mailbox, devices with their labels, a nonce it spends once, and a digest of the request) for each confirmed action. A factor proof's challenge carries the descriptor's digest in its associated data (A6), so the browser can open, and answer, only the challenge for the action it is about to send; the upgrade's key proof does the same; an email attestation names the digest. At the call, Mail computes the request's digest itself and compares. | A factor answer passes through the dashboard. Before this, whoever relays it (the dashboard, or anyone holding a session token) could pair it with a request of their own, including a rotation to their own key, because Mail checks a rotation's shape, never its seals. |
| **D37** | **A kept device names its account, checked before any key is opened** (G42, §7a). The browser keeps one record per mailbox **and account** (the dashboard's account id, which is the capability's `sub`). `resumeDevice` takes the page's account and reads only that account's record; another account's record is never opened, used or wiped. Mail answers a device of another account with `Forbidden`, never `DeviceRevoked` (which wipes). | Before this the record was keyed by mailbox only: another member signed in on the same browser profile opened the mailbox key in their own page before Mail refused the device, and the refusal then wiped the owner's record. |
| **D38** | **A session needs the key and something only the owner has.** While sessions are required, `openSession` needs a key proof **and** either a kept device's signature or a factor proof bound to `open-session`. | Revoking without rotating (D35) stops a device's signature, but a page holding a copied mailbox key could still answer a key proof. With this rule a copied key alone opens nothing, so revocation is immediate. The cost: a shared computer, which keeps no device key, asks for a factor again after an hour. |
| **D39** | **Factors sign what they authorize** (model findings 1 and 2). Each factor gets a **signing key**, derived from its secret like its factor key (A2). It signs every key transition it confirms, and **admits** every device and factor it confirms (a factor being added countersigns its own admission). A device signs its own unlock key. Browsers accept a successor key only with a transition signed by a factor connected to the one they trust, and seal a key only to recipients admitted the same way; Mail checks the same signatures before it stores anything. A removed factor's record is kept (without its wrap or seals), so the signatures it made still verify. Binding tags (A5) stay as a second check. | A tag can be made by anyone who holds the mailbox key, and that includes someone who copied an old key from a removed device or holds a stolen unlocked one. Together with whoever controls the servers, they could fork the key chain from the old key (finding 1) or list a recipient with a genuine tag that the owner's next rotation would seal the new key to (finding 2). A factor's secret never leaves the person. *Considered and set aside:* re-wrapping each factor's anchor at every use (a hostile server can serve the older wrap), and relying on Mail's checks alone (the promise names whoever controls the servers). |
| **D40** | **Several devices in one rotation** (§7a's first limit). `removeDevices` takes 0 to 20 devices; 0 only to finish a rotation that is due. A browser that sees flagged devices removes all of them in the same step. | Two flagged devices were a dead end: each removal sealed the new key to the other, so the browser refused both. |
| **D41** | **A device's last accepted key only moves forward** (model finding 4). The record's `lastKeyId` changes only while it still holds the key the walk started from, read and written in one IndexedDB transaction. Otherwise that page resumes again from the newer value. | Two tabs shown different keys at the same moment could move the device's anchor back one step. |
| **D42** | **Repairing a factor whose listed keys are wrong** (§7a's second limit): specified here, built only if it is ever needed. On the owner's request the operator opens a 24-hour repair window for one factor (`MailAdmin`, audited). In it, a session with a key proof bound to `rekey-factor` may set that factor's factor key, signing key and admission once; the window then closes. The repairing browser unlocked through that factor's wrap cannot check the chain's signatures from that factor (its listed key is the wrong one), so during a repair it accepts the chain by its successor seals alone, and the screen says so. | It can arise only from a bug that derives a factor's keys differently from when they were registered: Mail now checks every factor's own signature when it is registered, and the vectors pin the derivation. A hostile server holding an old key could mislead the one repairing browser during the window, which is why it needs the operator, the owner's request and an audit row. |
| **D44** | **Factor signing keys are Ed25519** (amends D39, A2b; decided 2026-10-22 while building). The 32 bytes HKDF derives from the factor's secret are the Ed25519 private key; the engine computes the public key. | WebKit imports a P-256 private key only together with its public point (WebKit bug 233705, open; reported again on Safari 26), and that point could only come from arithmetic on the secret scalar in JavaScript (not constant-time, not zeroable) or from a key stored wrapped at Mail. An Ed25519 key imports from its 32 bytes alone in Chrome 137+, Firefox 129+, Safari 17+ and Workers, as the X25519 factor key already does. Device keys stay P-256 (they must survive IndexedDB in WebKit, D24). |
| **D43** | **"Passkey" means the phone's or laptop's own** (O5 is reworded by it; D33's words are replaced). A mailbox's factors are the person's passkey (iCloud Keychain, Google Password Manager or Windows Hello, through the PRF extension) and the recovery key. Every confirmation works with the passkey. Screens and texts call the factors "passkey" and "recovery key" and nothing else, and mention no hardware. | That is what owners have. The design never depended on a hardware key; only the words and the example did. |

## 7. The existing mailbox (migration)

The first mailbox was enrolled under 001: one key, a passkey wrap and a
recovery wrap, no factor keys, `sessions: "optional"`.

- After the Mail Worker and the dashboard ship this, **everything keeps
  working as today**. Wraps are untouched, a factor still unlocks, and no
  session is needed (R10).
- **The upgrade, in this order:** in a browser where the mailbox's passkey
  does PRF, unlock with the **passkey**, choose "this device is mine", then
  type the **recovery key** when the inbox asks for it. The upgrade gives both
  factors their public keys, signing keys and admissions in one step (D39),
  turns sessions on for good, and keeps that browser. It needs every factor
  of the mailbox; one the owner no longer uses is removed first, and the
  phone's passkey can be added after (F8).
- From then on each browser needs one unlock with either factor to be kept.
- Nothing is re-encrypted. Old mail keeps opening with the same key until the
  first device removal rotates it; after that the old key opens old mail
  through the chain.
- **Rolling back.** After the upgrade, a dashboard without sessions is
  refused by Mail until it is rolled forward. After the **first device
  removal**, rolling back either side locks the inbox until it is rolled
  forward: the new active key is reachable only through seals, which an older
  Mail Worker does not serve and an older dashboard cannot open. Nothing is
  lost either way (an older Mail Worker skips migration 0003 and keeps sealing
  arriving mail to the active key), and `sessions` never returns to
  `"optional"` (M13). The first device removal is the point of no return for
  both.

## 7a. Before the first client mailbox (2026-10-19, updated 2026-10-22)

The operator's own mailbox can use this as it is; these come first for a
client's:

- **D30 wired:** done as D34 (round 3), once the dashboard's spec 008 is
  live. On a preview, under Access, the setting still reads "Until I lock it".
- **A kept device names its account:** done as D37 (round 3).
- **D32's external review**, now also of D35, D36, D38 and D39.
- **Two limits of K3 and K9 found while building round 2:**
  - Two flagged devices were a dead end: fixed by D40 (several devices in
    one rotation).
  - A recovery factor whose listed factor key is wrong (K9), in a mailbox
    with no other factor, cannot be repaired from the browser: Mail seals that
    factor's challenges to the wrong key, so no factor proof is possible. The
    operator repair is specified as D42.
- **The owner-facing words of round 3** (the promise's "without your
  passkey", "Lost a device?", "Finish removing it") are the operator's to
  approve before a client reads them.
- **D24's trade, in full, in the owner's words:** any script that runs on the
  dashboard's origin (an XSS bug, a compromised dependency, a browser
  extension with access to the page) can read the seal from `mailbox()` and
  open it with `deriveBits` on the stored unlock key whenever the device is
  kept unlocked, and so take a copy of the mailbox key. **Later option:**
  where engines can store X25519 keys (Chromium, Firefox, Safari once its
  serializer accepts them), keep the opened mailbox key itself,
  non-extractable, and make device seals one-shot (deleted once opened), so
  the stored state can be used but never copied.

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
- **Deferred 2026-10-19: the workaround for WebKit bug 307095** (WebKitGTK and
  WPE on Linux, §9). It is kept on the branch `feat/002-webkitgtk-workaround`.
  CI tests WebKit on macOS only (the Cocoa port, Safari's Web Crypto), until
  the fix reaches a WebKitGTK and WPE release. Until then a Linux WebKit
  browser fails some keys closed (§9).

## 9. Facts this rests on (checked 2026-10-16)

| Fact | Source |
|---|---|
| `CryptoKey` is serializable; IndexedDB stores it by structured clone, and a non-extractable key stays non-extractable | MDN (SubtleCrypto "Storing keys", CryptoKey.extractable), through context7 |
| WebKit cannot read an X25519 `CryptoKey` back from IndexedDB ("Unable to deserialize data"): its OKP serializer accepts Ed25519 only, and writes no public/private distinction | the bun project's fix of the same WebCore code (PR #33553), and an application's Safari report (cipheroom PR #13); secondary sources, consistent with each other |
| Safari private windows cannot store any `CryptoKey` in IndexedDB (no per-origin wrapping key in an ephemeral session) | an application's report (open-chat issue #9343), marked unverified on a device there too |
| PRF needs a browser and a passkey provider that both support it; where one does not, that passkey cannot be a factor and the recovery key is the way in (D31's rule, applied to factors) | the WebAuthn PRF extension as MDN describes it (`prf` on `create()` and `get()`, `enabled` on creation), through context7 |
| Two PRF inputs (`first`, `second`) per assertion | Yubico's developer guide (its key-rotation example) |
| DBSC: Chrome 146 on Windows (rollout from May 2026), macOS from Chrome 147; no Safari or Firefox implementation announced; keys in the TPM or Secure Enclave | Google Workspace updates (2026-05), press coverage (2026-04, 2026-10) |
| X25519 in Web Crypto: Chrome 133, Firefox 130, Safari 17 | caniuse/MDN compat data (and 001 §8, reproduced) |
| Workers Web Crypto: ECDSA sign/verify, ECDH and X25519 deriveBits, HKDF, HMAC, AES-GCM wrapKey/unwrapKey | Cloudflare Workers docs, through context7 |
| `@hpke/core` 1.9.0 exports the export-only AEAD (`ExportOnly`) and `export()` on both contexts, and takes a `CryptoKey` (or pair) as the recipient key; DHKEM(P-256) is native Web Crypto | its installed type declarations (read) |

**Checked while building (2026-10-18 and 19):**

| Fact | Source |
|---|---|
| WebKit's libgcrypt backend (WebKitGTK and WPE on Linux, and Playwright's WebKit there) drops a leading zero byte from an X25519 scalar: it refuses a PKCS #8 key whose first scalar byte is zero (DataError, 300 of 300), and its X25519 `generateKey` fails about 1 draw in 256 (OperationError). It is WebKit bug 307095, fixed on WebKit main on 2026-10-09 (323215@main) and in no Playwright build yet | mail-client's WebKit probe in CI (runs 39166192512, 39168798436); the WebKit bug tracker |
| mail-crypto works around it with no byte of any output changed: a factor key (never serialized) is imported with the three low bits of its first byte set, which X25519 ignores (RFC 7748 §5), and a fresh X25519 pair is drawn again after an OperationError | mail-crypto `src/keys.ts`, `test/engines.test.ts`; CI run 39178472679 green in WebKit on Linux and macOS, Chromium and Firefox |
| WebKit's Cocoa port, the Web Crypto code Safari ships, does not have the bug, and keeps non-extractable P-256 keys across a reload | the probe and the kept-device browser tests on macOS (CI job `browsers-macos`); its source (`importPkcs8` copies the bytes) |
| A mailbox key another engine made with a zero first scalar byte cannot be opened in an unfixed WebKitGTK or WPE browser. It fails closed, as a factor that did not work. Chromium never makes such a key; Firefox makes about 1 in 256 | the probe's tally of 1,200 keys per engine |
| `@hpke/core` 1.9.0 opens a seal with a non-extractable P-256 recipient key only when it is given the key pair: from the private key alone it rebuilds the public key with an even y, which is the wrong point for about half of all keys. So a kept device keeps its unlock key's public form (K5), and opens its seal with both | the D1 builder's probe of the installed package (22 of 40 failed without the pair) |

**Checked for round 3 (2026-10-22):**

| Fact | Source |
|---|---|
| Better Auth renews a session by updating `expiresAt` and `updatedAt` on the same session row (looked up by its token), so the session's id does not change while it is renewed; signing out deletes the row | Better Auth's `getSession` refresh path and `internalAdapter.deleteSession`, through context7; the dashboard's spec 008 pins 1.7.11 |
| RFC 8785 fixes one serialization per JSON value: members sorted by UTF-16 code units, no whitespace, strings and numbers as ECMAScript writes them, and it refuses duplicate names and lone surrogates | RFC 8785 §3, read from the RFC Editor |
| `@hpke/common` 1.10.1 imports a derived P-256 scalar as PKCS #8 without its public key, which works in Chromium, Firefox, Node and workerd but **not in WebKit**: WebKit's `CryptoKeyECCocoa.cpp` requires the `publicKey` field (bug 233705), so CI's macOS WebKit job refused it (`DataError`). Hence D44 | its installed source, `kems/dhkemPrimitives/ec.js`; WebKit's source and bug tracker, read by the R3-1a builder; CI runs 39731532745 and 39732195642 |
| Ed25519 in Web Crypto: Chrome 137, Firefox 129, Safari 17 (Safari's signatures are randomized); Workers support Ed25519 sign, verify and import (Secure Curves) | MDN browser-compat-data (`SubtleCrypto` sign/verify/importKey `ed25519`); Cloudflare's Web Crypto docs, through context7 |

**Reported, not verified** (both on the operator's own devices first; until
then a passkey that does not open its wrap fails as "that didn't work", and
the recovery key remains):

- iCloud Keychain passkeys return PRF results in Safari 18 and later on macOS
  15 and iOS 18, but not over the cross-device (QR code) flow; and one report
  says a passkey synced to a second Apple device returns a different PRF
  output there. If that holds, the passkey works as a factor on the device
  that made its wrap, and another Apple device needs the recovery key once
  (K9 would flag the mismatch). Sources: Apple Developer Forums threads 774112,
  774111 and 822523 (user reports; one Apple engineer called the cross-device
  difference a bug).

**Not verified**, and where it gets checked:

- Real Safari on macOS and iOS. Playwright's macOS WebKit runs the same Web
  Crypto code (see above), and passes; the first check on Safari itself is the
  operator's own iPhone. Until then, D31 makes a failure safe.
- Which passkey providers return PRF in Firefox on macOS and Linux. Not
  needed for the design (the recovery key covers any browser); worth knowing
  for the owner.
- That a non-extractable X25519 key may `deriveBits` with its own public key in
  every engine (A5). Checked in the browser tests.
