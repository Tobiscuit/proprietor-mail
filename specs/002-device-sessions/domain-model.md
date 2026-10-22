# Domain model — unlock once per device, with revocation

**Spec:** `spec.md` · **Plan:** `plan.md` · **Written:** 2026-10-16, round 3
amended 2026-10-22 (G42 rewritten, G43–G49, M15′, M17′, M18′, M21′, M22–M25,
K2″, K3′, K10–K13) ·
continues `../001-inbox-module/domain-model.md` (its G1–G25, M1–M12, K1–K2).

## 0. Gaps this pass found

Each one is a place where a requirement as first stated conflicts with
another, or names a concept the model did not have, or leaves ownership
unclear. Each has its resolution, and each resolution is a test.

| # | Gap | What happens if it is missed | Resolution |
|---|---|---|---|
| G26 | **WebKit cannot keep an X25519 key in IndexedDB**, and private windows keep no key at all. | "Store the mailbox key in the browser" fails on every iPhone, where a passkey from another provider may not do PRF either. | Device keys are P-256. The mailbox key is never stored in the browser: a seal at Mail, opened by the device's unlock key (D24). A storage check before the first use; a failure means a shared computer (D31). |
| G27 | **Anyone can seal a key to a public key.** A seal says nothing about who made it. | A server could seal a key it controls to a device and advertise it as the mailbox's new key. The device would open it, it would match the advertised key (K2 passes), and drafts and new mail would be readable by the server. | K2′: a sealed key is accepted only when successor seals lead from it to a key the browser already trusts. A successor seal can only be made by a holder of the older private key. |
| G28 | **The server could add a recipient** (a device or factor key it controls) to the key ring. | The next rotation would seal the new key to it, and through the chain every old key. | K3: binding tags, an HMAC under a key derived from the mailbox key itself (contract A5), over every recipient. The rotating browser checks them before it seals. A recipient whose tag fails is flagged, never sealed to, shown to the owner and removable; the rest of the inbox keeps working (amended 2026-10-19). |
| G29 | **A stolen device that is unlocked holds a session and the key.** | It could remove the owner's other devices, rotate to a key only it holds, add its own passkey, or change the recovery key: a takeover. | D25: those operations need a factor proof that Mail checks against the factor's public key. The device holds no factor. |
| G30 | **Mail has never seen a factor's public key** for the mailbox enrolled under 001, so it cannot check one. | Either no factor proofs at all, or a first registration on trust that someone holding the key could also make. | D26: one upgrade, with every factor of the mailbox at once, only while no factor has a key, and before any device is kept. After it, every new factor key needs a proof from a factor Mail already knows (amended 2026-10-19). |
| G31 | **Rotation needs the new key "wrapped under the recovery key", but the rotating browser may not have the recovery secret** (the owner used a passkey). | The recovery key would stop reaching new mail, and the last way back would be gone. | Every factor has a public factor key derived from its secret (contract A2). A rotation seals the new key to it, with no secret needed. M5′: rotation is refused unless a recovery factor receives the new key. |
| G32 | **A device or factor added after a rotation gets only the active key.** | Mail sealed to retired keys would not open on it. | Successor seals: each retired key is sealed to its successor. Any holder of the active key walks back through the chain. |
| G33 | **A key proof asks the browser to decrypt something for Mail.** | Mail could pass a message's key envelope off as a challenge and get the message key back: a decryption oracle. | K4: challenges are their own HPKE domain (`info` used by nothing else). Anything else fails to open, and the browser answers nothing. |
| G34 | **A locked device still has its signing key, and the dashboard cookie still works.** | A locked, stolen device could still send mail as the business. | D27: a session needs a key proof, which a locked device cannot make. |
| G35 | **The dashboard's send route belongs to its shell**, not to the inbox. | A session carried as an argument would need a change in another session's code before anything ships. | D29: `send` carries the session inside its request, which the route passes on unchanged. |
| G36 | **"Lock when I sign out" needs to know when a sign-in ended**, and the inbox cannot see that. | A setting whose name is not what it does. | D30: a per-sign-in id from the shell. Until it exists, the setting is labeled "until I lock it". |
| G37 | **Web Crypto lets the caller of `unwrapKey` choose `extractable`.** A device's unlock key can open its seal as an extractable key. | K1, as written in 001, would quietly stop being true on kept devices. | K1′ says what holds: honest code never asks for an extractable copy except for one sealing or wrapping step after a factor. Any code on the dashboard's origin could. This is said in the spec's threat model (§4). |
| G38 | **Two browsers can change the key ring at once** (a rotation while another browser keeps itself). | A rotation that misses a new device, or a seal made under a key that is no longer active. | Every write names the key it was made under (`rotation.from`, `tagKeyId`). Mail refuses a stale one, and a rotation must name every remaining recipient exactly. The browser refreshes and tries again. |
| G39 | **A session token passes through the dashboard.** | A bearer secret in another application's hands. | It lasts 60 minutes, is renewed only with a fresh key proof, is stored as a hash, and is never logged or stored by the dashboard (contract A8). |
| G40 | **An unlocked session holds only the active key today.** | After the first rotation, old mail would show "could not be decrypted". | The session holds every key the chain reaches, by keyId. |
| G41 | **The unread badge is read by the dashboard's shell outside any session.** | Requiring a session there would break the badge, or push sessions into the shell. | `unread` stays outside sessions. The count is metadata the platform already sees (001 §4). |
| G42 | **A device belongs to a person, not just to a mailbox.** Two people can share one browser profile. | One person's kept device opening the inbox for another; and (found 2026-10-19) the other person's page opening the mailbox key before Mail refuses, then wiping the owner's record on the refusal. | D37 (rewritten 2026-10-22): the browser keeps one record per mailbox and account, and reads only the signed-in account's, so nothing is opened for anyone else (K10). Mail opens sessions for a device only for the account that kept it, and answers anyone else `Forbidden`, which wipes nothing (M21′). |
| G43 | **An email code proves only that someone reads the owner's email.** | If it could confirm a rotation, whoever makes the successor key would know it: an email-only actor would read every later message. | D35: an email code confirms `revoke-device` and nothing else (M22). The rotation waits for a factor (M23). |
| G44 | **A confirmation travels through the dashboard** (model finding 3). | The relay pairs a factor answer with its own request, for example a rotation to its own key. Mail checks a rotation's shape, never its seals. | D36: an action descriptor per confirmed action; the factor challenge's associated data holds its digest, so the browser answers only its own action; Mail recomputes the request's digest (M17′). |
| G45 | **A copy of the mailbox key answers key proofs.** | Revoking without rotating would stop a device's signature but not a page with a copied key: it opens a session without a device. | D38: a session needs a key proof and a device signature or a factor proof (M15′). |
| G46 | **Binding tags prove only that the tagger held the mailbox key** (model findings 1 and 2). | With a key from a removed device or a stolen unlocked one, and a hostile server: a forked chain the browser accepts, or a planted recipient the owner's next rotation seals to. | D39: factors sign transitions and admit recipients; devices sign their unlock keys; browsers trust only what a connected factor signed (K2″, K3′); Mail checks the same (M25). |
| G47 | **Two flagged devices** (§7a). | Each removal seals the new key to the other flagged device, which K3 refuses: neither can go. | D40: several devices in one rotation (M18′). |
| G48 | **Two tabs move one anchor** (model finding 4). | A device's `lastKeyId` steps back to an older honest key. | D41: compare-and-swap in one IndexedDB transaction (K11). |
| G49 | **A recovery factor whose listed keys are wrong, and no other factor** (§7a). | No factor proof is possible, so nothing that needs one can be done. | D42: an operator-opened, audited repair window, specified only. |

## 1. Bounded contexts: what changes

| Context | Change |
|---|---|
| **Key Custody** (browser, `mail-crypto` + `mail-client`) | Grows: factor keys, device keys, key seals, successor seals, binding tags, challenges, device proofs; the kept-device store (the only persistence, K5); the lock engine (K6). |
| **Mail Storage** (the `Mailbox` Durable Object) | Grows: the key ring gains factor keys, devices, seals and successor seals; new entities Challenge and MailSession, with their lifecycles; the `sessions` switch. |
| **Identity & Access** (the dashboard shell) | Capability v1 gains one optional claim, `confirmation` (round 3). It gives the inbox a per-sign-in id (D30, D34) and sends email codes for one action Mail described, attesting them in the capability (D35). Its sign-in still says who the person is; it no longer suffices to reach mail, and an email code only revokes. |
| **Presence** | Unchanged: the unread count stays outside sessions (G41). |

## 2. Context map

```
  Identity & Access ── capability v1 (+ confirmation, round 3) ─▶ Mail Storage
       sends the email code for an action descriptor Mail issued; reads the
       kind and the device names from the same bytes it hashes
       (action-descriptor-v1: a Published Language both sides parse)
  dashboard inbox ── Open Host Service: MailService + device-v1 §B ─▶ Mail Storage
       (relays the session token; never mints, reads or stores it)
  Key Custody ◀── Shared Kernel: envelope v1 + device-v1 §A ──▶ Mail Storage
       one implementation in packages/mail-crypto; the Worker uses only
       sealChallenge and verifyDeviceProof (src/proofs.ts)
```

The new Shared Kernel half is device-v1 Part A. As with envelope v1, there is
one implementation of every format, in `packages/mail-crypto`.

## 3. Aggregates and their invariants

### Mailbox (root): the key ring, devices and sessions in one boundary

Devices, seals and sessions live in the same Durable Object as the key ring,
because a removal, its rotation and the end of sessions must happen in one
transaction (M18). Every invariant below is a test.

- **M5′ — The active key is always reachable by a recovery factor.** It has a
  recovery wrap, or a seal to a recovery factor's key. A rotation that would
  break this is refused. The last recovery factor that reaches the active key
  cannot be removed. (Replaces 001's M5, which said only "a recovery wrap".)
- **M13 — Sessions, once required, stay required.** `sessions` goes from
  `optional` to `required` (upgrade, or an enrollment with factor keys) and
  never back.
- **M14 — Every mailbox call except `mailboxes`, `mailbox`, `unread`, `enroll`,
  `challenge` and `openSession` needs a live session of the calling account**
  while sessions are required. A session tied to a device ends with the
  device.
- **M15′ — A session opens only with a key proof, and (while sessions are
  required) either a kept device's signature or a factor proof bound to
  `open-session`** (D38; amended 2026-10-22). While sessions are optional, a
  key proof alone still opens one, as before.
- **M16 — A challenge is used once, lives 2 minutes, and is consumed even when
  its answer is wrong.** At most 20 are live per mailbox.
- **M17′ — Keeping a device, removing devices (with their rotation), adding
  or removing a factor each consume a fresh factor proof** once sessions are
  required, and the upgrade consumes a key proof. **Each proof answers a
  challenge whose descriptor names that call's own request** (its digest,
  recomputed by Mail at the call), and is spent by the first call that
  presents it (D36; amended 2026-10-22).
- **M18′ — Removing devices rotates the key, in one transaction**: the
  devices (0 to 20; none only when a rotation is due), their seals and their
  sessions are gone; a new key is active; the old one is retired with its
  successor seal and the transition signature of the factor whose proof was
  spent; every remaining device with an unlock key and every factor with a
  factor key has a seal of the new key and a new tag; every other session has
  ended; no rotation is due. Nothing is written when any check fails
  (amended 2026-10-22, D39, D40).
- **M19 — Seals exist only for the active key**; a retired key is reachable
  only through its successor seal.
- **M20 — The upgrade happens once**: while sessions are optional and no
  factor has a key, with a live session, and naming every factor the mailbox
  has (amended 2026-10-19).
- **M21′ — A device works only for the account that kept it** (G42). For
  another account it is `Forbidden`, never `DeviceRevoked`, and nothing is
  written (D37).
- **M22 — An email code revokes and does nothing else** (D35). `revokeDevices`
  with a valid attestation deletes the named devices, their seals and their
  sessions, and marks a rotation due, in one transaction. No key, seal, tag or
  factor is written. Every other method ignores an attestation.
- **M23 — A due rotation stays due until a rotation**, and a new key enters
  the mailbox only through `removeDevices` with a factor proof whose factor
  signed the transition (D35, D39). Enrollment makes the first key; nothing
  else makes one.
- **M24 — A factor record is never deleted** (D39). Removing a factor deletes
  its wrap and its seals and records `removedAt`; Mail never again accepts its
  proof. Its signing key, admission and the signatures it made stay, so the
  chain and the admissions it signed keep verifying.
- **M25 — Mail stores only what verifies**: every device's admission signed by
  the factor whose proof the call spent, every unlock key signed by its
  device, every factor's admission signed by the confirming factor and by
  itself (at enrollment and the upgrade, each by the next factor in id order,
  and by itself), every transition signed by the factor whose proof the
  rotation spent (D39).

The invariants of 001 stand: M1 (no plaintext at rest; a token, an answer or
a seal's content is never written in the clear), M3 (no private key on the
server), M4 (another business's mailbox is NotFound).

### KeyRing (inside Mailbox), extended

- **Key** `{ keyId, publicKey, createdAt, createdBy, retiredAt, successor:
  { keyId, sealed } | null }`.
- **Factor**: a wrap record (`wrp_` id, kind, credentialId, label, its
  envelope v1 wrap of the key that was active when it was added) plus
  `factorKey`, `signingKey`, `admission { by, signature, selfSignature }`,
  `tag`, `tagKeyId`, `removedAt | null` (round 3). Its envelope v1 wrap is its
  **anchor**: proof, made with the factor's own secret, of the key it was
  added under.
- **Device** `{ id, accountId, label, signingKey, unlockKey | null,
  unlockSignature | null, admission { by, signature }, tag, tagKeyId,
  createdAt, lastSeenAt }`.
- **Transition** (on a retired key's successor, round 3): `{ keyId, sealed,
  signedBy, signature }`: the factor that confirmed the rotation signed
  "this key's successor is that key".
- **RotationDue** (on the mailbox, round 3): `{ since, by, devices }` after an
  email-code revocation, until the next rotation.
- **Seal** `{ keyId (the active key), to: { kind: device | factor, id },
  sealed }`.

### Challenge (entity inside Mailbox)

`{ id, purpose: session | factor | key | email, targetId, answerHash | null,
nonce, accountId, descriptor | null, actionDigest | null, createdAt,
expiresAt, usedAt | null }` (round 3: the `key` and `email` purposes and the
descriptor). Lifecycle: live → used, or live → expired. Never reused.

### MailSession (entity inside Mailbox)

`{ tokenHash, accountId, deviceId | null, createdAt, expiresAt }`. Lifecycle:
live → expired, or live → ended (its device was removed, or a rotation ended
every other session).

### The kept device (Key Custody, in the browser)

A value the browser keeps in IndexedDB per mailbox **and account** (round 3):
`{ mailboxId, accountId, deviceId, label, signingKey, unlockKey | null,
signingPublic, unlockPublic | null, lastKeyId, trustRoot, lockAfter,
lastActiveAt, signInId }`. `trustRoot` is the signing key of the factor last
used on this device: the factors connected to it are the ones whose
signatures this device trusts (K2″, K3′). States:

```
   (none) ──keep (factor)──▶ kept, unlocked ──lock (setting, Lock now, sign-out)──▶ kept, locked
                                  ▲   │                                                  │
                                  │   └──────────── unlock (factor) ◀───────────────────┘
                                  │
            removed (DeviceRevoked, or absent from mailbox()) ──▶ wiped ──▶ (none)
```

Invariants of Key Custody (contract Part C): **K1′** (keys in a session are
non-extractable and decrypt-only; extractable only for one sealing or
wrapping step just after a factor), **K2″** (a key is accepted only along a
chain to a trusted key, each step signed by a trusted factor; no rollback),
**K3′** (seal only to recipients whose tag verifies and whom a trusted factor
admitted; check every one at unlock), **K4** (answer only challenges, and a
factor challenge only for the action this browser is sending), **K5** (only a
kept device persists, and only P-256 keys and plain facts), **K6** (lock
settings are the browser's), **K7** (a removed device keeps nothing), **K10**
(another account's record is never read, opened or wiped), **K11** (the last
accepted key only moves forward), **K12** (confirmations are bound: build the
descriptor yourself and compare), **K13** (a browser holding a fresh factor
finishes a due rotation first). 001's K2 (the advertised key checked at every
unlock) is part of K2″.

## 4. Ubiquitous language

| Term | Means | Does not mean |
|---|---|---|
| **Device** | One browser profile on one computer or phone, kept by one person | A person; a passkey |
| **Kept device** | A device the owner said is theirs, with keys in its browser | Any browser that unlocked once |
| **Shared computer** | A browser that keeps nothing | A device |
| **Factor** | The person's passkey (with PRF), or the recovery key | A device |
| **Factor signing key** | The P-256 signing key derived from a factor's secret; Mail holds its public half (round 3) | The factor key, which receives seals |
| **Admission** | A factor's signature saying "this device (or factor) is the owner's" (round 3) | A binding tag |
| **Transition** | A factor's signature saying "this key's successor is that key" (round 3) | A successor seal |
| **Action descriptor** | The bytes Mail issues naming one action to confirm, with a nonce spent once (round 3) | A request |
| **Revoked** (device) | Removed by an email code: refused at once, the rotation still due (round 3) | Removed with a rotation |
| **Rotation due** | The state after a revocation, until a factor holder rotates (round 3) | A failure |
| **Factor key** | The X25519 key pair derived from a factor's secret; Mail holds its public half | The factor's secret |
| **Unlock key** | A kept device's ECDH P-256 key; the mailbox key is sealed to it | The mailbox key |
| **Signing key** | A kept device's ECDSA P-256 key; it signs session challenges | A passkey |
| **Seal** | A mailbox private key encrypted to one recipient's public key | Envelope v1's message sealing |
| **Successor seal** | A retired key sealed to the key that replaced it | A backup |
| **Binding tag** | An HMAC, under a key only mailbox-key holders can derive, over a recipient's public keys | A signature Mail can check |
| **Mail session** | An hour of mailbox calls, opened with a key proof | The dashboard's sign-in |
| **Key proof / factor proof / device proof** | The answer to a challenge sealed to the active key / to a factor key; a device's signature over a challenge | A password |
| **Locked** (device) | Its unlock key is deleted; a factor is needed | Removed |
| **Removed** (device) | Gone from the mailbox; refused; the key rotated | Locked |
| **Upgrade** | The one-time step that gives an existing mailbox's factors their keys and turns sessions on | A software update |
| **Rotation** | A new active key, the old one retired with its successor seal, done with every removal | Re-encrypting old mail |

## 5. Lifecycles

```
Mailbox sessions:   optional ──upgrade / enroll with factor keys──▶ required   (never back: M13)

Key:                active ──removeDevices──▶ retired (successor seal + transition set)   (never deleted)

Rotation:           none ──revokeDevices (email code)──▶ due ──removeDevices (factor)──▶ none

Factor:             legacy (no factor key) ──upgrade (every factor at once)──▶ keyed ──removeWrap──▶ removed (record kept, M24)
                    (a keyed factor gets a seal of each new key at every rotation)

Device:             registered (unlock key) ⇄ locked (no unlock key)  ──removeDevices / revokeDevices──▶ gone
                    (updateDevice moves between the two; a locked device's stale unlock key
                     and seal are replaced at its next unlock)
```
