# Contract: kept devices, factor keys and mail sessions, version 1

**Spec:** `specs/002-device-sessions/` (the decisions and the threat model are
there; this file fixes the bytes and the calls).
**Implemented by:** `packages/mail-crypto` (every byte format below, in one
place; `src/proofs.ts` holds the two functions the Worker calls), the Mail
Worker (`MailService`, `Mailbox`: Part B), `packages/mail-client` (the
browser's half and its rules: Part C and `mail-client-v1.md`).
**Status:** written 2026-10-16, before any code. A builder who finds that a
format below cannot be built as written proposes the change to the architect,
who changes this file first.

Envelope v1 is unchanged: every message, draft and wrap stored today stays
readable, and nothing here re-encrypts them. This contract adds formats next
to it. Any change to a byte below is a new version (`device-v2`), never an
edit of v1, once a mailbox has stored it.

Notation as in `envelope-v1.md`: UTF-8 strings, `||` is concatenation,
base64url is RFC 4648 §5 without padding, random bytes come from
`crypto.getRandomValues`. `ctx(label, a, b, …)` is the UTF-8 of
`"proprietor-mail/v1/" + label + "|" + a + "|" + b + …`, the same rule as
envelope v1's associated data: no part is empty and no part contains `|`
(implementations refuse such a part). `b64u(x)` is the base64url of `x`.

## Part A — formats

### A1. Identifiers

| Prefix | What | Made by |
|---|---|---|
| `dev_` | a kept device | the browser |
| `chl_` | a challenge | Mail |

Both follow envelope v1's rule: the prefix, then 26 lowercase Crockford base32
characters of 16 random bytes. A factor's id is its wrap's id (`wrp_`, envelope
v1): a factor and its first wrap are one record.

### A2. Factor keys

Every factor (a passkey with PRF, or the recovery key) has an X25519 key pair
derived from its secret, so that a browser that holds the mailbox key can seal
a new key to a factor that is not present, and Mail can check that a factor
was just used without ever holding its secret.

```
secret = the passkey's 32-byte PRF output for prfInput(mailboxId, factorId)   (kind "passkey-prf";
         the same evaluation that opens its envelope v1 wrap)
       | the 32-byte recovery secret                                            (kind "recovery")
ikm    = HKDF-SHA256 over the secret, with the factor id (as UTF-8) for salt,
         info = ctx("factor-key", mailboxId, factorId, kind), and L = 32
(skF, pkF) = DeriveKeyPair(ikm)   for DHKEM(X25519, HKDF-SHA256)   (RFC 9180 §7.1.3)
```

`pkF` (32 bytes) is the factor's public key; Mail stores it. `skF` exists only
in the browser, for the moments after the person used the factor, imported as
a non-extractable key with usage `deriveBits`; the derived scalar is zeroed
after the import. The KEK of envelope v1 and the factor key come from one
PRF evaluation through different HKDF info strings, so neither reveals the
other.

### A3. Device keys

A kept device holds two P-256 key pairs, generated in the browser with
non-extractable private keys:

| Key | Algorithm | Usage | Public form |
|---|---|---|---|
| signing key | ECDSA P-256 | `sign` | raw uncompressed point, 65 bytes (`0x04 ‖ X ‖ Y`) |
| unlock key | ECDH P-256 | `deriveBits` | raw uncompressed point, 65 bytes |

P-256, not X25519, because WebKit cannot read an X25519 `CryptoKey` back from
IndexedDB (spec §9). The mailbox key itself is never stored in the browser.
The unlock key exists only while the device is kept unlocked. The device
deletes it to lock, and makes a new one at its next unlock.

### A4. Key seals

A key seal is a mailbox private key (X25519) encrypted to one recipient public
key, made with Web Crypto's `wrapKey` so the private key never exists as bytes
in JavaScript (envelope v1, D21).

```
suite  = HPKE base mode (RFC 9180): KEM = DHKEM(X25519, HKDF-SHA256) 0x0020 for a factor or
         successor recipient, DHKEM(P-256, HKDF-SHA256) 0x0010 for a device recipient;
         KDF = HKDF-SHA256 0x0001; AEAD = export-only 0xFFFF
info   = ctx("key-seal", mailboxId, sealedKeyId, toKind, toId)
         toKind = "device" | "factor" | "successor";
         toId   = the device id | the factor id | the successor's keyId
(enc, context) = SetupBaseS(pkR, info)
kek    = context.Export(UTF-8("proprietor-mail/v1/key-seal/kek"), 32)  → an AES-256-GCM key
iv     = 12 random bytes
ct     = wrapKey("pkcs8", sealedPrivateKey, kek, { AES-GCM, iv, additionalData = info })
         (48 bytes of PKCS #8 PrivateKeyInfo, envelope v1 §"Wrapping", + 16-byte tag = 64)
bytes  = 0x01 ‖ enc ‖ iv ‖ ct
```

| Recipient | enc | Total |
|---|---|---|
| factor, successor (X25519) | 32 | **109 bytes** |
| device (P-256) | 65 | **142 bytes** |

Opening: `SetupBaseR(enc, skR, info)`, the same export, then
`unwrapKey("pkcs8", ct, kek, { AES-GCM, iv, additionalData = info }, X25519,
extractable, ["deriveBits"])`. A reader refuses any other length or lead byte,
and refuses the result unless its keyId equals `sealedKeyId`. `extractable` is
false unless the caller is about to seal or wrap that key again (Part C, K1).

A **successor seal** is a key seal of a retired key to the public key of the
key that replaced it: `toKind = "successor"`, `toId` = the successor's keyId,
the recipient public key = the successor's. Only a holder of the retired
private key can make one, so a successor seal proves that whoever introduced
the new key held the old one.

### A5. The binding key and binding tags

A browser that holds a mailbox key must be able to tell whether a device or a
factor key in the key ring was put there by another holder of that key, or by
whoever controls the server. Mail cannot make or check these tags.

```
z      = X25519(sk, pk)      sk = the mailbox private key, pk = its own public key (32 bytes)
kbind  = HKDF-SHA256(ikm = z, salt = "" (empty), info = ctx("binding", mailboxId, keyId), L = 32)
         → an HMAC-SHA-256 key, non-extractable, usages sign and verify
tag    = HMAC-SHA-256(kbind, message), 32 bytes

message for a device = ctx("recipient", mailboxId, keyId, "device", deviceId,
                           b64u(UTF-8(label)), b64u(signingKey), unlockKey === null ? "-" : b64u(unlockKey))
message for a factor = ctx("recipient", mailboxId, keyId, "factor", factorId, kind,
                           b64u(UTF-8(label)), b64u(factorKey), credentialId ?? "-")
```

`z` is the X25519 product of the private key with its own public key. Computing
it from the public key alone is as hard as computational Diffie-Hellman.
`keyId` is the key the tag is made under: always the active key when it is
written (`tagKeyId` in Part B). When the key changes, every remaining
recipient is tagged again under the new key, in the same transaction
(Part B, B7). A device's tag also covers its label, so a renamed device is
detectable.

### A6. Challenges

Mail proves nothing to the browser, but it must learn two things from it: that
the browser holds the mailbox key now (a **key proof**), and that the person
just used a factor (a **factor proof**). Both answer a challenge.

```
answer = 32 random bytes, drawn by Mail; nonce = 32 random bytes, drawn by Mail
target = the active mailbox public key (purpose "session"), targetId = its keyId
       | a factor public key (purpose "factor"),            targetId = the factor id
sealed = enc ‖ ct = HPKE base mode Seal(pkR = target, info = UTF-8("proprietor-mail/v1/challenge"),
         aad = ctx("challenge", mailboxId, challengeId, purpose, targetId), pt = answer)
         with DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM: 32 + 48 = 80 bytes
```

The browser opens `sealed` with the mailbox private key (purpose `session`) or
the factor's `skF` (purpose `factor`), and returns `answer`. Mail keeps only
SHA-256(answer) and compares hashes.

**No decryption oracle (K4).** A challenge opens only under its own `info`,
which nothing else uses, so a browser that answers challenges can never be
made to decrypt a message key, a draft, a wrap or a seal for Mail: any other
ciphertext presented as a challenge fails to open, and the browser answers
nothing.

### A7. Device proofs

```
message   = ctx("device-proof", mailboxId, deviceId, challengeId, b64u(nonce))
signature = ECDSA P-256 with SHA-256 over message, IEEE P1363 form (r ‖ s), 64 bytes
```

The device's signing key signs nothing else.

### A8. Mail sessions

A mail session token is 32 random bytes drawn by Mail, sent as base64url (43
characters). Mail stores SHA-256(token) only. The token is a bearer secret for
at most 60 minutes. It lives in the browser's memory and passes through the
dashboard for one request at a time, and is never stored or logged there.

### A9. Vectors

`contracts/device-v1.vectors.json` (written by the mail-crypto builder): a
fixed mailbox key pair, a fixed PRF output and recovery secret with the factor
keys they derive, open vectors for a key seal to each recipient kind and a
successor seal (the recipient's private key, the bytes, the keyId they open
to), the binding key's tags for one device and one factor, a challenge for
each purpose with its answer, and a device proof with its public key. Negative
cases: a seal opened with another `toId` or `toKind`, a challenge opened as a
key seal and a key seal opened as a challenge, a message key envelope (envelope
v1) presented as a challenge, a tag over a changed label, a device proof over
another nonce.

## Part B — `MailService` additions

`mail-service-v1.md` still holds: every answer is a `MailResult` value, and
refusals are never thrown. This part adds an argument, eleven things to
check, and three error names.

### B1. The `auth` argument

```ts
/** The last argument of every method marked "session" in B3. */
interface Auth {
  /** The token from openSession(). */
  session?: string;
  /** A fresh factor proof, for the methods marked "factor". */
  factorProof?: { challengeId: string; answer: string };   // answer: base64url, 32 bytes
}
```

`send` is the exception: its session travels **inside the request**, as
`request.session`, because the request is built in the browser
(`encodeSendForm`) and the dashboard's send route hands it on unchanged.

### B2. When a session is required

Each mailbox has `sessions: "optional" | "required"`. It starts `"optional"`
(every mailbox enrolled before this contract), and becomes `"required"`
through `upgrade`, or at once through an `enroll` whose wraps carry factor
keys. **It never goes back** (M13).

While `"required"`, a method marked "session" refuses with `SessionRequired`
unless `auth.session` (for `send`, `request.session`) names a live session of
the calling account (the capability's `sub`). A session tied to a device that
no longer exists is deleted and answered with `DeviceRevoked`. While
`"optional"`, an absent session is accepted as before, and a present but bad
one is refused (a token is never silently ignored).

### B3. The methods

| Method | Needs | Notes |
|---|---|---|
| `mailboxes(cap)` | — | unchanged |
| `mailbox(cap)` | — | the view gains B4's fields |
| `unread(cap)` | — | unchanged: the dashboard's badge reads it outside any session |
| `enroll(cap, input)` | — | B5 |
| `challenge(cap, request)` | — | B6 |
| `openSession(cap, request)` | — | B6 |
| `upgrade(cap, request, auth)` | session | B5; allowed only while `"optional"` |
| `list`, `body`, `update`, `purge`, `drafts`, `saveDraft`, `deleteDraft`, `setPolicy`, `audit` | session | each takes `auth` after its current arguments, e.g. `list(cap, query, auth)`, `body(cap, messageId, auth)`, `drafts(cap, auth)` |
| `send(cap, request)` | session (in the request) | `request.session` |
| `addWrap(cap, wrap, auth)` | session, factor | B7; while `"optional"` it works as before and takes no factor key |
| `removeWrap(cap, wrapId, auth)` | session, factor | B7 |
| `registerDevice(cap, request, auth)` | session, factor | B7 |
| `updateDevice(cap, request, auth)` | a device's session | B7 |
| `removeDevice(cap, request, auth)` | session, factor | B7: the key rotates |
| `setFactorKey(cap, request, auth)` | session, factor | B7 |

"factor" means `auth.factorProof` answers a live `purpose: "factor"` challenge
for a factor that has a factor key; it is consumed by the call. While a
mailbox is `"optional"`, `registerDevice`, `removeDevice` and `setFactorKey`
refuse with `InvalidRequest` (upgrade first).

Roles are unchanged: reading needs `openRoles`, sending `sendRoles`, and every
key, device or policy change needs `owner`. `challenge` and `openSession` need
`openRoles`.

### B4. The view

```ts
interface MailboxView {   // what mailbox() answers; the earlier fields unchanged
  sessions: "optional" | "required";
  keys: { keyId; publicKey; createdAt; createdBy; retiredAt;
          successor: { keyId: string; sealed: string } | null }[];   // a retired key's successor seal
  wraps: { id; keyId; kind; credentialId; label; wrapped; createdAt; createdBy;
           factorKey: string | null; tag: string | null; tagKeyId: string | null }[];
  devices: { id: string; label: string; signingKey: string; unlockKey: string | null;
             tag: string; tagKeyId: string; createdAt: string; createdBy: string; lastSeenAt: string | null }[];
  seals: { keyId: string; to: { kind: "device" | "factor"; id: string }; sealed: string }[];
  // ...policy, addresses, status, displayName as before
}
```

Every seal in `seals` is a seal of the active key (M19). Public keys, seals and
tags are base64url.

### B5. `enroll` and `upgrade`

`enroll(cap, { publicKey, wraps, device? })`: as before (M5), and when every
wrap carries `factorKey`, `tag` and `tagKeyId` (the new key; Mail also takes a
wrap without `tagKeyId`, since only the new key can be meant), the mailbox
starts `"required"`. `device`, when present, is `{ device: DeviceInput, seal }`
(B7's shapes) for the browser that enrolls. Mixing wraps with and without
factor keys is refused.

`upgrade(cap, { factors: { id, factorKey, tag, tagKeyId }[] }, auth)` is the
one moment an existing mailbox learns factor keys without a factor proof
(spec D26, G30). Conditions: the mailbox is `"optional"`; no wrap has a factor
key yet; `auth.session` is live (it was opened with a key proof); every listed
id is a wrap of the active key; `tagKeyId` is the active key; **at least one
listed factor is a recovery wrap**. Effect: the factor keys and tags are
stored and `sessions` becomes `"required"`, in one transaction; audit
`mailbox-upgraded` with the factor ids.

### B6. Challenges and sessions

`challenge(cap, { purpose: "session" } | { purpose: "factor", factorId })` →
`{ id, purpose, keyId: string | null, factorId: string | null, nonce, sealed,
expiresAt }`. `keyId` is the active key (purpose `session`); `factorId` is the
factor (purpose `factor`), which must have a factor key, else `NotFound`. A
challenge lives **2 minutes** and is used **once**. At most **20** live
challenges per mailbox; one more answers `RateLimited` with the seconds until
the oldest expires.

`openSession(cap, { challengeId, answer, device? })` where
`device = { id, signature }` → `{ session, expiresAt, device: string | null }`.
Mail checks that the challenge is live, of purpose `session`, made for this
account, and that SHA-256(answer) matches. When `device` is given, it also
checks that the device exists, belongs to this account, and that `signature`
verifies over A7's message. The challenge is consumed **whether or not the
answer is right**. A wrong answer or signature is `ProofRejected` and is
audited as `proof-rejected`. A challenge that does not exist, or that another
account asked for, is `ProofRejected` too, and spends nothing and writes
nothing, not even an audit row: anyone could repeat it without end. A used or
expired challenge is audited the first time it comes back, and only then. An
unknown device id, or one registered by another account, is `DeviceRevoked`. A session lives **60 minutes** and records its
device. Opening one updates that device's `lastSeenAt`.

A factor proof is checked the same way against a `purpose: "factor"`
challenge, when the method that carries it runs; it is consumed there.

### B7. Devices, factors and the rotation

```ts
interface DeviceInput {
  id: string;                  // dev_…, made by the browser
  label: string;               // 1–40 characters, one line
  signingKey: string;          // 65 bytes
  unlockKey: string | null;    // 65 bytes; null for a device that keeps nothing (lock after: right away)
  tag: string;                 // A5, under tagKeyId
  tagKeyId: string;            // must be the active key
}
registerDevice(cap, { device: DeviceInput, seal: string | null }, auth)        → DeviceView
updateDevice(cap, { unlockKey: string | null, tag, tagKeyId, seal: string | null }, auth) → DeviceView
removeDevice(cap, { deviceId, rotation: Rotation }, auth)                         → { keyId }
setFactorKey(cap, { factorId, factorKey, tag, tagKeyId, seal: string | null }, auth) → null

interface Rotation {
  from: string;                // the active keyId; anything else is refused (another browser rotated first)
  publicKey: string;           // the new key, 32 bytes
  successorSeal: string;       // the old key sealed to the new one (A4), 109 bytes
  seals: { to: { kind: "device" | "factor"; id: string }; sealed: string }[];   // the new key, to each remaining recipient
  tags:  { to: { kind: "device" | "factor"; id: string }; tag: string }[];      // each remaining recipient, under the new key
}
```

- `registerDevice`: `seal` is the active key sealed to `unlockKey`
  (`toKind "device"`, `toId` = the device id). It is present exactly when
  `unlockKey` is. At most **20** devices. The caller's session becomes this
  device's session. Audit `device-registered`.
- `updateDevice`: only from a session of that device. It replaces the unlock
  key, its tag and its seal, and deletes the device's earlier seals. `null`
  clears them (the device locked). Audit `device-unlock-key` with `set` or
  `cleared`.
- `setFactorKey`: gives a factor that has none its factor key, after the
  upgrade. The factor proof must come from **another** factor. `seal` is the
  active key sealed to the new factor key; it is required exactly when the
  factor's wrap is of a retired key. Audit `factor-key-set`.
- `addWrap` once `"required"`: the wrap is of the active key and carries
  `factorKey`, `tag` and `tagKeyId` (the active key). `removeWrap` once
  `"required"` also deletes that factor's seals. Neither may leave the active
  key unreachable by a recovery factor (M5′).
- `removeDevice`, in **one transaction** (M18):
  1. The device exists. `rotation.from` is the active key. The new public key
     is 32 bytes and new to the mailbox. The successor seal is 109 bytes.
  2. The remaining recipients are every other device with an unlock key, and
     every factor with a factor key. `seals` names exactly those, once each.
     Device seals are 142 bytes and factor seals 109.
  3. `tags` names exactly every other device and every factor with a factor
     key.
  4. A recovery factor with a factor key is among the remaining recipients
     (M5′).
  5. Effect: the device, its seals and its sessions are deleted. The new key
     becomes active. The old key gets `retiredAt`, `successor.keyId` and
     `successor.sealed`. Every seal of the old key is deleted, and the new
     seals and tags are stored. **Every other session ends**, because each
     was opened with a proof of the old key. Audit `device-removed` and
     `key-rotated` (from, to, how many seals).
  6. From the next arrival on, mail is sealed to the new key. Earlier mail
     keeps the keyId it was sealed to.

Every id, length and shape above is checked before anything is written. A
check that fails answers `InvalidRequest` and changes nothing.

### B8. Errors

Three names join the ten (`mail-service-v1.md`):

| Name | Means | The browser |
|---|---|---|
| `SessionRequired` | no live session, or a bad token | opens a session and calls again, once |
| `DeviceRevoked` | the device is not in the mailbox | wipes its record (Part C) and asks for a factor |
| `ProofRejected` | a key proof, factor proof or device signature failed, or its challenge expired or was used | shows "that did not work, try again"; never retries on its own |

A caller that does not know a name still treats it as `InternalError`.

### B9. Housekeeping and audit

The daily housekeeping deletes expired challenges and sessions. Audit rows
carry ids, kinds, counts and labels, never a token, an answer, a seal or a key.
The audit actions are `mailbox-upgraded`, `device-registered`,
`device-unlock-key`, `device-removed`, `key-rotated`, `factor-key-set` and
`proof-rejected`, plus the existing `wrap-added` and `wrap-removed`.

## Part C — what the browser must do

The API is `mail-client-v1.md` (amended); these are the rules it implements.

- **K1′ — Keys in a session stay non-extractable and decrypt-only.** A key is
  opened extractable only for the steps that seal or wrap it again in the one
  flow the person just started with a factor (a FreshFactor: two removals in a
  row, or a new recovery key and the old one's removal), for at most 2 minutes,
  and is dropped when the flow ends or the 2 minutes pass. After a rotation the
  FreshFactor holds the new key in that form, for the rest of its time. On a kept device the unlock key can open the device's seal.
  Web Crypto lets the caller of `unwrapKey` choose `extractable`, so any code
  running on the dashboard's origin while that device is unlocked could take
  an extractable copy. That is inside D2's trust boundary, and the spec says
  so (§4).
- **K2′ — A key is accepted only along a chain the browser can check.** The
  advertised active key is accepted when its private key was opened from:
  (a) an envelope v1 wrap with the factor just used (that wrap can only have
  been made with the factor's secret); or (b) a seal (to this device, or to
  the factor just used) **and** the successor seals lead from it back to a key
  the browser already trusts (the key (a) opened, or the key this device last
  accepted). Walking back means: for the key `k`, find the key whose
  `successor.keyId` is `k`, open its successor seal with `k`, require the keyId
  it names, and repeat. A seal of a key that does not lead back stops
  everything with the key-substitution warning (domain-model G7). So does an
  advertised key older than the one this device last accepted (a rollback).
  The opened active key must also match the advertised public key (K2).
- **K3 — A key is sealed only to recipients whose tag verifies.** Before
  sealing anything to a device or a factor, the browser checks that
  recipient's tag under the active key. At every unlock it checks every tag in
  the key ring, and one that fails stops everything with the same warning.
- **K4 — Only challenges are answered** (A6).
- **K5 — Only a kept device persists, and only P-256 keys and plain facts:**
  in IndexedDB, per mailbox: the device id, its label, the two private keys
  (non-extractable `CryptoKey`s, A3), their public forms, the keyId it last
  accepted, its lock setting, its last activity time, and the sign-in id it was
  unlocked under. Never a mailbox key, a factor secret, a token or decrypted
  content. A browser whose storage cannot keep such keys (checked before the
  first use) is treated as a shared computer, and the screen says so.
- **K6 — Lock settings are enforced by the browser alone**, when the inbox
  loads and while it is open. Mail cannot enforce them, and the spec says so.
  Locking deletes the unlock key, then clears it at Mail when a session is
  live.
- **K7 — A removed device keeps nothing.** On `DeviceRevoked`, or on a
  `mailbox()` view that no longer lists it, the browser deletes its record and
  drops every key it holds.
