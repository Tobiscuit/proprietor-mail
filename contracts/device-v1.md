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

**Amended 2026-10-22 (round 3, spec D34–D43), before any mailbox stored a
device-v1 byte:** spec 002 has not been deployed, so these are edits of v1,
not a v2. New: A2b (factor signing keys), A10 (action descriptors and the
requests they cover), A11 (signed statements), B7a (`revokeDevices`),
K10–K13. Changed: A6 (the `factor` and `key` challenges carry an action
digest), A7, B1–B9, K2″, K3′, K4. Each change is marked "(round 3)".

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

### A2b. Factor signing keys (round 3, D39)

From the same secret, every factor also has an ECDSA P-256 key pair, with
which it signs what it authorizes (A11):

```
ikmS       = HKDF-SHA256 over the secret, with the factor id (as UTF-8) for salt,
             info = ctx("factor-signing-key", mailboxId, factorId, kind), and L = 32
(sS, vS)   = DeriveKeyPair(ikmS) for DHKEM(P-256, HKDF-SHA256)   (RFC 9180 §7.1.3: the
             candidate loop with its counter, bitmask 0xFF, until 0 < sk < n)
```

`sS` is imported for ECDSA P-256 as a non-extractable key with usage `sign`;
every byte string that held the secret, `ikmS` or the scalar is zeroed after
the import. `vS` is its public key, a raw uncompressed point (65 bytes); Mail
stores it as the factor's `signingKey`. Like `skF`, `sS` exists only in the
browser in the moments after the person used the factor (a FreshFactor). The
`info` strings keep the KEK, the factor key and the signing key apart, so none
of them reveals another.

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
target = the active mailbox public key (purposes "session" and "key"), targetId = its keyId
       | a factor public key (purpose "factor"),                       targetId = the factor id
aad    = ctx("challenge", mailboxId, challengeId, purpose, targetId)                  for "session"
       | ctx("challenge", mailboxId, challengeId, purpose, targetId, actionDigest)    for "factor" and "key"
sealed = enc ‖ ct = HPKE base mode Seal(pkR = target, info = UTF-8("proprietor-mail/v1/challenge"),
         aad, pt = answer)
         with DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM: 32 + 48 = 80 bytes
```

`actionDigest` (round 3, D36) is the digest of the challenge's action
descriptor (A10): base64url of SHA-256 over its bytes. The browser computes
the descriptor it expects for the request it is about to send, compares it
with the bytes Mail returned, and opens `sealed` with the `aad` made from
**its own** digest. A challenge issued for another action does not open, so
nothing is answered (K4). A challenge of purpose `email` (B6) has no `sealed`
and no answer: the dashboard's attestation of an email code stands for it.

The browser opens `sealed` with the mailbox private key (purposes `session`
and `key`) or the factor's `skF` (purpose `factor`), and returns `answer`.
Mail keeps only SHA-256(answer) and compares hashes.

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

The device's signing key signs these and its own unlock-key statements (A11),
nothing else; the `ctx` labels keep them apart (round 3).

### A8. Mail sessions

A mail session token is 32 random bytes drawn by Mail, sent as base64url (43
characters). Mail stores SHA-256(token) only. The token is a bearer secret for
at most 60 minutes. It lives in the browser's memory and passes through the
dashboard for one request at a time, and is never stored or logged there.

### A10. Action descriptors, and the request each one covers (round 3, D36)

The format, the reading rules and the kinds are `action-descriptor-v1.md`,
with its own vectors. Here: what each kind's `request` digest covers. The
digest is base64url (no padding) of SHA-256 over the RFC 8785 serialization of
the object below, **exactly as the call sends it** (Mail computes it again
from the call's arguments; the browser from the request it built). Every such
object holds only strings, `null`, arrays and objects.

| `kind` | The call it confirms | `request` is the digest of | `targets` |
|---|---|---|---|
| `revoke-device` | `revokeDevices(cap, { deviceIds })` | — (no `request`; `deviceIds`, sorted, must be the targets' ids) | the devices, with Mail's labels |
| `remove-devices` | `removeDevices(cap, request, auth)` | `{ deviceIds, rotation }`, the call's `request` | the devices, with Mail's labels |
| `register-device` | `registerDevice(cap, request, auth)` | `{ device, seal }`, the call's `request` | the new device, with its label from the request |
| `add-factor` | `addWrap(cap, wrap, auth)` | the `wrap` argument | none |
| `remove-factor` | `removeWrap(cap, wrapId, auth)` | `{ wrapId }` | none |
| `open-session` | `openSession(cap, request)` | `{ challengeId }`, the session challenge the same call answers | none |
| `upgrade` | `upgrade(cap, request, auth)` | `{ factors }`, the call's `request` | none |

`challenge` takes the action as:

```ts
type ActionInput =
  | { kind: "revoke-device"; deviceIds: string[] }                          // purpose "email" only
  | { kind: "remove-devices"; deviceIds: string[]; request: string }        // purpose "factor"
  | { kind: "register-device"; device: { id: string; label: string }; request: string }   // "factor"
  | { kind: "add-factor" | "remove-factor" | "open-session"; request: string }             // "factor"
  | { kind: "upgrade"; request: string };                                   // purpose "key"
```

Mail checks the kind against the purpose, that every named device exists
(for `revoke-device` and `remove-devices`), takes their labels from its own
records, draws the nonce, and issues the bytes.

### A11. Signed statements (round 3, D39)

ECDSA P-256 with SHA-256, IEEE P1363 form (`r ‖ s`, 64 bytes), base64url, as
A7. A factor signs with `sS` (A2b), a device with its signing key (A3).

```
admission of a device  = ctx("admit-device", mailboxId, deviceId, b64u(UTF-8(label)), b64u(signingKey), admitterId)
                         signed by the admitting factor
unlock key of a device = ctx("unlock-key", mailboxId, deviceId, b64u(unlockKey))
                         signed by the device itself; none while it has no unlock key
admission of a factor  = ctx("admit-factor", mailboxId, factorId, kind, b64u(UTF-8(label)), b64u(factorKey),
                             b64u(signingKey), credentialId ?? "-", admitterId, b64u(admitter's signingKey))
                         signed by the admitting factor (signature) and by the factor itself (selfSignature)
transition             = ctx("transition", mailboxId, fromKeyId, toKeyId, b64u(toPublicKey), signerId)
                         signed by the factor whose proof the rotation spends
```

- **Who admits whom.** A device or a factor added later is admitted by the
  factor whose proof the call spends. At enrollment and at the upgrade, where
  every factor is present, the factors are sorted by id (UTF-16 code units)
  and each is admitted by the next one, the last by the first; a single
  factor admits itself.
- **The factor graph** (what a browser trusts, K2″ and K3′). Its nodes are
  every factor record in the view, removed ones included (B4). An edge joins a
  factor and its admitter when the admission's `signature` verifies with the
  admitter's listed signing key, its `selfSignature` with the factor's own,
  and the admitter key inside the statement is the admitter's listed one. The
  **trusted factors** are the connected component of the browser's start:
  the factor just used, once K9 confirms the factor key and signing key it
  derives are the listed ones; or, on a kept device, the factor whose signing
  key the record holds as `trustRoot`.
- **Trusted recipients.** A device is trusted when its admission verifies
  with a trusted factor's signing key and, while it has an unlock key, its
  unlock-key signature verifies with its own signing key. A factor is a
  recipient when it is trusted, keyed and not removed. Each must also pass its
  binding tag (A5).
- **Trusted transitions.** A successor step is accepted only when its
  transition verifies with a trusted factor's signing key, removed or not.

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
another nonce. Round 3 adds: each factor's signing key (`vS`) for the fixed
secrets; a `factor` and a `key` challenge with their descriptor and digest,
and each refused when opened with another digest; one of each A11 statement
with its signature, and each refused after one changed field; a transition
signed by a factor outside the graph.

## Part B — `MailService` additions

`mail-service-v1.md` still holds: every answer is a `MailResult` value, and
refusals are never thrown. This part adds an argument, the checks below,
and three error names; round 3 adds `revokeDevices`, the `key` and `email`
challenges, and the signed statements Mail checks.

### B1. The `auth` argument

```ts
/** The last argument of every method marked "session" in B3. */
interface Auth {
  /** The token from openSession(). */
  session?: string;
  /** A fresh factor proof, for the methods marked "factor". */
  factorProof?: { challengeId: string; answer: string };   // answer: base64url, 32 bytes
  /** A key proof bound to the call (round 3), for `upgrade`. */
  keyProof?: { challengeId: string; answer: string };
}
```

Every `factorProof` and `keyProof` answers a challenge whose action
descriptor (A10) names the very call that carries it (round 3, D36). An
email code is not in `auth`: the dashboard attests it in the capability's
`confirmation` claim (`capability-v1.md`), which only `revokeDevices` reads.

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

While `"required"`, a session opens only with a key proof **and** either the
signature of a device of the calling account or a factor proof bound to
`open-session` (B6, M15′, round 3). While `"optional"`, a key proof alone
opens one, as before.

### B3. The methods

| Method | Needs | Notes |
|---|---|---|
| `mailboxes(cap)` | — | unchanged |
| `mailbox(cap)` | — | the view gains B4's fields |
| `unread(cap)` | — | unchanged: the dashboard's badge reads it outside any session |
| `enroll(cap, input)` | — | B5 |
| `challenge(cap, request)` | — | B6; purposes `email` and `key`, and any action, need `owner` |
| `openSession(cap, request)` | — | B6 |
| `upgrade(cap, request, auth)` | session, key proof | B5; allowed only while `"optional"` |
| `list`, `body`, `update`, `purge`, `drafts`, `saveDraft`, `deleteDraft`, `setPolicy`, `audit` | session | each takes `auth` after its current arguments, e.g. `list(cap, query, auth)`, `body(cap, messageId, auth)`, `drafts(cap, auth)` |
| `send(cap, request)` | session (in the request) | `request.session` |
| `addWrap(cap, wrap, auth)` | session, factor | B7; while `"optional"` it works as before and takes no factor key |
| `removeWrap(cap, wrapId, auth)` | session, factor | B7 |
| `registerDevice(cap, request, auth)` | session, factor | B7 |
| `updateDevice(cap, request, auth)` | a device's session | B7 |
| `removeDevices(cap, request, auth)` | session, factor | B7: the key rotates (round 3: replaces `removeDevice`, and takes 0 to 20 devices) |
| `revokeDevices(cap, request)` | an email code in the capability | B7a (round 3): no session needed, no key written |

"factor" means `auth.factorProof` answers a live `purpose: "factor"` challenge
for a factor that has a factor key and is not removed, **and that
challenge's descriptor is this call's** (kind, targets, and the request's
digest, A10); it is consumed by the call, right or wrong. While a mailbox is
`"optional"`, `registerDevice`, `removeDevices` and `revokeDevices` refuse
with `InvalidRequest` (upgrade first).

Roles are unchanged: reading needs `openRoles`, sending `sendRoles`, and every
key, device or policy change needs `owner`. `challenge` and `openSession` need
`openRoles`.

### B4. The view

```ts
interface MailboxView {   // what mailbox() answers; the earlier fields unchanged
  sessions: "optional" | "required";
  keys: { keyId; publicKey; createdAt; createdBy; retiredAt;
          successor: { keyId: string; sealed: string;
                       signedBy: string; signature: string } | null }[];   // successor seal and its transition (A11)
  wraps: { id; keyId; kind; credentialId; label; wrapped; createdAt; createdBy;
           factorKey: string | null; signingKey: string | null; admission: Admission | null;
           tag: string | null; tagKeyId: string | null }[];
  removedFactors: { id; kind; credentialId; label; factorKey; signingKey; admission: Admission;
                    removedAt: string }[];                              // round 3: kept for the factor graph (M24)
  devices: { id: string; label: string; signingKey: string; unlockKey: string | null;
             unlockSignature: string | null; admission: { by: string; signature: string };
             tag: string; tagKeyId: string; createdAt: string; createdBy: string; lastSeenAt: string | null }[];
  seals: { keyId: string; to: { kind: "device" | "factor"; id: string }; sealed: string }[];
  rotationDue: { since: string; by: string; devices: string[] } | null;   // round 3: after revokeDevices (B7a)
  // ...policy, addresses, status, displayName as before
}
interface Admission { by: string; signature: string; selfSignature: string }   // a factor's (A11)
```

A device's `createdBy` is the account that kept it (M21′); the screens list
another account's devices apart, and a browser opens nothing of them (K10).
Round 3's new fields are `null` only on a mailbox that is still
`"optional"`.

Every seal in `seals` is a seal of the active key (M19). Public keys, seals and
tags are base64url.

### B5. `enroll` and `upgrade`

`enroll(cap, { publicKey, wraps, device? })`: as before (M5), and when every
wrap carries `factorKey`, `signingKey`, `admission`, `tag` and `tagKeyId` (the
new key; Mail also takes a wrap without `tagKeyId`, since only the new key can
be meant), the mailbox starts `"required"`. The admissions follow A11's rule
for the factors present at enrollment (each by the next in id order), and
Mail verifies every signature. `device`, when present, is
`{ device: DeviceInput, seal }` (B7's shapes) for the browser that enrolls,
admitted by one of these factors. Mixing wraps with and without factor keys
is refused.

`upgrade(cap, { factors: { id, factorKey, signingKey, admission, tag, tagKeyId }[] }, auth)`
is the one moment an existing mailbox learns factor keys without a factor
proof (spec D26, G30). Conditions: the mailbox is `"optional"`; no wrap has a
factor key yet; `auth.session` is live (it was opened with a key proof);
`auth.keyProof` answers a `key` challenge whose descriptor is this call's
(kind `upgrade`, round 3: a relay holding the session cannot upgrade with
factor keys of its own); the admissions follow A11's rule and verify; every listed
id is a wrap of the active key; `tagKeyId` is the active key; **the list
names every wrap the mailbox has, exactly once** (so every factor, the
recovery key included, gets its key in this one step; a factor the owner no
longer has is removed with `removeWrap` first, which needs no proof while the
mailbox is `"optional"`). Effect: the factor keys and tags are stored and
`sessions` becomes `"required"`, in one transaction; audit `mailbox-upgraded`
with the factor ids. (Amended 2026-10-19: this said "at least one recovery
wrap", and a factor left out could not reach any key made after the first
rotation; `setFactorKey`, which repaired that, is gone.)

### B6. Challenges and sessions

```ts
challenge(cap,
  | { purpose: "session" }
  | { purpose: "factor"; factorId: string; action: ActionInput }   // A10
  | { purpose: "key"; action: ActionInput }                        // kind "upgrade"
  | { purpose: "email"; action: ActionInput })                     // kind "revoke-device"
→ { id, purpose, keyId: string | null, factorId: string | null, nonce,
    sealed: string | null, descriptor: string | null, expiresAt }
```

`keyId` is the active key (purposes `session` and `key`); `factorId` is the
factor (purpose `factor`), which must have a factor key and not be removed,
else `NotFound`. `descriptor` (round 3) is base64url of the action
descriptor's bytes (A10), for every purpose but `session`; `sealed` is `null`
for `email`. An action whose kind does not belong to its purpose, or that
names a device Mail does not hold, is `InvalidRequest`. A challenge lives
**2 minutes** (purpose `email`: **10 minutes**, for the email to arrive) and
is used **once**. At most **20** live challenges per mailbox; one more answers
`RateLimited` with the seconds until the oldest expires.

`openSession(cap, { challengeId, answer, device?, factorProof? })` where
`device = { id, signature }` and `factorProof = { challengeId, answer }`
(a `factor` challenge of kind `open-session` whose request is
`{ challengeId }` of this session challenge) → `{ session, expiresAt,
device: string | null }`. While `"required"`, exactly one of `device` and
`factorProof` is given (round 3, D38); while `"optional"`, `factorProof` is
refused and `device` stays optional.
Mail checks that the challenge is live, of purpose `session`, made for this
account, and that SHA-256(answer) matches. When `device` is given, it also
checks that the device exists, belongs to this account, and that `signature`
verifies over A7's message. The challenge (and the factor
challenge, when given) is consumed **whether or not the answer is right**. A wrong answer or signature is `ProofRejected` and is
audited as `proof-rejected`. A challenge that does not exist, or that another
account asked for, is `ProofRejected` too, and spends nothing and writes
nothing, not even an audit row: anyone could repeat it without end. A used or
expired challenge is audited the first time it comes back, and only then. An
unknown device id is `DeviceRevoked`; one registered by **another account**
is `Forbidden`, writes nothing and spends nothing (round 3, D37, M21′: a
refusal another person's page receives must never wipe the owner's record).
A session lives **60 minutes** and records its device. Opening one updates
that device's `lastSeenAt`.

A factor proof is checked the same way against a `purpose: "factor"`
challenge, when the method that carries it runs; it is consumed there.

### B7. Devices, factors and the rotation

```ts
interface DeviceInput {
  id: string;                  // dev_…, made by the browser
  label: string;               // 1–40 code points, one line (action-descriptor-v1's label rule)
  signingKey: string;          // 65 bytes
  unlockKey: string | null;    // 65 bytes; null for a device that keeps nothing (lock after: right away)
  unlockSignature: string | null;   // round 3: A11, by signingKey; present exactly when unlockKey is
  admission: { by: string; signature: string };   // round 3: A11, by the factor whose proof the call spends
  tag: string;                 // A5, under tagKeyId
  tagKeyId: string;            // must be the active key
}
registerDevice(cap, { device: DeviceInput, seal: string | null }, auth)                          → DeviceView
updateDevice(cap, { unlockKey: string | null, unlockSignature: string | null, tag, tagKeyId,
                    seal: string | null }, auth)                                                  → DeviceView
removeDevices(cap, { deviceIds: string[], rotation: Rotation }, auth)                             → { keyId }
revokeDevices(cap, { deviceIds: string[] })                                                       → { revoked: string[] }

interface Rotation {
  from: string;                // the active keyId; anything else is refused (another browser rotated first)
  publicKey: string;           // the new key, 32 bytes
  successorSeal: string;       // the old key sealed to the new one (A4), 109 bytes
  transition: { signedBy: string; signature: string };   // round 3: A11, by the factor whose proof the call spends
  seals: { to: { kind: "device" | "factor"; id: string }; sealed: string }[];   // the new key, to each remaining recipient
  tags:  { to: { kind: "device" | "factor"; id: string }; tag: string }[];      // each remaining recipient, under the new key
}
```

- `registerDevice`: `seal` is the active key sealed to `unlockKey`
  (`toKind "device"`, `toId` = the device id). It is present exactly when
  `unlockKey` is. At most **20** devices. The admission is signed by the
  factor whose proof the call spends (`admission.by` names it) and the unlock
  key by the device; Mail verifies both (M25). The caller's session becomes
  this device's session. Audit `device-registered`.
- `updateDevice`: only from a session of that device. It replaces the unlock
  key, its signature, its tag and its seal, and deletes the device's earlier
  seals. `null` clears them (the device locked). Mail verifies the unlock-key
  signature with the device's signing key. Audit `device-unlock-key` with
  `set` or `cleared`.
- `addWrap` once `"required"`: the wrap is of the active key and carries
  `factorKey`, `signingKey`, `admission` (by the factor whose proof the call
  spends, and by the new factor itself; Mail verifies both), `tag` and
  `tagKeyId` (the active key). `removeWrap` once `"required"` deletes that
  factor's wrap and seals and records `removedAt`; the factor's record stays
  (M24) and Mail never accepts its proof again. Neither may leave the active
  key unreachable by a recovery factor (M5′).
- `removeDevices` (round 3: replaces `removeDevice`), in **one transaction**
  (M18′):
  1. `deviceIds` names 0 to 20 distinct devices of the mailbox; **0 only while
     a rotation is due** (B7a). `rotation.from` is the active key. The new
     public key is 32 bytes and new to the mailbox. The successor seal is 109
     bytes.
  2. The factor proof's descriptor is this call's (A10). `transition.signedBy`
     is that same factor, and `transition.signature` verifies with its signing
     key over A11's transition from `from` to the new key (M23, M25).
  3. The remaining recipients are every device not named with an unlock key,
     and every factor with a factor key that is not removed. `seals` names
     exactly those, once each. Device seals are 142 bytes and factor seals
     109.
  4. `tags` names exactly every device not named and every such factor.
  5. A recovery factor with a factor key is among the remaining recipients
     (M5′).
  6. Effect: the named devices, their seals and their sessions are deleted.
     The new key becomes active. The old key gets `retiredAt` and its
     `successor` (`keyId`, `sealed`, `signedBy`, `signature`). Every seal of
     the old key is deleted, and the new seals and tags are stored. **Every
     other session ends**, because each was opened with a proof of the old
     key. No rotation is due any more. Audit `device-removed` for each device
     and `key-rotated` (from, to, how many seals, the factor).
  7. From the next arrival on, mail is sealed to the new key. Earlier mail
     keeps the keyId it was sealed to.

Every id, length, shape and signature above is checked before anything is
written. A check that fails answers `InvalidRequest` and changes nothing.

### B7a. `revokeDevices`: an email code revokes, and nothing else (round 3, D35)

`revokeDevices(cap, { deviceIds })` needs the `owner` role, **no session**,
and a capability whose `confirmation` claim (`capability-v1.md`) passes every
rule of `action-descriptor-v1.md`'s attestation table: `method`
`email-code`; `accountId` = `sub`; `actionKind` `revoke-device`, the only kind
on Mail's list for email codes; `actionDigest` the digest of a live, unspent
challenge of purpose `email` this account asked for; `at` at most 300 seconds
old, at most 5 seconds ahead, and not before the descriptor's `issuedAt`; and
`deviceIds`, sorted, exactly the descriptor's targets. The challenge is spent
by the first call that presents the attestation, whatever that call's
outcome; a second call with the same attestation is `ProofRejected`.

In **one transaction** (M22): the devices, their seals and their sessions are
deleted, and `rotationDue` becomes `{ since, by: sub, devices }` (merged with
one already due). **No key, seal, tag or factor is written.** Mail goes on
sealing arriving mail to the active key until a `removeDevices` (with a
factor) rotates it, which clears `rotationDue`. Audit `device-revoked` for
each device, with the method (`email-code`) and the attestation's `codeId`,
and `rotation-due`.

A device revoked this way is refused at once: its sessions are gone, its
signature names no device, and a key proof alone opens no session (B2).

### B8. Errors

Three names join the ten (`mail-service-v1.md`):

| Name | Means | The browser |
|---|---|---|
| `SessionRequired` | no live session, or a bad token | opens a session and calls again, once |
| `DeviceRevoked` | the device is not in the mailbox | wipes **this account's** record (Part C) and asks for a factor |
| `ProofRejected` | a key proof, factor proof or device signature failed, or its challenge expired or was used | shows "that did not work, try again"; never retries on its own |

A caller that does not know a name still treats it as `InternalError`.

Round 3 uses an existing name in one new place: a device of **another
account** is `Forbidden` (B6), and the browser wipes nothing on it (K10).

### B9. Housekeeping and audit

The daily housekeeping deletes expired challenges and sessions. Audit rows
carry ids, kinds, counts and labels, never a token, an answer, a seal or a key.
The audit actions are `mailbox-upgraded`, `device-registered`,
`device-unlock-key`, `device-removed`, `key-rotated` and `proof-rejected`, plus the existing `wrap-added` and `wrap-removed`.
Round 3 adds `device-revoked` (with the method and the email code's `codeId`)
and `rotation-due`.

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
- **K2″ — A key is accepted only along a chain the browser can check, each
  step signed by a trusted factor** (round 3, D39: the rule below, and every
  successor step's transition must verify with the signing key of a factor in
  the browser's trusted component, A11; a step without one stops everything
  as below). The
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
- **K3′ — A key is sealed only to recipients whose tag verifies and whom a
  trusted factor admitted** (round 3, D39: the rule below holds with "tag
  verifies" read as "tag, admission and, for a device with an unlock key, its
  unlock-key signature verify", A11; a recipient that fails any of them is
  flagged). Before
  sealing anything to a device or a factor, the browser checks that
  recipient's tag under the active key. At every unlock it checks every tag in
  the key ring. A device or factor whose tag fails is **flagged, not
  trusted**: it is never sealed to, the owner is shown it as one a holder of
  the key did not add, and it can be removed (a removal is the only rotation
  allowed while it is there, so nothing new is ever sealed to it). The rest
  of the inbox keeps working, because the key itself is trusted (K2′). Only a
  failure of the key itself (K2, K2′) stops everything. (Amended 2026-10-19:
  this stopped everything on any failing tag, so one bad record, with no way
  past it in the inbox, stopped every browser.)
- **K4 — Only challenges are answered** (A6), **and a `factor` or `key`
  challenge only for the action this browser is about to send** (round 3):
  the browser builds the descriptor it expects (A10) from its own request,
  compares it with the bytes Mail returned, and opens the challenge with the
  associated data made from its own digest.
- **K8 — A rotation proves itself before it is sent** (round 3: and its
  transition signature verifies). The browser opens the
  successor seal with the new key, and the new key's seal for the factor just
  used with that factor's key, and sends the rotation only when both give back
  the keys they name. A rotation whose seals cannot be opened would leave mail
  that arrives after it readable only in the page that made it.
- **K9 — The factor just used is the one Mail lists.** After a factor is used,
  the browser derives its factor key (A2) and checks that it is the
  `factorKey` the key ring lists for that factor. A factor that does not match
  is flagged as in K3: nothing is sealed to it, and the owner is asked to
  remove it and add it again.
- **K5 — Only a kept device persists, and only P-256 keys and plain facts:**
  in IndexedDB, per mailbox **and account** (round 3): the account id, the
  device id, its label, the two private keys (non-extractable `CryptoKey`s,
  A3), their public forms, the keyId it last accepted, the signing key of the
  factor it trusts (`trustRoot`, round 3), its lock setting, its last
  activity time, and the sign-in id it was unlocked under. Never a mailbox key, a factor secret, a token or decrypted
  content. A browser whose storage cannot keep such keys (checked before the
  first use) is treated as a shared computer, and the screen says so.
- **K6 — Lock settings are enforced by the browser alone**, when the inbox
  loads and while it is open. Mail cannot enforce them, and the spec says so.
  Locking deletes the unlock key, then clears it at Mail when a session is
  live.
- **K7 — A removed device keeps nothing.** On `DeviceRevoked`, or on a
  `mailbox()` view that no longer lists it, the browser deletes **the signed-in
  account's** record and drops every key it holds.
- **K10 — Another account's record is never touched** (round 3, D37). The
  browser reads, opens, uses and deletes only the record of the account the
  page is signed in as (the capability's `sub`, which the dashboard gives the
  inbox). On `Forbidden` it wipes nothing.
- **K11 — The last accepted key only moves forward** (round 3, D41). A record's
  `lastKeyId` is written only while it still holds the key the walk started
  from, read and written in one IndexedDB `readwrite` transaction. When it
  does not, the page resumes again from the record as it now is.
- **K12 — A rotation and an admission carry the factor's signature** (round 3,
  D39). The browser that holds a FreshFactor signs the transition of a
  rotation, the admission of a device it keeps or a factor it adds (with the
  new factor's own signature), and its own device's unlock key.
- **K13 — A due rotation comes first** (round 3, D35). A browser that holds a
  FreshFactor while `rotationDue` is set finishes it (`removeDevices` with no
  devices, or with every flagged one) before any other change, and the inbox
  asks for a factor on every unlocked page until it is done.
