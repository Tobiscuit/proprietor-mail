# Contract: action descriptors, version 1

**Spec:** `specs/002-device-sessions/` (D34–D37 say why). **Issued by** the Mail
Worker. **Read by** the browser (`packages/mail-client`, through
`packages/mail-crypto`), the Mail Worker, and the dashboard that sends email
codes (a separate application). **Vectors:** `action-descriptor-v1.vectors.json`.
**Status:** written 2026-10-22, before any code.

## Why it exists

A confirmation says "the person agreed to *this*". Every confirmation the
mailbox accepts names its action by an **action descriptor**: a short byte
string that Mail issues, with a nonce Mail spends once. A confirmation carries
the descriptor's digest, so it cannot be moved to another action, another
mailbox, or a second use:

- **an email code** (the dashboard sends it to the signed-in person's email,
  checks it, and attests it inside the Mail capability: `capability-v1.md`,
  the `confirmation` claim);
- **a factor proof** (a passkey or the recovery key answers a challenge whose
  associated data holds the digest: `device-v1.md` A6);
- **a key proof** for the one-time upgrade (the same, sealed to the mailbox
  key).

Whoever shows the person what they are confirming (the email's words, the
screen) reads the kind and the device names **from the same bytes** it hashes,
so a page cannot hash one action and show another.

## Format

The descriptor is the UTF-8 encoding of the **RFC 8785 (JSON Canonicalization
Scheme)** serialization of one JSON object. RFC 8785 fixes one byte sequence
per value: members sorted by their names' UTF-16 code units, no whitespace,
strings escaped exactly as ECMAScript's `JSON.stringify` escapes them (only
`"`, `\` and U+0000 to U+001F; everything else is written as UTF-8), and
numbers as ECMAScript writes them. Nothing beyond `JSON.parse` is needed to
read it, and any RFC 8785 implementation can produce it.

| Member | Type | Rule |
|---|---|---|
| `version` | number | exactly `1` |
| `kind` | string | one of the kinds below |
| `mailboxId` | string | `mbx_` and 26 lowercase Crockford base32 symbols, the first `0`–`7` (envelope v1's id rule) |
| `targets` | array | the devices the action names, each exactly `{ "deviceId", "label" }`, sorted by `deviceId`, each device once; how many depends on the kind |
| `targets[].deviceId` | string | `dev_` and 26 symbols, as for `mailboxId` |
| `targets[].label` | string | the device's name as Mail holds it: 1 to 40 Unicode code points; none of U+0000–U+001F, U+007F–U+009F, U+2028, U+2029; no lone surrogate |
| `nonce` | string | 32 random bytes drawn by Mail, base64url without padding (43 characters) |
| `issuedAt` | number | when Mail issued it: a whole number of seconds since 1970-01-01T00:00:00Z, at least 0 |
| `request` | string | present exactly for the kinds marked below: base64url (43 characters, no padding) of SHA-256 over the RFC 8785 serialization of the request the confirmed call will carry (`device-v1.md` A10 names the object per kind) |

No other member. The longest possible descriptor (twenty devices, each label
forty four-byte code points) is 4,509 bytes; a reader may refuse anything
longer than 8,192 bytes.

### Kinds

| `kind` | Confirmed by | `targets` | `request` |
|---|---|---|---|
| `revoke-device` | **an email code**, attested by the dashboard | 1 to 20 devices: Mail refuses them at once; the key rotates later (`device-v1.md` B7a) | absent |
| `remove-devices` | a factor proof | 0 to 20 devices, removed with a rotation; 0 finishes a rotation that is due | present |
| `register-device` | a factor proof | exactly 1, the device being kept | present |
| `add-factor` | a factor proof | none | present |
| `remove-factor` | a factor proof | none | present |
| `open-session` | a factor proof | none | present |
| `upgrade` | a key proof | none | present |

**An email code confirms `revoke-device` and nothing else.** Revoking grants
no key material. Every other kind either gives a key to someone or makes the
key that future mail is sealed to, and whoever makes a key knows it; so it
needs a factor (spec D35).

## Reading one

Every reader (Mail, the browser, the dashboard) does the same, in this order,
and refuses the descriptor at the first failure:

1. At most 8,192 bytes; strict UTF-8 (a byte order mark is not allowed).
2. `JSON.parse`, then serialize the result with RFC 8785. **The bytes must
   be exactly the bytes read.** This one check refuses whitespace, members out
   of order, duplicate members, escapes RFC 8785 does not write (`A`,
   `\/`), and lone surrogates.
3. A JSON object with exactly the members of the table, for its kind.
4. Every rule of the table.

The **digest** is base64url, without padding, of SHA-256 over the exact bytes
(43 characters). A reader never re-serializes to compute it.

What the dashboard accepts for an email code is narrower: `kind` must be
`revoke-device`, and so the object has exactly six members (`issuedAt`,
`kind`, `mailboxId`, `nonce`, `targets`, `version`). It renders the device
names as escaped text and never as markup. It may also refuse a descriptor
whose `issuedAt` is more than 10 minutes in the past by its own clock (with a
minute of tolerance): Mail will refuse it then anyway.

## Issuing and spending

- Mail issues a descriptor only through `challenge` (`device-v1.md` B6), for
  the calling account, after checking the action against its own records
  (the devices exist; the labels are Mail's). The browser passes the bytes
  through untouched (base64url) to whoever shows the action to the person.
- Mail stores the digest with the challenge. The challenge, and so the nonce,
  is spent by the **first** call that presents a confirmation for it, whether
  that call then succeeds or not. Two calls with one confirmation: exactly one
  is applied, the other is refused.
- A challenge of an email descriptor lives **10 minutes**; one of a factor or
  key descriptor lives 2 minutes (M16).

## The dashboard's attestation of an email code

Copied unchanged into the capability's `confirmation` claim
(`capability-v1.md`), in the same server action that mints the capability,
never by way of the browser:

```json
{ "method": "email-code", "accountId": "<sub>", "actionKind": "revoke-device",
  "actionDigest": "<43 characters>", "at": 1792627350, "codeId": "<the code's id>" }
```

Mail accepts it only when **all** hold:

| Rule | |
|---|---|
| exactly these six members, with these types (`at` a whole number) | |
| `method` is `"email-code"` | |
| `accountId` equals the capability's `sub` | the code went to the account that acts |
| `actionKind` is `"revoke-device"` | Mail's own list of kinds an email code may confirm; nothing else is on it |
| `actionDigest` is the digest of a live, unspent challenge of purpose `email` that this account asked for, whose descriptor's kind is `actionKind` | |
| `at` is at most 300 seconds before Mail's clock, at most 5 seconds after it, and not before the descriptor's `issuedAt` | the code was checked moments ago, for this descriptor |
| the call's own request names exactly the descriptor's devices | |

`codeId` (at most 64 characters, `[A-Za-z0-9_-]`) goes into Mail's audit row
with the action, so one confirmation can be traced across both applications.

## Vectors

`action-descriptor-v1.vectors.json`: eight valid descriptors (object, UTF-8,
hex, digest), from one device to the longest possible, labels outside ASCII
and with `"` and `\`, and `remove-devices` with and without targets; 33
refused ones, each with the rule it breaks; and the attestation rules above
as twelve cases (three accepted at the edges, nine refused), each with its own
clock and each refused case breaking exactly one rule (amended 2026-10-23:
the first set shared one clock, so "301 seconds ago" also broke the
issued-at rule and could not catch a reader that skipped the age check). Every valid vector was produced
by two RFC 8785 implementations that agree byte for byte (this repository's
generator, `scripts/action-descriptor-vectors.mjs`, and the `canonicalize`
package, version 5.1.0). Every reader runs all of them.

## Facts this rests on

| Fact | Source |
|---|---|
| RFC 8785: members sorted by UTF-16 code units, no whitespace, strings and numbers as ECMAScript serializes them, I-JSON (no duplicate names, no lone surrogates) | RFC 8785 §3.2, read 2026-10-22 |
| `JSON.stringify` escapes only `"`, `\` and U+0000–U+001F in strings, and `Array.prototype.sort` with no comparator orders strings by UTF-16 code units | ECMA-262, as RFC 8785 §3.2.2.2 cites it; the `canonicalize` package relies on both |
