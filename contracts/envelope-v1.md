# Contract: mail envelope and key wrapping, version 1

**Implemented once**, in `packages/mail-crypto`, and used by both sides: the
Mail Worker seals arriving and sent mail; the owner's browser opens it, seals
drafts and wraps the mailbox key. **Status:** implemented by slice S1 and
verified independently against its vectors, 2026-09-26. Any change to a byte
below is a new version (`v2`), never an edit of `v1`: stored mail must stay
readable.

All strings are UTF-8. `||` is byte concatenation. "base64url" is RFC 4648 §5
without padding. Random bytes come from `crypto.getRandomValues`.

## Identifiers

`<prefix>_<26 lowercase Crockford base32 characters of 16 random bytes>`:
`mbx_` mailbox, `msg_` message, `drf_` draft, `wrp_` key wrap. The Worker makes
mailbox and message ids; the browser makes draft and wrap ids.

Crockford base32 here, and in the recovery key below, reads the bytes as one
big-endian number and zero-extends it: the pad bits are **leading** (the ULID
and TypeID convention), so an id's first character is always 0–3. Ids never
contain `|` (the associated-data separator); implementations refuse an empty id
or one containing `|`.

## The mailbox key pair

- X25519. The public key is its raw 32 bytes. The private key is serialized as
  its raw 32 bytes, clamped (RFC 9180 §7.1.2, RFC 7748), so that wraps are
  portable between implementations; a reader clamps on import, so an
  unclamped wrap written elsewhere still opens.
- `keyId` = lowercase hex of the first 16 bytes of SHA-256(public key).
- The **fingerprint** shown to people = `keyId` in groups of four, e.g.
  `3f9a 07c1 …`.

## Sealing one message

HPKE (RFC 9180), base mode, suite **DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 /
AES-256-GCM** (KEM 0x0020, KDF 0x0001, AEAD 0x0002).

1. **Message key.** `dek` = 32 random bytes. A new one for every message and
   every draft save.
2. **Key envelope.** `(enc, ct) = HPKE.Seal(pkR = mailbox public key,
   info = "platform-mail/v1/message-key",
   aad = "platform-mail/v1/message-key|" + mailboxId + "|" + objectId,
   pt = dek)`. Stored bytes: `enc (32) || ct (48)` = 80 bytes, base64url.
   `objectId` is the message id or the draft id.
3. **Header block.** `iv` = 12 random bytes;
   `aad = "platform-mail/v1/header|" + mailboxId + "|" + messageId`;
   bytes = `0x01 || iv || AES-256-GCM(dek, iv, aad, UTF-8 JSON of MessageHeader)`
   (the 16-byte tag is at the end, as Web Crypto produces it). Stored base64url.
4. **Body object** (R2, key `mbx/<mailboxId>/msg/<messageId>`). `iv` = 12
   random bytes; `aad = "platform-mail/v1/body|" + mailboxId + "|" + messageId`;
   bytes = `"PMB1" || iv || AES-256-GCM(dek, iv, aad, raw RFC 5322 message)`.
   The raw message is exactly the bytes that arrived, or exactly the bytes
   handed to SES.

The associated data binds every blob to its mailbox and its id. A server that
moves a header or a body to another message or another mailbox produces a
decryption failure in the browser, not a quietly wrong message.

**Drafts** use steps 1 and 2 with the draft id, and one block like step 3 with
`aad = "platform-mail/v1/draft|" + mailboxId + "|" + draftId` over the UTF-8
JSON of a Draft.

## MessageHeader (the plaintext inside the header block)

```jsonc
{
  "v": 1,
  "direction": "in",                 // "in" | "out"
  "envelopeFrom": "bounce@x.example", // SMTP MAIL FROM; null for sent mail
  "from": { "name": "Ana Ruiz", "address": "ana@example.com" },   // or null
  "to": [{ "name": "", "address": "hello@example.com" }],
  "cc": [],
  "bcc": [],                         // sent copies only
  "replyTo": [],
  "subject": "Kitchen remodel quote",
  "date": "2026-09-26T15:04:05.000Z",  // the Date header as ISO 8601, or null if absent/unparseable
  "messageId": "abc@example.com",      // without angle brackets, or null
  "inReplyTo": null,
  "references": [],
  "snippet": "Hi — we'd like a quote for…",   // ≤ 200 characters of text, whitespace collapsed
  "attachments": [{ "filename": "plan.pdf", "mimeType": "application/pdf", "size": 48213, "inline": false }]
}
```

For a sent copy (`direction: "out"`), `messageId` is the id recipients see.
SES replaces the `Message-ID` and `Date` headers of the raw message it is
given, so this is `<SES MessageId>@email.amazonses.com` (us-east-1; the
domain for other regions is unverified), while the sealed body keeps exactly
the bytes that were handed to SES. Replies thread on this id.

Every key is always present. The serialized JSON is at most 64 KiB: if it
would be larger, `references` keeps its last 20 entries and `snippet` is
shortened. If it is still larger (thousands of recipients or attachments),
the writer stores a **minimal header** instead: `v`, `direction`,
`envelopeFrom`, `date`, `messageId` and `inReplyTo` kept; `from` kept when its
JSON is under 1 KiB; `to`, `cc`, `bcc`, `replyTo`, `references` and
`attachments` empty; `subject` cut to 200 characters; `snippet` empty. The
full headers are always in the sealed body, so nothing is lost and the browser
can re-read them from the raw message. A reader ignores keys it does not know
(forward compatibility inside v1); a plaintext missing a v1 key is treated as
a decryption failure.

## Draft (the plaintext inside a draft block)

```jsonc
{ "v": 1, "to": [], "cc": [], "bcc": [], "subject": "", "text": "",
  "inReplyTo": null, "references": [], "updatedAt": "2026-09-26T15:04:05.000Z" }
```

## Wrapping the private key

A wrap is the mailbox private key encrypted under a key-encryption key (KEK)
that only an owner's device or recovery key can reproduce.

- `kek = HKDF-SHA256(ikm = secret, salt = wrapId, info = "platform-mail/v1/kek/" + kind)`,
  32 bytes, used as an AES-256-GCM key.
- `kind = "passkey-prf"`: `secret` is the 32-byte WebAuthn PRF output for the
  input `prf.eval.first = SHA-256("platform-mail/v1/prf|" + mailboxId + "|" + wrapId)`.
- `kind = "recovery"`: `secret` is the 32-byte recovery secret.
- `aad = "platform-mail/v1/wrap|" + mailboxId + "|" + wrapId + "|" + kind + "|" + keyId`.
- Stored bytes: `0x01 || iv (12) || AES-256-GCM(kek, iv, aad, private key raw 32 bytes)`, base64url.

## The recovery key as people see it

The 32-byte secret, followed by the first 2 bytes of SHA-256(secret), written
in Crockford base32: 55 characters, shown upper-case in 11 groups of 5 joined
by hyphens. Parsing accepts lower case, spaces and hyphens, reads `I`/`L` as
`1` and `O` as `0`, and rejects a checksum mismatch as a typo before any
decryption is tried.

## Checks the browser makes

- After unwrapping, derive the public key from the private key and compare it
  with the mailbox's advertised public key. A mismatch stops everything and
  shows the key-substitution warning (domain-model G7).
- An authentication failure on any block is shown as "this message could not
  be decrypted", never as an empty message.

## Test vectors

`contracts/envelope-v1.vectors.json` (produced by the S1 builder): a fixed
mailbox key pair, and for each of a small message, a message with a non-ASCII
subject and an attachment, and a draft — the ids, the sealed bytes, and the
plaintext they open to. Plus a passkey wrap (with a fixed PRF output) and a
recovery wrap (with its display string), and negative cases: a header moved to
another message id, a body moved to another mailbox, a truncated tag, a
recovery key with a one-character typo.
