# Contract: Mail capability, version 1

**Minted by** the dashboard shell (spec 007, SEO-engine repo).
**Verified by** `platform-mail`'s `MailService` entrypoint before any read or
write. **Status:** proposed 2026-09-26 from the SEO-engine session's answer
(b); the minting side is theirs to implement against this document and its
test vectors.

## Why it exists

Mail must not trust a bare tenant id passed over a service binding: any
Worker that is given a binding could then open any mailbox. The dashboard
already knows who the person is (Access today, Better Auth later) and which
tenants they belong to. It states that, for one mailbox, for at most 60
seconds, signed with a key only the dashboard and Mail hold. Mail verifies the
statement and never learns which login provider produced it.

## Format

A JWT (RFC 7519) in JWS compact serialization, algorithm **HS256** only.

Protected header:

```json
{ "alg": "HS256", "typ": "JWT", "kid": "<key id>" }
```

Claims:

| Claim | Type | Rule |
|---|---|---|
| `iss` | string | exactly `"platform-dashboard"` |
| `aud` | string | exactly `"platform-mail"` |
| `sub` | string | the dashboard's account id of the person acting |
| `tenant` | string | the tenant id the person chose, already checked against their memberships |
| `mbx` | string, optional | the mailbox id; required by every method that reads or writes a mailbox; absent only for `mailboxes()` |
| `role` | `"owner"` \| `"editor"` | the person's role in that tenant |
| `iat` | NumericDate | when it was minted |
| `exp` | NumericDate | `exp - iat` must be between 1 and 60 inclusive |
| `jti` | string, **required** | random, at least 16 bytes of entropy; both Workers log it with the method and the outcome, so one request can be traced across them |

## Verification rules (Mail)

1. The header's `alg` is `HS256` (the `none` algorithm and every other
   algorithm are refused before any key is looked up).
2. `kid` names a key in `MAIL_CAPABILITY_KEYS`; unknown `kid` is refused.
3. The signature verifies (jose `jwtVerify`, which compares in constant time).
4. `iss` and `aud` match exactly.
5. `iat` is not more than 5 seconds in the future; `exp` has not passed, with
   5 seconds of tolerance; `exp - iat ≤ 60`.
6. `tenant`, `sub` and `jti` are non-empty strings; `role` is one of the two
   values.
7. Then the mailbox rules: the Directory row for `mbx` exists, is not
   `closed`, and its `tenant_id` equals `tenant`. Any mismatch answers
   `NotFound`, exactly as for a mailbox that does not exist.
8. Then the mailbox policy: `role` must be in `openRoles` to read, in
   `sendRoles` to send, and must be `owner` to change keys or policy.

A refused capability raises `CapabilityRejected` with a reason of `invalid` or
`expired` and nothing else. The dashboard re-mints and retries once on
`expired`.

Mail logs one line per call: the method, the `jti`, and the outcome (accepted,
or rejected and why). Never an address, a subject or any other content.

## Serialization

Byte-identical tokens are **not** required: a minted token conforms when it
verifies under the reference verifier with the vectors' fixed key and clock
and decodes to exactly the expected claims. For readability and for the
canonical vector, the order is fixed anyway: protected header `alg, typ, kid`;
claims `iss, aud, sub, tenant, mbx, role, iat, exp, jti`; `exp = iat + 60`.

## Keys

- Secret `MAIL_CAPABILITY_KEYS` in both Workers: a JSON object mapping key ids
  to base64url-encoded 32-byte random keys, e.g.
  `{"2026-09-a": "<43 chars>"}`.
- The dashboard also has `MAIL_CAPABILITY_KID`, the id it signs with.
- Source of truth: Vault `secret/platform-mail/capability`, fields `keys` and
  `current_kid`. Loaded into each Worker as secrets through the process
  environment (`wrangler secret put` reading stdin), never through argv or a
  kept file.
- Rotation: add the new key to both Workers → switch `MAIL_CAPABILITY_KID` →
  wait five minutes (twelve times the lifetime) → remove the old key from both.

## Test vectors

`contracts/capability-v1.vectors.json` (produced by the S2 builder) holds a
fixed key, a fixed clock and:

- one valid token with every claim, and the claims it decodes to;
- refused tokens, each with the rule it breaks: `alg: none`; a wrong `aud`; a
  wrong `iss`; `exp - iat = 61`; expired by 6 seconds; `iat` 6 seconds in the
  future; an unknown `kid`; one flipped payload byte; a missing `tenant`; a
  missing `jti`.

Both repositories run the same vectors: the dashboard proves it mints what Mail
accepts, and Mail proves it refuses what it must.

## What it deliberately does not carry

No email address, no session id, no Access token and no Better Auth token.
Mail needs to know which account acts (for its audit log) and whether that
account may, and nothing else.
