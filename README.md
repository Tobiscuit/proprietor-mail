# platform-mail

The Inbox module of a small business platform: one mailbox per business,
read inside the platform's dashboard, with mail that **the operator of the
platform cannot read at rest**. Every arriving message is encrypted to the
mailbox's public key before it is stored, and only the owner's own devices
hold the private key.

This repository is public so that claim can be checked. It holds everything
that touches message plaintext or key material on the server side:

| Path | What it is |
|---|---|
| `src/`, `migrations/` | The Mail Worker (Cloudflare Workers, Agents SDK): receives mail from Email Routing, seals and stores it, serves ciphertext to the dashboard over RPC, sends through Amazon SES |
| `packages/mail-crypto/` | `@platform-mail/crypto`: the envelope format and key wrapping. The Worker uses it to seal; the owner's browser uses it to generate keys, unlock and decrypt |
| `packages/mail-outbound/` | `@platform-mail/outbound`: an RFC 5322 / MIME builder and an SES v2 raw sender |
| `contracts/` | The byte formats and RPC contracts, with test vectors: `envelope-v1`, `capability-v1`, `mail-service-v1` |
| `specs/001-inbox-module/` | The spec (what and why, and the decisions), the domain model, the plan, the task list |

The dashboard (sign-in, the inbox screens) is a separate application and is
not published here; `contracts/` is the interface between the two.

**Status:** built and tested, not deployed. Nothing here has handled real
mail yet.

## The promise, and its limits

**What the operator cannot do:** read stored mail. Subjects, senders, bodies,
attachments, drafts, threads and search exist on the server only as
ciphertext. The key that opens them is generated in the owner's browser and
stored on the server only in wrapped form: once per passkey (under a key
derived from the passkey's WebAuthn PRF output) and once under a recovery key
that is shown to the owner once and never stored. Whoever has the database,
the object store, a backup or the operator's cloud accounts holds ciphertext,
and so does anyone who asks the operator for a client's mail.

**What the operator can see** (`specs/001-inbox-module/spec.md` §4):

| What | Where | Why |
|---|---|---|
| That a message arrived, when, how large, for which mailbox | Mailbox storage | Sorting, quotas, the unread count |
| Folder, read and starred flags | Mailbox storage | Set by the owner's own actions |
| Envelope sender and recipient of arriving mail | Email Routing, in transit | That is how SMTP delivery works |
| The full message, for the moment it arrives | Mail Worker memory | It is encrypted there, immediately |
| Recipients, subject and full message of mail the owner sends, for the moment of sending | Mail Worker memory; SES delivery events include the subject | SES needs the message to send it |
| That new mail arrived (a count, never content) | The dashboard, for push notifications | So the phone can buzz |
| Which devices and recovery keys exist (labels and times, not secrets) | The mailbox's key ring | So the owner can manage devices |

**Two limits no web-based encrypted mail service escapes**, stated rather
than hidden (spec §2):

1. **Mail in transit.** Internet mail arrives and leaves as plaintext. The
   Worker encrypts an arriving message at once and holds an outgoing one only
   while it hands it to SES, but in those moments the operator's code has the
   plaintext, and a changed version of that code could copy it.
2. **The code in the browser comes from the operator.** Decryption happens in
   JavaScript the dashboard serves. A changed version of it could read the key
   after the owner unlocks. Publishing this code, and a hash manifest of every
   dashboard deploy, puts such a change on the public record; no mainstream
   browser can check a page against that record yet.

A mailbox's AI assistant is **off**, and v1 cannot turn it on: nothing on the
server can decrypt, so a server-side assistant would break the promise
(Decision D1). The alternatives, each with its own honest wording, are in
spec §2 and plan §9.

## How it fits together

```
  Email Routing ──▶ Mail Worker: email() ──▶ Mailbox (one Durable Object per mailbox)
                                               seal to the mailbox public key (HPKE)
                                               sealed header → SQLite, sealed body → R2

  owner's browser ◀── dashboard ◀── MailService (RPC, a 60-second signed capability per call)
   unlock with a passkey or the recovery key; decrypt headers, bodies, drafts

  owner's browser ──▶ dashboard ──▶ MailService.send ──▶ MIME ──▶ SES
                                    (the Sent copy is sealed like any message)
```

- **Envelope v1** (`contracts/envelope-v1.md`): HPKE (RFC 9180,
  DHKEM(X25519, HKDF-SHA256), AES-256-GCM) seals a fresh 256-bit message key;
  the header block and the raw message are AES-256-GCM under it, each bound to
  its mailbox and message id by associated data, so a server that moves a
  blob produces a decryption failure, not a wrong message.
- **The browser checks the server**: after unlocking it derives the public key
  from the private key and compares it with the one the server advertises, so
  a substituted key is caught (domain model G7).
- **Capability v1** (`contracts/capability-v1.md`): the dashboard signs, for
  one mailbox and at most 60 seconds, who is acting and in which role. Mail
  verifies it on every call and never learns how the person signed in.
- **Refusals are values** (`contracts/mail-service-v1.md`): every RPC answer
  is `{ ok: true, value }` or `{ ok: false, error }`.

The invariants the Worker keeps (no plaintext at rest, no key no mail, no
private key on the server, one tenant per mailbox for life, and more) are
listed in `specs/001-inbox-module/domain-model.md` §3, each with a test.

## Running the tests

Node 26.4.0 (see `.nvmrc`); nothing else to install. No test sends or
receives real mail.

```sh
npm ci
npm run typecheck
npm test
```

`npm test` runs three kinds of project: the Worker inside workerd with a real
D1, real SQLite-backed Durable Objects and a real R2 simulation; each package
in Node with its own config; and Node-side checks of the scripts and config.
Among them: the M1 marker scan (a message whose subject, sender, body and
attachment name carry markers, then every table, every R2 object and the
captured logs are searched for them in plain, base64 and quoted-printable
form), byte-for-byte golden MIME messages, and both contracts' test vectors.
The run also fails if workerd logs an exception that escaped an RPC call
(`test/README.md`). A live SES test exists and is skipped unless credentials
for the SES mailbox simulator are set.

## Verifying a release of `@platform-mail/crypto`

A tag `mail-crypto-vX.Y.Z` on `main` makes CI build one tarball and one
`SHA256SUMS` (the package's `src/`, file by file), attest both with GitHub
artifact attestations, stage the tarball on npm with provenance through
trusted publishing, and attach both files to a GitHub release
(`.github/workflows/release-mail-crypto.yml`). Nobody computes those files by
hand. To check them:

```sh
REPO=Tobiscuit/platform-mail
V=0.1.0   # the version you are checking

# The release's files were built by this repository's release workflow, from that tag.
gh release download "mail-crypto-v$V" --repo "$REPO"
for f in SHA256SUMS "platform-mail-crypto-$V.tgz"; do
  gh attestation verify "$f" --repo "$REPO" \
    --signer-workflow "$REPO/.github/workflows/release-mail-crypto.yml" \
    --source-ref "refs/tags/mail-crypto-v$V" --deny-self-hosted-runners
done

# The package on npm is that same tarball.
mkdir -p npm-copy && npm pack "@platform-mail/crypto@$V" --pack-destination npm-copy
cmp "npm-copy/platform-mail-crypto-$V.tgz" "platform-mail-crypto-$V.tgz"

# SHA256SUMS is what the tagged source hashes to, and your copy matches it.
git clone "https://github.com/$REPO" src-copy && git -C src-copy checkout "mail-crypto-v$V"
(cd src-copy && node packages/mail-crypto/scripts/sha256sums.mjs) | diff - SHA256SUMS
(cd path/to/your/vendored/mail-crypto && sha256sum --check --strict /path/to/SHA256SUMS)
```

In a project that installs the package, `npm audit signatures` checks npm's
own provenance for it.

The Mail Worker is deployed by the operator, and nobody outside can verify
what is running; that is the promise's first limit, above. What is public is
the code the deployment is built from.

### Releases (maintainers)

npm only lets a trusted publisher be added to a package that already exists,
so the first release takes one manual step:

1. Publish a placeholder with no code (a `package.json` and a README) as
   `@platform-mail/crypto@0.0.0-reserved`, from a maintainer's machine with
   2FA, and deprecate it.
2. Add the trusted publisher, staging only, and refuse tokens (npm 11.15.0 or
   later; `$REPO` as above):
   `npm trust github @platform-mail/crypto --file release-mail-crypto.yml --repo "$REPO" --env npm-publish --allow-stage-publish`
   and `npm access set mfa=publish @platform-mail/crypto`.
3. Create the `npm-publish` environment and allow only `mail-crypto-v*` tags
   to deploy to it.

From then on: bump `packages/mail-crypto/package.json`, merge, tag the merge
commit `mail-crypto-vX.Y.Z`, push the tag, and approve the staged version on
npm with 2FA (`npm stage approve <id>`).

## Contributing and security

- `CONTRIBUTING.md`: how to work on this repository.
- `SECURITY.md`: how to report a vulnerability privately. Please do not open
  a public issue for one.

## License

Apache License 2.0 (`LICENSE`). Parts of the Mail Worker are adapted from
[cloudflare/agentic-inbox](https://github.com/cloudflare/agentic-inbox), also
Apache-2.0; `NOTICE` names the adapted files, and each keeps Cloudflare's
copyright notice and says what was changed.
