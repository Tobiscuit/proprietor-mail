# @platform-mail/crypto

Envelope v1 and key wrapping for platform-mail, exactly as
[`contracts/envelope-v1.md`](../../contracts/envelope-v1.md) specifies. One
implementation, used by both sides:

- **the Mail Worker** seals (`sealMessage`; it holds public keys only);
- **the owner's browser** generates the mailbox key, opens headers, bodies and
  drafts, seals drafts, and wraps and unwraps the private key.

It runs unchanged in browsers, in Cloudflare workerd and in Node (the tests).
It uses only Web Crypto and `crypto.getRandomValues`: no `node:*` imports, no
`Buffer`, no DOM, no network.

```
npm test -w @platform-mail/crypto          # vitest: every acceptance test in tasks.md §S1
npm run typecheck -w @platform-mail/crypto # src/ with the DOM lib, src/ with @cloudflare/workers-types
                                           # (no DOM, as the Mail Worker compiles it), then src/ + test/
npm run write-vectors -w @platform-mail/crypto  # regenerate contracts/envelope-v1.vectors.json
```

## Dependencies

| Package | Version | Integrity (npm, checked 2026-09-26) |
| --- | --- | --- |
| `@hpke/core` | 1.9.0 | `sha512-pFxWl1nNJeQCSUFs7+GAblHvXBCjn9EPN65vdKlYQil2aURaRxfGMO6vBKGqm1YHTKwiAxJQNEI70PbSowMP9Q==` |
| `@hpke/common` | 1.10.1 | `sha512-moJwhmtLtuxiUzzNp1jpfBfx8yefKoO9D/RCR9dmwrnc7qjJqId1rEtQz+lSlU5cabX8daToMSx/7HayXOiaFw==` |

`@hpke/common` is `@hpke/core`'s only dependency (range `^1.10.0`). It is
declared here, pinned exactly, so the audited version is the one installed
without relying on a lockfile. Nothing else ships to a browser.

## Decisions

### Native X25519 only, no pure-JavaScript fallback

`@hpke/core`'s `DhkemX25519HkdfSha256` uses Web Crypto's `X25519` and has no
fallback. `@hpke/dhkem-x25519` would add one. It is **not** included,
because every engine that matters ships X25519 natively:

| Runtime | Native X25519 since | Source |
| --- | --- | --- |
| Chrome, Edge, Android WebView, Samsung Internet (Chromium) | 133 (Feb 2025), desktop and Android | chromestatus feature 6291245926973440 ("Enabled by default", M133); MDN BCD `api.SubtleCrypto.deriveBits.x25519` |
| Firefox (desktop and Android) | 130 (Sep 2024) | MDN BCD (same key); chromestatus records Gecko as shipped |
| Safari on macOS, iOS, iPadOS | 18.4 (Mar 2025) | WebKit, "WebKit Features in Safari 18.4" ("adds support for X25519 for Web Cryptography"). MDN BCD says 17; the WebKit implementation (bug 258279) landed on 2023-09-08, after Safari 17 branched, so the vendor's release notes are taken as authoritative |
| Cloudflare workerd | 2023-04-28 | Workers changelog and Web Crypto docs |
| Node | 16.17 (tests run on 26) | MDN BCD |

On 2026-09-26 the newest of those floors is 18 months old. Every one of
those browsers updates itself, and an iPhone that can run iOS 18 can run
18.4. The unlock path overlaps too: WebAuthn PRF arrived in Chrome 116,
Firefox 139 and Safari 18 (MDN BCD
`api.CredentialsContainer.create.publicKey_option.extensions.prf`), so the
only PRF-capable browsers without X25519 are Chrome 116–132 and Safari
18.0–18.3, both superseded for over a year. A fallback
would put a second, non-constant-time (BigInt) X25519 implementation inside
the key-handling code to serve only stale browsers.

The fallback stays possible later without migrating anything, because wraps
carry the private key as its raw 32 bytes, as the contract requires. Until
then, a runtime without X25519 surfaces Web Crypto's own `NotSupportedError`
(never `DecryptionFailed`). `x25519Supported()` lets a page check first and
ask for a browser update before a passkey ceremony.

### The private key never leaves the module

`MailboxPrivateKey` is a frozen `{ keyId }` handle. What it stands for lives
in a module-private `WeakMap`:

- a **non-extractable** X25519 `CryptoKey` (with its public half), used for
  every decryption;
- the **clamped 32-byte scalar**, read by one function only: `wrapPrivateKey`.

No property, `JSON.stringify`, `structuredClone`/`postMessage` or spread
reaches either. A clone, or a forged `{ keyId }`, is refused with a
`TypeError`.

The scalar is kept because an unlocked key must stay re-wrappable: enrolling
another passkey wraps the same key under a new PRF output. Web Crypto cannot
wrap a non-extractable key, so a non-extractable `CryptoKey` on its own could
not do this. This is also the honest limit of any design here. Code running
in the page can call `wrapPrivateKey` with a secret of its choosing, so the
page is the trust boundary (spec §2, Decision D2), not this module. What the
module does guarantee is that the key is never exposed by accident: through
logging, serialization, storage or a message to another context.

The public key is computed as X25519(k, 9) with `deriveBits` against the base
point (RFC 7748 §6.1, checked against its test vector), so the private
`CryptoKey` never has to be extractable. `@hpke/core` notes that Firefox
cannot always export JWK from imported X25519 private keys; this path avoids
that export entirely.

### Clamping (RFC 9180 §7.1.2)

RFC 9180 says `SerializePrivateKey` MUST clamp its output and
`DeserializePrivateKey` MUST clamp its input. `@hpke/core` does neither, and
the RFC's own test vectors carry unclamped `skRm`. So this package clamps
twice:

- **At generation**: the scalar is random bytes, clamped once. The raw bytes
  in a wrap are therefore the clamped scalar.
- **On unwrap**: the input is clamped again. An unclamped key wrapped by
  another implementation still unwraps to the same key pair. A test does this
  with RFC 7748's Alice key.

Clamping never changes the key, because X25519 clamps before use.

### Crockford base32

Crockford encodes a number, "zero-extended to make its bit-length a multiple
of 5". So the pad bits are **leading** zeros, as in ULID and TypeID:

- an id's 26 symbols start with 0–7;
- a recovery key's 55 symbols start with 0–3.

Decoding is canonical. A set pad bit, `U`, or any non-ASCII look-alike is a
typo. Every single-character substitution of a recovery key is therefore
either `RecoveryKeyTypo`, or (with probability 2^-16, from the checksum) a
different secret whose wrap fails. The test tries all of them.

### Synchronous SHA-256 for the recovery checksum

`newRecoveryKey` and `parseRecoveryKey` are synchronous in the published API,
but Web Crypto's `digest` is asynchronous. The 2-byte checksum therefore uses
a small FIPS 180-4 SHA-256 (`src/sha256.ts`). A test checks it against
`crypto.subtle.digest` for every length from 0 to 300 bytes. Nothing else
uses it.

### What `sealMessage` enforces

- **The 64 KiB rule.** When the header JSON would exceed 64 KiB,
  `references` keeps its last 20 entries, then `snippet` is shortened by
  whole code points, only as far as needed. A header still too large after
  both steps is refused with `RangeError`: the contract names nothing else
  to drop.
- **Every header key is present** (`TypeError` if not). `snippet` length and
  whitespace are the header builder's job.
- **Consistent keys.** A `keyId` must belong to its public key (`TypeError`
  otherwise), so mail is never stored under the wrong key id.
- **Unambiguous associated data.** An id must be a non-empty string without
  `|`, the separator. Ids from `newId` always are.

### Errors

| Error | When |
| --- | --- |
| `DecryptionFailed` | Any failure while opening: tag mismatch, wrong key, moved blob, malformed base64url, wrong length, wrong version byte or magic, JSON that is not a v1 plaintext. Never an empty or partial result. |
| `RecoveryKeyTypo` | `parseRecoveryKey` input that is not exactly a valid key. Detected before any decryption. |
| `TypeError` | A caller mistake: a handle this module did not make, a wrong-length key or secret, an unknown id prefix or wrap kind, an id containing `\|`. |
| `NotSupportedError` (`DOMException`) | A runtime without Web Crypto X25519 (see above). |

## Content Security Policy

The dashboard runs this package under a nonce CSP with `'strict-dynamic'`,
Trusted Types, and neither `'unsafe-eval'` nor `'wasm-unsafe-eval'`. The
package and its runtime dependencies therefore:

- use no `eval`, no `Function` constructor, no timers and no WebAssembly;
- touch no DOM and no injection sink;
- make no network request.

`test/runtime.test.ts` enforces this. It resolves the runtime dependency
closure from `package.json` (today `@hpke/core` and `@hpke/common`). It then
scans that closure's shipped JavaScript (ESM and CommonJS builds) and `src/`
with targeted patterns. Every finding must match an allow-list entry with a
reason, and an unused entry fails the test. There are two entries:

- `@hpke/common`'s `import("crypto")` / `require("crypto")`: a Node ≤ 18
  fallback taken only when `globalThis.crypto` is undefined, which never
  happens in browsers, workerd or Node ≥ 19. Bundlers keep it as an
  unresolved dynamic import (esbuild leaves it verbatim), and it never runs.
- A JSDoc comment in `@hpke/common`: "Key Derivation Function (KDF)
  identifiers".

## Vendoring

The dashboard vendors this package byte for byte. `src/` is plain TypeScript
with extensionless relative imports, and it needs no path aliases, build step
or loader option. Its only bare imports are the two pinned dependencies above.
A test checks this, and that `src/` compiles without Node types. The package's
whole browser footprint, bundled and minified with esbuild, is about 41 KB
(12 KB gzipped).

### Releases: one set of bytes, three ways to check it

A release is a tag `mail-crypto-vX.Y.Z` on a commit that is already on `main`,
where X.Y.Z is this `package.json`'s `version`.
`.github/workflows/release-mail-crypto.yml` refuses any other tag. It runs the
tests, then, without installing anything:

- computes `SHA256SUMS`: one line per file under `src/`, by
  `scripts/sha256sums.mjs` from the tagged tree, in sha256sum's format with
  paths relative to this directory. From the directory that holds a vendored
  `src/`, `sha256sum --check --strict SHA256SUMS` checks the copy;
- packs the npm tarball once (`src/`, this README, `package.json` and
  `LICENSE`);
- attests both files with GitHub artifact attestations;
- stages that tarball on npm through trusted publishing, with npm provenance.
  A maintainer approves the staged version with 2FA before it can be
  installed;
- attaches both files to the GitHub release.

The published package is the TypeScript source itself, with no build step,
as the dashboard vendors it: it is meant for a bundler (esbuild, Vite,
wrangler), not for Node to import directly. The repository's `README.md`
shows how to verify a release end to end.
