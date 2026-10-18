# @proprietor/mail-crypto

Envelope v1 and key wrapping for proprietor-mail, exactly as
[`contracts/envelope-v1.md`](../../contracts/envelope-v1.md) specifies. One
implementation, used by both sides:

- **the Mail Worker** seals (`sealMessage`; it holds public keys only);
- **the owner's browser** generates the mailbox key, opens headers, bodies and
  drafts, seals drafts, and wraps and unwraps the private key.

It runs unchanged in browsers, in Cloudflare workerd and in Node (the tests).
It uses only Web Crypto and `crypto.getRandomValues`: no `node:*` imports, no
`Buffer`, no DOM, no network.

```
npm test -w @proprietor/mail-crypto          # vitest: every acceptance test in tasks.md §S1
npm run typecheck -w @proprietor/mail-crypto # src/ with the DOM lib, src/ with @cloudflare/workers-types
                                           # (no DOM, as the Mail Worker compiles it), then src/ + test/
npm run write-vectors -w @proprietor/mail-crypto  # regenerate contracts/envelope-v1.vectors.json
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
carry the private key in its standard PKCS #8 form, as the contract requires.
Until then, a runtime without X25519 surfaces Web Crypto's own
`NotSupportedError` (never `DecryptionFailed`). `x25519Supported()` lets a
page check first and ask for a browser update before a passkey ceremony.

### The private key never leaves the module

`MailboxPrivateKey` is a frozen `{ keyId }` handle. What it stands for lives
in a module-private `WeakMap`: an X25519 `CryptoKey` (with its public half),
used for every decryption. **This module never reads the private key as
bytes** (D21, domain-model K1): a fresh key comes from `generateKey`, a stored
one is opened by `unwrapKey`, and a wrap is made by `wrapKey`, which
serializes (PKCS #8) and encrypts inside Web Crypto in one step.

No property, `JSON.stringify`, `structuredClone`/`postMessage` or spread
reaches the key. A clone, or a forged `{ keyId }`, is refused with a
`TypeError`.

A key is **wrappable** (extractable, for `wrapKey` only) in two cases: it was
just generated, because enrollment must wrap it; or `unwrapPrivateKey` was
called with `{ wrappable: true }`, which an unlock does only for the one
operation that wraps the key again (another passkey, a new recovery key).
Every other unwrapped key is non-extractable and decrypt-only, and
`wrapPrivateKey` refuses it with a `TypeError`. The honest limit remains:
code running in the page can unlock with the person's secret and wrap the
key under one of its choosing, so the page is the trust boundary (spec §2,
Decision D2), not this module. What the module guarantees is that the key is
never exposed by accident, and that an unlocked session holds nothing that
can be wrapped.

The public key is computed as X25519(k, 9) with `deriveBits` against the base
point (RFC 7748 §6.1, checked against its test vector), so the private
`CryptoKey` never has to be extractable. `@hpke/core` notes that Firefox
cannot always export JWK from imported X25519 private keys; this path avoids
that export entirely.

### Clamping (RFC 9180 §7.1.2)

RFC 9180 says `SerializePrivateKey` MUST clamp its output and
`DeserializePrivateKey` MUST clamp its input. `@hpke/core` does neither, and
the RFC's own test vectors carry unclamped `skRm`. Clamping never changes
the key, because X25519 clamps before every use (RFC 7748 §5), and that is
what this package relies on:

- **At generation** the engine decides the bytes, and `wrapKey` carries
  them as they are. Measured by the browser probe (1,200 keys each, October
  2026): WebKit on macOS (the CryptoKit backend Safari uses) and Node
  (OpenSSL) clamp. Chromium (BoringSSL) does the exact opposite on purpose:
  it sets the three low bits and the top bit and clears bit 254 of every
  key, so that an implementation that forgets to clamp fails at once.
  Firefox leaves the 32 random bytes as drawn. A wrap therefore holds an
  unclamped scalar whenever the key came from Chromium or Firefox.
- **On unwrap**: Web Crypto clamps before every use, so an unclamped key
  wrapped by another implementation still unwraps to the same key pair. A
  test does this with RFC 7748's Alice key.
- **On import of a raw scalar** (`importPrivateScalar`, A2's factor keys):
  an extractable key, the kind the test vectors wrap, is clamped first. A
  non-extractable one is never serialized, and is handed over with the
  three low bits set instead, as Chromium's keys are: the same key, never a
  zero first byte (next section).

### One engine's defect: WebKit bug 307095 (libgcrypt)

WebKit has two Web Crypto backends: CryptoKit in Safari (macOS, iOS,
iPadOS), and libgcrypt in WebKitGTK and WPE on Linux, which Playwright's
WebKit on Linux uses. The libgcrypt one drops a leading zero byte from an
X25519 scalar ([WebKit bug 307095](https://bugs.webkit.org/show_bug.cgi?id=307095),
fixed on WebKit main on 2026-10-09 as 323215@main; no Playwright WebKit
build has the fix yet). So it refuses a PKCS #8 X25519 key whose first byte
is zero (`DataError`), and its `generateKey` fails when it drew such a
scalar (`OperationError`, 1 draw in 256). The probe in
`packages/mail-client/test/browser` measured it over 300 inputs per check:
every zero-first-byte scalar refused on import and on unwrap, 9 and 10 of
300 random clamped scalars, 3 `OperationError`s in 1,203 `generateKey`
draws, and nothing at all in WebKit on macOS (Safari's backend), Chromium or
Firefox. What the package does, pinned by `test/engines.test.ts`:

- **A key it never serializes** (a factor key, A2) is imported with the
  three low bits set, so its first byte is never zero. Before this, 1
  factor in 32 could not be used in that engine.
- **A fresh X25519 key pair** (a mailbox key, every HPKE seal's ephemeral
  key, `x25519Supported`'s probe) is drawn again after an `OperationError`,
  at most four times. Nothing has kept the failed draw, so another one loses
  nothing; any other error is thrown at once.
- **Not reachable here**: a mailbox key with a zero first byte that another
  engine made and wrapped. That is 1 key in 32 made by WebKit on macOS or by
  Node, 1 in 256 made by Firefox, none made by Chromium or by this engine (its
  `generateKey` cannot hold one). Its bytes exist only inside Web Crypto
  (K1), so that engine refuses it and the unwrap fails closed, as
  `DecryptionFailed`, until WebKitGTK or WPE carries the fix.

No output changes: every public key, tag, seal and wrap format is what it
was, and the vectors are unchanged.

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

### Kept devices, factor keys and sessions (device-v1 Part A)

[`contracts/device-v1.md`](../../contracts/device-v1.md) Part A adds formats
next to envelope v1, and this package is their one implementation. The
browser's half is here: `deriveFactorKey`/`factorPublicKey` (A2),
`generateSigningKey`/`generateUnlockKey` (A3), `sealKey`/`openKeySeal`
(A4), `bindingKey`/`bindingTag`/`verifyBindingTag` (A5), `openChallenge`
(A6) and `signDeviceProof` (A7). The Worker's half (`sealChallenge`,
`verifyDeviceProof`) is `src/proofs.ts`. The vectors are
`contracts/device-v1.vectors.json` (`npm run write-device-vectors`), and
`test/device-vectors.test.ts` reads each one a second time from the
contract's text with OpenSSL, `@hpke/core` and raw Web Crypto.

- **Factor keys** use RFC 9180 DeriveKeyPair written here, not
  `@hpke/core`'s `deriveKeyPair`: in 1.9.0 that one imports the private
  key extractable and leaves its PKCS #8 buffer unzeroed. Here skF is
  non-extractable, and the secret's copy, ikm and the scalar are zeroed.
  Checked against RFC 9180 A.1.1, `@hpke/core` and OpenSSL.
- **A P-256 seal opens only with the recipient's key pair.** Given a
  non-extractable private key alone, `@hpke/core` 1.9.0 recomputes the
  public key for the KEM context and picks the even-y point
  (`Ec._derivePublicKeyWithoutJwkExport`), the wrong point for about half
  of all keys. `openKeySeal` takes the device's public form with its
  private key; a test shows both behaviours.
- **The KEK is bytes for one import.** HPKE's `export()` returns an
  `ArrayBuffer`; it becomes a non-extractable AES-GCM key at once and is
  zeroed. The mailbox key itself still never exists as bytes: `wrapKey`
  and `unwrapKey` move it.
- **Opened keys are non-extractable** unless the caller asks for
  `wrappable` for one sealing step (Part C, K1′), and a seal is refused
  unless it holds the key it names.
- **Tags never throw on what Mail sent**: `verifyBindingTag` is false for
  anything malformed. Labels must be well-formed Unicode, because
  `TextEncoder` maps every lone surrogate to U+FFFD and two labels would
  otherwise share a tag.
- **A challenge's purpose and target come from the key**: a mailbox key
  answers only session challenges for its keyId, a factor key only factor
  challenges for its id (K4).
- The key-seal `info` strings are 129 to 134 bytes. `@hpke/core` 1.9.0
  enforces 2^28 bytes (its type comment's "128 bytes" is stale); RFC 9180
  asks implementations to support at least 64.

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
