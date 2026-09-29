# Security policy

This repository exists so that the claim "the operator cannot read your stored
mail" can be checked. A flaw that breaks that claim is the most important
kind of report we can get.

## Reporting a vulnerability

Report privately through GitHub: the repository's **Security** tab →
**Report a vulnerability** ([open a private report](../../security/advisories/new)).
The report is visible only to the maintainers until an advisory is
published.

Please do not open a public issue, pull request or discussion for a
vulnerability.

A useful report says what an attacker can do, from which position (anyone on
the internet, a sender of mail, the holder of a dashboard account, the
operator of the platform), and how to reproduce it. A failing test or a
change to one of the test vectors is ideal.

We aim to acknowledge a report within seven days and to keep you informed
until it is resolved. Fixes are released first and disclosed after, through
a GitHub security advisory that credits you unless you would rather not be
named.

## Scope

In scope, including anything in `main` that is not yet released:

- `packages/mail-crypto`: the envelope, key wrapping, recovery keys, and the
  byte formats in `contracts/envelope-v1.md`;
- the Mail Worker (`src/`): capability verification, isolation between businesses, the
  storage invariants in `specs/001-inbox-module/domain-model.md` §3 (for
  example, anything that stores or logs message content in plaintext, or lets
  one business reach another business's mailbox);
- `packages/mail-outbound`: header injection, or anything that lets a
  request choose the sender;
- the release path: `.github/workflows/` and anything that could make a
  published `@proprietor/mail-crypto` differ from this repository's source.

Not vulnerabilities, because the design states them as limits
(`specs/001-inbox-module/spec.md` §2 and §4):

- the platform handles each message in readable form for the moment it
  arrives and the moment it is sent;
- the code that decrypts in the browser is served by the operator;
- the metadata listed in spec §4 (arrival times, sizes, flags, envelope
  addresses in transit).

A way to make any of these worse than the spec says, for example metadata
that is stored when it should not be, is in scope.

The dashboard that calls this code is a separate application. If you find a
problem in how it uses this repository's code, report it here the same way.

## Supported versions

Security fixes go to `main` and to the latest `@proprietor/mail-crypto`
release. The Mail Worker has no releases of its own; the operator deploys it
from `main`.
