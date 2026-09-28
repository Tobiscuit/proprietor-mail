# Contributing

Thank you for looking. This is a small repository with a narrow job, so a
short note first: for anything beyond a small fix, open an issue before you
write code. The spec (`specs/001-inbox-module/`) is the source of truth, and
some changes (anything to a byte format, anything that widens what the server
can see) are decisions before they are code.

Security issues go through `SECURITY.md`, never a public issue.

## Working on it

Node 26.4.0 (`.nvmrc`). From the repository root:

```sh
npm ci
npm run typecheck
npm test
```

Everything runs locally; no test sends or receives real mail, and none needs
an account or a credential.

## The rules this code keeps

- **Tests first.** Write the test, watch it fail for the right reason, then
  make it pass. A fix comes with the test that would have caught it.
- **The contracts are fixed.** A change to any byte in
  `contracts/envelope-v1.md` is a new version (`v2`), never an edit of `v1`:
  stored mail must stay readable. The test vectors change only with the
  contract they belong to.
- **No plaintext at rest, no private key on the server.** The invariants in
  `specs/001-inbox-module/domain-model.md` §3 each have a test; keep it that
  way.
- **Dependencies are pinned exactly** and added only with a reason. Nothing
  in `packages/mail-crypto` or its runtime dependencies may use `eval`, the
  `Function` constructor, timers, WebAssembly, the DOM or the network; its
  tests scan for them.
- **Code adapted from elsewhere** keeps its copyright header, adds a
  "Modified by" line saying what changed, and is listed in `NOTICE`.

## Writing for a public audience

Commit messages, pull requests, comments and specs here are public.

- Use `example.com`, `example.org` and `example.net` (RFC 2606) for
  addresses and domains, and invented names for people and businesses.
- No real client or personal data, and no infrastructure identifiers:
  account ids, resource ids, secret-store paths, internal hostnames.
- No secrets, ever: not in code, tests, logs or commit messages. Test keys
  are derived from public labels and say so.

## License

By contributing you agree that your contribution is licensed under the
Apache License 2.0, the same as the rest of the repository (`LICENSE`,
section 5).
