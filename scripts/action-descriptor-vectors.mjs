// Generates contracts/action-descriptor-v1.vectors.json (contracts/action-descriptor-v1.md).
//
// Two RFC 8785 canonicalizers must agree on every valid vector: the restricted
// one below (objects, arrays, strings, safe integers: all a descriptor holds)
// and the `canonicalize` package (erdtman, 5.1.0 when the vectors were made),
// installed anywhere outside this repository and named by its path:
//
//   npm install --prefix /tmp/jcs canonicalize@5.1.0
//   node scripts/action-descriptor-vectors.mjs /tmp/jcs/node_modules/canonicalize/lib/canonicalize.js \
//     contracts/action-descriptor-v1.vectors.json
//
// Every id, nonce and time is fixed, so a rerun writes the same file.
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const reference = (await import(pathToFileURL(process.argv[2]).href)).default;
const out = process.argv[3];

function jcs(value) {
  if (typeof value === "string") {
    if (!value.isWellFormed()) throw new Error("lone surrogate");
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("only safe integers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${jcs(k)}:${jcs(value[k])}`).join(",")}}`;
  }
  throw new Error(`unsupported ${typeof value}`);
}

const LOWER = "0123456789abcdefghjkmnpqrstvwxyz";
function crockford(bytes) {
  const length = Math.ceil((bytes.length * 8) / 5);
  let bits = length * 5 - bytes.length * 8;
  let acc = 0;
  let s = "";
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      s += LOWER[(acc >>> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  return s;
}
const fixed = (seed, n) => Uint8Array.from({ length: n }, (_, i) => (seed * 31 + i * 7 + 3) & 0xff);
const id = (prefix, seed) => `${prefix}_${crockford(fixed(seed, 16))}`;
const b64u = (bytes) => Buffer.from(bytes).toString("base64url");
const sha = (bytes) => b64u(createHash("sha256").update(bytes).digest());

const MAILBOX = id("mbx", 1);
const NONCE = b64u(fixed(9, 32));
const ISSUED = 1792627200; // 2026-10-22T00:00:00Z
const dev = (n) => id("dev", 100 + n);

function encode(object) {
  const mine = jcs(object);
  const theirs = reference(object);
  if (mine !== theirs) throw new Error(`canonicalizers disagree:\n${mine}\n${theirs}`);
  return Buffer.from(mine, "utf8");
}

function valid(name, object, extra = {}) {
  const bytes = encode(object);
  return { name, emailAllowed: object.kind === "revoke-device", object, utf8: bytes.toString("utf8"), hex: bytes.toString("hex"), sha256: sha(bytes), ...extra };
}
const revoke = (targets, more = {}) => ({ version: 1, kind: "revoke-device", mailboxId: MAILBOX, targets, nonce: NONCE, issuedAt: ISSUED, ...more });
const sorted = (targets) => [...targets].sort((a, b) => (a.deviceId < b.deviceId ? -1 : a.deviceId > b.deviceId ? 1 : 0));

const one = [{ deviceId: dev(1), label: "Laptop" }];
const two = sorted([{ deviceId: dev(2), label: "Kitchen tablet" }, { deviceId: dev(3), label: "Old phone" }]);
const unicode = sorted([
  { deviceId: dev(4), label: "Büro-PC (alt)" },
  { deviceId: dev(5), label: "店のパソコン" },
  { deviceId: dev(6), label: "Truck 🚚 iPad" },
  { deviceId: dev(7), label: 'Front desk "main" \\ left' },
]);
const forty = "a".repeat(39) + "🚚"; // 40 code points, 43 bytes of UTF-8
const twenty = sorted(Array.from({ length: 20 }, (_, i) => ({ deviceId: dev(20 + i), label: `Device ${i + 1}` })));
const longest = sorted(Array.from({ length: 20 }, (_, i) => ({ deviceId: dev(60 + i), label: "🚚".repeat(40) })));

const vectors = {
  contract: "contracts/action-descriptor-v1.md",
  note: "utf8 is the descriptor as text; hex is the same bytes; sha256 is base64url (no padding) of SHA-256 over those bytes. Every valid vector was produced by two RFC 8785 canonicalizers that agree byte for byte.",
  fixed: { mailboxId: MAILBOX, nonce: NONCE, issuedAt: ISSUED },
  valid: [
    valid("revoke one device", revoke(one)),
    valid("revoke two devices, targets sorted by deviceId", revoke(two)),
    valid("labels outside ASCII, a quote and a backslash (escaped by RFC 8785, nothing else is)", revoke(unicode)),
    valid("a label of exactly 40 code points", revoke([{ deviceId: dev(8), label: forty }])),
    valid("twenty devices, the most a descriptor names", revoke(twenty)),
    valid("the longest descriptor: twenty devices, each label 40 four-byte code points", revoke(longest)),
    valid("remove-devices (a factor proof confirms it; never an email code)", {
      version: 1,
      kind: "remove-devices",
      mailboxId: MAILBOX,
      targets: one,
      nonce: NONCE,
      issuedAt: ISSUED,
      request: sha(Buffer.from(jcs({ example: "the request's own canonical bytes" }), "utf8")),
    }),
    valid("remove-devices with no targets: finishing a rotation that is due", {
      version: 1,
      kind: "remove-devices",
      mailboxId: MAILBOX,
      targets: [],
      nonce: NONCE,
      issuedAt: ISSUED,
      request: sha(Buffer.from(jcs({ example: "a rotation" }), "utf8")),
    }),
  ],
  invalid: [],
};

const good = vectors.valid[0].utf8;
const bad = (name, text, why) => vectors.invalid.push({ name, utf8: text, hex: Buffer.from(text, "utf8").toString("hex"), why });
bad("whitespace between tokens", good.replace('{"issuedAt"', '{ "issuedAt"'), "not the canonical form (RFC 8785 emits no whitespace)");
bad("a trailing newline", `${good}\n`, "not the canonical form");
bad("a byte order mark", `﻿${good}`, "not the canonical form");
bad("members out of order", good.replace(/^\{("issuedAt":\d+),("kind":"revoke-device")/, "{$2,$1"), "not the canonical form (members sorted by UTF-16 code units)");
bad("a duplicate member", good.replace('{"issuedAt"', `{"issuedAt":${ISSUED + 1},"issuedAt"`), "a duplicate member (I-JSON); its re-serialization differs");
bad("an escape RFC 8785 does not produce", good.replace('"Laptop"', '"L\\u0061ptop"'), "not the canonical form");
bad("an unknown member", jcs({ ...revoke(one), extra: "x" }), "an unknown member");
bad("a missing member (nonce)", jcs((({ nonce, ...rest }) => rest)(revoke(one))), "a missing member");
bad("version 2", jcs(revoke(one, { version: 2 })), "an unknown version");
bad("version as a string", jcs(revoke(one, { version: "1" })), "version must be the number 1");
bad("an unknown kind", jcs(revoke(one, { kind: "revoke-everything" })), "an unknown kind");
bad("request on revoke-device", jcs(revoke(one, { request: sha(Buffer.from("x")) })), "revoke-device carries no request");
bad("remove-devices without request", jcs({ ...revoke(one), kind: "remove-devices" }), "remove-devices needs its request digest");
bad("no targets for revoke-device", jcs(revoke([])), "revoke-device names 1 to 20 devices");
bad("twenty-one targets", jcs(revoke(sorted(Array.from({ length: 21 }, (_, i) => ({ deviceId: dev(200 + i), label: `D${i}` }))))), "at most 20 devices");
bad("targets not sorted", jcs(revoke([...two].reverse())), "targets are sorted by deviceId");
bad("the same device twice", jcs(revoke([one[0], { ...one[0], label: "Laptop again" }])), "a device appears once");
bad("a target with an extra member", jcs(revoke([{ ...one[0], seen: "yesterday" }])), "a target is exactly { deviceId, label }");
bad("a device id with the wrong prefix", jcs(revoke([{ deviceId: id("wrp", 5), label: "Laptop" }])), "deviceId is dev_ and 26 Crockford symbols");
bad("a device id in upper case", jcs(revoke([{ deviceId: one[0].deviceId.toUpperCase().replace("DEV_", "dev_"), label: "Laptop" }])), "ids are lower case");
bad("a mailbox id that is not one", jcs(revoke(one, { mailboxId: "mbx_short" })), "mailboxId is mbx_ and 26 Crockford symbols");
bad("an empty label", jcs(revoke([{ deviceId: dev(1), label: "" }])), "a label has 1 to 40 code points");
bad("a label of 41 code points", jcs(revoke([{ deviceId: dev(1), label: "a".repeat(41) }])), "a label has 1 to 40 code points");
bad("a label with a control character", jcs(revoke([{ deviceId: dev(1), label: "Lap\u0007top" }])), "no U+0000-U+001F or U+007F-U+009F");
bad("a label with U+0085", jcs(revoke([{ deviceId: dev(1), label: "Lap\u0085top" }])), "no U+0000-U+001F or U+007F-U+009F");
bad("a label with a line separator", jcs(revoke([{ deviceId: dev(1), label: "Lap\u2028top" }])), "no U+2028 or U+2029");
bad("a label with a lone surrogate (written as an escape)", good.replace('"Laptop"', '"Lap\\ud800top"'), "a lone surrogate (RFC 8785 refuses it; the bytes are not canonical either)");
bad("a nonce of 31 bytes", jcs(revoke(one, { nonce: b64u(fixed(9, 31)) })), "nonce is base64url of 32 bytes (43 characters)");
bad("a nonce with padding", jcs(revoke(one, { nonce: `${NONCE}=` })), "nonce is unpadded base64url");
bad("issuedAt with a fraction", good.replace(`"issuedAt":${ISSUED}`, `"issuedAt":${ISSUED}.5`), "issuedAt is a whole number of seconds");
bad("issuedAt as a string", jcs(revoke(one, { issuedAt: String(ISSUED) })), "issuedAt is a number");
bad("issuedAt negative", jcs(revoke(one, { issuedAt: -1 })), "issuedAt is at least 0");
bad("an array at the top", jcs([revoke(one)]), "a descriptor is an object");


// The dashboard's attestation (capability-v1 `confirmation`), as Mail checks it.
const SUB = "acct_example_owner";
const first = vectors.valid[0];
const attestation = { method: "email-code", accountId: SUB, actionKind: "revoke-device", actionDigest: first.sha256, at: ISSUED + 150, codeId: "code_example_1" };
vectors.attestations = {
  note: "Mail's checks, with the capability's sub and Mail's clock as given. `descriptor` names the valid vector whose digest Mail holds for its pending challenge.",
  sub: SUB,
  now: ISSUED + 200,
  descriptor: first.name,
  accepted: [{ name: "the code was confirmed 50 seconds ago", attestation }],
  refused: [
    { name: "another account", attestation: { ...attestation, accountId: "acct_example_other" }, why: "accountId must equal the capability's sub" },
    { name: "another method", attestation: { ...attestation, method: "passkey" }, why: "method is exactly email-code" },
    { name: "a kind an email code may not confirm", attestation: { ...attestation, actionKind: "remove-devices" }, why: "an email code confirms only revoke-device" },
    { name: "another digest", attestation: { ...attestation, actionDigest: vectors.valid[1].sha256 }, why: "actionDigest must be the digest of the descriptor of Mail's pending challenge" },
    { name: "confirmed 301 seconds ago", attestation: { ...attestation, at: ISSUED + 200 - 301 }, why: "at is at most 300 seconds old" },
    { name: "confirmed in the future", attestation: { ...attestation, at: ISSUED + 200 + 6 }, why: "at is at most 5 seconds ahead of Mail's clock" },
    { name: "confirmed before the descriptor was issued", attestation: { ...attestation, at: ISSUED - 1 }, why: "at is not before the descriptor's issuedAt" },
    { name: "an extra member", attestation: { ...attestation, extra: true }, why: "exactly six members" },
    { name: "at as a string", attestation: { ...attestation, at: String(ISSUED + 150) }, why: "at is a whole number of seconds" },
  ],
};

writeFileSync(out, `${JSON.stringify(vectors, null, 2)}\n`);
console.log(`valid ${vectors.valid.length}, invalid ${vectors.invalid.length}; longest ${Math.max(...vectors.valid.map((v) => v.hex.length / 2))} bytes`);
