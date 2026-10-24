// Round 3, contracts/action-descriptor-v1.md: an action descriptor is the RFC 8785 serialization
// of one object; a reader parses it, serializes it again and requires the very bytes it read, then
// checks the members and every rule of the table. The digest is base64url SHA-256 of the exact
// bytes. Every vector of contracts/action-descriptor-v1.vectors.json runs here: each valid one
// builds to exactly its bytes from its object, reads back to its object and has its digest; each
// invalid one is refused.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import {
  ACTION_KINDS,
  actionDescriptorFor,
  actionDigest,
  actionPurpose,
  buildActionDescriptor,
  isDeviceLabel,
  MAX_ACTION_DESCRIPTOR_BYTES,
  newId,
  readActionDescriptor,
  requestDigest,
  type ActionDescriptor,
  type ActionInput,
  type ActionKind,
} from "../src/index";
import { fromHex, hex } from "./reference";

const vectorsPath = resolve(dirname(fileURLToPath(import.meta.url)), "../../../contracts/action-descriptor-v1.vectors.json");

interface ValidVector { name: string; emailAllowed: boolean; object: ActionDescriptor; utf8: string; hex: string; sha256: string }
interface InvalidVector { name: string; utf8: string; hex: string; why: string }
const vectors: { fixed: { mailboxId: string; nonce: string; issuedAt: number }; valid: ValidVector[]; invalid: InvalidVector[] } = JSON.parse(readFileSync(vectorsPath, "utf8"));
const { mailboxId, nonce, issuedAt } = vectors.fixed;
const sha256b64u = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("base64url");

const deviceA = "dev_0000000000000000000000000a";
const deviceB = "dev_0000000000000000000000000b";
const request = vectors.valid.find((v) => v.object.request !== undefined)!.object.request!;

function descriptor(kind: ActionKind, more: Partial<ActionDescriptor> = {}): ActionDescriptor {
  const base: ActionDescriptor = { version: 1, kind, mailboxId, targets: [], nonce, issuedAt };
  if (kind === "revoke-device") base.targets = [{ deviceId: deviceA, label: "Laptop" }];
  else base.request = request;
  if (kind === "register-device") base.targets = [{ deviceId: deviceA, label: "Laptop" }];
  return { ...base, ...more };
}

describe("action-descriptor-v1 vectors", () => {
  test("the file has the contract's 8 valid and 33 invalid descriptors", () => {
    expect(vectors.valid.length).toBe(8);
    expect(vectors.invalid.length).toBe(33);
  });

  test.each(vectors.valid.map((v) => [v.name, v] as const))("valid: %s", async (_, v) => {
    const bytes = fromHex(v.hex);
    expect(new TextDecoder().decode(bytes)).toBe(v.utf8);
    expect(hex(buildActionDescriptor(v.object))).toBe(v.hex);
    expect(readActionDescriptor(bytes)).toEqual(v.object);
    expect(await actionDigest(bytes)).toBe(v.sha256);
    expect(sha256b64u(bytes)).toBe(v.sha256);
    expect(v.emailAllowed).toBe(actionPurpose(v.object.kind) === "email");
  });

  test.each(vectors.invalid.map((v) => [v.name, v] as const))("invalid: %s", (_, v) => {
    expect(hex(new TextEncoder().encode(v.utf8))).toBe(v.hex);
    expect(readActionDescriptor(fromHex(v.hex))).toBeNull();
  });

  test("the longest descriptor the contract allows is 4,509 bytes", () => {
    expect(Math.max(...vectors.valid.map((v) => v.hex.length / 2))).toBe(4509);
  });
});

describe("buildActionDescriptor", () => {
  test.each(ACTION_KINDS.map((k) => [k] as const))("%s: builds, reads back to the same object, and its bytes are canonical", (kind) => {
    const d = descriptor(kind);
    const bytes = buildActionDescriptor(d);
    expect(readActionDescriptor(bytes)).toEqual(d);
    expect(hex(buildActionDescriptor(readActionDescriptor(bytes)!))).toBe(hex(bytes));
  });

  test("targets are sorted by deviceId as they are built", () => {
    const targets = [
      { deviceId: deviceB, label: "Phone" },
      { deviceId: deviceA, label: "Laptop" },
    ];
    const bytes = buildActionDescriptor(descriptor("revoke-device", { targets }));
    expect(readActionDescriptor(bytes)!.targets.map((t) => t.deviceId)).toEqual([deviceA, deviceB]);
    expect(targets[0]!.deviceId).toBe(deviceB); // the caller's array is not reordered
  });

  test.each([
    ["an unknown kind", { kind: "revoke-everything" }],
    ["version 2", { version: 2 }],
    ["a request on revoke-device", { request }],
    ["a mailbox id that is not one", { mailboxId: "mbx_short" }],
    ["a nonce of 31 bytes", { nonce: nonce.slice(0, 42) }],
    ["a nonce with padding", { nonce: `${nonce}=` }],
    ["issuedAt with a fraction", { issuedAt: issuedAt + 0.5 }],
    ["issuedAt negative", { issuedAt: -1 }],
    ["no targets", { targets: [] }],
    ["the same device twice", { targets: [{ deviceId: deviceA, label: "A" }, { deviceId: deviceA, label: "B" }] }],
    ["a target with an extra member", { targets: [{ deviceId: deviceA, label: "A", seen: "x" }] }],
    ["an empty label", { targets: [{ deviceId: deviceA, label: "" }] }],
    ["an unknown member", { extra: "x" }],
  ])("revoke-device with %s is a TypeError", (_, more) => {
    expect(() => buildActionDescriptor(descriptor("revoke-device", more as Partial<ActionDescriptor>))).toThrow(TypeError);
  });

  test("each kind's target count: revoke-device 1-20, remove-devices 0-20, register-device exactly 1, the rest none", () => {
    const many = (n: number) => Array.from({ length: n }, (_, i) => ({ deviceId: `dev_${String(i).padStart(26, "0")}`, label: `D${i}` }));
    const counts: Record<ActionKind, [number[], number[]]> = {
      "revoke-device": [[1, 20], [0, 21]],
      "remove-devices": [[0, 1, 20], [21]],
      "register-device": [[1], [0, 2]],
      "add-factor": [[0], [1]],
      "remove-factor": [[0], [1]],
      "open-session": [[0], [1]],
      upgrade: [[0], [1]],
    };
    for (const kind of ACTION_KINDS) {
      const [allowed, refused] = counts[kind];
      for (const n of allowed) expect(() => buildActionDescriptor(descriptor(kind, { targets: many(n) })), `${kind} ${n}`).not.toThrow();
      for (const n of refused) expect(() => buildActionDescriptor(descriptor(kind, { targets: many(n) })), `${kind} ${n}`).toThrow(TypeError);
    }
  });

  test("every kind but revoke-device needs its request digest, 43 base64url characters of 32 bytes", () => {
    for (const kind of ACTION_KINDS.filter((k) => k !== "revoke-device")) {
      const { request: _, ...without } = descriptor(kind);
      expect(() => buildActionDescriptor(without as ActionDescriptor), kind).toThrow(TypeError);
      expect(() => buildActionDescriptor(descriptor(kind, { request: request.slice(0, 42) })), kind).toThrow(TypeError);
      expect(() => buildActionDescriptor(descriptor(kind, { request: `${request.slice(0, 42)}+` })), kind).toThrow(TypeError);
    }
  });
});

describe("readActionDescriptor: steps 1 to 4", () => {
  const good = fromHex(vectors.valid[0]!.hex);

  test("refuses more than 8,192 bytes before anything else, and anything that is not bytes", () => {
    expect(MAX_ACTION_DESCRIPTOR_BYTES).toBe(8192);
    const long = new TextEncoder().encode(JSON.stringify("x".repeat(8191)));
    expect(long.length).toBe(8193);
    expect(readActionDescriptor(long)).toBeNull();
    expect(readActionDescriptor(vectors.valid[0]!.utf8 as never)).toBeNull();
    expect(readActionDescriptor(new Uint8Array(0))).toBeNull();
  });

  test("refuses bytes that are not strict UTF-8", () => {
    const broken = new Uint8Array(good);
    broken[broken.length - 3] = 0xff;
    expect(readActionDescriptor(broken)).toBeNull();
    // "L" (0x4c) written as the overlong two-byte form 0xc1 0x8c, which strict UTF-8 refuses.
    const at = hex(good).indexOf(hex(new TextEncoder().encode('"Laptop"'))) / 2 + 1;
    const overlong = new Uint8Array([...good.subarray(0, at), 0xc1, 0x8c, ...good.subarray(at + 1)]);
    expect(readActionDescriptor(overlong)).toBeNull();
  });

  test("a descriptor read is a fresh, frozen object: changing it is impossible, and the bytes stay the source", () => {
    const d = readActionDescriptor(good)!;
    expect(Object.isFrozen(d)).toBe(true);
    expect(Object.isFrozen(d.targets)).toBe(true);
    expect(Object.isFrozen(d.targets[0])).toBe(true);
  });
});

describe("actionDescriptorFor: an ActionInput (A10) as Mail issues it", () => {
  const labels = new Map([
    [deviceA, "Laptop"],
    [deviceB, "Kitchen tablet"],
  ]);
  const issue = { mailboxId, nonce, issuedAt, labels };

  test("revoke-device and remove-devices take each device's label from Mail's records, sorted by id", () => {
    const revoke = actionDescriptorFor({ kind: "revoke-device", deviceIds: [deviceB, deviceA] }, issue);
    expect(revoke).toEqual({ version: 1, kind: "revoke-device", mailboxId, targets: [{ deviceId: deviceA, label: "Laptop" }, { deviceId: deviceB, label: "Kitchen tablet" }], nonce, issuedAt });
    const remove = actionDescriptorFor({ kind: "remove-devices", deviceIds: [], request }, issue);
    expect(remove).toEqual({ version: 1, kind: "remove-devices", mailboxId, targets: [], nonce, issuedAt, request });
  });

  test("register-device names the new device with the label from its request", () => {
    const d = actionDescriptorFor({ kind: "register-device", device: { id: deviceA, label: "New phone" }, request }, issue);
    expect(d.targets).toEqual([{ deviceId: deviceA, label: "New phone" }]);
  });

  test.each(["add-factor", "remove-factor", "open-session", "upgrade"] as const)("%s names no device and carries the request digest", (kind) => {
    expect(actionDescriptorFor({ kind, request }, issue)).toEqual({ version: 1, kind, mailboxId, targets: [], nonce, issuedAt, request });
  });

  test("the result builds: Mail's bytes and the browser's expected bytes come from one function", () => {
    const action: ActionInput = { kind: "remove-devices", deviceIds: [deviceA], request };
    const bytes = buildActionDescriptor(actionDescriptorFor(action, issue));
    expect(readActionDescriptor(bytes)!.targets).toEqual([{ deviceId: deviceA, label: "Laptop" }]);
  });

  test.each([
    ["an unknown kind", { kind: "rotate", request }],
    ["a device Mail does not hold", { kind: "revoke-device", deviceIds: [newId("dev")] }],
    ["the same device twice", { kind: "revoke-device", deviceIds: [deviceA, deviceA] }],
    ["a request on revoke-device", { kind: "revoke-device", deviceIds: [deviceA], request }],
    ["no request on remove-devices", { kind: "remove-devices", deviceIds: [deviceA] }],
    ["deviceIds on add-factor", { kind: "add-factor", deviceIds: [deviceA], request }],
    ["an extra member", { kind: "upgrade", request, extra: "x" }],
    ["a register-device whose device has an extra member", { kind: "register-device", device: { id: deviceA, label: "x", seen: "y" }, request }],
    ["deviceIds that are not an array", { kind: "revoke-device", deviceIds: deviceA }],
  ])("refuses %s with a TypeError", (_, action) => {
    expect(() => actionDescriptorFor(action as unknown as ActionInput, issue)).toThrow(TypeError);
  });
});

describe("actionPurpose and the device label rule", () => {
  test("an email code confirms revoke-device only; upgrade takes a key proof; the rest a factor proof", () => {
    expect(ACTION_KINDS).toEqual(["revoke-device", "remove-devices", "register-device", "add-factor", "remove-factor", "open-session", "upgrade"]);
    expect(ACTION_KINDS.map(actionPurpose)).toEqual(["email", "factor", "factor", "factor", "factor", "factor", "key"]);
    expect(() => actionPurpose("rotate" as ActionKind)).toThrow(TypeError);
  });

  test("a label is 1 to 40 code points with no control character, line separator or lone surrogate", () => {
    for (const ok of ["a", "Laptop", "a".repeat(39) + "🚚", "🚚".repeat(40), 'Front desk "main" \\ left', "Büro-PC (alt)"]) expect(isDeviceLabel(ok), ok).toBe(true);
    for (const bad of ["", "a".repeat(41), "🚚".repeat(41), "Lap\u0007top", "Lap\u0085top", "Lap\u007ftop", "Lap\u2028top", "Lap\u2029top", "Lap\ud800top", "Lap\udc00top", 7, null]) {
      expect(isDeviceLabel(bad), String(bad)).toBe(false);
    }
  });

  test("the digest is over the exact bytes it is given, never a re-serialization", async () => {
    const bytes = fromHex(vectors.valid[1]!.hex);
    expect(await actionDigest(bytes)).toBe(sha256b64u(bytes));
    expect(await requestDigest({ example: "the request's own canonical bytes" })).toBe(vectors.valid[6]!.object.request);
  });
});
