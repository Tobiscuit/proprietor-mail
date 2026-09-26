import { describe, expect, it } from "vitest";
import { parseCapabilityKeys, verifyCapability } from "../src/capability";
import {
  canonicalClaims,
  canonicalHeader,
  flipPayloadByte,
  signToken,
  type Json,
} from "./support/capability-tokens";
import { TEST_CAPABILITY_KEYS, TEST_KEY_B64URL, TEST_KID } from "./support/test-keys";
import { bytesFromBase64url } from "./support/capability-tokens";

const NOW = 1_790_424_000; // 2026-09-26T12:00:00Z
const KEY = bytesFromBase64url(TEST_KEY_B64URL);
const keys = parseCapabilityKeys(JSON.stringify(TEST_CAPABILITY_KEYS));

function claims(over: Json = {}, lifetime = 60): Json {
  return {
    ...canonicalClaims({ sub: "acc_1", tenant: "tnt_1", mbx: "mbx_1", role: "owner", iat: NOW, jti: "jti-1", lifetime }),
    ...over,
  };
}

async function refusal(token: string, now = NOW): Promise<unknown> {
  try {
    await verifyCapability(token, keys, now);
  } catch (err) {
    return err;
  }
  throw new Error("expected the capability to be refused");
}

async function expectRefused(token: string, reason: "invalid" | "expired", now = NOW) {
  const err = (await refusal(token, now)) as Error & { reason?: string };
  expect(err.name).toBe("CapabilityRejected");
  expect(err.reason).toBe(reason);
}

describe("capability v1: verification (contracts/capability-v1.md)", () => {
  it("accepts a well-formed token and returns exactly its claims", async () => {
    const token = await signToken(canonicalHeader(TEST_KID), claims(), KEY);
    expect(await verifyCapability(token, keys, NOW)).toEqual({
      iss: "platform-dashboard",
      aud: "platform-mail",
      sub: "acc_1",
      tenant: "tnt_1",
      mbx: "mbx_1",
      role: "owner",
      iat: NOW,
      exp: NOW + 60,
      jti: "jti-1",
    });
  });

  it("accepts a token without `mbx` (only mailboxes() takes one)", async () => {
    const { mbx: _mbx, ...rest } = claims();
    const token = await signToken(canonicalHeader(TEST_KID), rest, KEY);
    const cap = await verifyCapability(token, keys, NOW);
    expect(cap.mbx).toBeUndefined();
  });

  // Rule 1: the header's alg is HS256, checked before any key is looked up.
  it("rule 1: refuses alg none", async () => {
    await expectRefused(await signToken(canonicalHeader(TEST_KID, "none"), claims(), KEY), "invalid");
  });
  it("rule 1: refuses every other algorithm, even with the right key", async () => {
    await expectRefused(await signToken(canonicalHeader(TEST_KID, "HS512"), claims(), KEY), "invalid");
    await expectRefused(await signToken(canonicalHeader(TEST_KID, "HS384"), claims(), KEY), "invalid");
  });

  // Rule 2: kid names a configured key.
  it("rule 2: refuses an unknown kid", async () => {
    await expectRefused(await signToken(canonicalHeader("2026-01-z"), claims(), KEY), "invalid");
  });
  it("rule 2: refuses a token with no kid", async () => {
    await expectRefused(await signToken({ alg: "HS256", typ: "JWT" }, claims(), KEY), "invalid");
  });

  // Rule 3: the signature verifies.
  it("rule 3: refuses one flipped payload byte", async () => {
    const good = await signToken(canonicalHeader(TEST_KID), claims(), KEY);
    await expectRefused(flipPayloadByte(good, 20), "invalid");
  });
  it("rule 3: refuses a token signed with another key", async () => {
    const other = crypto.getRandomValues(new Uint8Array(32));
    await expectRefused(await signToken(canonicalHeader(TEST_KID), claims(), other), "invalid");
  });
  it("rule 3: refuses garbage", async () => {
    await expectRefused("not.a.token", "invalid");
    await expectRefused("", "invalid");
  });

  // Rule 4: iss and aud exactly.
  it("rule 4: refuses a wrong aud, a wrong iss, and an aud array", async () => {
    await expectRefused(await signToken(canonicalHeader(TEST_KID), claims({ aud: "platform-dashboard" }), KEY), "invalid");
    await expectRefused(await signToken(canonicalHeader(TEST_KID), claims({ iss: "platform-mail" }), KEY), "invalid");
    await expectRefused(
      await signToken(canonicalHeader(TEST_KID), claims({ aud: ["platform-mail", "elsewhere"] }), KEY),
      "invalid",
    );
  });

  // Rule 5: the clock.
  it("rule 5: refuses a lifetime of 61 seconds, and of 0", async () => {
    await expectRefused(await signToken(canonicalHeader(TEST_KID), claims({}, 61), KEY), "invalid");
    await expectRefused(await signToken(canonicalHeader(TEST_KID), claims({}, 0), KEY), "invalid");
  });
  it("rule 5: accepts up to 5 seconds past exp, refuses 6 as expired", async () => {
    const token = await signToken(canonicalHeader(TEST_KID), claims(), KEY);
    await expect(verifyCapability(token, keys, NOW + 60 + 4)).resolves.toBeTruthy();
    await expectRefused(token, "expired", NOW + 60 + 6);
  });
  it("rule 5: accepts iat 5 seconds in the future, refuses 6", async () => {
    await expect(
      verifyCapability(await signToken(canonicalHeader(TEST_KID), claims({ iat: NOW + 5, exp: NOW + 65 }), KEY), keys, NOW),
    ).resolves.toBeTruthy();
    await expectRefused(await signToken(canonicalHeader(TEST_KID), claims({ iat: NOW + 6, exp: NOW + 66 }), KEY), "invalid");
  });

  // Rule 6: the identity claims, and jti (required since the 2026-09-26 amendment).
  it.each([
    ["a missing tenant", { tenant: undefined }],
    ["an empty tenant", { tenant: "" }],
    ["a missing sub", { sub: undefined }],
    ["an empty sub", { sub: "" }],
    ["a role outside the two", { role: "admin" }],
    ["a missing jti", { jti: undefined }],
    ["an empty jti", { jti: "" }],
    ["an empty mbx", { mbx: "" }],
    ["a numeric tenant", { tenant: 7 }],
  ])("rule 6: refuses %s", async (_what, over) => {
    const c = claims(over);
    for (const [k, v] of Object.entries(c)) if (v === undefined) delete c[k];
    await expectRefused(await signToken(canonicalHeader(TEST_KID), c, KEY), "invalid");
  });

  it("says only `invalid` or `expired`, never why in more detail", async () => {
    const err = (await refusal(await signToken(canonicalHeader(TEST_KID), claims({ aud: "x" }), KEY))) as Error;
    expect(err.message).toBe("capability rejected: invalid");
    expect(Object.keys(err).sort()).toEqual(["name", "reason"]);
  });
});

describe("MAIL_CAPABILITY_KEYS", () => {
  it("parses the contract's JSON map of kid → base64url 32-byte key", () => {
    expect([...keys.keys()]).toEqual([TEST_KID]);
    expect(keys.get(TEST_KID)).toEqual(KEY);
  });

  it("fails closed: malformed JSON, or a key that is not 32 bytes, yields no usable key", async () => {
    expect(parseCapabilityKeys("not json").size).toBe(0);
    expect(parseCapabilityKeys(undefined).size).toBe(0);
    expect(parseCapabilityKeys(JSON.stringify({ short: "AAEC" })).size).toBe(0);
    const token = await signToken(canonicalHeader(TEST_KID), claims(), KEY);
    await expect(verifyCapability(token, parseCapabilityKeys("[]"), NOW)).rejects.toMatchObject({
      name: "CapabilityRejected",
      reason: "invalid",
    });
  });
});
