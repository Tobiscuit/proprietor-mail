import { describe, expect, it } from "vitest";
import committed from "../contracts/capability-v1.vectors.json?raw";
import { parseCapabilityKeys, verifyCapability } from "../src/capability";
import { buildCapabilityVectors, renderCapabilityVectors } from "./support/capability-vectors";

// contracts/capability-v1.vectors.json: "Both repositories run the same
// vectors: the dashboard proves it mints what Mail accepts, and Mail proves it
// refuses what it must."
const vectors = JSON.parse(committed) as Awaited<ReturnType<typeof buildCapabilityVectors>>;
const keys = parseCapabilityKeys(JSON.stringify(vectors.keys));

describe("contracts/capability-v1.vectors.json", () => {
  it("is exactly what the deterministic builder produces (regenerate with scripts/generate-capability-vectors.ts)", async () => {
    expect(committed).toBe(renderCapabilityVectors(await buildCapabilityVectors()));
  });

  it("covers every refused case the contract lists, plus the missing jti", () => {
    const names = vectors.refused.map((v) => v.name);
    for (const required of [
      "alg-none",
      "wrong-aud",
      "wrong-iss",
      "lifetime-61",
      "expired-by-6s",
      "iat-6s-in-future",
      "unknown-kid",
      "flipped-payload-byte",
      "missing-tenant",
      "missing-jti",
    ]) {
      expect(names).toContain(required);
    }
  });

  it("the valid token verifies at `now` and decodes to exactly the listed claims", async () => {
    const cap = await verifyCapability(vectors.valid.canonicalToken, keys, vectors.now);
    expect(cap).toEqual(vectors.valid.claims);
    // The canonical serialization's order (contract amendment, 2026-09-26).
    expect(Object.keys(vectors.valid.claims)).toEqual(["iss", "aud", "sub", "tenant", "mbx", "role", "iat", "exp", "jti"]);
    expect(Object.keys(vectors.valid.header)).toEqual(["alg", "typ", "kid"]);
    expect((vectors.valid.claims.exp as number) - (vectors.valid.claims.iat as number)).toBe(60);
  });

  for (const v of vectors.refused) {
    it(`refuses ${v.name} (rule ${v.rule}: ${v.breaks}) as ${v.reason}`, async () => {
      await expect(verifyCapability(v.token, keys, vectors.now)).rejects.toMatchObject({
        name: "CapabilityRejected",
        reason: v.reason,
      });
    });
  }
});
