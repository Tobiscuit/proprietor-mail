// Round 3, contracts/device-v1.md A11: the factor graph (K2″, K3′), as pure functions over a
// view-like input. Nodes: every factor record, removed ones included. An edge joins a factor and
// its admitter when the admission's signature verifies with the admitter's listed signing key, its
// selfSignature with the factor's own, and the admitter key inside the statement is the admitter's
// listed one. Trusted factors: the connected component of the start (a factor signing key).
// Trusted recipients: a device admitted by a trusted factor whose unlock key (while it has one) its
// own key signed; a factor that is trusted, keyed and not removed. Trusted transitions: signed by a
// trusted factor, removed or not. Bootstrap: sorted by id, each admitted by the next, the last by
// the first, a single factor by itself.
import { describe, expect, test } from "vitest";
import {
  bootstrapAdmitters,
  deriveFactorKey,
  factorPublicKey,
  factorSigningKey,
  generateMailboxKey,
  generateSigningKey,
  generateUnlockKey,
  isFactorRecipient,
  isTrustedDevice,
  isTrustedTransition,
  newId,
  signStatement,
  trustedFactors,
  type FactorPrivateKey,
  type GraphDevice,
  type GraphFactor,
  type WrapKind,
} from "../src/index";
import { factorMaterialOf } from "../src/factor-keys";
import { statementMessage } from "../src/statements";
import { b64urlEncode } from "./reference";

const mailboxId = newId("mbx");
const b64 = (bytes: Uint8Array) => b64urlEncode(bytes);
const secret = () => crypto.getRandomValues(new Uint8Array(32)); // pragma: allowlist secret (random test values)

async function factor(kind: WrapKind) {
  const id = newId("wrp");
  return deriveFactorKey({ mailboxId, factorId: id, kind, secret: secret() }); // pragma: allowlist secret (public test keys, random test values)
}

/** A factor's record as Mail lists it, admitted by `admitter` (A11), every key base64url. */
async function record(f: FactorPrivateKey, admitter: FactorPrivateKey, label = f.kind === "recovery" ? "Recovery key" : "Phone"): Promise<GraphFactor> {
  const credentialId = f.kind === "passkey-prf" ? b64(crypto.getRandomValues(new Uint8Array(16))) : null;
  const statement = {
    kind: "admit-factor" as const,
    mailboxId,
    factorId: f.factorId,
    factorKind: f.kind,
    label,
    factorKey: factorPublicKey(f),
    signingKey: factorSigningKey(f), // pragma: allowlist secret (a public key)
    credentialId,
    admitterId: admitter.factorId,
    admitterSigningKey: factorSigningKey(admitter), // pragma: allowlist secret (public test keys, random test values)
  };
  return {
    id: f.factorId,
    kind: f.kind,
    label,
    credentialId,
    factorKey: b64(factorPublicKey(f)),
    signingKey: b64(factorSigningKey(f)), // pragma: allowlist secret (a public key)
    admission: { by: admitter.factorId, signature: await signStatement(admitter, statement), selfSignature: await signStatement(f, statement) },
  };
}

/** A kept device as Mail lists it, admitted by `admitter`, with or without an unlock key. */
async function deviceRecord(admitter: FactorPrivateKey, withUnlockKey: boolean, label = "Kitchen laptop"): Promise<GraphDevice & { signer: CryptoKey }> {
  const id = newId("dev");
  const signing = await generateSigningKey();
  const unlock = withUnlockKey ? await generateUnlockKey() : null;
  return {
    id,
    label,
    signingKey: b64(signing.publicKey), // pragma: allowlist secret (a public key)
    unlockKey: unlock === null ? null : b64(unlock.publicKey),
    unlockSignature: unlock === null ? null : await signStatement(signing.privateKey, { kind: "unlock-key", mailboxId, deviceId: id, unlockKey: unlock.publicKey }),
    admission: { by: admitter.factorId, signature: await signStatement(admitter, { kind: "admit-device", mailboxId, deviceId: id, label, signingKey: signing.publicKey, admitterId: admitter.factorId }) }, // pragma: allowlist secret (public test keys, random test values)
    signer: signing.privateKey,
  };
}

// The mailbox: a passkey P and the recovery key R enrolled together (A11's cycle), a later passkey N
// admitted by P, a device D1 admitted by R that keeps an unlock key, a device D2 admitted by N that
// keeps none, and an outsider Z that admits itself but is joined to nothing.
const P = await factor("passkey-prf");
const R = await factor("recovery");
const N = await factor("passkey-prf");
const Z = await factor("recovery");
const cycle = bootstrapAdmitters([P.factorId, R.factorId]);
const byId = new Map([P, R, N, Z].map((f) => [f.factorId, f]));
const recordP = await record(P, byId.get(cycle.find((c) => c.factorId === P.factorId)!.admitterId)!);
const recordR = await record(R, byId.get(cycle.find((c) => c.factorId === R.factorId)!.admitterId)!);
const recordN = await record(N, P);
const recordZ = await record(Z, Z);
const D1 = await deviceRecord(R, true);
const D2 = await deviceRecord(N, false);
const view = deepFreeze({ id: mailboxId, wraps: [recordP, recordR, recordN], removedFactors: [] as GraphFactor[] });
const vS = (f: FactorPrivateKey) => factorSigningKey(f);

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null) {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

describe("A11 bootstrapAdmitters", () => {
  test("sorted by id (UTF-16 code units), each admitted by the next, the last by the first", () => {
    expect(bootstrapAdmitters(["wrp_c", "wrp_a", "wrp_b"])).toEqual([
      { factorId: "wrp_a", admitterId: "wrp_b" },
      { factorId: "wrp_b", admitterId: "wrp_c" },
      { factorId: "wrp_c", admitterId: "wrp_a" },
    ]);
    expect(bootstrapAdmitters(["b", "B", "a"]).map((c) => c.factorId)).toEqual(["B", "a", "b"]);
  });

  test("a single factor admits itself", () => {
    expect(bootstrapAdmitters(["wrp_a"])).toEqual([{ factorId: "wrp_a", admitterId: "wrp_a" }]);
  });

  test("refuses no factors, the same id twice, and an id that is not a string", () => {
    expect(() => bootstrapAdmitters([])).toThrow(TypeError);
    expect(() => bootstrapAdmitters(["wrp_a", "wrp_a"])).toThrow(TypeError);
    expect(() => bootstrapAdmitters(["wrp_a", 7 as unknown as string])).toThrow(TypeError);
  });
});

describe("A11's node rule (clarified 2026-10-22)", () => {
  test("a record is a node only when its own admission verifies and its id is listed once; the start nodes are the nodes whose signing key is the start key", async () => {
    // M is admitted by N, N by P. N's own admission is broken (its selfSignature is another record's).
    // M's admission by N still verifies with N's listed key, but N is no node, so the edge M-N does
    // not count: neither N nor M joins P's component, and N's factor key is never trusted.
    const M = await factor("recovery");
    const recordM = await record(M, N);
    const brokenN = { ...recordN, admission: { ...recordN.admission!, selfSignature: recordR.admission!.selfSignature } };
    const withBroken = { ...view, wraps: [recordP, recordR, brokenN, recordM] };
    expect([...(await trustedFactors(withBroken, vS(P))).ids].sort()).toEqual([P.factorId, R.factorId].sort());
    // From M's own key, M is a start node and a component of its own: N is no node, so nothing joins it.
    expect((await trustedFactors(withBroken, vS(M))).ids).toEqual([M.factorId]);
    // From N's key: N lists that key but is no node, so it is no start and nothing is trusted.
    expect((await trustedFactors(withBroken, vS(N))).ids).toEqual([]);
    // With N's admission intact, all four are one component.
    expect([...(await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, recordM] }, vS(P))).ids].sort()).toEqual([P.factorId, R.factorId, N.factorId, M.factorId].sort());
    // An id listed twice (once in wraps, once in removedFactors, both genuine) is no node.
    expect((await trustedFactors({ ...view, wraps: [recordP, recordR, recordN], removedFactors: [recordN] }, vS(P))).ids).not.toContain(N.factorId);
  });
});

describe("A11 trustedFactors: the connected component of the start", () => {
  test("from any of the three factors, all three are trusted: the cycle joins P and R, N's admission joins it to P", async () => {
    for (const start of [P, R, N]) {
      const trusted = await trustedFactors(view, vS(start));
      expect(trusted.mailboxId).toBe(mailboxId);
      expect([...trusted.ids].sort()).toEqual([P.factorId, R.factorId, N.factorId].sort());
    }
  });

  test("the start may be given as base64url, as the view lists it", async () => {
    expect((await trustedFactors(view, recordR.signingKey!)).ids.length).toBe(3);
  });

  test("a later factor is connected through its admission (N, admitted by P, is trusted from R)", async () => {
    expect((await trustedFactors(view, vS(R))).ids).toContain(N.factorId);
  });

  test("an admission whose self-signature fails is no edge: N is not trusted", async () => {
    const forged = { ...recordN, admission: { ...recordN.admission!, selfSignature: recordP.admission!.selfSignature } };
    expect((await trustedFactors({ ...view, wraps: [recordP, recordR, forged] }, vS(R))).ids).not.toContain(N.factorId);
  });

  test("a changed factor key breaks its own admission: that factor is not trusted (and nothing is sealed to the new key)", async () => {
    const swapped = { ...recordN, factorKey: b64(factorPublicKey(Z)) };
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordR, swapped] }, vS(R));
    expect(trusted.ids).not.toContain(N.factorId);
    expect(isFactorRecipient(trusted, N.factorId)).toBe(false);
  });

  test("an admission whose admitter key fails is no edge: signed for another admitter key than the listed one", async () => {
    // X claims P as its admitter, but the statement carries Z's signing key and Z signed it.
    const X = await factor("passkey-prf");
    const statement = {
      kind: "admit-factor" as const,
      mailboxId,
      factorId: X.factorId,
      factorKind: X.kind,
      label: "Phone",
      factorKey: factorPublicKey(X),
      signingKey: vS(X), // pragma: allowlist secret (a public key)
      credentialId: null,
      admitterId: P.factorId,
      admitterSigningKey: vS(Z),
    };
    const planted: GraphFactor = {
      id: X.factorId,
      kind: X.kind,
      label: "Phone",
      credentialId: null,
      factorKey: b64(factorPublicKey(X)),
      signingKey: b64(vS(X)), // pragma: allowlist secret (a public key)
      admission: { by: P.factorId, signature: await signStatement(Z, { ...statement, admitterId: Z.factorId }), selfSignature: await signStatement(X, statement) },
    };
    expect((await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, recordZ, planted] }, vS(P))).ids).not.toContain(X.factorId);
  });

  test("a factor that admits itself but is joined to nothing is not trusted", async () => {
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, recordZ] }, vS(P));
    expect(trusted.ids).not.toContain(Z.factorId);
    expect((await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, recordZ] }, vS(Z))).ids).toEqual([Z.factorId]);
  });

  test("removed factors are nodes: R removed still joins P and N, and stays trusted", async () => {
    const removed = { ...view, wraps: [recordP, recordN], removedFactors: [recordR] };
    expect([...(await trustedFactors(removed, vS(P))).ids].sort()).toEqual([P.factorId, R.factorId, N.factorId].sort());
    // Through R alone: N joins only through P, and P through the cycle with R.
    expect([...(await trustedFactors(removed, vS(R))).ids].sort()).toEqual([P.factorId, R.factorId, N.factorId].sort());
  });

  test("a record that copies a trusted factor's signing key, with another id and factor key, is never a start and never trusted", async () => {
    const copy: GraphFactor = { ...recordN, id: newId("wrp"), factorKey: b64(factorPublicKey(Z)) };
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, copy] }, vS(N));
    expect(trusted.ids).not.toContain(copy.id);
    expect(trusted.ids).toContain(N.factorId);
  });

  test("a factor id listed twice is no node at all (a view that lists one factor two ways is not believed)", async () => {
    const twice = { ...view, wraps: [recordP, recordR, recordN], removedFactors: [{ ...recordN, factorKey: b64(factorPublicKey(Z)) }] };
    const trusted = await trustedFactors(twice, vS(P));
    expect(trusted.ids).not.toContain(N.factorId);
    expect(trusted.ids).toContain(R.factorId);
  });

  test("a start that is no node trusts nothing: unknown, or its own admission fails", async () => {
    expect((await trustedFactors(view, vS(Z))).ids).toEqual([]);
    const broken = { ...recordP, label: "Phone (renamed by someone)" };
    expect((await trustedFactors({ ...view, wraps: [broken, recordR, recordN] }, vS(P))).ids).toEqual([]);
  });

  test("a legacy record (no signing key or admission yet) is no node, and malformed entries are skipped, never thrown on", async () => {
    const legacy: GraphFactor = { id: newId("wrp"), kind: "recovery", label: "Recovery key", credentialId: null, factorKey: null };
    const garbage = { id: 7, kind: "x", label: null, credentialId: 3, signingKey: "*", admission: { by: 1 } } as unknown as GraphFactor;
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, legacy, garbage] }, vS(P));
    expect([...trusted.ids].sort()).toEqual([P.factorId, R.factorId, N.factorId].sort());
    expect((await trustedFactors({ id: mailboxId, wraps: [] }, vS(P))).ids).toEqual([]);
  });

  test("bound to the mailbox: the same records under another mailbox id verify nothing", async () => {
    expect((await trustedFactors({ ...view, id: newId("mbx") }, vS(P))).ids).toEqual([]);
  });

  test("refuses a start that is not a 32-byte Ed25519 key (TypeError: a caller's mistake)", async () => {
    await expect(trustedFactors(view, new Uint8Array(65))).rejects.toBeInstanceOf(TypeError);
    await expect(trustedFactors(view, new Uint8Array(31))).rejects.toBeInstanceOf(TypeError);
    await expect(trustedFactors(view, "*")).rejects.toBeInstanceOf(TypeError);
  });

  test("the result is an opaque, frozen handle: a forged or edited one is refused", async () => {
    const trusted = await trustedFactors(view, vS(P));
    expect(Object.isFrozen(trusted)).toBe(true);
    expect(Object.isFrozen(trusted.ids)).toBe(true);
    expect(() => isFactorRecipient({ mailboxId, ids: [Z.factorId] }, Z.factorId)).toThrow(TypeError);
  });
});

describe("A11 trusted recipients", () => {
  test("a factor is a recipient when it is trusted, keyed and not removed", async () => {
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordN, recordZ], removedFactors: [recordR] }, vS(P));
    expect(isFactorRecipient(trusted, P.factorId)).toBe(true);
    expect(isFactorRecipient(trusted, N.factorId)).toBe(true);
    expect(isFactorRecipient(trusted, R.factorId)).toBe(false); // removed
    expect(isFactorRecipient(trusted, Z.factorId)).toBe(false); // not trusted
    expect(isFactorRecipient(trusted, newId("wrp"))).toBe(false);
  });

  test("a device is trusted when a trusted factor admitted it and, while it has an unlock key, it signed that key", async () => {
    const trusted = await trustedFactors(view, vS(P));
    expect(await isTrustedDevice(trusted, D1)).toBe(true);
    expect(await isTrustedDevice(trusted, D2)).toBe(true);
  });

  test("a device admitted by a removed factor stays trusted", async () => {
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordN], removedFactors: [recordR] }, vS(P));
    expect(await isTrustedDevice(trusted, D1)).toBe(true);
  });

  test("a planted device with a genuine-looking admission by a factor outside the graph is not trusted", async () => {
    const planted = await deviceRecord(Z, true);
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, recordZ] }, vS(P));
    expect(await isTrustedDevice(trusted, planted)).toBe(false);
  });

  test.each([
    ["no admission", { admission: null }],
    ["an admission naming another trusted factor than the one that signed", { admission: { by: P.factorId, signature: D1.admission!.signature } }],
    ["a changed label", { label: "Kitchen laptop (2)" }],
    ["a changed signing key", { signingKey: D2.signingKey }], // pragma: allowlist secret (public test keys, random test values)
    ["an unlock key its own key did not sign", { unlockSignature: null }],
    ["an unlock key signed by another device", { unlockSignature: "SIGNED_ELSEWHERE" }],
    ["a changed unlock key", { unlockKey: "OTHER_UNLOCK_KEY" }],
  ])("a device with %s is not trusted", async (_, change) => {
    const trusted = await trustedFactors(view, vS(P));
    const other = await deviceRecord(R, true);
    const replacements: Record<string, string | null> = { SIGNED_ELSEWHERE: other.unlockSignature!, OTHER_UNLOCK_KEY: other.unlockKey };
    const changed = Object.fromEntries(Object.entries(change).map(([k, v]) => [k, typeof v === "string" && v in replacements ? replacements[v] : v]));
    expect(await isTrustedDevice(trusted, { ...D1, ...changed } as GraphDevice)).toBe(false);
  });

  test("a device without an unlock key carries no unlock signature; one that does is malformed", async () => {
    const trusted = await trustedFactors(view, vS(P));
    expect(await isTrustedDevice(trusted, { ...D2, unlockSignature: D1.unlockSignature })).toBe(false);
  });

  test("a malformed device is not trusted, never thrown on", async () => {
    const trusted = await trustedFactors(view, vS(P));
    for (const bad of [null, {}, { ...D1, id: 5 }, { ...D1, signingKey: "*" }, { ...D1, admission: { by: P.factorId } }]) {
      expect(await isTrustedDevice(trusted, bad as unknown as GraphDevice)).toBe(false);
    }
  });
});

const [k1, k2] = (await Promise.all([generateMailboxKey(), generateMailboxKey()])).map((k) => k.publicKey);

describe("A11 trusted transitions", () => {
  async function step(signer: FactorPrivateKey, signedBy = signer.factorId) {
    const signature = await signStatement(signer, { kind: "transition", mailboxId, fromKeyId: k1!.keyId, toKeyId: k2!.keyId, toPublicKey: k2!.publicKey, signerId: signer.factorId });
    return { fromKeyId: k1!.keyId, toKeyId: k2!.keyId, toPublicKey: b64(k2!.publicKey), signedBy, signature };
  }

  test("a transition signed by a trusted factor is trusted, removed or not", async () => {
    expect(await isTrustedTransition(await trustedFactors(view, vS(P)), await step(N))).toBe(true);
    const removed = await trustedFactors({ ...view, wraps: [recordP, recordN], removedFactors: [recordR] }, vS(P));
    expect(await isTrustedTransition(removed, await step(R))).toBe(true);
  });

  test("a transition signed by a factor outside the component is refused, though its signature is genuine", async () => {
    const trusted = await trustedFactors({ ...view, wraps: [recordP, recordR, recordN, recordZ] }, vS(P));
    expect(await isTrustedTransition(trusted, await step(Z))).toBe(false);
  });

  test("a transition that names a trusted factor but was signed by another key is refused", async () => {
    const trusted = await trustedFactors(view, vS(P));
    const byZ = await step(Z);
    expect(await isTrustedTransition(trusted, { ...byZ, signedBy: P.factorId })).toBe(false);
  });

  test("a changed from, to or public key, or a public key that is not the toKeyId's, is refused", async () => {
    const trusted = await trustedFactors(view, vS(P));
    const good = await step(P);
    const k3 = (await generateMailboxKey()).publicKey;
    for (const changed of [
      { ...good, fromKeyId: k3.keyId },
      { ...good, toKeyId: k3.keyId },
      { ...good, toPublicKey: b64(k3.publicKey) },
      { ...good, toKeyId: k3.keyId, toPublicKey: b64(k3.publicKey) },
    ]) {
      expect(await isTrustedTransition(trusted, changed)).toBe(false);
    }
  });

  test("a transition whose public key is not its toKeyId's is refused even when a trusted factor signed exactly that", async () => {
    // signStatement refuses to sign such a statement; sign its message with the factor's key directly.
    const k3 = (await generateMailboxKey()).publicKey;
    const message = statementMessage({ kind: "transition", mailboxId, fromKeyId: k1!.keyId, toKeyId: k2!.keyId, toPublicKey: k3.publicKey, signerId: P.factorId });
    const signature = b64(new Uint8Array(await crypto.subtle.sign("Ed25519", factorMaterialOf(P).signingKey, message)));
    const trusted = await trustedFactors(view, vS(P));
    expect(await isTrustedTransition(trusted, { fromKeyId: k1!.keyId, toKeyId: k2!.keyId, toPublicKey: b64(k3.publicKey), signedBy: P.factorId, signature })).toBe(false);
  });

  test("a step without a transition (a successor seal alone) or a malformed one is refused, never thrown on", async () => {
    const trusted = await trustedFactors(view, vS(P));
    const good = await step(P);
    for (const bad of [null, {}, { ...good, signature: null }, { ...good, signedBy: undefined }, { ...good, toPublicKey: "*" }]) {
      expect(await isTrustedTransition(trusted, bad as never)).toBe(false);
    }
  });
});
