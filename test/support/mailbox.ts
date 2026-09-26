import { getAgentByName } from "agents";
import { runInDurableObject } from "cloudflare:test";
import { env } from "cloudflare:workers";
import type { Role } from "../../src/capability";
import type { MailboxStatus } from "../../src/directory/directory";
import type { CallContext, Mailbox } from "../../src/mailbox/mailbox";
import { base64urlFromBytes, canonicalClaims, canonicalHeader, randomJti, signToken } from "./capability-tokens";
import { type FakePorts, fakePorts } from "./fakes";
import { freshMailboxId, freshTenantId, testId } from "./ids";
import { TEST_KEY_B64URL, TEST_KID } from "./test-keys";
import { bytesFromBase64url } from "./capability-tokens";

export interface TestMailbox {
  id: string;
  tenantId: string;
  address: string;
  stub: DurableObjectStub<Mailbox>;
  ports: FakePorts;
  /** Present once a key is enrolled. */
  key?: TestKey;
}

export interface TestKey {
  keyId: string;
  publicKey: Uint8Array;
  /** Raw X25519 private key bytes, held by the TEST only: M3 scans storage for them. */
  privateKey: Uint8Array; // pragma: allowlist secret (a field name, not a value)
}

export async function insertMailboxRow(row: {
  id: string;
  tenantId: string;
  address: string;
  status: MailboxStatus;
  sesTenant?: string | null;
  sesConfigurationSet?: string | null;
}): Promise<void> {
  await env.DIRECTORY.prepare(
    "INSERT INTO mailboxes (id, tenant_id, address, status, ses_tenant, ses_configuration_set, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  )
    .bind(
      row.id,
      row.tenantId,
      row.address,
      row.status,
      row.sesTenant === undefined ? "client-test" : row.sesTenant,
      row.sesConfigurationSet === undefined ? "send-test-mail" : row.sesConfigurationSet,
      new Date().toISOString(),
    )
    .run();
}

export async function setStatus(id: string, status: MailboxStatus): Promise<void> {
  await env.DIRECTORY.prepare("UPDATE mailboxes SET status = ? WHERE id = ?").bind(status, id).run();
}

export async function directoryRow(id: string) {
  return env.DIRECTORY.prepare("SELECT * FROM mailboxes WHERE id = ?").bind(id).first<Record<string, unknown>>();
}

/** The same stub the Worker uses: through getAgentByName, so the Agent's lifecycle has started. */
export async function mailboxStub(id: string): Promise<DurableObjectStub<Mailbox>> {
  return getAgentByName(env.Mailbox, id);
}

/** Replaces the live Mailbox object's ports with fakes. The object stays in memory for the test. */
export async function injectPorts(stub: DurableObjectStub<Mailbox>, ports: FakePorts): Promise<void> {
  await runInDurableObject(stub, (instance: Mailbox) => {
    instance.ports = ports;
  });
}

export async function newKeyPair(): Promise<TestKey> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
  const publicKey = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer);
  const jwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey;
  const privateKey = bytesFromBase64url(jwk.d ?? ""); // pragma: allowlist secret (a field name, not a value)
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  const keyId = [...digest.slice(0, 16)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { keyId, publicKey, privateKey };
}

/** A recovery wrap of the right SHAPE (0x01 || iv || 48 bytes). The Worker cannot tell it from a real one, by design. */
export function recoveryWrap(keyId: string, over: Record<string, unknown> = {}) {
  const bytes = new Uint8Array(61);
  bytes[0] = 1;
  bytes.set(crypto.getRandomValues(new Uint8Array(60)), 1);
  return { id: testId("wrp"), keyId, kind: "recovery", label: "Recovery key", wrapped: base64urlFromBytes(bytes), ...over };
}

export function passkeyWrap(keyId: string, over: Record<string, unknown> = {}) {
  return { ...recoveryWrap(keyId), kind: "passkey-prf", credentialId: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(16))), label: "Phone", ...over }; // pragma: allowlist secret (a field name, not a value)
}

export function callContext(mb: TestMailbox, opts: { role?: Role; accountId?: string; status?: MailboxStatus } = {}): CallContext {
  return {
    mailbox: {
      id: mb.id,
      tenantId: mb.tenantId,
      address: mb.address,
      status: opts.status ?? "active",
      sesTenant: "client-test",
      sesConfigurationSet: "send-test-mail",
      createdAt: new Date().toISOString(),
      activatedAt: null,
      closedAt: null,
    },
    actor: { accountId: opts.accountId ?? "acc_owner", role: opts.role ?? "owner" },
  };
}

/**
 * A mailbox in the Directory, its Durable Object running with fake ports and,
 * unless `status` says otherwise, a key enrolled and the Directory row active,
 * exactly as enrolment leaves it.
 */
export async function provisionMailbox(
  opts: { status?: MailboxStatus; enroll?: boolean; sesConfigurationSet?: string | null } = {},
): Promise<TestMailbox> {
  const status = opts.status ?? "active";
  const id = freshMailboxId();
  const tenantId = freshTenantId();
  const address = `hello.${id.slice(4, 12)}@mail.test`;
  await insertMailboxRow({
    id,
    tenantId,
    address,
    status: "provisioned",
    ...(opts.sesConfigurationSet === undefined ? {} : { sesConfigurationSet: opts.sesConfigurationSet }),
  });
  const stub = await mailboxStub(id);
  const ports = fakePorts();
  await injectPorts(stub, ports);
  const mb: TestMailbox = { id, tenantId, address, stub, ports };
  if (opts.enroll ?? status !== "provisioned") {
    const key = await newKeyPair();
    await stub.enroll(callContext(mb, { status: "provisioned" }), {
      publicKey: base64urlFromBytes(key.publicKey),
      wraps: [recoveryWrap(key.keyId)],
    });
    mb.key = key;
  }
  if (status !== "provisioned") await setStatus(id, status);
  return mb;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** A capability as the dashboard would mint it (contracts/capability-v1.md), signed with the test key. */
export async function mint(opts: { tenant: string; mbx?: string; role?: Role; sub?: string; iat?: number; jti?: string }): Promise<string> {
  const claims = canonicalClaims({
    sub: opts.sub ?? "acc_owner",
    tenant: opts.tenant,
    ...(opts.mbx === undefined ? {} : { mbx: opts.mbx }),
    role: opts.role ?? "owner",
    iat: opts.iat ?? nowSeconds(),
    jti: opts.jti ?? randomJti(),
  });
  return signToken(canonicalHeader(TEST_KID), claims, bytesFromBase64url(TEST_KEY_B64URL));
}

export const capFor = (mb: TestMailbox, opts: { role?: Role; sub?: string; jti?: string } = {}) =>
  mint({ tenant: mb.tenantId, mbx: mb.id, ...opts });

/**
 * The error an RPC call rejects with. Awaited plainly on purpose: vitest's
 * `expect(p).rejects` reads properties off workerd's RPC promise, and each
 * property read on an RPC promise is itself a pipelined call that rejects too,
 * unhandled. (workerd also logs "Uncaught (in promise)" for every rejected DO
 * RPC method; that line is the runtime's, and the error still arrives intact.)
 */
export async function rejectionOf(p: PromiseLike<unknown>): Promise<Error & Record<string, unknown>> {
  try {
    await p;
  } catch (err) {
    return err as Error & Record<string, unknown>;
  }
  throw new Error("expected the call to be refused");
}
