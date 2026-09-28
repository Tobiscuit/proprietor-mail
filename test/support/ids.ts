/**
 * Test-side ids in the contract's shape (contracts/envelope-v1.md,
 * "Identifiers"): `<prefix>_<26 lowercase Crockford base32 characters of 16
 * random bytes>`. The Worker's production ids come from `newId` in
 * @proprietor/mail-crypto (slice S1); tests make their own so they never depend
 * on that stub.
 */
const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

export function testId(prefix: "mbx" | "msg" | "drf" | "wrp"): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return `${prefix}_${out}`;
}

export const freshMailboxId = () => testId("mbx");

export function freshBusinessId(): string {
  return `biz_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}
