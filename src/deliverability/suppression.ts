/**
 * How a mailbox remembers a suppressed recipient (domain-model M11, spec D15):
 * never the address, only HMAC-SHA-256 of its lower-cased form under a random
 * 32-byte key the mailbox keeps for itself. The key is per mailbox, so the
 * same address hashes differently in every mailbox and no table joins across
 * them; the hash is keyed, so a list of addresses cannot be tried against the
 * table without the key.
 */

export const SUPPRESSION_KEY_BYTES = 32;

export function newSuppressionKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(SUPPRESSION_KEY_BYTES));
}

/** Lower-case hex of HMAC-SHA-256(key, utf8(trimmed, lower-cased address)). */
export async function hashRecipient(key: Uint8Array, address: string): Promise<string> {
  const hmacKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(address.trim().toLowerCase())));
  return [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
}
