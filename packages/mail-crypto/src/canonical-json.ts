/**
 * RFC 8785, the JSON Canonicalization Scheme, for the values action
 * descriptors and requests hold (contracts/action-descriptor-v1.md "Format",
 * contracts/device-v1.md A10): plain objects, arrays, strings, safe integers
 * and null. Everything else is refused with a TypeError, so no value reaches
 * the bytes in a form two implementations could write differently:
 *
 *   - members sorted by their names' UTF-16 code units (RFC 8785 §3.2.3), which
 *     is what Array.prototype.sort does with no comparator; never the engine's
 *     own property order, which puts integer-like names first;
 *   - no whitespace (§3.2.1);
 *   - strings as ECMAScript's JSON.stringify writes them (§3.2.2.2): only `"`,
 *     `\` and U+0000 to U+001F are escaped; a lone surrogate is refused;
 *   - numbers only as safe integers, which ECMAScript writes as plain decimal
 *     digits (§3.2.2.3 for the rest is not needed and not implemented);
 *   - true and false are refused: nothing here holds them.
 *
 * Written here rather than taken from a package: the package has no runtime
 * dependency beyond @hpke, and the restricted form is a few lines. The
 * vectors were made by this rule and by the `canonicalize` package together.
 */
import { base64url, utf8 } from "./bytes";

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** A value this serializer writes. */
export type CanonicalValue = string | number | null | readonly CanonicalValue[] | { readonly [member: string]: CanonicalValue };

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === Object.prototype || proto === null;
}

function string(value: string): string {
  if (LONE_SURROGATE.test(value)) throw new TypeError("RFC 8785 refuses a lone surrogate");
  return JSON.stringify(value);
}

function serialize(value: unknown, integers: boolean, open: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "string") return string(value);
  if (typeof value === "number") {
    if (!integers) throw new TypeError("a request holds no numbers (contracts/device-v1.md A10)");
    if (!Number.isSafeInteger(value)) throw new TypeError("only safe integers are serialized here");
    return JSON.stringify(value); // -0 is written as 0, as RFC 8785 requires
  }
  if (typeof value !== "object") throw new TypeError(`RFC 8785 here takes no ${typeof value}`);
  if (open.has(value)) throw new TypeError("a cycle cannot be serialized");
  open.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) throw new TypeError("only plain arrays are serialized");
      const parts: string[] = [];
      for (let i = 0; i < value.length; i++) {
        if (!Object.hasOwn(value, i)) throw new TypeError("an array with a hole cannot be serialized");
        parts.push(serialize(value[i], integers, open));
      }
      return `[${parts.join(",")}]`;
    }
    if (!isPlainObject(value)) throw new TypeError("only plain objects are serialized");
    const record = value as Record<string, unknown>;
    const names = Object.keys(record).sort();
    return `{${names.map((name) => `${string(name)}:${serialize(record[name], integers, open)}`).join(",")}}`;
  } finally {
    open.delete(value);
  }
}

/** The RFC 8785 serialization of `value` (plain objects, arrays, strings, safe integers, null). */
export function canonicalJson(value: unknown): string {
  return serialize(value, true, new Set());
}

/**
 * A10: base64url (no padding) of SHA-256 over the RFC 8785 serialization of a
 * request, exactly as the call sends it. A request is an object that holds
 * only strings, null, arrays and objects; anything else is a TypeError.
 */
export async function requestDigest(request: { readonly [member: string]: unknown }): Promise<string> {
  if (typeof request !== "object" || request === null || Array.isArray(request)) throw new TypeError("a request is a JSON object");
  const bytes = utf8(serialize(request, false, new Set()));
  return base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}
