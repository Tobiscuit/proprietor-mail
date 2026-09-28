/**
 * The fixed capability key used by the tests and by
 * contracts/capability-v1.vectors.json. Test-only: 32 sequential bytes
 * (0x00..0x1f), chosen to be recognisable as a test key at a glance. It is not,
 * and must never become, a key any deployed Worker holds.
 */
export const TEST_KID = "test-2026-09";

// base64url of the bytes 0x00, 0x01, ... 0x1f.
export const TEST_KEY_B64URL = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"; // pragma: allowlist secret

export const TEST_CAPABILITY_KEYS: Record<string, string> = { [TEST_KID]: TEST_KEY_B64URL };
