/**
 * The only way this Worker writes a log line. Values are ids, sizes, counts and
 * outcomes: the type admits primitives only, and callers pass nothing from a
 * message (domain-model M1, spec D8: no addresses, no subjects, no content).
 */
export type LogValue = string | number | boolean | null;

export function logEvent(event: string, fields: Record<string, LogValue> = {}): void {
  console.log(JSON.stringify({ event, ...fields }));
}

export function logAlert(kind: string, fields: Record<string, LogValue> = {}): void {
  // An operator alert: a failure that lost nothing but needs a person to look.
  console.error(JSON.stringify({ event: "operator-alert", kind, ...fields }));
}
