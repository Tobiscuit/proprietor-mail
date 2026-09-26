import { beforeAll, describe, expect, it } from "vitest";
import { buildMime, sesRawMailer, type ComposedMessage, type RawMailer } from "../src/index";
import { ALTERNATIVE, MIXED, TEXT_ONLY } from "./fixtures";

/**
 * Live check against Amazon SES, and only against its mailbox simulator.
 *
 * Skipped unless SES_TEST_ACCESS_KEY_ID, SES_TEST_SECRET_ACCESS_KEY,
 * SES_TEST_FROM and SES_TEST_CONFIGURATION_SET are set. Optional:
 * SES_TEST_SESSION_TOKEN, SES_TEST_REGION (default us-east-1), SES_TEST_TENANT.
 * Read the client-mail principal's credential from Vault into the environment
 * of this one command; never into a file:
 *
 *   SES_TEST_ACCESS_KEY_ID=… SES_TEST_SECRET_ACCESS_KEY=… \
 *   SES_TEST_FROM=hello@operator.example SES_TEST_CONFIGURATION_SET=send-operator-mail \
 *   npm test -w @platform-mail/outbound -- test/ses.live.test.ts
 *
 * Do not run it with the SEO engine's notification credential: that
 * principal's events feed the engine's production database.
 */

const env = process.env;
const LIVE = Boolean(env.SES_TEST_ACCESS_KEY_ID && env.SES_TEST_SECRET_ACCESS_KEY && env.SES_TEST_FROM && env.SES_TEST_CONFIGURATION_SET);

// "Using the mailbox simulator": https://docs.aws.amazon.com/ses/latest/dg/send-an-email-from-console.html
const SUCCESS = "success@simulator.amazonses.com";
const BOUNCE = "bounce@simulator.amazonses.com";
const COMPLAINT = "complaint@simulator.amazonses.com";

/** Every recipient must be a simulator address; anything else throws before a request is made. */
export function assertSimulatorOnly(recipients: readonly string[]): void {
  if (recipients.length === 0) throw new Error("live SES test: no recipients");
  for (const r of recipients) {
    if (!/^[a-z0-9+._-]+@simulator\.amazonses\.com$/.test(r)) {
      throw new Error("live SES test: refusing to send to an address outside the SES mailbox simulator");
    }
  }
}

describe("assertSimulatorOnly", () => {
  it("lets only simulator addresses through", () => {
    expect(() => assertSimulatorOnly([SUCCESS, BOUNCE, COMPLAINT])).not.toThrow();
    for (const bad of [[], ["ana@example.com"], [SUCCESS, "x@simulator.amazonses.com.evil.example"], ["success@SIMULATOR.amazonses.com.example"]]) {
      expect(() => assertSimulatorOnly(bad)).toThrow();
    }
  });
});

describe.skipIf(!LIVE)("SES live, mailbox simulator only", () => {
  // Built in beforeAll, not while the suite is collected: a skipped suite's
  // body still runs, and without credentials the constructor would throw.
  let from: string;
  let mailer: RawMailer;
  beforeAll(() => {
    from = env.SES_TEST_FROM!;
    const accessKeyId = env.SES_TEST_ACCESS_KEY_ID!;
    const secretAccessKey = env.SES_TEST_SECRET_ACCESS_KEY!;
    const sessionToken = env.SES_TEST_SESSION_TOKEN || undefined;
    const region = env.SES_TEST_REGION ?? "us-east-1";
    mailer = sesRawMailer({ accessKeyId, secretAccessKey, sessionToken, region }, { timeoutMs: 30_000 });
  });

  async function sendTo(shape: ComposedMessage, to: string) {
    const msg: ComposedMessage = { ...shape, from: { name: "platform-mail live test", address: from }, to: [{ address: to }], cc: [], bcc: [], replyTo: [] };
    const built = buildMime(msg, { messageIdDomain: from.split("@")[1]! });
    assertSimulatorOnly(built.recipients);
    const { providerMessageId } = await mailer.send({
      raw: built.raw,
      fromAddress: from,
      recipients: built.recipients,
      configurationSet: env.SES_TEST_CONFIGURATION_SET!,
      ...(env.SES_TEST_TENANT ? { tenantName: env.SES_TEST_TENANT } : {}),
    });
    expect(providerMessageId).toMatch(/\S/);
  }

  it.each([
    ["text only", TEXT_ONLY],
    ["alternative", ALTERNATIVE],
    ["mixed", MIXED],
  ] as const)("%s to the success simulator", async (_name, shape) => {
    await sendTo(shape, SUCCESS);
  });

  it("one to the bounce simulator", async () => {
    await sendTo(ALTERNATIVE, BOUNCE);
  });

  it("one to the complaint simulator", async () => {
    await sendTo(ALTERNATIVE, COMPLAINT);
  });
});
