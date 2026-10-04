// searchMessages (contracts/mail-client-v1.md "Reading"): decrypted headers, snippets and attachment
// names, case- and accent-insensitive, every word must match.
import { describe, expect, test } from "vitest";
import { searchMessages } from "../src/index";
import { opened } from "./support";

const quote = opened({ subject: "Cotización baño", snippet: "Hola, adjunto el plano.", from: { name: "José Nguyễn", address: "jose@example.com" }, attachments: [{ filename: "plano-baño.pdf", mimeType: "application/pdf", size: 1, inline: false }] });
const kitchen = opened({ subject: "Kitchen remodel", snippet: "We'd like a quote for the kitchen", from: { name: "Ana Ruiz", address: "ana@example.com" }, envelopeTo: "team@example.com" });
const broken = opened({ subject: "x" }, { header: null, undecryptable: true });
const all = [quote, kitchen, broken];

describe("searchMessages", () => {
  test("an empty query is every message, undecryptable ones included", () => {
    expect(searchMessages(all, "")).toEqual(all);
    expect(searchMessages(all, "   ")).toEqual(all);
  });

  test("case- and accent-insensitive on the subject", () => {
    expect(searchMessages(all, "cotizacion BANO")).toEqual([quote]);
    expect(searchMessages(all, "Cotización")).toEqual([quote]);
  });

  test("matches the snippet, the sender's name and address, an attachment name and the address it arrived for", () => {
    expect(searchMessages(all, "plano")).toEqual([quote]);
    expect(searchMessages(all, "nguyen")).toEqual([quote]);
    expect(searchMessages(all, "ana@example.com")).toEqual([kitchen]);
    expect(searchMessages(all, "plano-bano.pdf")).toEqual([quote]);
    expect(searchMessages(all, "team@")).toEqual([kitchen]);
  });

  test("every word must match, in any field", () => {
    expect(searchMessages(all, "kitchen quote")).toEqual([kitchen]);
    expect(searchMessages(all, "kitchen plano")).toEqual([]);
    expect(searchMessages(all, "quote")).toEqual([kitchen]);
  });

  test("a message that could not be decrypted matches no query", () => {
    expect(searchMessages([broken], "x")).toEqual([]);
    expect(searchMessages(all, "zzz")).toEqual([]);
  });
});
