import { Agent } from "agents";
import type { Env } from "../env";

/** One mailbox: an Agents SDK Agent, which is a SQLite-backed Durable Object. */
export class Mailbox extends Agent<Env> {}
