#!/usr/bin/env node
/**
 * Regenerates contracts/capability-v1.vectors.json from the deterministic
 * builder in test/support/capability-vectors.ts (fixed key, fixed clock, fixed
 * jti values). The test suite fails if the committed file and the builder
 * disagree.
 *
 *   node scripts/generate-capability-vectors.ts > contracts/capability-v1.vectors.json
 */
import { buildCapabilityVectors, renderCapabilityVectors } from "../test/support/capability-vectors.ts";

process.stdout.write(renderCapabilityVectors(await buildCapabilityVectors()));
