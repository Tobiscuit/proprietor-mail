#!/usr/bin/env node
// Prints SHA256SUMS for this package's src/: one "<sha256 hex>  src/<path>"
// line per file, which is sha256sum's own format, so `sha256sum -c` checks it.
// Paths are relative to the package and "/"-separated, sorted by their UTF-8
// bytes (as `LC_ALL=C sort` sorts), with LF line endings.
//
// The release workflow (.github/workflows/release-mail-crypto.yml) runs it on
// the tagged tree and attaches the output to the GitHub release; the dashboard's
// vendoring script checks its copy of src/ against that file.
//
//   node scripts/sha256sums.mjs [packageDir] > SHA256SUMS
//
// packageDir defaults to this package. It refuses, exiting 1 with nothing on
// stdout, when it could not describe src/ faithfully: no files at all, a
// symbolic link or other non-file, or a name sha256sum would have to escape.
// Only node: built-ins, so it needs no `npm ci`.
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/** Every regular file under `rel` (relative to packageDir), "/"-separated. */
function filesUnder(packageDir, rel) {
  const files = [];
  for (const name of readdirSync(join(packageDir, rel))) {
    const path = `${rel}/${name}`;
    // sha256sum escapes a name holding "\" or a newline (the line then starts
    // with "\"); any control character is refused along with them.
    if (/[\\\u0000-\u001f\u007f]/.test(name)) throw new Error(`${JSON.stringify(path)}: a name sha256sum would escape`);
    const stat = lstatSync(join(packageDir, path));
    if (stat.isDirectory()) files.push(...filesUnder(packageDir, path));
    else if (stat.isFile()) files.push(path);
    else throw new Error(`${JSON.stringify(path)} is not a regular file or directory`);
  }
  return files;
}

function sha256sums(packageDir) {
  const files = filesUnder(packageDir, "src");
  if (files.length === 0) throw new Error("src/ holds no files");
  files.sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
  return files
    .map((path) => `${createHash("sha256").update(readFileSync(join(packageDir, path))).digest("hex")}  ${path}\n`)
    .join("");
}

try {
  const packageDir = resolve(process.argv[2] ?? fileURLToPath(new URL("..", import.meta.url)));
  process.stdout.write(sha256sums(packageDir));
} catch (error) {
  process.stderr.write(`sha256sums: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
