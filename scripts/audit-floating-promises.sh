#!/usr/bin/env bash
# Floating-promise audit of src/ (tasks.md S2r): typescript-eslint's type-aware
# no-floating-promises and no-misused-promises.
#
# typescript-eslint cannot run under this project's TypeScript 7.0.2: the
# TS 7 package ships no compiler API (its main export is lib/version.cjs), and
# typescript-eslint 8.70.1 accepts typescript >=4.8.4 <6.1.0 and throws at
# import under TS 7. So this installs it with TypeScript 6 into a throwaway
# directory and lints src/ against src/tsconfig.json from there; nothing is
# added to the project. It needs the npm registry. Exit code 0 = no findings.
#
# Type-aware rules cannot see a promise behind a `void` or `any` type. The one
# such call in src/ is the Agents SDK's AgentEmail.setReject (typed void, an
# RPC to the EmailBridge at runtime), awaited in Mailbox.reject.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tools="$(mktemp -d)"
trap 'rm -rf "$tools"' EXIT
cd "$tools"
printf '{ "name": "floating-promise-audit", "private": true, "type": "module" }\n' > package.json
npm install --no-audit --no-fund --silent eslint@10.11.0 typescript-eslint@8.70.1 typescript@6.0.3
cat > eslint.config.mjs <<CONFIG
import tseslint from "typescript-eslint";
export default [
  {
    files: ["src/**/*.ts"],
    languageOptions: { parser: tseslint.parser, parserOptions: { project: "./src/tsconfig.json", tsconfigRootDir: "$root" } },
    plugins: { "@typescript-eslint": tseslint.plugin },
    rules: {
      "@typescript-eslint/no-floating-promises": ["error", { checkThenables: true }],
      "@typescript-eslint/no-misused-promises": "error",
    },
  },
];
CONFIG
cd "$root"
"$tools/node_modules/.bin/eslint" -c "$tools/eslint.config.mjs" --no-warn-ignored src
echo "floating-promise audit: no findings in src/"
