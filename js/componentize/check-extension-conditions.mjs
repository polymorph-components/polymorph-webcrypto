// The registry gate for the extension-condition table: `EXTENSION_ERRORS`
// in webcrypto.js must mirror wit/extension-conditions.json exactly —
// every registered (origin, name) pair present with the registered
// DOMException name, and no pair beyond the registry. Run by
// `just componentize::typecheck`; catches the drift the runtime cannot
// (an unlisted pair falls back to "OperationError", which the registered
// mappings currently coincide with).
//
// The table is extracted from the module source: webcrypto.js is a single
// module whose only imports are the WIT specifiers componentize-js
// resolves, so it cannot be imported here and cannot import the registry.
// The extraction is brace-matched from the declaration and fails loudly if
// the declaration moves or stops being a plain object literal.

import { readFileSync } from "node:fs";

const here = (path) => new URL(path, import.meta.url);
const registry = JSON.parse(readFileSync(here("../../wit/extension-conditions.json"), "utf8"));
const source = readFileSync(here("./webcrypto.js"), "utf8");

const anchor = "const EXTENSION_ERRORS = ";
const start = source.indexOf(anchor);
if (start === -1) {
  console.error("webcrypto.js no longer declares `const EXTENSION_ERRORS = `");
  process.exit(1);
}
const open = start + anchor.length;
if (source[open] !== "{") {
  console.error("EXTENSION_ERRORS is not a plain object literal; update this gate's extraction");
  process.exit(1);
}
let depth = 0;
let end = open;
for (; end < source.length; end++) {
  if (source[end] === "{") depth++;
  else if (source[end] === "}" && --depth === 0) break;
}
if (depth !== 0) {
  console.error("EXTENSION_ERRORS literal has unbalanced braces; update this gate's extraction");
  process.exit(1);
}
// The slice is a string-keyed, string-valued object literal (the gate's
// mismatch reporting below keeps it honest if that ever changes).
const extensionErrors = new Function(`return (${source.slice(open, end + 1)});`)();

const failures = [];
const registered = new Set();
for (const condition of registry.conditions) {
  const { origin, name, "dom-exception": domException } = condition;
  registered.add(`${origin}\u0000${name}`);
  const served = extensionErrors[origin]?.[name];
  if (served === undefined) {
    failures.push(`missing: (${origin}, ${name}) — the registry maps it to ${domException}`);
  } else if (served !== domException) {
    failures.push(
      `mismatch: (${origin}, ${name}) — the table says ${served}, the registry ${domException}`,
    );
  }
}
for (const [origin, names] of Object.entries(extensionErrors)) {
  for (const name of Object.keys(names ?? {})) {
    if (!registered.has(`${origin}\u0000${name}`)) {
      failures.push(`unregistered: (${origin}, ${name}) — not in wit/extension-conditions.json`);
    }
  }
}

if (failures.length > 0) {
  console.error("webcrypto.js's EXTENSION_ERRORS does not mirror wit/extension-conditions.json:");
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`extension conditions: ${registry.conditions.length} pairs mirror the registry`);
