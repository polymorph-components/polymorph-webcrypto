// The registry gate for the extension-condition table: `EXTENSION_ERRORS`
// (extension-errors.js) must mirror wit/extension-conditions.json exactly —
// every registered (origin, name) pair present with the registered
// DOMException name, and no pair beyond the registry. Run by
// `just componentize::typecheck`; catches the drift the runtime cannot
// (an unlisted pair falls back to "OperationError", which the registered
// mappings currently coincide with).

import { readFileSync } from "node:fs";
import { EXTENSION_ERRORS } from "./extension-errors.js";

const registryPath = new URL("../../wit/extension-conditions.json", import.meta.url);
const registry = JSON.parse(readFileSync(registryPath, "utf8"));

const failures = [];
const registered = new Set();
for (const condition of registry.conditions) {
  const { origin, name, "dom-exception": domException } = condition;
  registered.add(`${origin}\u0000${name}`);
  const served = EXTENSION_ERRORS[origin]?.[name];
  if (served === undefined) {
    failures.push(`missing: (${origin}, ${name}) — the registry maps it to ${domException}`);
  } else if (served !== domException) {
    failures.push(
      `mismatch: (${origin}, ${name}) — the table says ${served}, the registry ${domException}`,
    );
  }
}
for (const [origin, names] of Object.entries(EXTENSION_ERRORS)) {
  for (const name of Object.keys(names ?? {})) {
    if (!registered.has(`${origin}\u0000${name}`)) {
      failures.push(`unregistered: (${origin}, ${name}) — not in wit/extension-conditions.json`);
    }
  }
}

if (failures.length > 0) {
  console.error("extension-errors.js does not mirror wit/extension-conditions.json:");
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}
console.log(`extension conditions: ${registry.conditions.length} pairs mirror the registry`);
