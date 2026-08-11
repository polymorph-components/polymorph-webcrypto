// deltic-browser driver for the ported conformance suites: both suites'
// case loops run inside headless Chromium via the upstream page driver
// against this repo's deltic host module (js/deltic over the browser's
// Web Crypto) — the worker is one deno-bundled module (see
// browser/worker-entry.ts) linking the suite COMPONENT at run time: no
// transpile step, no generated tree, no core files. This file is the
// frame: per-suite configuration and results writing, the browser
// sibling of ./run.ts exactly as ../jco/run-browser.mjs is jco-node's.
//
// Gates in CI (the Actions runner image ships Chrome); locally it needs
// a Chrome/Chromium install and runs only when opted in with
// CONFORMANCE_BROWSER=1 (`just conformance-ct::all`), or directly with
// `just conformance-ct::run-deltic-browser`.
import { access } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import {
  buildHarnessPage,
  findChrome,
  runPageHarness,
} from "@polymorph/component-test-js/browser-driver";
import { writeResultsFile } from "@polymorph/component-test-js/node-runner";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const RESULTS_DIR = fileURLToPath(new URL("../results/", import.meta.url));
const WORKER_URL = "/target/deltic-browser/webcrypto-worker.mjs";
// Version-free: the lock owns @deltic versioning now (see the migration
// contract), so this output path carries no tag.
const TRANSLATOR_URL = "/target/deltic-browser/deltic-translator-shim.wasm";
// CI hardware headroom, not a platform gap (the deno leg's 300 s case
// timeout precedent): the 19k-case census and the slowest vector
// batches can hold the heartbeat quiet for minutes on a 2-core runner.
const STALL_TIMEOUT_MS = 300_000;

// The per-suite missing-features declarations are passed by the justfile
// (like run-browser's), keeping them next to the jco ones and in sync
// with targets.toml / targets-signing.toml, which the aggregate
// cross-checks.
const { values } = parseArgs({
  options: {
    missing: { type: "string", default: "" },
    "missing-signing": { type: "string", default: "" },
    target: { type: "string", default: "deltic-browser" },
  },
});

const common = {
  target: values.target,
  translatorUrl: TRANSLATOR_URL,
  // One suite instance per shard: this corpus's per-case fresh instances
  // outrun the renderer's wasm-memory reservations (19k cases; a trapped
  // case then poisons the rest of the shard, loudly). Every other leg of
  // these suites keeps fresh-per-case.
  freshCases: false,
};
const SUITES = [
  {
    ...common,
    key: "deltic-browser",
    suite: "conformance-guest-ct",
    suiteUrl: "/target/wasm32-wasip2/release/conformance_guest_ct.wasm",
    missing: values.missing.split(",").filter(Boolean),
  },
  {
    ...common,
    key: "deltic-browser-signing",
    suite: "conformance-signing-guest-ct",
    suiteUrl: "/target/wasm32-wasip2/release/conformance_signing_guest_ct.wasm",
    missing: values["missing-signing"].split(",").filter(Boolean),
  },
];
for (const [what, rel] of [
  ["bundled worker (run `just conformance-ct::run-deltic-browser`)", WORKER_URL],
  ["translator asset (run `just conformance-ct::run-deltic-browser`)", common.translatorUrl],
  ...SUITES.map((s) => [`suite component (run \`just conformance-ct::build\`)`, s.suiteUrl]),
]) {
  try {
    await access(fileURLToPath(new URL(`.${rel}`, `file://${REPO_ROOT}`)));
  } catch {
    throw new Error(`missing ${rel}: ${what}`);
  }
}

const playwright = await import("playwright-core");
const outcome = await runPageHarness({
  playwright,
  engine: "chromium",
  executablePath: await findChrome(),
  repoRoot: REPO_ROOT,
  html: buildHarnessPage({
    title: "polymorph:webcrypto conformance (deltic-browser)",
    // Sequential: a worker pool holds one live suite instance per shard,
    // and this corpus's instances are large enough that a full pool trips
    // Chromium's wasm-memory allocation ceiling.
    config: { jobs: 1, workerUrl: WORKER_URL, suites: SUITES },
  }),
  stallTimeoutMs: STALL_TIMEOUT_MS,
});

let failed = 0;
for (const { key } of SUITES) {
  const run = outcome[key];
  if (!run) throw new Error(`the page reported no run for ${key}`);
  const outPath = await writeResultsFile({ dir: RESULTS_DIR, target: key, lines: run.lines });
  const c = run.counts;
  process.stderr.write(
    `${values.target} ${key}: ${c.passed} passed, ${c.failed} failed, ` +
      `${c.skipped} skipped, ${c.na} not applicable, ${c.total} total ` +
      `(wrote ${outPath})\n`,
  );
  failed += c.failed;
}
process.exit(failed === 0 ? 0 : 1);
