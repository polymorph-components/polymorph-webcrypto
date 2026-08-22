// jco browser drivers for the ported conformance suites: one engine per
// invocation (`--engine chromium|firefox|webkit`), both suites' case
// loops running inside the headless engine via the upstream page driver
// — page, worker pool, stall watchdog, and Chrome ladder all live in
// @jsr/polymorph__test — and writing results/<target>.jsonl +
// results/<target>-signing.jsonl plus a results/<target>.meta.json
// provenance sidecar (engine + version, consumed by the compat page).
// This file is the frame: engine selection, core-URL enumeration,
// per-suite configuration, results writing. The shard worker is the
// local reuse-worker.mjs — one component instance per shard, the
// polyengine legs' measured-and-argued containment trade (its header) —
// unless --fresh-cases restores the upstream per-case worker.
//
// Engine → target key: chromium → jco-browser, firefox → jco-firefox,
// webkit → jco-webkit. Chromium prefers a system Chrome (findChrome —
// the CI runner image ships one; Playwright's Chromium is the fallback);
// firefox and webkit always run Playwright's own pinned builds, so each
// target key names one engine everywhere (the upstream driver applies
// Gecko's JSPI pref to Firefox). Install an engine once with
// `npx playwright-core install --with-deps <engine>` (from this
// directory).
//
// WebKit is macOS-only here: Playwright's WebKit uses Apple's crypto
// backend there — the mobile-Safari proxy the jco-webkit ledger records —
// while the Linux port's backend serves less and represents no shipping
// Safari, so this driver refuses `--engine webkit` off darwin rather
// than record facts for the wrong platform. The leg runs as the
// dedicated macOS CI job (`just conformance-ct::run-webkit`).
//
// EXIT STATUS. Case failures do NOT fail this driver (the polyengine
// pattern — see ../polyengine/run.ts): engine targets carry declared
// expected-fail debt (targets.toml / targets-signing.toml), and the
// aggregate is what assesses each failure as declared-or-not, failing
// the gate on any undeclared failure or stale declaration. Runner-level
// problems (launch failure, stall, a suite reporting no run) still exit
// nonzero.
//
// Chromium gates in CI (the Actions runner image ships Chrome); locally
// it runs only when opted in with CONFORMANCE_BROWSER=1 (`just
// conformance-ct::all`), or directly with `just conformance-ct::run-browser`.
// Firefox gates in CI too; locally CONFORMANCE_FIREFOX=1, or `just
// conformance-ct::run-firefox`.
import { execFile } from "node:child_process";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";

import {
  buildHarnessPage,
  findChrome,
  runPageHarness,
} from "@jsr/polymorph__test/browser-driver";
import { writeResultsFile } from "@jsr/polymorph__test/node-runner";

const REPO_ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const RESULTS_DIR = fileURLToPath(new URL("../results/", import.meta.url));
const BASE = "/conformance/driver-ct/jco";
// Stall bounds for the driver's inactivity watchdog: the pool heartbeats
// per suite and per 25 rows, so the tolerable quiet time is a batch of
// the slowest cases — and the batch pace is the engine's. Chromium gets
// the tight bound; Firefox and WebKit run markedly slower on the heavy
// RSA rows (and Playwright's fallback builds slower still), so their
// bound is sized to a slow batch, not a wedged page.
const STALL_TIMEOUT_MS = { chromium: 90_000, firefox: 420_000, webkit: 420_000 };

const TARGETS = {
  chromium: "jco-browser",
  firefox: "jco-firefox",
  webkit: "jco-webkit",
};

// The per-suite missing-features declarations are passed by the justfile
// (like jco-node's --missing), keeping them next to the jco-node ones and
// in sync with targets.toml / targets-signing.toml, which the aggregate
// cross-checks.
const { values } = parseArgs({
  options: {
    engine: { type: "string", default: "chromium" },
    missing: { type: "string", default: "" },
    "missing-signing": { type: "string", default: "" },
    // Worker-pool cap for the in-page case loop (default: the harness's
    // hardware-based count). Lower it when a slow engine build needs
    // memory or CPU headroom.
    jobs: { type: "string", default: "" },
    // Restore the upstream worker's fresh-instance-per-case containment
    // (see reuse-worker.mjs: reuse is the default — one instance per
    // shard — because per-case instantiation dominates wall time under
    // browser engines and the suites are KAT-shaped).
    "fresh-cases": { type: "boolean", default: false },
  },
});
const ENGINE = values.engine;
if (!(ENGINE in TARGETS)) {
  console.error("usage: node run-browser.mjs [--engine chromium|firefox|webkit] [--missing a,b] [--missing-signing a,b]");
  process.exit(2);
}
if (ENGINE === "webkit" && process.platform !== "darwin") {
  console.error(
    "run-browser.mjs: --engine webkit runs on macOS only — the jco-webkit " +
      "ledger records Apple's crypto backend, and the Linux port's backend " +
      "represents no shipping Safari.",
  );
  process.exit(2);
}
const TARGET = TARGETS[ENGINE];
// System Chrome for chromium (the ladder ends at Playwright's build);
// Playwright's own pinned builds for the other engines.
const executablePath = ENGINE === "chromium" ? await findChrome() : undefined;

// Both suites run under one target key in their respective aggregates,
// so the report (and the results file) is keyed per entry.
const common = {
  target: TARGET,
  importsUrl: `${BASE}/browser-imports.mjs`,
  // The driver's test-context (diagnostic sink wiring), not the
  // upstream default.
  contextUrl: `/conformance/driver-ct/context.js`,
};
const SUITES = [
  {
    ...common,
    key: TARGET,
    suite: "conformance-guest-ct",
    missing: values.missing.split(",").filter(Boolean),
  },
  {
    ...common,
    key: `${TARGET}-signing`,
    suite: "conformance-signing-guest-ct",
    missing: values["missing-signing"].split(",").filter(Boolean),
  },
];

// Resolve each suite's core-module list Node-side (the transpile emits
// however many cores the composition needs), so the page never fetches
// a missing file — a 404 would be tolerated but pollutes the console
// the driver mirrors.
for (const entry of SUITES) {
  const names = (await readdir(new URL("./generated/", import.meta.url))).sort();
  entry.moduleUrl = `${BASE}/generated/${entry.suite}.js`;
  entry.coreUrls = names
    .filter((n) => n.startsWith(`${entry.suite}.core`) && n.endsWith(".wasm"))
    .map((n) => `${BASE}/generated/${n}`);
}

// Engine provenance for the results sidecar: a system Chrome reports its
// own version; Playwright builds carry theirs in playwright-core's
// browsers.json manifest. Best effort — an unknown version is omitted,
// never fabricated.
async function engineVersion() {
  if (executablePath !== undefined) {
    try {
      const { stdout } = await promisify(execFile)(executablePath, ["--version"]);
      return stdout.trim() || undefined;
    } catch {
      return undefined;
    }
  }
  try {
    const manifest = JSON.parse(
      await readFile(
        new URL("./node_modules/playwright-core/browsers.json", import.meta.url),
        "utf8",
      ),
    );
    const entry = manifest.browsers?.find((b) => b.name === ENGINE);
    return entry?.browserVersion && `${ENGINE} ${entry.browserVersion}`;
  } catch {
    return undefined;
  }
}

const playwright = await import("playwright-core");
const outcome = await runPageHarness({
  playwright,
  engine: ENGINE,
  executablePath,
  repoRoot: REPO_ROOT,
  html: buildHarnessPage({
    title: "polymorph:webcrypto conformance (component-test stack)",
    config: {
      suites: SUITES,
      // The shard worker: one component instance per shard (reuse) by
      // default — reuse-worker.mjs carries the rationale — or the
      // upstream per-case-containment worker with --fresh-cases.
      ...(values["fresh-cases"] ? {} : { workerUrl: `${BASE}/reuse-worker.mjs` }),
      ...(values.jobs && { jobs: Number(values.jobs) }),
    },
  }),
  stallTimeoutMs: STALL_TIMEOUT_MS[ENGINE],
});

const version = await engineVersion();
await writeFile(
  `${RESULTS_DIR}${TARGET}.meta.json`,
  JSON.stringify({ target: TARGET, engine: ENGINE, ...(version && { version }) }) + "\n",
);

let failed = 0;
for (const { key } of SUITES) {
  const run = outcome[key];
  if (!run) throw new Error(`the page reported no run for ${key}`);
  const outPath = await writeResultsFile({ dir: RESULTS_DIR, target: key, lines: run.lines });
  const c = run.counts;
  process.stderr.write(
    `${TARGET} ${key}: ${c.passed} passed, ${c.failed} failed, ` +
      `${c.skipped} skipped, ${c.na} not applicable, ${c.total} total ` +
      `(wrote ${outPath})\n`,
  );
  failed += c.failed;
}
if (failed > 0) {
  process.stderr.write(
    `${TARGET}: ${failed} case failure(s) — the aggregate assesses these ` +
      `against the declared expected-fail ledger\n`,
  );
}
process.exit(0);
