// The deltic-native leg of the conformance matrix: the `deltic-deno`
// target for BOTH suites (shared and signing), runtime-linked under stock
// Deno.
//
// This is the deltic analogue of `conformance/driver-ct/jco/runner.mjs`,
// mirroring it leg for leg:
//
//   runner.mjs (jco-node)                      | this runner
//   -------------------------------------------+--------------------------------
//   transpiled `generated/` tree               | translate at run time (Translator)
//   `bindImports({ wasi, env: [], sut })`      | `wasiShims(...)` + `webcryptoImports()`
//   `sut["polymorph:test/test-context"]`       | supplied by ct-runner itself
//   `--missing sha1-checked` (shared suite)    | SUITES.shared.missing
//   `--suite conformance-signing-guest-ct`     | `--suite signing`
//   `envelope(target, suite)`                  | ct-runner's envelope (same identity)
//   worker pool, `--jobs`                      | single-threaded case loop
//
// deltic is a runtime linker: unlike the jco legs there is no transpile
// step, no generated tree, no npm install, and no engine flag — the
// suite's async exports run on the callback ABI under stock Deno.
//
//   just conformance-ct::run-deltic          # both legs
//   … run.ts --translator <shim.wasm> [--suite shared|signing] [--only SUB] [--jspi]
//
// SUITE ARTIFACTS. Both legs run the BARE suites — the same components
// the jco leg transpiles (jco/package.json's `transpile` /
// `transpile:signing` scripts name them), with `polymorph:webcrypto/*`
// still imported and served by the host module under test
// (js/deltic/src/mod.ts). The sibling `composed` artifact has the
// RustCrypto provider plugged in-guest and would exercise no host module
// at all. Because the artifact IS the locked one, ct-runner's envelope
// `artifact-sha256` (computed from these bytes) is the lockfile's
// identity — no `--suite-artifact` indirection is needed, unlike the
// composed leg.
//
// EXIT STATUS. Case failures do NOT fail this runner: the `deltic-deno`
// target carries declared expected-fail debt (targets.toml /
// targets-signing.toml, tracked in polymorph-webcrypto#351), and the
// aggregate is what assesses a failure as expected-or-not and fails the
// gate on an undeclared one — or on a declaration that has gone stale.
// A runner-level problem (translate error, inventory drift, missing
// imports) still throws and exits nonzero.
//
// MODULE-IDENTITY CONSTRAINT: deltic's wasi-shims module imports
// `@deltic/runtime/embedder` by bare specifier internally; this leg's
// `deno.json` AND `js/deltic/deno.json` must map that specifier to the
// IDENTICAL pinned URL, or the embedder module loads twice and
// `instanceof WitError` stops holding across the module boundary.
// `fetch-translator.ts`'s `assertPinConsistency` gates that.

import { Translator } from "@deltic/runtime/shim";
import type { ComponentArtifacts } from "@deltic/runtime/embedder";
import { runSuite } from "@deltic/ct-runner";
import { wasiShims } from "@deltic/wasi-shims";
import { webcryptoImports } from "../../../js/deltic/src/mod.ts";

// This file sits at conformance/driver-ct/deltic/run.ts, so the repo root
// is three levels up.
const ROOT = new URL("../../../", import.meta.url);
const SUITE_DIR = new URL("target/wasm32-wasip2/release/", ROOT);
const RESULTS = new URL("conformance/driver-ct/results/", ROOT);

/**
 * Per-case wall bound. The other legs use harness.mjs's 60s, but this
 * leg's boundary-heavy worst case needs more headroom on CI hardware:
 * `probe/large-stream` measures 6.1s on a workstation and 72s on the
 * 2-core Actions runner (run 31394527207) — a hardware ratio, not a
 * hang. 300s keeps the hang guard while clearing that worst case with
 * ~4x margin; the next-slowest case is 10.3s on the same runner.
 */
const CASE_TIMEOUT_MS = 300_000;

interface SuiteSpec {
  /** Envelope suite name; ct-runner normalizes `-` to the lockfile's `_`. */
  name: string;
  wasm: URL;
  /** Results file, mirroring the jco leg's `jco-node{,-signing}.jsonl`. */
  out: URL;
  /** The features THIS target lacks; must mirror the target manifests. */
  missing: string[];
}

// The `missing` lists mirror targets.toml / targets-signing.toml's
// `[targets.deltic-deno]` entries, which the aggregate cross-checks.
const SUITES: Readonly<Record<string, SuiteSpec>> = {
  shared: {
    name: "conformance-guest-ct",
    wasm: new URL("conformance_guest_ct.wasm", SUITE_DIR),
    out: new URL("deltic-deno.jsonl", RESULTS),
    // No platform WebCrypto carries sha1dc collision detection, so the
    // host module declines `sha1-checked` fail-closed
    // (js/deltic/src/sha1Checked.ts) — as jco-node does. The suite's
    // `!sha1-checked` decline case still runs, verifying the refusal.
    missing: ["sha1-checked"],
  },
  signing: {
    name: "conformance-signing-guest-ct",
    wasm: new URL("conformance_signing_guest_ct.wasm", SUITE_DIR),
    out: new URL("deltic-deno-signing.jsonl", RESULTS),
    // Deno's `crypto.subtle` serves the gated RSA private-key mints, so
    // the host module serves them here too — the Node posture, not the
    // browser one (see js/deltic/src/rsaSignature.ts). Nothing missing.
    missing: [],
  },
};

interface Cli {
  only?: string;
  jspi: boolean;
  target: string;
  translator?: string;
  suites: string[];
  /** Override for a single-suite run; refused for a multi-suite one. */
  out?: string;
  missing?: string[];
}

function parseArgs(argv: string[]): Cli {
  const cli: Cli = { jspi: false, target: "deltic-deno", suites: [] };
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case "--only":
        cli.only = argv[++i];
        break;
      case "--jspi":
        cli.jspi = true;
        break;
      case "--out":
        cli.out = argv[++i];
        break;
      case "--target":
        cli.target = argv[++i];
        break;
      case "--translator":
        cli.translator = argv[++i];
        break;
      case "--suite":
        cli.suites.push(argv[++i]);
        break;
      case "--missing":
        cli.missing = argv[++i].split(",").filter((s) => s.length > 0);
        break;
      default:
        throw new Error(`unknown argument ${argv[i]}`);
    }
  }
  if (cli.suites.length === 0) cli.suites = Object.keys(SUITES);
  for (const s of cli.suites) {
    if (!(s in SUITES)) {
      throw new Error(
        `unknown suite '${s}' (known: ${Object.keys(SUITES).join(", ")})`,
      );
    }
  }
  if (cli.out !== undefined && cli.suites.length > 1) {
    throw new Error("--out takes a single --suite");
  }
  return cli;
}

async function loadArtifacts(
  translatorPath: string,
  wasm: URL,
): Promise<ComponentArtifacts> {
  const translator = await Translator.create(
    await Deno.readFile(translatorPath),
  );
  const componentBytes = await Deno.readFile(wasm);
  const { plan, adapters } = translator.translate(componentBytes);
  return { plan, componentBytes, adapters };
}

async function runOne(spec: SuiteSpec, cli: Cli): Promise<void> {
  const artifacts = await loadArtifacts(cli.translator!, spec.wasm);
  // The whole import surface: WASI (no ambient environment — the suites
  // read none, exactly as the jco legs' `env: []`) plus every
  // `polymorph:webcrypto/*` interface from the host module under test.
  // ct-runner adds `polymorph:test/test-context` itself.
  const imports = {
    ...wasiShims({ cli: { env: {}, passthrough: false } }),
    ...webcryptoImports(),
  };
  const out = cli.out ?? spec.out.pathname;
  const lines: string[] = [];
  const started = performance.now();
  const counts = await runSuite(artifacts, {
    imports,
    target: cli.target,
    suiteName: spec.name,
    only: cli.only,
    missing: cli.missing ?? spec.missing,
    caseTimeoutMs: CASE_TIMEOUT_MS,
    jspi: cli.jspi,
    emit: (line) => lines.push(line),
  });
  await Deno.writeTextFile(out, lines.join("\n") + "\n");
  console.error(
    `[${cli.target}/${spec.name}] ${counts.passed} passed | ${counts.failed} failed | ` +
      `${counts.skipped} skipped | ${counts.na} n/a (${counts.total} total) in ` +
      `${((performance.now() - started) / 1000).toFixed(1)}s -> ${out}`,
  );
}

async function main() {
  const cli = parseArgs(Deno.args);

  if (!cli.translator) {
    throw new Error(
      "missing required --translator <path>; fetch the pinned release " +
        "asset with `deno run ... conformance/driver-ct/deltic/fetch-translator.ts` " +
        "(see that script for exact permissions).",
    );
  }

  await Deno.mkdir(RESULTS, { recursive: true });
  for (const key of cli.suites) await runOne(SUITES[key], cli);
  // No failure-derived exit status: see the EXIT STATUS note in the
  // header — the aggregate owns that verdict.
}

if (import.meta.main) await main();
