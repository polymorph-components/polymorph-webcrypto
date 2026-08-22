// The polyengine-native leg of the conformance matrix: the `polyengine-deno`
// target for BOTH suites (shared and signing), runtime-linked under stock
// Deno.
//
// This is the polyengine analogue of `conformance/driver-ct/jco/runner.mjs`,
// mirroring it leg for leg:
//
//   runner.mjs (jco-node)                      | this runner
//   -------------------------------------------+--------------------------------
//   transpiled `generated/` tree               | translate at run time (Translator)
//   `bindImports({ wasi, env: [], sut })`      | `wasi(...)` + `webcryptoImports()`
//   `sut["polymorph:test/test-context"]`       | supplied by ct-runner itself
//   `--missing sha1-checked` (shared suite)    | SUITES.shared.missing
//   `--suite conformance-signing-guest-ct`     | `--suite signing`
//   `envelope(target, suite)`                  | ct-runner's envelope (same identity)
//   worker pool, `--jobs`                      | single-threaded case loop
//
// polyengine is a runtime linker: unlike the jco legs there is no transpile
// step, no generated tree, no npm install, and no engine flag — the
// suite's async exports run on the callback ABI under stock Deno.
//
//   just conformance-ct::run-polyengine          # both legs
//   … run.ts [--translator <shim.wasm>] [--suite shared|signing] [--only SUB]
//            [--fresh-cases] [--jspi]
//
// SUITE ARTIFACTS. Both legs run the BARE suites — the same components
// the jco leg transpiles (jco/package.json's `transpile` /
// `transpile:signing` scripts name them), with `polymorph:webcrypto/*`
// still imported and served by the host module under test
// (js/polyengine/src/mod.ts). The sibling `composed` artifact has the
// RustCrypto provider plugged in-guest and would exercise no host module
// at all. Because the artifact IS the locked one, ct-runner's envelope
// `artifact-sha256` (computed from these bytes) is the lockfile's
// identity — no `--suite-artifact` indirection is needed, unlike the
// composed leg.
//
// EXIT STATUS. Case failures do NOT fail this runner: the `polyengine-deno`
// target carries declared expected-fail debt (targets.toml /
// targets-signing.toml, tracked in polymorph-webcrypto#351), and the
// aggregate is what assesses a failure as expected-or-not and fails the
// gate on an undeclared one — or on a declaration that has gone stale.
// A runner-level problem (translate error, inventory drift, missing
// imports) still throws and exits nonzero.
//
// CONTAINMENT MODE. This leg runs each suite on ONE component instance
// (ct-runner's `freshCases: false`), not the family's fresh-instance-
// per-case convention. That convention is an artifact of wasmtime
// economics — a fresh instance is ~free there (precompiled module,
// CoW memory image) — while under a runtime linker each fresh instance
// re-copies the suite's ~14 MB of embedded vectors and re-lifts all
// 19k case handles, which multiplied out to ~95% of this leg's wall
// time (measured: shared suite 440s fresh vs 20s reused, verdict
// streams byte-identical).
//
// Reuse is sound for THESE suites specifically because they are
// KAT-shaped — cross-case contamination cannot manufacture a quiet
// green, only loud noise:
//   - a positive KAT cannot pass by luck: outputs are compared against
//     fixed vectors;
//   - a contamination-flipped negative KAT (spurious accept) REPORTS as
//     a failure — undeclared, so the aggregate goes red;
//   - a contaminated pass of a declared expected-fail trips the
//     aggregate's stale-declaration check — also red.
//
// The residual hazard is the L1 contract's poisoning clause
// (wit/tests.wit: a trap poisons the suite instance; a timed-out case
// leaves its call in flight): under reuse, rows after such an event are
// unreliable. Both suites measure zero traps and zero timeouts (every
// verdict is provenance `returned`), and any poisoning event mid-run
// makes later rows either loudly wrong or correct — never quietly
// green — per the KAT asymmetry above. When debugging any such run,
// `--fresh-cases` restores per-case containment.
//
// MODULE-IDENTITY CONSTRAINT: polyengine's wasi module imports
// `@polyengine/runtime/embedder` by bare specifier internally; this leg's
// `deno.json` AND `js/polyengine/deno.json` must map that specifier to the
// IDENTICAL exact-pinned JSR version, or the embedder module loads twice
// and `instanceof ComponentException` stops holding across the module boundary.
// `just conformance-ct::polyengine-pin-check` gates that.

import { Translator } from "@polyengine/runtime/shim";
import type { ComponentArtifacts } from "@polyengine/runtime/embedder";
import { runSuite } from "@polyengine/ct-runner";
import { wasi } from "@polyengine/wasi";
import { defaultTranslator } from "@polyengine/translator";
import { webcryptoImports } from "../../../js/polyengine/src/mod.ts";

// This file sits at conformance/driver-ct/polyengine/run.ts, so the repo root
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
// `[targets.polyengine-deno]` entries, which the aggregate cross-checks.
const SUITES: Readonly<Record<string, SuiteSpec>> = {
  shared: {
    name: "conformance-guest-ct",
    wasm: new URL("conformance_guest_ct.wasm", SUITE_DIR),
    out: new URL("polyengine-deno.jsonl", RESULTS),
    // Two capabilities no `crypto.subtle` host can serve here, mirroring
    // targets.toml's `[targets.polyengine-deno] missing-features`:
    //   sha1-checked    — no platform carries sha1dc collision detection,
    //                     so the host declines it fail-closed
    //                     (js/polyengine/src/sha1Checked.ts), as jco-node does.
    //   rsa-verify-8192 — Deno refuses to IMPORT an 8192-bit RSA public
    //                     key at all (polymorph-webcrypto#351), so the
    //                     whole rsassa-…-8192 row is unservable.
    // Each one's `!feature` decline case still runs, verifying the refusal.
    missing: ["sha1-checked", "rsa-verify-8192"],
  },
  signing: {
    name: "conformance-signing-guest-ct",
    wasm: new URL("conformance_signing_guest_ct.wasm", SUITE_DIR),
    out: new URL("polyengine-deno-signing.jsonl", RESULTS),
    // Deno's `crypto.subtle` serves the gated RSA private-key mints, so
    // the host module serves them here too — the Node posture, not the
    // browser one (see js/polyengine/src/rsaSignature.ts). Nothing missing.
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
  /** Opt back into fresh-instance-per-case (see CONTAINMENT MODE). */
  freshCases: boolean;
}

function parseArgs(argv: string[]): Cli {
  const cli: Cli = {
    jspi: false,
    target: "polyengine-deno",
    suites: [],
    freshCases: false,
  };
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
      case "--fresh-cases":
        cli.freshCases = true;
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
  translatorPath: string | undefined,
  wasm: URL,
): Promise<ComponentArtifacts> {
  const translator = translatorPath
    ? await Translator.create(await Deno.readFile(translatorPath))
    : await defaultTranslator();
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
    ...wasi({ cli: { env: {}, passthrough: false } }),
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
    // One instance per suite run by default — see CONTAINMENT MODE.
    freshCases: cli.freshCases,
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

  await Deno.mkdir(RESULTS, { recursive: true });
  for (const key of cli.suites) await runOne(SUITES[key], cli);
  // No failure-derived exit status: see the EXIT STATUS note in the
  // header — the aggregate owns that verdict.
}

if (import.meta.main) await main();
