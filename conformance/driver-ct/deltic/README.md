# `conformance/driver-ct/deltic` — the deltic-native conformance leg

The `deltic-deno` target in both conformance matrices: the suites run
runtime-linked under stock Deno — no transpile step, no generated tree, no
npm install, no engine flag (the suites' async exports run on the callback
ABI) — against [`js/deltic/src/mod.ts`](../../../js/deltic/src/mod.ts).
This is the deltic analogue of the jco Node leg
(`conformance/driver-ct/jco/runner.mjs`); see `run.ts`'s header for the
leg-for-leg mirror.

Both suites run under the **one** target key `deltic-deno`, exactly as
`jco-node` does, writing:

| suite | results file | `missing-features` |
| --- | --- | --- |
| shared (`conformance_guest_ct`) | `results/deltic-deno.jsonl` | `sha1-checked` |
| signing (`conformance_signing_guest_ct`) | `results/deltic-deno-signing.jsonl` | — |

## Running it

```sh
just conformance-ct::run-deltic
```

which builds the suites and runs both through `ct-runner`, resolving the
`@deltic/translator` package's packaged wasm through the module graph
(no fetch step, no net grant — the JSR lock carries integrity).

The suite artifacts are the **bare** suites — the same components the jco
leg transpiles, with `polymorph:webcrypto/*` still imported and served by
the host module under test. Because that is the locked artifact, the
envelope's `artifact-sha256` is the lockfile's identity directly; no
`--suite-artifact` indirection is needed (the composed leg needs one
because its artifact has the provider plugged in).

## Expected-fail debt

`deltic-deno` is the only target with declared expected failures
(`targets.toml`, `targets-signing.toml`, tracked in
[#351](https://github.com/polymorph-components/polymorph-webcrypto/issues/351)):
Deno's WebCrypto is narrower than Node's and the browsers' in a few
parameter windows the WIT admits. `run.ts` therefore does not derive its
exit status from case failures — **the aggregate is the verdict**, and it
fails on an undeclared failure *or* on a declaration that has gone stale
(declared-but-passing). Never silence a new failure by adding an entry
without a named cause and a tracking link.

## Containment: one instance per suite run

This leg runs each suite on a **single reused component instance**
(`freshCases: false`), departing from the family's
fresh-instance-per-case convention — a declared property of the
`deltic-deno` target, documented at length in `run.ts`'s CONTAINMENT
MODE header. In brief:

- The convention prices fresh instances at wasmtime rates (precompiled
  module + CoW memory ≈ free). Under a runtime linker, each fresh
  instance re-copies the suite's ~14 MB of embedded vectors and
  re-enumerates all 19k cases: ~95% of the leg's wall time (measured:
  shared suite 440 s fresh vs 20 s reused, verdict streams
  byte-identical, run 2026-08-10 against `pre-58b2404`).
- Reuse is sound *for these suites* because they are KAT-shaped:
  contamination cannot forge a green (outputs are compared against
  fixed vectors; a flipped negative check reports as an undeclared
  failure; a contaminated pass of a declared expected-fail trips the
  stale check). Both failure directions are loud.
- The residual hazard is trap/timeout poisoning (wit/tests.wit's
  poisoning clause). Both suites measure zero of either — every verdict
  is provenance `returned` — and any poisoning event is itself an
  undeclared failure, so a poisoned run cannot go green. To debug one:
  `run.ts --fresh-cases` restores per-case containment.

This is a per-suite judgment, not family policy: a suite with
deliberate trap cases or stateful host interactions should keep
fresh-per-case.

## The pin

deltic publishes `@deltic/{runtime,translator,wasi-shims,ct-runner}` to
JSR as `0.1.0-pre.g<shorthash>` on every green upstream commit — an
exact-pinned, non-ordered prerelease version naming one commit (see
deltic's README, "Consuming the unstable prereleases"). This repo pins
that version in **two** places, cross-checked by
`just conformance-ct::deltic-pin-check`:

- `deno.json` (this directory) — `jsr:@deltic/<pkg>@<version>` import-map
  entries for `@deltic/ct-runner`, `@deltic/runtime/embedder`,
  `@deltic/runtime/shim`, `@deltic/wasi-shims`, and `@deltic/translator`
  (the packaged translator wasm loader — no separate fetch/sha step).
  `deno.lock` carries integrity hashes for that module graph, enforced
  with `--frozen`.
- [`../../../js/deltic/deno.json`](../../../js/deltic/deno.json) — the
  SAME `@deltic/runtime/embedder` version (the module-identity
  constraint: deltic's `wasi-shims` imports that specifier by bare name
  internally, so every config resolving it must agree, or the embedder
  module loads twice and `instanceof ComponentException` stops holding across the
  boundary).

Both `deno.json` files also carry
`"minimumDependencyAge": { "age": "P1D", "exclude": ["jsr:@deltic/*"] }`,
required per the deltic README because the pinned prereleases are
typically published well under 24h before consumption.

The browser leg's assets (the worker bundle and the translator wasm) are
built from this SAME pinned JSR graph rather than fetched as separate
sha-pinned GitHub release assets — see `browser-bundle-entry.ts` and the
`run-deltic-browser` recipe.

To bump: update the version in both `deno.json` files (this directory's
and `js/deltic/deno.json`), delete BOTH `deno.lock` files (this directory
and `js/deltic/`), re-run `deno install` in both directories (`--frozen`
elsewhere depends on the regenerated lock), confirm
`just conformance-ct::deltic-pin-check` passes, then re-run
`just conformance-ct::run-deltic` plus
`just conformance-ct::aggregate aggregate-signing` and commit the diff
(including the regenerated matrices, via
`just conformance-ct::matrix-update`).
