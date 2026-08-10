# The compatibility matrix

An MDN-style support matrix of the `polymorph:webcrypto` surface across
every conformance target: columns are the five platform-backed hosts
(Chromium, Firefox, WebKit, Node, Deno) plus the two Rust
implementations (the native Wasmtime host and the composed in-guest
provider); rows are algorithms, grouped by the WIT interface that owns
them (`mac`, `aead`, …); subrows appear exactly where targets diverge
within an algorithm (an IV window, a tag-size floor, a policy refusal).

The matrix is **generated, never committed**: `compat.rs` (the `compat`
binary in this crate) derives `results/compat.json` from the same
inputs the conformance aggregate reads — the results JSONL, the target
manifests, the suite lockfiles — plus the curated
[`registry.toml`](registry.toml), and [`index.html`](index.html)
renders it. The registry carries only what results cannot: display
structure (groups, rows, labels) and the *names* of divergences
(aspects). Which cells are green is always computed from results.

## Inputs

Relative to `conformance/driver-ct/`:

| Input | Role |
| --- | --- |
| `../guest-ct/tests.lock`, `../signing-guest-ct/tests.lock` | the case census (names + feature tags) per suite (`shared`, `signing`) |
| `targets.toml`, `targets-signing.toml` | per-suite target manifests: `missing-features`, `expected-fail` ledgers, `optional` |
| `results/<target>.jsonl`, `results/<target>-signing.jsonl` | per-target results (`wasmtime-rustcrypto` uses `wasmtime-signing.jsonl` for the signing suite) |
| `results/<target>.meta.json` | optional provenance sidecars (engine version) written by the runners |
| `compat/registry.toml` | the curated structure (below) |

A target present in a suite's manifest but without a results file is
tolerated as a **no-data** column (the local story for the
optional browser legs) unless `--require-all` is passed — the CI
aggregate job passes it, so the published matrix is never partial.

## The registry (`registry.toml`)

```toml
version = "0.1"

[[columns]]            # display order; one per manifest target
target = "jco-browser" # manifest/results key
label = "Chromium"
kind = "host"          # or "implementation"

[[groups]]             # display order; the WIT generic kinds plus
id = "mac"             # a trailing contracts group
label = "mac — message authentication"

[[rows]]
id = "hmac-sha2"
group = "mac"
label = "HMAC-SHA2"
wit = ["hmac-sha2"]    # the minting/owning interface(s), for display
select = ["shared:hmac-sha256/", "shared:hmac-sha384/"]

[[rows.aspects]]       # a named divergence: a subrow
id = "example"
label = "what diverges, phrased as the capability"
select = ["shared:hmac-sha256/wycheproof/tc1/"]
tracking = "https://github.com/..."   # optional

[[excluded]]           # cases the matrix deliberately does not render
select = ["shared:sha1-checked/decline/"]
why = "decline cases prove refusal on targets missing the feature; the row's positive cases already render the absence"

[[structural]]         # suite-absence with a recorded reason
target = "composed"
row = "ecdsa-sign"
note = "class D: the in-guest provider never exports this interface, so the suite's world cannot link"
```

A `select` entry is `<suite>:<prefix>` — a plain prefix match on the
full case name (`shared` = the shared suite, `signing` = the signing
suite). Rows, aspects, and exclusions may also carry `cases`: the same
syntax matched **exactly**, for case names that are themselves prefixes
of sibling names (`tc32` beside `tc320`). All selects of a row (aspects
included) must name one suite.

## Validation (all fail-closed)

The binary validates before it emits; any violation is an error naming
the cases or ids involved.

- **Total ownership.** Every census case is matched by exactly one
  row's selects or one `excluded` select. No select may match a case
  another row or exclusion also matches; an aspect's selects must match
  only cases its own row's selects match (aspects partition their row).
  A select matching nothing is dead and errors.
- **Uniformity.** For each (row, target) the effective statuses of the
  row's cases *outside its aspects* must agree, and for each
  (aspect, target) the aspect's cases must agree. Effective statuses:
  `pass`; `xfail` (a failure declared in the manifest's expected-fail
  ledger); `na` (not applicable — the runner scheduled the case out for
  a declared missing feature). A mixed cell means the aspect
  partition no longer matches reality — refine the registry.
- **Ledger agreement.** An undeclared failure or a stale expected-fail
  declaration (declared but passing) is an error, as in the aggregate.
  An `na` case whose lockfile tags name no feature the target declares
  missing is an error.
- **Aspect liveness.** When every manifest target has results, an
  aspect whose cells agree across all columns names no divergence and
  errors — fold it back into its row. (Skipped on partial runs, where
  the divergent column may be the absent one.)
- **Structural agreement.** A `structural` entry must name a (target,
  row) where the target is genuinely absent from the row's suite's
  manifest, and every such absence must carry a `structural` entry.
- **Statuses.** Only `pass`, `fail`, and `na` may appear in results
  feeding the matrix; anything else (`skip`, `deselected`, unknown)
  errors — a filtered or partial run must not publish.

## Cell semantics (`compat.json`)

Per (row, target): `yes` (core and every aspect pass), `partial` (core
passes, some aspect does not), `no` (the core itself is `xfail` or
`na`), `absent` (structural), `no-data`. Aspect cells: `yes`, `no`
(`xfail`), `unsupported` (`na`, with the feature name), `absent`,
`no-data`. `no`/`partial` cells carry the tracking links of the
aspects (or the ledger entries) behind them.

The output also carries the column list (labels, kinds, per-target
meta sidecars when present) and a provenance block (`--commit`, ISO
generation time).

## Recipes

- `just conformance-ct::compat-data` — validate and write
  `results/compat.json` from whatever results are present.
- `just conformance-ct::compat-check` — validate only (the CI aggregate
  job runs it with `--require-all` after merging every target's
  results).
- `just conformance-ct::web` — serves the repository root; the page is
  at `/conformance/driver-ct/compat/` once `compat-data` has run.

The Pages site publishes the page with the `compat.json` from the
latest main CI run's `conformance-results` artifact, alongside the
results viewer.
