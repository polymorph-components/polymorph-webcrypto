//! `compat`: derives the compatibility matrix data (`results/compat.json`)
//! from the conformance inputs — the suite lockfiles, the target manifests,
//! the results JSONL — plus the curated `compat/registry.toml`.
//!
//! Usage: compat [--root DIR] [--require-all] [--commit SHA] [-o PATH]
//!
//! See compat/README.md for the registry schema, the validation rules and
//! the cell semantics; that document is the specification.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const SHARED: &str = "shared";
const SIGNING: &str = "signing";
const SHARED_SUITE_NAME: &str = "conformance_guest_ct";
const SIGNING_SUITE_NAME: &str = "conformance_signing_guest_ct";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let mut root: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut commit: Option<String> = None;
    let mut require_all = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                root =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        anyhow::anyhow!("--root needs a directory")
                    })?));
            }
            "--commit" => {
                commit = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--commit needs a value"))?,
                );
            }
            "-o" => {
                out = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("-o needs a path"))?,
                ));
            }
            "--require-all" => require_all = true,
            other => bail!(
                "unexpected argument `{other}`; usage: compat [--root DIR] \
                 [--require-all] [--commit SHA] [-o PATH]"
            ),
        }
    }
    let root = match root {
        Some(r) => r,
        None => std::env::current_dir().context("resolving the current directory")?,
    };

    match build(&root, require_all, commit)? {
        Ok(output) => {
            if let Some(path) = out {
                let mut json = serde_json::to_string_pretty(&output)?;
                json.push('\n');
                if let Some(parent) = path.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent)
                            .with_context(|| format!("creating {}", parent.display()))?;
                    }
                }
                std::fs::write(&path, json)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            Ok(ExitCode::SUCCESS)
        }
        Err(violations) => {
            for v in &violations {
                eprintln!("error: {v}");
            }
            eprintln!("{} validation error(s)", violations.len());
            Ok(ExitCode::FAILURE)
        }
    }
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct LockFile {
    suite: LockSuite,
    #[serde(default)]
    case: Vec<LockCase>,
    #[serde(default)]
    generated: Vec<LockGenerated>,
}

#[derive(Deserialize)]
struct LockSuite {
    name: String,
}

#[derive(Deserialize)]
struct LockCase {
    name: String,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct LockGenerated {
    prefix: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    cases: Vec<String>,
}

/// One suite's census: case names in lockfile order, with their tags.
struct Census {
    order: Vec<String>,
    tags: BTreeMap<String, Vec<String>>,
}

impl Census {
    fn contains(&self, name: &str) -> bool {
        self.tags.contains_key(name)
    }

    /// The tags that name a feature the case needs (as opposed to the
    /// `!feature` decline tags, which name a feature it needs *absent*).
    fn positive_tags(&self, name: &str) -> Vec<String> {
        self.tags
            .get(name)
            .map(|t| {
                t.iter()
                    .filter(|t| !t.starts_with('!'))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    fn has_negative_tag(&self, name: &str) -> bool {
        self.tags
            .get(name)
            .map(|t| t.iter().any(|t| t.starts_with('!')))
            .unwrap_or(false)
    }
}

fn load_census(path: &Path, expected_suite: &str) -> Result<Census> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lock: LockFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    if lock.suite.name != expected_suite {
        bail!(
            "{}: suite is `{}`, expected `{expected_suite}`",
            path.display(),
            lock.suite.name
        );
    }
    let mut census = Census {
        order: Vec::new(),
        tags: BTreeMap::new(),
    };
    let mut push = |name: String, tags: Vec<String>| {
        if census.tags.insert(name.clone(), tags).is_none() {
            census.order.push(name);
        }
    };
    for c in lock.case {
        push(c.name, c.tags);
    }
    for g in lock.generated {
        for leaf in g.cases {
            push(format!("{}/{leaf}", g.prefix), g.tags.clone());
        }
    }
    Ok(census)
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    targets: BTreeMap<String, ManifestTarget>,
}

#[derive(Deserialize)]
struct ManifestTarget {
    #[serde(default, rename = "missing-features")]
    missing_features: Vec<String>,
    #[serde(default, rename = "expected-fail")]
    expected_fail: Vec<ExpectedFail>,
}

#[derive(Deserialize)]
struct ExpectedFail {
    case: String,
    #[allow(dead_code)]
    reason: Option<String>,
    tracking: Option<String>,
}

fn load_manifest(path: &Path) -> Result<Manifest> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

#[derive(Deserialize)]
struct Registry {
    #[serde(default)]
    columns: Vec<RegColumn>,
    #[serde(default)]
    groups: Vec<RegGroup>,
    #[serde(default)]
    rows: Vec<RegRow>,
    #[serde(default)]
    excluded: Vec<RegExcluded>,
    #[serde(default)]
    structural: Vec<RegStructural>,
}

#[derive(Deserialize)]
struct RegColumn {
    target: String,
    label: String,
    kind: String,
    /// A second target this column absorbs: the same platform behind
    /// another host stack. The builder asserts the two targets' cells
    /// are identical wherever both have results — the merge is sound
    /// exactly while the arms agree, and a divergence fails the build,
    /// forcing the columns apart (or the divergence fixed).
    #[serde(default)]
    merges: Option<String>,
}

#[derive(Deserialize)]
struct RegGroup {
    id: String,
    label: String,
}

#[derive(Deserialize)]
struct RegRow {
    id: String,
    group: String,
    label: String,
    #[serde(default)]
    wit: Vec<String>,
    #[serde(default)]
    select: Vec<String>,
    #[serde(default)]
    cases: Vec<String>,
    #[serde(default)]
    aspects: Vec<RegAspect>,
}

#[derive(Deserialize)]
struct RegAspect {
    id: String,
    label: String,
    #[serde(default)]
    select: Vec<String>,
    #[serde(default)]
    cases: Vec<String>,
    tracking: Option<String>,
}

#[derive(Deserialize)]
struct RegExcluded {
    #[serde(default)]
    select: Vec<String>,
    #[serde(default)]
    cases: Vec<String>,
}

#[derive(Deserialize)]
struct RegStructural {
    target: String,
    row: String,
    note: String,
}

fn load_registry(path: &Path) -> Result<Registry> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

#[derive(Deserialize)]
struct Meta {
    target: Option<String>,
    engine: Option<String>,
    version: Option<String>,
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct Output {
    provenance: Provenance,
    columns: Vec<OutColumn>,
    groups: Vec<OutGroup>,
}

#[derive(Serialize)]
struct Provenance {
    commit: Option<String>,
    generated: String,
}

#[derive(Serialize)]
struct OutColumn {
    target: String,
    label: String,
    kind: String,
    present: OutPresent,
    #[serde(skip_serializing_if = "Option::is_none")]
    meta: Option<OutMeta>,
}

#[derive(Serialize)]
struct OutPresent {
    shared: bool,
    signing: bool,
}

#[derive(Serialize)]
struct OutMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    engine: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
}

#[derive(Serialize)]
struct OutGroup {
    id: String,
    label: String,
    rows: Vec<OutRow>,
}

#[derive(Serialize)]
struct OutRow {
    id: String,
    label: String,
    wit: Vec<String>,
    cells: BTreeMap<String, OutCell>,
    aspects: Vec<OutAspect>,
}

#[derive(Serialize, PartialEq, Eq)]
struct OutCell {
    support: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    features: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracking: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize)]
struct OutAspect {
    id: String,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tracking: Option<String>,
    cells: BTreeMap<String, OutAspectCell>,
}

#[derive(Serialize, PartialEq, Eq)]
struct OutAspectCell {
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    features: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// A case's effective status on one target.
#[derive(Clone, PartialEq, Eq)]
enum Eff {
    Pass,
    Xfail(Option<String>),
    Na(Vec<String>),
}

impl Eff {
    fn kind(&self) -> &'static str {
        match self {
            Eff::Pass => "pass",
            Eff::Xfail(_) => "xfail",
            Eff::Na(_) => "na",
        }
    }
}

fn results_path(root: &Path, target: &str, suite: &str) -> PathBuf {
    let name = if suite == SHARED {
        format!("{target}.jsonl")
    } else if target == "wasmtime-rustcrypto" {
        // The signing suite's results for this target predate the
        // `<target>-signing.jsonl` convention.
        "wasmtime-signing.jsonl".to_string()
    } else {
        format!("{target}-signing.jsonl")
    };
    root.join("results").join(name)
}

/// One results file's case statuses, or the violations that reading it found.
fn read_results(
    path: &Path,
    target: &str,
    suite_name: &str,
    errs: &mut Vec<String>,
) -> BTreeMap<String, String> {
    let mut statuses = BTreeMap::new();
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            errs.push(format!("{}: {e}", path.display()));
            return statuses;
        }
    };
    let mut envelope_seen = false;
    let mut ended = false;
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                errs.push(format!("{}:{}: malformed JSON: {e}", path.display(), n + 1));
                continue;
            }
        };
        if ended {
            errs.push(format!(
                "{}:{}: content after the segment-end marker",
                path.display(),
                n + 1
            ));
            continue;
        }
        if value.get("segment-end").is_some() {
            ended = true;
            continue;
        }
        if let Some(case) = value.get("case").and_then(|c| c.as_str()) {
            let status = value
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            if statuses.insert(case.to_string(), status).is_some() {
                errs.push(format!("{}: duplicate case line `{case}`", path.display()));
            }
            continue;
        }
        if !envelope_seen {
            envelope_seen = true;
            let got_target = value.get("target").and_then(|t| t.as_str()).unwrap_or("");
            if got_target != target {
                errs.push(format!(
                    "{}: envelope target `{got_target}`, expected `{target}`",
                    path.display()
                ));
            }
            // The envelope's `suite` is either the suite name or a table
            // carrying it.
            let got_suite = match value.get("suite") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Object(o)) => o
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if got_suite != suite_name {
                errs.push(format!(
                    "{}: envelope suite `{got_suite}`, expected `{suite_name}`",
                    path.display()
                ));
            }
            continue;
        }
        errs.push(format!(
            "{}:{}: unrecognized line (neither envelope, case, nor segment-end)",
            path.display(),
            n + 1
        ));
    }
    if !ended {
        errs.push(format!(
            "{}: truncated results (no segment-end)",
            path.display()
        ));
    }
    statuses
}

fn parse_select(sel: &str) -> Option<(&str, &str)> {
    let (suite, prefix) = sel.split_once(':')?;
    if suite != SHARED && suite != SIGNING {
        return None;
    }
    Some((suite, prefix))
}

/// The union of the cases a set of selects matches within one suite's census.
fn matched(census: &Census, suite: &str, selects: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for sel in selects {
        if let Some((s, prefix)) = parse_select(sel) {
            if s == suite {
                for name in &census.order {
                    if name.starts_with(prefix) {
                        out.insert(name.clone());
                    }
                }
            }
        }
    }
    out
}

fn matched_one(census: &Census, suite: &str, sel: &str) -> BTreeSet<String> {
    matched(census, suite, std::slice::from_ref(&sel.to_string()))
}

/// Exact-name counterpart of [`matched`]: a `cases` entry claims one case,
/// never a prefix family — the form for case names that are themselves
/// prefixes of sibling names (`tc32` beside `tc320`).
fn matched_exact(census: &Census, suite: &str, sel: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some((s, name)) = parse_select(sel) {
        if s == suite && census.contains(name) {
            out.insert(name.to_string());
        }
    }
    out
}

fn build(
    root: &Path,
    require_all: bool,
    commit: Option<String>,
) -> Result<std::result::Result<Output, Vec<String>>> {
    let mut errs: Vec<String> = Vec::new();

    let censuses: BTreeMap<&str, Census> = BTreeMap::from([
        (
            SHARED,
            load_census(&root.join("../guest-ct/tests.lock"), SHARED_SUITE_NAME)?,
        ),
        (
            SIGNING,
            load_census(
                &root.join("../signing-guest-ct/tests.lock"),
                SIGNING_SUITE_NAME,
            )?,
        ),
    ]);
    let manifests: BTreeMap<&str, Manifest> = BTreeMap::from([
        (SHARED, load_manifest(&root.join("targets.toml"))?),
        (SIGNING, load_manifest(&root.join("targets-signing.toml"))?),
    ]);
    let registry = load_registry(&root.join("compat/registry.toml"))?;

    let census_of = |suite: &str| -> &Census { &censuses[suite] };
    let manifest_of = |suite: &str| -> &Manifest { &manifests[suite] };
    let suite_name_of = |suite: &str| -> &'static str {
        if suite == SHARED {
            SHARED_SUITE_NAME
        } else {
            SIGNING_SUITE_NAME
        }
    };

    // --- registry structure -------------------------------------------------

    let mut group_ids: BTreeSet<&str> = BTreeSet::new();
    for g in &registry.groups {
        if !group_ids.insert(&g.id) {
            errs.push(format!("registry: duplicate group id `{}`", g.id));
        }
    }
    let mut row_ids: BTreeSet<&str> = BTreeSet::new();
    for r in &registry.rows {
        if !row_ids.insert(&r.id) {
            errs.push(format!("registry: duplicate row id `{}`", r.id));
        }
        if !group_ids.contains(r.group.as_str()) {
            errs.push(format!(
                "registry: row `{}` names unknown group `{}`",
                r.id, r.group
            ));
        }
        let mut aspect_ids: BTreeSet<&str> = BTreeSet::new();
        for a in &r.aspects {
            if !aspect_ids.insert(&a.id) {
                errs.push(format!(
                    "registry: row `{}` has duplicate aspect id `{}`",
                    r.id, a.id
                ));
            }
        }
    }
    for g in &registry.groups {
        if !registry.rows.iter().any(|r| r.group == g.id) {
            errs.push(format!("registry: group `{}` has no rows", g.id));
        }
    }

    // Columns must exactly cover the union of the manifests' targets;
    // a target may be covered by the column that names it or by one
    // absorbing it via `merges`.
    let mut column_targets: BTreeSet<&str> = BTreeSet::new();
    let mut merged_into: BTreeMap<&str, &str> = BTreeMap::new();
    for c in &registry.columns {
        if !column_targets.insert(&c.target) {
            errs.push(format!("registry: duplicate column target `{}`", c.target));
        }
        if let Some(m) = &c.merges {
            if merged_into.insert(m.as_str(), c.target.as_str()).is_some() {
                errs.push(format!("registry: target `{m}` is merged by two columns"));
            }
        }
    }
    for (m, primary) in &merged_into {
        if column_targets.contains(m) {
            errs.push(format!(
                "registry: target `{m}` is both a column and merged into `{primary}`"
            ));
        }
    }
    let mut manifest_targets: BTreeSet<&str> = BTreeSet::new();
    for suite in [SHARED, SIGNING] {
        for t in manifest_of(suite).targets.keys() {
            manifest_targets.insert(t.as_str());
        }
    }
    for t in &manifest_targets {
        if !column_targets.contains(t) && !merged_into.contains_key(t) {
            errs.push(format!("registry: no column for manifest target `{t}`"));
        }
    }
    for t in &column_targets {
        if !manifest_targets.contains(t) {
            errs.push(format!(
                "registry: column target `{t}` is in no target manifest"
            ));
        }
    }
    for m in merged_into.keys() {
        if !manifest_targets.contains(m) {
            errs.push(format!(
                "registry: merged target `{m}` is in no target manifest"
            ));
        }
    }

    // --- ownership ----------------------------------------------------------

    struct RowPlan<'a> {
        row: &'a RegRow,
        suite: &'static str,
        core: BTreeSet<String>,
        aspects: Vec<(&'a RegAspect, BTreeSet<String>)>,
    }

    let mut plans: Vec<RowPlan> = Vec::new();
    // case -> owner description, for the overlap and total-ownership checks.
    let mut owner: BTreeMap<(&str, String), String> = BTreeMap::new();
    let claim = |errs: &mut Vec<String>,
                 owner: &mut BTreeMap<(&str, String), String>,
                 suite: &'static str,
                 cases: &BTreeSet<String>,
                 who: &str| {
        for case in cases {
            if let Some(prev) = owner.get(&(suite, case.clone())) {
                errs.push(format!(
                    "registry: case `{suite}:{case}` is claimed by both {prev} and {who}"
                ));
            } else {
                owner.insert((suite, case.clone()), who.to_string());
            }
        }
    };

    for r in &registry.rows {
        // Every select of a row, aspects included, must name one suite.
        let mut suites: BTreeSet<&str> = BTreeSet::new();
        let mut malformed = false;
        for sel in r.select.iter().chain(&r.cases).chain(
            r.aspects
                .iter()
                .flat_map(|a| a.select.iter().chain(&a.cases)),
        ) {
            match parse_select(sel) {
                Some((s, _)) => {
                    suites.insert(s);
                }
                None => {
                    malformed = true;
                    errs.push(format!(
                        "registry: row `{}`: malformed select `{sel}` \
                         (expected `shared:<prefix>` or `signing:<prefix>`)",
                        r.id
                    ));
                }
            }
        }
        if suites.len() > 1 {
            let names: Vec<&str> = suites.iter().copied().collect();
            errs.push(format!(
                "registry: row `{}` mixes suites {names:?}; all selects of a row must name one",
                r.id
            ));
        }
        if suites.is_empty() {
            if !malformed {
                errs.push(format!("registry: row `{}` selects nothing", r.id));
            }
            continue;
        }
        let suite: &'static str = if suites.contains(SHARED) {
            SHARED
        } else {
            SIGNING
        };
        let census = census_of(suite);

        for sel in &r.select {
            if matched_one(census, suite, sel).is_empty() {
                errs.push(format!(
                    "registry: row `{}`: dead select `{sel}` (matches no case)",
                    r.id
                ));
            }
        }
        for sel in &r.cases {
            if matched_exact(census, suite, sel).is_empty() {
                errs.push(format!(
                    "registry: row `{}`: dead case `{sel}` (not in the census)",
                    r.id
                ));
            }
        }
        let mut row_cases = matched(census, suite, &r.select);
        for sel in &r.cases {
            row_cases.extend(matched_exact(census, suite, sel));
        }

        let mut aspect_plans: Vec<(&RegAspect, BTreeSet<String>)> = Vec::new();
        let mut aspect_owned: BTreeMap<String, &str> = BTreeMap::new();
        let mut consumed: BTreeSet<String> = BTreeSet::new();
        for a in &r.aspects {
            for sel in &a.select {
                if matched_one(census, suite, sel).is_empty() {
                    errs.push(format!(
                        "registry: row `{}` aspect `{}`: dead select `{sel}` (matches no case)",
                        r.id, a.id
                    ));
                }
            }
            for sel in &a.cases {
                if matched_exact(census, suite, sel).is_empty() {
                    errs.push(format!(
                        "registry: row `{}` aspect `{}`: dead case `{sel}` (not in the census)",
                        r.id, a.id
                    ));
                }
            }
            let mut cases = matched(census, suite, &a.select);
            for sel in &a.cases {
                cases.extend(matched_exact(census, suite, sel));
            }
            for case in &cases {
                if !row_cases.contains(case) {
                    errs.push(format!(
                        "registry: row `{}` aspect `{}` selects `{case}`, \
                         which its row does not select",
                        r.id, a.id
                    ));
                }
                if let Some(prev) = aspect_owned.insert(case.clone(), &a.id) {
                    errs.push(format!(
                        "registry: row `{}`: case `{case}` is claimed by aspects \
                         `{prev}` and `{}`",
                        r.id, a.id
                    ));
                }
            }
            consumed.extend(cases.iter().cloned());
            aspect_plans.push((a, cases));
        }
        let core: BTreeSet<String> = row_cases.difference(&consumed).cloned().collect();
        if core.is_empty() && !row_cases.is_empty() {
            errs.push(format!(
                "registry: row `{}`: its aspects consume every case it selects; \
                 a row is its core",
                r.id
            ));
        }

        claim(
            &mut errs,
            &mut owner,
            suite,
            &row_cases,
            &format!("row `{}`", r.id),
        );

        // Decline cases (a `!feature` tag) are proofs of refusal, not
        // capability: they belong in [[excluded]].
        for case in &row_cases {
            if census.has_negative_tag(case) {
                errs.push(format!(
                    "registry: row `{}` selects decline case `{case}`; \
                     decline cases belong in [[excluded]]",
                    r.id
                ));
            }
        }

        plans.push(RowPlan {
            row: r,
            suite,
            core,
            aspects: aspect_plans,
        });
    }

    let mut excluded_cases: BTreeSet<(&str, String)> = BTreeSet::new();
    for (i, ex) in registry.excluded.iter().enumerate() {
        for (sel, exact) in ex
            .select
            .iter()
            .map(|s| (s, false))
            .chain(ex.cases.iter().map(|s| (s, true)))
        {
            let Some((suite, _)) = parse_select(sel) else {
                errs.push(format!("registry: excluded[{i}]: malformed select `{sel}`"));
                continue;
            };
            let suite: &'static str = if suite == SHARED { SHARED } else { SIGNING };
            let cases = if exact {
                matched_exact(census_of(suite), suite, sel)
            } else {
                matched_one(census_of(suite), suite, sel)
            };
            if cases.is_empty() {
                errs.push(format!(
                    "registry: excluded[{i}]: dead select `{sel}` (matches no case)"
                ));
            }
            claim(
                &mut errs,
                &mut owner,
                suite,
                &cases,
                &format!("excluded[{i}]"),
            );
            excluded_cases.extend(cases.into_iter().map(|c| (suite, c)));
        }
    }

    for suite in [SHARED, SIGNING] {
        for case in &census_of(suite).order {
            if !owner.contains_key(&(suite, case.clone())) {
                errs.push(format!(
                    "case `{suite}:{case}` is matched by no row and no exclusion"
                ));
            }
        }
    }

    // --- results ------------------------------------------------------------

    // (suite, target) -> statuses, absent when the results file is not there.
    let mut results: BTreeMap<(&str, String), BTreeMap<String, String>> = BTreeMap::new();
    for suite in [SHARED, SIGNING] {
        let census = census_of(suite);
        for target in manifest_of(suite).targets.keys() {
            let path = results_path(root, target, suite);
            if !path.exists() {
                if require_all {
                    errs.push(format!(
                        "--require-all: no results for target `{target}` in the {suite} suite \
                         ({})",
                        path.display()
                    ));
                }
                continue;
            }
            let statuses = read_results(&path, target, suite_name_of(suite), &mut errs);
            for case in statuses.keys() {
                if !census.contains(case) {
                    errs.push(format!(
                        "{}: case `{case}` is not in the {suite} census",
                        path.display()
                    ));
                }
            }
            for case in &census.order {
                if !statuses.contains_key(case) {
                    errs.push(format!(
                        "{}: census case `{case}` has no result line",
                        path.display()
                    ));
                }
            }
            results.insert((suite, target.clone()), statuses);
        }
    }

    // The expected-fail ledgers, keyed by (suite, target, case).
    let mut ledger: BTreeMap<(&str, &str, &str), Option<String>> = BTreeMap::new();
    for suite in [SHARED, SIGNING] {
        let census = census_of(suite);
        for (target, entry) in &manifest_of(suite).targets {
            for xf in &entry.expected_fail {
                if !census.contains(&xf.case) {
                    errs.push(format!(
                        "targets ({suite}): target `{target}` declares expected-fail \
                         `{}`, which is not in the census",
                        xf.case
                    ));
                    continue;
                }
                ledger.insert((suite, target, &xf.case), xf.tracking.clone());
                if let Some(statuses) = results.get(&(suite, target.clone())) {
                    match statuses.get(&xf.case).map(String::as_str) {
                        Some("fail") => {}
                        Some(other) => errs.push(format!(
                            "targets ({suite}): target `{target}`: expected-fail `{}` \
                             is stale — the case reports `{other}`",
                            xf.case
                        )),
                        None => {}
                    }
                }
            }
        }
    }

    // The effective status of every (suite, target, case) with results.
    // Excluded cases (decline proofs) never feed a cell: the aggregate
    // polices their statuses, including the inverted `!feature`
    // scheduling this pass would misread.
    let mut effective: BTreeMap<(&str, String, String), Eff> = BTreeMap::new();
    for suite in [SHARED, SIGNING] {
        let census = census_of(suite);
        for (target, entry) in &manifest_of(suite).targets {
            let Some(statuses) = results.get(&(suite, target.clone())) else {
                continue;
            };
            for case in &census.order {
                if excluded_cases.contains(&(suite, case.clone())) {
                    continue;
                }
                let Some(status) = statuses.get(case) else {
                    continue;
                };
                let eff = match status.as_str() {
                    "pass" => Eff::Pass,
                    "fail" => match ledger.get(&(suite, target.as_str(), case.as_str())) {
                        Some(tracking) => Eff::Xfail(tracking.clone()),
                        None => {
                            errs.push(format!("{target} ({suite}): undeclared failure `{case}`"));
                            continue;
                        }
                    },
                    "not-applicable" => {
                        let features: Vec<String> = census
                            .positive_tags(case)
                            .into_iter()
                            .filter(|t| entry.missing_features.contains(t))
                            .collect();
                        if features.is_empty() {
                            errs.push(format!(
                                "{target} ({suite}): case `{case}` reports `not-applicable`, \
                                 but its tags name no feature the target declares missing"
                            ));
                            continue;
                        }
                        Eff::Na(features)
                    }
                    other => {
                        errs.push(format!(
                            "{target} ({suite}): case `{case}` reports status `{other}`; \
                             only pass, fail and not-applicable may feed the matrix"
                        ));
                        continue;
                    }
                };
                effective.insert((suite, target.clone(), case.clone()), eff);
            }
        }
    }

    // --- structural agreement ----------------------------------------------

    let mut structural: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    for s in &registry.structural {
        if structural
            .insert((s.target.as_str(), s.row.as_str()), s.note.as_str())
            .is_some()
        {
            errs.push(format!(
                "registry: duplicate structural entry for target `{}`, row `{}`",
                s.target, s.row
            ));
        }
        let Some(plan) = plans.iter().find(|p| p.row.id == s.row) else {
            errs.push(format!(
                "registry: structural entry names unknown row `{}`",
                s.row
            ));
            continue;
        };
        if manifest_of(plan.suite).targets.contains_key(&s.target) {
            errs.push(format!(
                "registry: spurious structural entry: target `{}` is present in the \
                 {} manifest that row `{}` belongs to",
                s.target, plan.suite, s.row
            ));
        }
    }
    for plan in &plans {
        for column in &registry.columns {
            if !manifest_of(plan.suite).targets.contains_key(&column.target)
                && !structural.contains_key(&(column.target.as_str(), plan.row.id.as_str()))
            {
                errs.push(format!(
                    "registry: target `{}` is absent from the {} manifest, so row `{}` \
                     needs a [[structural]] entry",
                    column.target, plan.suite, plan.row.id
                ));
            }
        }
    }

    // --- cells --------------------------------------------------------------

    let mut groups: Vec<OutGroup> = registry
        .groups
        .iter()
        .map(|g| OutGroup {
            id: g.id.clone(),
            label: g.label.clone(),
            rows: Vec::new(),
        })
        .collect();

    for plan in &plans {
        let suite = plan.suite;
        let manifest = manifest_of(suite);
        let mut aspects_out: Vec<OutAspect> = Vec::new();

        // Aspect cells first: the row's support reads them. Cells are
        // computed for every column target AND every merged arm — the
        // merged-column pass then asserts the arms agree and folds
        // them, so a merged target is fully validated, never skipped.
        let cell_targets: Vec<&String> = registry
            .columns
            .iter()
            .flat_map(|c| [Some(&c.target), c.merges.as_ref()])
            .flatten()
            .collect();
        for (aspect, cases) in &plan.aspects {
            let mut cells: BTreeMap<String, OutAspectCell> = BTreeMap::new();
            for &target in &cell_targets {
                if !manifest.targets.contains_key(target) {
                    cells.insert(
                        target.clone(),
                        OutAspectCell {
                            state: "absent".into(),
                            features: None,
                        },
                    );
                    continue;
                }
                if !results.contains_key(&(suite, target.clone())) {
                    cells.insert(
                        target.clone(),
                        OutAspectCell {
                            state: "no-data".into(),
                            features: None,
                        },
                    );
                    continue;
                }
                let effs: Vec<&Eff> = cases
                    .iter()
                    .filter_map(|c| effective.get(&(suite, target.clone(), c.clone())))
                    .collect();
                let Some(state) = uniform(
                    &mut errs,
                    &format!("row `{}` aspect `{}`", plan.row.id, aspect.id),
                    target,
                    cases,
                    &effs,
                    &effective,
                    suite,
                ) else {
                    continue;
                };
                cells.insert(
                    target.clone(),
                    OutAspectCell {
                        state: match state.kind() {
                            "pass" => "yes".into(),
                            "xfail" => "no".into(),
                            _ => "unsupported".to_string(),
                        },
                        features: match &state {
                            Eff::Na(f) => Some(dedup(f.clone())),
                            _ => None,
                        },
                    },
                );
            }

            // An aspect names a divergence: on a complete run its cells
            // cannot all agree.
            let complete = manifest
                .targets
                .keys()
                .all(|t| results.contains_key(&(suite, t.clone())));
            if complete {
                let present: Vec<&OutAspectCell> = registry
                    .columns
                    .iter()
                    .filter(|c| manifest.targets.contains_key(&c.target))
                    .filter_map(|c| cells.get(&c.target))
                    .collect();
                if present.len() > 1 && present.iter().all(|c| *c == present[0]) {
                    errs.push(format!(
                        "registry: row `{}` aspect `{}` names no divergence — \
                         fold it into its row",
                        plan.row.id, aspect.id
                    ));
                }
            }

            aspects_out.push(OutAspect {
                id: aspect.id.clone(),
                label: aspect.label.clone(),
                tracking: aspect.tracking.clone(),
                cells,
            });
        }

        let mut cells: BTreeMap<String, OutCell> = BTreeMap::new();
        for &target in &cell_targets {
            if !manifest.targets.contains_key(target) {
                cells.insert(
                    target.clone(),
                    OutCell {
                        support: "absent".into(),
                        features: None,
                        tracking: None,
                        note: structural
                            .get(&(target.as_str(), plan.row.id.as_str()))
                            .map(|n| n.to_string()),
                    },
                );
                continue;
            }
            if !results.contains_key(&(suite, target.clone())) {
                cells.insert(
                    target.clone(),
                    OutCell {
                        support: "no-data".into(),
                        features: None,
                        tracking: None,
                        note: None,
                    },
                );
                continue;
            }
            let effs: Vec<&Eff> = plan
                .core
                .iter()
                .filter_map(|c| effective.get(&(suite, target.clone(), c.clone())))
                .collect();
            let Some(state) = uniform(
                &mut errs,
                &format!("row `{}`", plan.row.id),
                target,
                &plan.core,
                &effs,
                &effective,
                suite,
            ) else {
                continue;
            };
            let non_yes_aspects: Vec<&OutAspect> = aspects_out
                .iter()
                .filter(|a| {
                    a.cells
                        .get(target)
                        .map(|c| c.state != "yes")
                        .unwrap_or(false)
                })
                .collect();
            let support = match state.kind() {
                "pass" => {
                    if non_yes_aspects.is_empty() {
                        "yes"
                    } else {
                        "partial"
                    }
                }
                // A feature-gated absence (the target declares the tagged
                // feature missing) renders apart from a ledgered
                // divergence, mirroring the aspect states.
                "na" => "unsupported",
                _ => "no",
            };
            let mut tracking: Vec<String> = Vec::new();
            for e in &effs {
                if let Eff::Xfail(Some(t)) = e {
                    tracking.push(t.clone());
                }
            }
            for a in &non_yes_aspects {
                if let Some(t) = &a.tracking {
                    tracking.push(t.clone());
                }
            }
            let tracking = dedup(tracking);
            let features = match &state {
                Eff::Na(f) => Some(dedup(f.clone())),
                _ => None,
            };
            cells.insert(
                target.clone(),
                OutCell {
                    support: support.into(),
                    features,
                    tracking: if support == "yes" || tracking.is_empty() {
                        None
                    } else {
                        Some(tracking)
                    },
                    note: None,
                },
            );
        }

        let out_row = OutRow {
            id: plan.row.id.clone(),
            label: plan.row.label.clone(),
            wit: plan.row.wit.clone(),
            cells,
            aspects: aspects_out,
        };
        if let Some(g) = groups.iter_mut().find(|g| g.id == plan.row.group) {
            g.rows.push(out_row);
        }
    }

    // --- merged columns -----------------------------------------------------
    // A column's `merges` target must agree with the column wherever
    // both have data; its cells then fold into the column's key and
    // leave the emitted maps. Comparison skips no-data (a run-shape
    // fact, not behavior); with --require-all every cell has data, so
    // the gate is total in CI.
    fn fold_merged<C: PartialEq>(
        errs: &mut Vec<String>,
        who: &str,
        cells: &mut BTreeMap<String, C>,
        primary: &str,
        merged: &str,
        is_no_data: impl Fn(&C) -> bool,
        render: impl Fn(&C) -> String,
    ) {
        let Some(m) = cells.remove(merged) else {
            return;
        };
        match cells.get(primary) {
            None => {
                cells.insert(primary.to_string(), m);
            }
            Some(p) if is_no_data(p) && !is_no_data(&m) => {
                cells.insert(primary.to_string(), m);
            }
            Some(p) => {
                if !is_no_data(&m) && *p != m {
                    errs.push(format!(
                        "{who}: the merged column arms diverge — `{primary}` reports {} \
                         where `{merged}` reports {}; split the columns",
                        render(p),
                        render(&m)
                    ));
                }
            }
        }
    }
    for c in &registry.columns {
        let Some(merged) = &c.merges else { continue };
        for g in &mut groups {
            for row in &mut g.rows {
                fold_merged(
                    &mut errs,
                    &format!("row `{}`", row.id),
                    &mut row.cells,
                    &c.target,
                    merged,
                    |cell| cell.support == "no-data",
                    |cell| format!("`{}`", cell.support),
                );
                for aspect in &mut row.aspects {
                    fold_merged(
                        &mut errs,
                        &format!("row `{}` aspect `{}`", row.id, aspect.id),
                        &mut aspect.cells,
                        &c.target,
                        merged,
                        |cell| cell.state == "no-data",
                        |cell| format!("`{}`", cell.state),
                    );
                }
            }
        }
    }

    // --- columns ------------------------------------------------------------

    let mut columns: Vec<OutColumn> = Vec::new();
    for c in &registry.columns {
        // Provenance: the column's own sidecar, else the merged arm's —
        // the equality gate makes them the same platform.
        let mut meta = None;
        for t in [Some(&c.target), c.merges.as_ref()].into_iter().flatten() {
            let meta_path = root.join("results").join(format!("{t}.meta.json"));
            let Ok(text) = std::fs::read_to_string(&meta_path) else {
                continue;
            };
            match serde_json::from_str::<Meta>(&text) {
                Ok(m) => {
                    meta = Some(OutMeta {
                        target: m.target,
                        engine: m.engine,
                        version: m.version,
                    });
                }
                Err(e) => errs.push(format!("{}: {e}", meta_path.display())),
            }
            break;
        }
        let arm_present = |suite: &'static str| {
            results.contains_key(&(suite, c.target.clone()))
                || c.merges
                    .as_ref()
                    .is_some_and(|m| results.contains_key(&(suite, m.clone())))
        };
        columns.push(OutColumn {
            target: c.target.clone(),
            label: c.label.clone(),
            kind: c.kind.clone(),
            present: OutPresent {
                shared: arm_present(SHARED),
                signing: arm_present(SIGNING),
            },
            meta,
        });
    }

    if !errs.is_empty() {
        errs.sort();
        errs.dedup();
        return Ok(Err(errs));
    }

    Ok(Ok(Output {
        provenance: Provenance {
            commit,
            generated: now_iso8601(),
        },
        columns,
        groups,
    }))
}

/// The single effective status of a cell's cases, or `None` when they
/// disagree (which the caller has then recorded as a violation).
#[allow(clippy::too_many_arguments)]
fn uniform(
    errs: &mut Vec<String>,
    who: &str,
    target: &str,
    cases: &BTreeSet<String>,
    effs: &[&Eff],
    effective: &BTreeMap<(&str, String, String), Eff>,
    suite: &str,
) -> Option<Eff> {
    let first = effs.first()?;
    if effs.iter().all(|e| e.kind() == first.kind()) {
        // `na` cells report every feature their cases name.
        if let Eff::Na(_) = first {
            let mut features = Vec::new();
            for e in effs {
                if let Eff::Na(f) = e {
                    features.extend(f.iter().cloned());
                }
            }
            return Some(Eff::Na(dedup(features)));
        }
        return Some((*first).clone());
    }
    let mut detail: Vec<String> = Vec::new();
    for case in cases {
        if let Some(e) = effective.get(&(suite, target.to_string(), case.clone())) {
            detail.push(format!("{case}={}", e.kind()));
        }
    }
    errs.push(format!(
        "{who} on `{target}`: mixed statuses — {}",
        detail.join(", ")
    ));
    None
}

fn dedup(mut v: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    v.retain(|s| seen.insert(s.clone()));
    v
}

/// The current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
fn now_iso8601() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to a
/// proleptic Gregorian date.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A disposable input tree: `<tmp>/compat-test-<pid>-<n>/driver-ct`.
    struct Fixture {
        base: PathBuf,
        root: PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    impl Fixture {
        fn write(&self, rel: &str, contents: &str) {
            let path = self.root.join(rel);
            std::fs::create_dir_all(path.parent().expect("relative path has a parent")).unwrap();
            std::fs::write(path, contents).unwrap();
        }

        fn remove(&self, rel: &str) {
            let _ = std::fs::remove_file(self.root.join(rel));
        }

        fn run(&self, require_all: bool) -> std::result::Result<Output, Vec<String>> {
            build(&self.root, require_all, Some("abc123".into())).expect("inputs are readable")
        }

        fn errors(&self, require_all: bool) -> Vec<String> {
            match self.run(require_all) {
                Ok(_) => panic!("expected validation errors, got a matrix"),
                Err(e) => e,
            }
        }
    }

    fn assert_mentions(errs: &[String], needle: &str) {
        assert!(
            errs.iter().any(|e| e.contains(needle)),
            "no error mentions `{needle}`; got: {errs:#?}"
        );
    }

    /// The baseline synthetic tree: two suites, three columns (one of them
    /// absent from the signing manifest), one aspect with a divergence, one
    /// structural row, one excluded decline case, one xfail, one `na`.
    fn fixture() -> Fixture {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("compat-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("driver-ct");
        std::fs::create_dir_all(&root).unwrap();
        let f = Fixture { base, root };

        f.write(
            "../guest-ct/tests.lock",
            r#"
version = "0.1"
[suite]
name = "conformance_guest_ct"

[[case]]
name = "hmac/contract/getters"

[[case]]
name = "hmac/contract/export"

[[case]]
name = "sha1/decline/minting"
tags = ["!sha1-checked"]

[[generated]]
prefix = "sha1/wycheproof"
tags = ["sha1-checked"]
cases = ["tc1/whole", "tc2/whole"]

[[generated]]
prefix = "aes-gcm/wycheproof"
cases = ["tc1/whole", "tc2/whole"]
"#,
        );
        f.write(
            "../signing-guest-ct/tests.lock",
            r#"
version = "0.1"
[suite]
name = "conformance_signing_guest_ct"

[[case]]
name = "ecdsa-sign/contract/mint"
"#,
        );
        f.write(
            "targets.toml",
            r#"
version = "0.1"
[features.sha1-checked]
kind = "gated"

[targets.wasmtime-rustcrypto]
missing-features = []

[targets.jco-node]
missing-features = ["sha1-checked"]

[targets.composed]
missing-features = []
[[targets.composed.expected-fail]]
case = "aes-gcm/wycheproof/tc2/whole"
reason = "synthetic"
tracking = "https://example.invalid/1"
"#,
        );
        f.write(
            "targets-signing.toml",
            r#"
version = "0.1"
[targets.wasmtime-rustcrypto]
missing-features = []

[targets.jco-node]
missing-features = []
"#,
        );
        f.write(
            "compat/registry.toml",
            r#"
version = "0.1"

[[columns]]
target = "wasmtime-rustcrypto"
label = "Wasmtime"
kind = "implementation"

[[columns]]
target = "jco-node"
label = "Node"
kind = "host"

[[columns]]
target = "composed"
label = "Composed"
kind = "implementation"

[[groups]]
id = "mac"
label = "mac"

[[groups]]
id = "signature"
label = "signature"

[[rows]]
id = "hmac-sha2"
group = "mac"
label = "HMAC-SHA2"
wit = ["hmac-sha2"]
select = ["shared:hmac/"]

[[rows]]
id = "sha1-checked"
group = "mac"
label = "SHA-1 (collision-checked)"
wit = ["sha1-checked"]
select = ["shared:sha1/wycheproof/"]

[[rows]]
id = "aes-gcm"
group = "mac"
label = "AES-GCM"
wit = ["aes-gcm"]
select = ["shared:aes-gcm/"]

[[rows.aspects]]
id = "tc2"
label = "the second vector"
select = ["shared:aes-gcm/wycheproof/tc2/"]
tracking = "https://example.invalid/aspect"

[[rows]]
id = "ecdsa-sign"
group = "signature"
label = "ECDSA signing"
wit = ["ecdsa-sign"]
select = ["signing:ecdsa-sign/"]

[[excluded]]
select = ["shared:sha1/decline/"]
why = "decline cases prove refusal"

[[structural]]
target = "composed"
row = "ecdsa-sign"
note = "class D"
"#,
        );

        for target in ["wasmtime-rustcrypto", "jco-node", "composed"] {
            let sha1 = if target == "jco-node" {
                "not-applicable"
            } else {
                "pass"
            };
            let decline = if target == "jco-node" {
                "pass"
            } else {
                "not-applicable"
            };
            let gcm2 = if target == "composed" { "fail" } else { "pass" };
            f.write(
                &format!("results/{target}.jsonl"),
                &format!(
                    concat!(
                        "{{\"target\":\"{t}\",\"suite\":{{\"name\":\"conformance_guest_ct\"}}}}\n",
                        "{{\"case\":\"hmac/contract/getters\",\"status\":\"pass\"}}\n",
                        "{{\"case\":\"hmac/contract/export\",\"status\":\"pass\"}}\n",
                        "{{\"case\":\"sha1/decline/minting\",\"status\":\"{decline}\"}}\n",
                        "{{\"case\":\"sha1/wycheproof/tc1/whole\",\"status\":\"{sha1}\"}}\n",
                        "{{\"case\":\"sha1/wycheproof/tc2/whole\",\"status\":\"{sha1}\"}}\n",
                        "{{\"case\":\"aes-gcm/wycheproof/tc1/whole\",\"status\":\"pass\"}}\n",
                        "{{\"case\":\"aes-gcm/wycheproof/tc2/whole\",\"status\":\"{gcm2}\"}}\n",
                        "{{\"segment-end\":true}}\n"
                    ),
                    t = target,
                    decline = decline,
                    sha1 = sha1,
                    gcm2 = gcm2
                ),
            );
        }
        // The decline case's `na` on the targets that serve sha1-checked is
        // not representable (it has only a negative tag), so those targets
        // report it as passing refusal instead.
        for target in ["wasmtime-rustcrypto", "composed"] {
            let path = format!("results/{target}.jsonl");
            let text = std::fs::read_to_string(f.root.join(&path)).unwrap();
            f.write(
                &path,
                &text.replace(
                    "\"case\":\"sha1/decline/minting\",\"status\":\"not-applicable\"",
                    "\"case\":\"sha1/decline/minting\",\"status\":\"pass\"",
                ),
            );
        }

        f.write(
            "results/wasmtime-signing.jsonl",
            concat!(
                "{\"target\":\"wasmtime-rustcrypto\",\"suite\":\"conformance_signing_guest_ct\"}\n",
                "{\"case\":\"ecdsa-sign/contract/mint\",\"status\":\"pass\"}\n",
                "{\"segment-end\":true}\n"
            ),
        );
        f.write(
            "results/jco-node-signing.jsonl",
            concat!(
                "{\"target\":\"jco-node\",\"suite\":\"conformance_signing_guest_ct\"}\n",
                "{\"case\":\"ecdsa-sign/contract/mint\",\"status\":\"pass\"}\n",
                "{\"segment-end\":true}\n"
            ),
        );
        f.write(
            "results/jco-node.meta.json",
            r#"{"target":"jco-node","engine":"node","version":"24.0.0","extra":1}"#,
        );
        f
    }

    fn cell<'a>(out: &'a Output, row: &str, target: &str) -> &'a OutCell {
        out.groups
            .iter()
            .flat_map(|g| &g.rows)
            .find(|r| r.id == row)
            .unwrap_or_else(|| panic!("row `{row}`"))
            .cells
            .get(target)
            .unwrap_or_else(|| panic!("cell `{row}`/`{target}`"))
    }

    #[test]
    fn happy_path() {
        let f = fixture();
        let out = f.run(true).unwrap_or_else(|e| panic!("{e:#?}"));

        assert_eq!(out.provenance.commit.as_deref(), Some("abc123"));
        assert_eq!(out.columns.len(), 3);
        assert_eq!(out.columns[0].target, "wasmtime-rustcrypto");
        assert!(out.columns[0].present.shared && out.columns[0].present.signing);
        assert!(out.columns[1].present.signing);
        assert!(!out.columns[2].present.signing);
        assert_eq!(
            out.columns[1].meta.as_ref().unwrap().version.as_deref(),
            Some("24.0.0")
        );
        assert!(out.columns[0].meta.is_none());

        // Groups and rows keep registry order.
        assert_eq!(out.groups[0].id, "mac");
        let ids: Vec<&str> = out.groups[0].rows.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["hmac-sha2", "sha1-checked", "aes-gcm"]);

        assert_eq!(cell(&out, "hmac-sha2", "jco-node").support, "yes");
        // `na` for a declared missing feature is unsupported.
        let sha1 = cell(&out, "sha1-checked", "jco-node");
        assert_eq!(sha1.support, "unsupported");
        assert_eq!(
            sha1.features.as_deref(),
            Some(&["sha1-checked".to_string()][..])
        );
        assert_eq!(
            cell(&out, "sha1-checked", "wasmtime-rustcrypto").support,
            "yes"
        );

        // The aspect diverges: composed's declared failure makes it partial.
        assert_eq!(cell(&out, "aes-gcm", "wasmtime-rustcrypto").support, "yes");
        let gcm = cell(&out, "aes-gcm", "composed");
        assert_eq!(gcm.support, "partial");
        assert_eq!(
            gcm.tracking.as_deref(),
            Some(&["https://example.invalid/aspect".to_string()][..])
        );
        let aspect = &out
            .groups
            .iter()
            .flat_map(|g| &g.rows)
            .find(|r| r.id == "aes-gcm")
            .unwrap()
            .aspects[0];
        assert_eq!(aspect.cells["composed"].state, "no");
        assert_eq!(aspect.cells["jco-node"].state, "yes");

        // The signing row is structurally absent on the composed column.
        let ecdsa = cell(&out, "ecdsa-sign", "composed");
        assert_eq!(ecdsa.support, "absent");
        assert_eq!(ecdsa.note.as_deref(), Some("class D"));
        assert_eq!(cell(&out, "ecdsa-sign", "jco-node").support, "yes");

        // The output is serializable and stable in shape.
        let json = serde_json::to_value(&out).unwrap();
        assert!(json["groups"][0]["rows"][0]["cells"]["jco-node"]["support"] == "yes");
    }

    #[test]
    fn unmapped_case() {
        let f = fixture();
        let text = std::fs::read_to_string(f.root.join("../guest-ct/tests.lock")).unwrap();
        f.write(
            "../guest-ct/tests.lock",
            &format!("{text}\n[[case]]\nname = \"orphan/case\"\n"),
        );
        assert_mentions(&f.errors(false), "matched by no row and no exclusion");
    }

    #[test]
    fn overlapping_selects() {
        let f = fixture();
        add_row(&f, "\n[[rows]]\nid = \"dup\"\ngroup = \"mac\"\nlabel = \"dup\"\nselect = [\"shared:hmac/contract/getters\"]\n");
        assert_mentions(&f.errors(false), "is claimed by both");
    }

    #[test]
    fn aspect_select_outside_its_row() {
        let f = fixture();
        replace_registry(
            &f,
            "select = [\"shared:aes-gcm/wycheproof/tc2/\"]",
            "select = [\"shared:hmac/contract/export\"]",
        );
        assert_mentions(&f.errors(false), "which its row does not select");
    }

    #[test]
    fn aspect_consuming_its_whole_row() {
        let f = fixture();
        replace_registry(
            &f,
            "select = [\"shared:aes-gcm/wycheproof/tc2/\"]",
            "select = [\"shared:aes-gcm/\"]",
        );
        assert_mentions(&f.errors(false), "a row is its core");
    }

    #[test]
    fn mixed_status_cell() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"case\":\"hmac/contract/export\",\"status\":\"pass\"",
            "\"case\":\"hmac/contract/export\",\"status\":\"not-applicable\"",
        );
        // The `na` itself is also invalid here (no tags), so assert the
        // mixed-status path via a target that can legitimately report `na`.
        let errs = f.errors(false);
        assert_mentions(&errs, "name no feature the target declares missing");
    }

    #[test]
    fn mixed_status_cell_reported() {
        let f = fixture();
        // Half the sha1 row goes back to passing on a target that reports the
        // other half `na`.
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"case\":\"sha1/wycheproof/tc1/whole\",\"status\":\"not-applicable\"",
            "\"case\":\"sha1/wycheproof/tc1/whole\",\"status\":\"pass\"",
        );
        assert_mentions(&f.errors(false), "mixed statuses");
    }

    #[test]
    fn stale_ledger_entry() {
        let f = fixture();
        patch_result(
            &f,
            "results/composed.jsonl",
            "\"case\":\"aes-gcm/wycheproof/tc2/whole\",\"status\":\"fail\"",
            "\"case\":\"aes-gcm/wycheproof/tc2/whole\",\"status\":\"pass\"",
        );
        assert_mentions(&f.errors(false), "is stale");
    }

    #[test]
    fn ledger_entry_outside_the_census() {
        let f = fixture();
        replace_targets(
            &f,
            "case = \"aes-gcm/wycheproof/tc2/whole\"",
            "case = \"aes-gcm/wycheproof/tc99/whole\"",
        );
        assert_mentions(&f.errors(false), "which is not in the census");
    }

    #[test]
    fn undeclared_failure() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"case\":\"aes-gcm/wycheproof/tc1/whole\",\"status\":\"pass\"",
            "\"case\":\"aes-gcm/wycheproof/tc1/whole\",\"status\":\"fail\"",
        );
        assert_mentions(&f.errors(false), "undeclared failure");
    }

    #[test]
    fn na_without_a_matching_missing_feature() {
        let f = fixture();
        replace_targets(
            &f,
            "[targets.jco-node]\nmissing-features = [\"sha1-checked\"]",
            "[targets.jco-node]\nmissing-features = []",
        );
        assert_mentions(
            &f.errors(false),
            "name no feature the target declares missing",
        );
    }

    #[test]
    fn dead_select() {
        let f = fixture();
        add_row(&f, "\n[[rows]]\nid = \"dead\"\ngroup = \"mac\"\nlabel = \"dead\"\nselect = [\"shared:nothing/\"]\n");
        assert_mentions(&f.errors(false), "dead select");
    }

    #[test]
    fn missing_structural_entry() {
        let f = fixture();
        replace_registry(
            &f,
            "[[structural]]\ntarget = \"composed\"\nrow = \"ecdsa-sign\"\nnote = \"class D\"\n",
            "",
        );
        assert_mentions(&f.errors(false), "needs a [[structural]] entry");
    }

    #[test]
    fn spurious_structural_entry() {
        let f = fixture();
        replace_registry(
            &f,
            "row = \"ecdsa-sign\"\nnote = \"class D\"",
            "row = \"hmac-sha2\"\nnote = \"class D\"",
        );
        assert_mentions(&f.errors(false), "spurious structural entry");
    }

    #[test]
    fn aspect_naming_no_divergence() {
        let f = fixture();
        // Every target now passes the aspect's case, so it names nothing.
        replace_targets(
            &f,
            "[[targets.composed.expected-fail]]\ncase = \"aes-gcm/wycheproof/tc2/whole\"\nreason = \"synthetic\"\ntracking = \"https://example.invalid/1\"\n",
            "",
        );
        patch_result(
            &f,
            "results/composed.jsonl",
            "\"case\":\"aes-gcm/wycheproof/tc2/whole\",\"status\":\"fail\"",
            "\"case\":\"aes-gcm/wycheproof/tc2/whole\",\"status\":\"pass\"",
        );
        assert_mentions(&f.errors(false), "names no divergence");
    }

    #[test]
    fn no_data_tolerated_unless_required() {
        let f = fixture();
        f.remove("results/jco-node.jsonl");
        let out = f.run(false).unwrap_or_else(|e| panic!("{e:#?}"));
        assert_eq!(cell(&out, "hmac-sha2", "jco-node").support, "no-data");
        // The signing file is still there, so absence is per-suite.
        assert_eq!(cell(&out, "ecdsa-sign", "jco-node").support, "yes");
        let col = out.columns.iter().find(|c| c.target == "jco-node").unwrap();
        assert!(!col.present.shared && col.present.signing);

        assert_mentions(&f.errors(true), "--require-all");
    }

    #[test]
    fn decline_case_selected_by_a_row() {
        let f = fixture();
        replace_registry(
            &f,
            "select = [\"shared:sha1/wycheproof/\"]",
            "select = [\"shared:sha1/\"]",
        );
        replace_registry(&f, "[[excluded]]\nselect = [\"shared:sha1/decline/\"]\nwhy = \"decline cases prove refusal\"\n", "");
        assert_mentions(&f.errors(false), "decline cases belong in [[excluded]]");
    }

    #[test]
    fn unknown_status() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"case\":\"hmac/contract/export\",\"status\":\"pass\"",
            "\"case\":\"hmac/contract/export\",\"status\":\"skip\"",
        );
        assert_mentions(
            &f.errors(false),
            "only pass, fail and not-applicable may feed the matrix",
        );
    }

    #[test]
    fn truncated_results() {
        let f = fixture();
        patch_result(&f, "results/jco-node.jsonl", "{\"segment-end\":true}\n", "");
        assert_mentions(&f.errors(false), "truncated results");
    }

    #[test]
    fn duplicate_case_line() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "{\"segment-end\":true}",
            "{\"case\":\"hmac/contract/export\",\"status\":\"pass\"}\n{\"segment-end\":true}",
        );
        assert_mentions(&f.errors(false), "duplicate case line");
    }

    #[test]
    fn case_outside_the_census() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "{\"segment-end\":true}",
            "{\"case\":\"stray/case\",\"status\":\"pass\"}\n{\"segment-end\":true}",
        );
        assert_mentions(&f.errors(false), "is not in the shared census");
    }

    #[test]
    fn census_case_without_a_result() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "{\"case\":\"hmac/contract/export\",\"status\":\"pass\"}\n",
            "",
        );
        assert_mentions(&f.errors(false), "has no result line");
    }

    #[test]
    fn envelope_mismatch() {
        let f = fixture();
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"target\":\"jco-node\"",
            "\"target\":\"other\"",
        );
        assert_mentions(&f.errors(false), "envelope target");
    }

    #[test]
    fn mixed_suite_selects_in_one_row() {
        let f = fixture();
        replace_registry(
            &f,
            "select = [\"shared:hmac/\"]",
            "select = [\"shared:hmac/\", \"signing:ecdsa-sign/\"]",
        );
        assert_mentions(&f.errors(false), "mixes suites");
    }

    #[test]
    fn malformed_select() {
        let f = fixture();
        replace_registry(&f, "select = [\"shared:hmac/\"]", "select = [\"hmac/\"]");
        assert_mentions(&f.errors(false), "malformed select");
    }

    #[test]
    fn column_not_in_any_manifest() {
        let f = fixture();
        replace_registry(
            &f,
            "[[groups]]\nid = \"mac\"",
            "[[columns]]\ntarget = \"ghost\"\nlabel = \"Ghost\"\nkind = \"host\"\n\n[[groups]]\nid = \"mac\"",
        );
        assert_mentions(&f.errors(false), "is in no target manifest");
    }

    #[test]
    fn empty_group() {
        let f = fixture();
        replace_registry(
            &f,
            "[[rows]]\nid = \"ecdsa-sign\"\ngroup = \"signature\"",
            "[[rows]]\nid = \"ecdsa-sign\"\ngroup = \"mac\"",
        );
        let errs = f.errors(false);
        assert_mentions(&errs, "has no rows");
    }

    /// `cases` entries match exactly: the aspect claims its named case and
    /// the run succeeds as with the equivalent prefix select.
    #[test]
    fn exact_cases_match_exactly() {
        let f = fixture();
        replace_registry(
            &f,
            "select = [\"shared:aes-gcm/wycheproof/tc2/\"]",
            "cases = [\"shared:aes-gcm/wycheproof/tc2/whole\"]",
        );
        let out = f.run(false).expect("exact case select validates");
        let row = out
            .groups
            .iter()
            .flat_map(|g| &g.rows)
            .find(|r| r.id == "aes-gcm")
            .expect("the aes-gcm row exists");
        assert_eq!(row.aspects.len(), 1);
    }

    /// A prefix-shaped string under `cases` names no census case and is a
    /// dead entry, not a silent prefix match.
    #[test]
    fn exact_cases_do_not_prefix_match() {
        let f = fixture();
        replace_registry(
            &f,
            "select = [\"shared:aes-gcm/wycheproof/tc2/\"]",
            "cases = [\"shared:aes-gcm/wycheproof/tc2/\"]",
        );
        let errs = f.errors(false);
        assert_mentions(&errs, "dead case `shared:aes-gcm/wycheproof/tc2/`");
    }

    fn merge_node_into_wasmtime(f: &Fixture) {
        replace_registry(
            f,
            "[[columns]]\ntarget = \"wasmtime-rustcrypto\"\nlabel = \"Wasmtime\"\nkind = \"implementation\"\n\n[[columns]]\ntarget = \"jco-node\"\nlabel = \"Node\"\nkind = \"host\"\n",
            "[[columns]]\ntarget = \"wasmtime-rustcrypto\"\nlabel = \"Wasmtime\"\nkind = \"implementation\"\nmerges = \"jco-node\"\n",
        );
    }

    /// Arms that agree fold into one column: the merged target's cells
    /// leave the output and the column carries both arms' presence.
    #[test]
    fn merged_column_folds_identical_arms() {
        let f = fixture();
        merge_node_into_wasmtime(&f);
        // Make the jco-node arm identical to wasmtime's: it serves
        // sha1-checked too.
        replace_targets(
            &f,
            "missing-features = [\"sha1-checked\"]",
            "missing-features = []",
        );
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"case\":\"sha1/wycheproof/tc1/whole\",\"status\":\"not-applicable\"",
            "\"case\":\"sha1/wycheproof/tc1/whole\",\"status\":\"pass\"",
        );
        patch_result(
            &f,
            "results/jco-node.jsonl",
            "\"case\":\"sha1/wycheproof/tc2/whole\",\"status\":\"not-applicable\"",
            "\"case\":\"sha1/wycheproof/tc2/whole\",\"status\":\"pass\"",
        );
        let out = f.run(false).expect("identical arms fold");
        for row in out.groups.iter().flat_map(|g| &g.rows) {
            assert!(
                !row.cells.contains_key("jco-node"),
                "row `{}` still carries the folded arm",
                row.id
            );
        }
        assert_eq!(
            cell(&out, "sha1-checked", "wasmtime-rustcrypto").support,
            "yes"
        );
        let col = out
            .columns
            .iter()
            .find(|c| c.target == "wasmtime-rustcrypto")
            .expect("the merged column exists");
        assert!(col.present.shared && col.present.signing);
        assert!(!out.columns.iter().any(|c| c.target == "jco-node"));
    }

    /// Arms that disagree fail the build: the merge is sound exactly
    /// while the platforms behave identically.
    #[test]
    fn merged_column_divergence_is_an_error() {
        let f = fixture();
        merge_node_into_wasmtime(&f);
        let errs = f.errors(false);
        assert_mentions(&errs, "merged column arms diverge");
    }

    /// A no-data primary takes the merged arm's cells instead of
    /// erroring: run shape is not behavior.
    #[test]
    fn merged_column_folds_over_no_data() {
        let f = fixture();
        merge_node_into_wasmtime(&f);
        f.remove("results/wasmtime-rustcrypto.jsonl");
        f.remove("results/wasmtime-signing.jsonl");
        let out = f.run(false).expect("the present arm serves the column");
        assert_eq!(
            cell(&out, "sha1-checked", "wasmtime-rustcrypto").support,
            "unsupported"
        );
        assert_eq!(
            cell(&out, "hmac-sha2", "wasmtime-rustcrypto").support,
            "yes"
        );
        let col = out
            .columns
            .iter()
            .find(|c| c.target == "wasmtime-rustcrypto")
            .expect("the merged column exists");
        assert!(col.present.shared && col.present.signing);
    }

    // --- fixture editing helpers -------------------------------------------

    fn edit(f: &Fixture, rel: &str, from: &str, to: &str) {
        let text = std::fs::read_to_string(f.root.join(rel)).unwrap();
        assert!(text.contains(from), "{rel} does not contain `{from}`");
        f.write(rel, &text.replace(from, to));
    }

    fn replace_registry(f: &Fixture, from: &str, to: &str) {
        edit(f, "compat/registry.toml", from, to);
    }

    fn replace_targets(f: &Fixture, from: &str, to: &str) {
        edit(f, "targets.toml", from, to);
    }

    fn patch_result(f: &Fixture, rel: &str, from: &str, to: &str) {
        edit(f, rel, from, to);
    }

    fn add_row(f: &Fixture, toml: &str) {
        let text = std::fs::read_to_string(f.root.join("compat/registry.toml")).unwrap();
        f.write("compat/registry.toml", &format!("{text}{toml}"));
    }
}
