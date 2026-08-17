// The jco browser legs' shard worker: upstream's browser-worker.mjs at
// the locked component-test rev, minus one line — the `freshCases`
// callback — so one component instance serves a worker's whole shard
// instead of ~19.9k instantiations per suite serving one case each.
//
// REUSE RATIONALE (the deltic-deno leg's, measured there at ~22x —
// see ../deltic/run.ts "CONTAINMENT MODE" for the full argument): a
// fresh instance per case is ~free under wasmtime but dominates wall
// time under a browser engine — Gecko most of all, where the fresh
// convention priced the jco-firefox leg near an hour. Reuse is sound
// for THESE suites specifically because they are KAT-shaped —
// cross-case contamination cannot manufacture a quiet green, only loud
// noise: a positive KAT compares outputs against fixed vectors, a
// contamination-flipped negative KAT reports as an undeclared failure
// (the aggregate goes red), and a contaminated pass of a declared
// expected-fail trips the stale-declaration check (also red). The
// residual hazard is the poisoning clause (a trap or timed-out JSPI
// suspension wedges the shared instance): later rows are then loudly
// wrong or the stall watchdog fires — never quietly green. When
// debugging any such run, `run-browser.mjs --fresh-cases` restores the
// upstream worker's per-case containment.
//
// Everything else mirrors the upstream worker verbatim (the run
// message, the reply kinds, the unhandled-rejection guard); a pin bump
// that changes the upstream worker's contract must be reflected here.

import {
  inventoryLookup,
  resolveTestsExport,
  runCases,
} from "/__component-test/viewer/harness.mjs";
import { Context as DefaultContext } from "/__component-test/viewer/context.js";

// A rejection escaping the awaited chain (e.g. a platform quirk
// surfacing through the transpiled guest's async plumbing) would
// otherwise leave the worker silently wedged: unhandled rejections
// fire neither the catch below nor the page's worker.onerror.
self.onunhandledrejection = (event) => {
  event.preventDefault?.();
  self.postMessage({ kind: "error", error: String(event.reason?.stack ?? event.reason) });
};

self.onmessage = async ({ data }) => {
  const {
    moduleUrl,
    coreUrls,
    importsUrl,
    contextUrl,
    env = [],
    missing = [],
    only,
    shard,
    caseTimeoutMs,
  } = data;
  try {
    const coreBytes = [];
    const modules = new Map();
    for (const url of coreUrls) {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`fetching ${url}: ${res.status}`);
      const bytes = new Uint8Array(await res.arrayBuffer());
      coreBytes.push(bytes);
      // instantiate() asks for cores by file name.
      modules.set(
        new URL(url, self.location.href).pathname.split("/").pop(),
        await WebAssembly.compile(bytes),
      );
    }
    const tagsOf = inventoryLookup(coreBytes);

    const { instantiate } = await import(moduleUrl);
    const { suiteImports } = await import(importsUrl);
    const Context = contextUrl ? (await import(contextUrl)).Context : DefaultContext;
    const imports = await suiteImports(env);
    const newTests = async () =>
      resolveTestsExport(await instantiate((name) => modules.get(name), imports));

    const counts = await runCases({
      cases: await (await newTests()).all(),
      Context,
      tagsOf,
      missing,
      only,
      shard,
      caseTimeoutMs,
      emit: (event, index) => self.postMessage({ kind: "event", index, event }),
    });
    self.postMessage({ kind: "counts", counts });
  } catch (err) {
    self.postMessage({ kind: "error", error: String(err?.stack ?? err) });
  }
};
