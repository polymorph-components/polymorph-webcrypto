// Stage component-test's results viewer (js/viewer at the Cargo.lock-
// pinned checkout, argv[2]) into ./viewer/, wired to this repository's
// data: the demo button loads the committed lockfiles/manifests plus
// the last run's results-JSONL, and the live pane defaults to this
// repository's suites — runtime-linked through the polyengine-browser
// worker bundle (built by `just conformance-ct::_polyengine-browser-bundle`).
// Every injected path is RELATIVE to the viewer page: the page is
// served from two roots that both mirror the repository layout — the
// repo root locally (`just conformance-ct::web`) and the project
// subpath on the published Pages site — and only page-relative URLs
// resolve inside both. Every rewrite is anchored on the upstream source
// it replaces and fails loudly when a pin bump changes the page's
// shape — the transforms then need re-anchoring, which is exactly the
// review the bump owes.
//
// Invoked by `conformance-ct::_viewer-prepared`, which also stages the
// viewer's wasm engine (the raw viewer-aggregate component — polyengine
// translates it in-page; no transpile) and the pinned polyengine release
// assets into viewer/generated/ and viewer/polyengine/; ./viewer/ is
// gitignored, stamped with the rev.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [src] = process.argv.slice(2);
if (!src) {
  console.error("usage: stage-viewer.mjs <component-test checkout>");
  process.exit(2);
}
const from = join(src, "js/viewer");
mkdirSync("viewer", { recursive: true });

/** Replace exactly one occurrence, or fail naming the missing anchor. */
function rewrite(text, anchor, replacement, what) {
  const first = text.indexOf(anchor);
  if (first === -1 || text.indexOf(anchor, first + 1) !== -1) {
    throw new Error(
      `stage-viewer: anchor for ${what} not found exactly once — the upstream ` +
        `viewer changed shape at this pin; re-anchor the transforms in stage-viewer.mjs`,
    );
  }
  return text.slice(0, first) + replacement + text.slice(first + anchor.length);
}

// Pass-through files: the page's import closure — app.mjs pulls
// harness.mjs and polyengine.mjs, and harness.mjs pulls context.js.
for (const file of ["viewer.css", "harness.mjs", "polyengine.mjs", "context.js"]) {
  copyFileSync(join(from, file), join("viewer", file));
}

// index.html: this repository's live-pane defaults, and a suite picker
// beside the demo button.
let html = readFileSync(join(from, "index.html"), "utf8");
html = rewrite(
  html,
  `<button id="btn-demo" class="secondary" title="Load the fixture-suite walkthrough from this repository (needs the page served from the repo root)">Load demo</button>`,
  `<select id="demo-suite" title="Which conformance suite to load"><option value="shared">shared suite</option><option value="signing">signing suite</option></select>\n` +
    `      <button id="btn-demo" class="secondary" title="Load this repository's committed inventory and the staged results (locally: the last conformance-ct run)">Load this repo's results</button>`,
  "the demo button",
);
html = rewrite(
  html,
  `<input type="text" id="live-url" value="./suite/" spellcheck="false">`,
  `<input type="text" id="live-url" value="../../../../target/wasm32-wasip2/release/conformance_guest_ct.wasm" title="A suite COMPONENT wasm, page-relative or absolute (locally: build with just conformance-ct::build)" spellcheck="false">`,
  "the live suite URL default",
);
html = rewrite(
  html,
  `<input type="text" id="live-name" value="fixture-suite" list="known-suites" spellcheck="false">`,
  `<input type="text" id="live-name" value="conformance-guest-ct" list="known-suites" spellcheck="false">`,
  "the live suite name default",
);
html = rewrite(
  html,
  `<option value="sample-suite"><option value="fixture-suite">`,
  `<option value="conformance-guest-ct"><option value="conformance-signing-guest-ct">`,
  "the known-suites options",
);
html = rewrite(
  html,
  `<input type="text" id="live-missing" placeholder="hsm" spellcheck="false">`,
  `<input type="text" id="live-missing" value="sha1-checked" title="jco-browser's declarations: sha1-checked (shared); rsa-sign,rsa-oaep-decrypt (signing)" spellcheck="false">`,
  "the live missing-features default",
);
html = rewrite(
  html,
  `<input type="text" id="live-target" value="native" spellcheck="false">`,
  `<input type="text" id="live-target" value="polyengine-browser" spellcheck="false">`,
  "the live target default",
);
writeFileSync("viewer/index.html", html);

// app.mjs: the demo handler loads this repository's suites instead of
// the fixture walkthrough. The replacement spans the whole upstream
// handler, anchored on its opening line and the fetch path it must
// contain (both change => re-anchor).
let app = readFileSync(join(from, "app.mjs"), "utf8");
const start = app.indexOf(`$("btn-demo").onclick = async () => {`);
const end = app.indexOf("\n};", start);
if (
  start === -1 ||
  end === -1 ||
  !app.slice(start, end).includes("../../components/fixture-suite/tests.lock")
) {
  throw new Error(
    "stage-viewer: the demo handler moved or changed shape at this pin; " +
      "re-anchor the transforms in stage-viewer.mjs",
  );
}
const handler = `$("btn-demo").onclick = async () => {
  // This repository's committed inventory and manifests, plus the
  // results-JSONL under conformance/driver-ct/results/ — locally the
  // last \`just conformance-ct::all\` run, on the published page the
  // latest main CI run's artifact. Paths are page-relative (the page is
  // served from a repo-layout-mirroring root both locally and on the
  // published site); \`at\` resolves them against this module. Absent
  // streams (e.g. the optional jco-browser leg of a local run) are
  // skipped; the aggregate then reports the absence per the manifest's
  // optionality.
  const at = (path) => new URL(path, import.meta.url).href;
  const ROOT = "../../../../";
  const RESULTS = ROOT + "conformance/driver-ct/results/";
  const SUITES = {
    shared: {
      lock: ROOT + "conformance/guest-ct/tests.lock",
      manifest: ROOT + "conformance/driver-ct/targets.toml",
      streams: [
        ["wasmtime-rustcrypto", RESULTS + "wasmtime-rustcrypto.jsonl"],
        ["composed", RESULTS + "composed.jsonl"],
        ["jco-node", RESULTS + "jco-node.jsonl"],
        ["jco-browser", RESULTS + "jco-browser.jsonl"],
        ["jco-firefox", RESULTS + "jco-firefox.jsonl"],
        ["jco-webkit", RESULTS + "jco-webkit.jsonl"],
        ["polyengine-deno", RESULTS + "polyengine-deno.jsonl"],
        ["polyengine-browser", RESULTS + "polyengine-browser.jsonl"],
      ],
    },
    signing: {
      lock: ROOT + "conformance/signing-guest-ct/tests.lock",
      manifest: ROOT + "conformance/driver-ct/targets-signing.toml",
      streams: [
        ["wasmtime-rustcrypto", RESULTS + "wasmtime-signing.jsonl"],
        ["jco-node", RESULTS + "jco-node-signing.jsonl"],
        ["jco-browser", RESULTS + "jco-browser-signing.jsonl"],
        ["jco-firefox", RESULTS + "jco-firefox-signing.jsonl"],
        ["jco-webkit", RESULTS + "jco-webkit-signing.jsonl"],
        ["polyengine-deno", RESULTS + "polyengine-deno-signing.jsonl"],
        ["polyengine-browser", RESULTS + "polyengine-browser-signing.jsonl"],
      ],
    },
  };
  const pick = SUITES[$("demo-suite")?.value] ?? SUITES.shared;
  const get = async (path) => {
    const res = await fetch(at(path));
    if (!res.ok)
      throw new Error(\`\${path}: \${res.status} (locally, serve from the repo root: just conformance-ct::web)\`);
    return res.text();
  };
  try {
    state.lock = await get(pick.lock);
    state.manifest = await get(pick.manifest);
    state.streams = [];
    for (const [target, path] of pick.streams) {
      const res = await fetch(at(path));
      if (!res.ok) continue;
      state.streams.push({ target, text: await res.text(), source: path.split("/").pop() });
    }
    refreshInputs();
    renderAggregate();
  } catch (err) {
    alert(String(err?.message ?? err));
  }
};`;
// Replace [start, end + "\n};".length) — the whole upstream handler —
// with the new one, which carries its own closing.
app = app.slice(0, start) + handler + app.slice(end + "\n};".length);
// app.mjs: the live pane's shard worker must serve this package's
// imports — the suites are runtime-linked and import polymorph:webcrypto,
// which upstream's stock (no-SUT) worker cannot satisfy — so it is the
// polyengine-browser worker bundle (polyengine engine + this repo's host module),
// built by `just conformance-ct::_polyengine-browser-bundle` and served from
// target/polyengine-browser/ (page-relative: the repo root is four levels up
// from viewer/). The translator must match the bundled engine's pin —
// this repository's polyengine pin, not the viewer checkout's — so the
// worker message's translatorUrl is rewritten to the shim extracted
// beside the bundle instead of the viewer's own polyengine assets.
app = rewrite(
  app,
  `new URL("../runner-polyengine/browser-worker.mjs", import.meta.url),`,
  `new URL("../../../../target/polyengine-browser/webcrypto-worker.mjs", import.meta.url),`,
  "the live pane's worker URL",
);
app = rewrite(
  app,
  `            bundleUrl,
            translatorUrl,
            suiteUrl,`,
  `            bundleUrl,
            translatorUrl: new URL(
              "../../../../target/polyengine-browser/polyengine-translator-shim.wasm",
              import.meta.url,
            ).href,
            suiteUrl,`,
  "the live pane's translator URL",
);
writeFileSync("viewer/app.mjs", app);

console.log("staged component-test viewer into viewer/");
