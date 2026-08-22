// The keystore browser probe: js/polyengine's `polymorph:webcrypto-keystore`
// host module driven against a real Chromium, where IndexedDB, the
// `CryptoKey` structured-clone steps, and a page reload all exist. The
// Deno unit suite (tests/families_test.ts) cannot reach any of that —
// Deno has no IndexedDB — so this is the lane that observes the module's
// actual promise: a key stored by one page is signed with by the next.
//
// Run it with `just polyengine-keystore-probe`, which builds the page bundle
// first (deno bundle --platform browser, the same tool the polyengine-browser
// conformance leg uses). Needs a Chromium: Playwright's pinned build
// (`npx playwright-core install chromium`) or a system Chrome, located
// the same way the conformance browser legs locate one.
//
// The page is served from memory over a loopback origin on an EPHEMERAL
// port — IndexedDB needs a real origin, and a fixed port would collide
// with a sibling checkout's probe and silently measure the wrong tree.
// The bytes served are the bytes just read from the bundle, so there is
// no build-identity question to get wrong.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { chromium } from "playwright-core";

const BUNDLE = fileURLToPath(
  new URL("../../../../target/polyengine-keystore-probe/probe.js", import.meta.url),
);

const PAGE = `<!doctype html>
<meta charset="utf-8">
<title>polymorph:webcrypto-keystore probe</title>
<script type="module" src="/probe.js"></script>
`;

async function serve(bundle) {
  const server = createServer((req, res) => {
    if (req.url === "/probe.js") {
      res.writeHead(200, { "content-type": "text/javascript" });
      res.end(bundle);
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(PAGE);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}/` };
}

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok, detail });
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
}

/** The page's module is loaded when the probe object is on the window. */
async function waitForProbe(page) {
  await page.waitForFunction(() => globalThis.keystoreProbe !== undefined, null, { timeout: 30_000 });
}

const bundle = await readFile(BUNDLE, "utf8");
if (!bundle.includes("keystoreProbe")) {
  console.error(`the bundle at ${BUNDLE} does not define the probe; rebuild it`);
  process.exit(1);
}

const { server, origin } = await serve(bundle);
const browser = await chromium.launch();
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  page.on("pageerror", (e) => console.error("page error:", e.message));
  await page.goto(origin);
  await waitForProbe(page);

  // The round trip's first half: mint a non-extractable key and store it.
  const minted = await page.evaluate(() => globalThis.keystoreProbe.mintAndPersist("pm-probe-roundtrip", "identity"));

  // A real reload: new realm, new module instances, nothing in memory
  // survives. Only the origin's IndexedDB does.
  await page.reload();
  await waitForProbe(page);

  const loaded = await page.evaluate(
    (publicKeyHex) => globalThis.keystoreProbe.loadAndSign("pm-probe-roundtrip", "identity", publicKeyHex),
    minted.publicKeyHex,
  );
  check(
    "persist, reload, load, sign: the loaded key is the key that was stored",
    loaded.loaded === true && loaded.verified === true,
    `loaded=${loaded.loaded} verified=${loaded.verified}`,
  );
  check(
    "the loaded key reports the policy it was minted with",
    loaded.extractable === false && loaded.canSign === true && loaded.algorithm === "Ed25519",
    `extractable=${loaded.extractable} canSign=${loaded.canSign} algorithm=${loaded.algorithm}`,
  );

  const extractable = await page.evaluate(() =>
    globalThis.keystoreProbe.persistExtractable("pm-probe-extractable", "identity")
  );
  check(
    "an extractable signing key is refused at persist, and nothing is stored",
    extractable.stored === false && extractable.message.includes("extractable"),
    `stored=${extractable.stored} refusal=${JSON.stringify(extractable.message)}`,
  );

  const missing = await page.evaluate(() => globalThis.keystoreProbe.loadMissing("pm-probe-roundtrip", "no-such-id"));
  check("an identifier nothing was stored under loads as none", missing.loaded === false, `loaded=${missing.loaded}`);

  const ungranted = await page.evaluate(() => globalThis.keystoreProbe.withoutKeystore());
  check(
    "without an embedder-granted namespace, both functions refuse",
    ungranted.persist.includes("no keystore") && ungranted.load.includes("no keystore"),
    `persist=${JSON.stringify(ungranted.persist)} load=${JSON.stringify(ungranted.load)}`,
  );

  const planted = await page.evaluate(() =>
    globalThis.keystoreProbe.plantedExtractable("pm-probe-planted", "identity")
  );
  check(
    "a stored key reporting extractable is not returned, and is discarded",
    planted.loaded === false && planted.remaining === false,
    `loaded=${planted.loaded} remaining=${planted.remaining}`,
  );

  const garbage = await page.evaluate(() => globalThis.keystoreProbe.plantedGarbage("pm-probe-garbage", "identity"));
  check(
    "a stored entry that is not a key is not returned, and is discarded",
    garbage.loaded === false && garbage.remaining === false,
    `loaded=${garbage.loaded} remaining=${garbage.remaining}`,
  );

  const isolation = await page.evaluate(() =>
    globalThis.keystoreProbe.namespaceIsolation("pm-probe-ns-a", "pm-probe-ns-b", "identity")
  );
  check(
    "namespaces are separate stores: one identifier, two answers",
    isolation.inA === true && isolation.inB === false,
    `inA=${isolation.inA} inB=${isolation.inB}`,
  );

  const empty = await page.evaluate(() => globalThis.keystoreProbe.emptyId("pm-probe-roundtrip"));
  check(
    "an empty identifier is refused on both functions",
    empty.persist.includes("empty") && empty.load.includes("empty"),
    `persist=${JSON.stringify(empty.persist)} load=${JSON.stringify(empty.load)}`,
  );

  const overwrite = await page.evaluate(() =>
    globalThis.keystoreProbe.restoreOverwrites("pm-probe-overwrite", "identity")
  );
  check(
    "storing twice under one identifier converges on the later key",
    overwrite.loaded === true && overwrite.isSecond === true,
    `loaded=${overwrite.loaded} isSecond=${overwrite.isSecond}`,
  );
} finally {
  await browser.close();
  server.close();
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
