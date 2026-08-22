// The injection probe: `webcryptoHost().inject` driven against a real
// Chromium, where the `CryptoKey`s an embedder actually holds —
// non-extractable, platform-minted — exist. The Deno unit suite covers
// the algorithms; what needs a browser here is the key shapes.
//
// Run it with `just polyengine-inject-probe`, which builds the page
// bundle first (deno bundle --platform browser, the same tool the
// polyengine-browser conformance leg uses). Needs a Chromium
// (Playwright's pinned build or a system Chrome).
//
// The page is served from memory over a loopback origin on an EPHEMERAL
// port: a fixed port would collide with a sibling checkout's probe and
// silently measure the wrong tree. The bytes served are the bytes just
// read from the bundle, so there is no build-identity question.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import process from "node:process";

import { chromium } from "playwright-core";

const BUNDLE = fileURLToPath(
  new URL("../../../../target/polyengine-inject-probe/probe.js", import.meta.url),
);

const PAGE = `<!doctype html>
<meta charset="utf-8">
<title>polymorph:webcrypto inject probe</title>
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

const bundle = await readFile(BUNDLE, "utf8");
if (!bundle.includes("injectProbe")) {
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
  await page.waitForFunction(() => globalThis.injectProbe !== undefined, null, { timeout: 30_000 });
  const run = (name) => page.evaluate((n) => globalThis.injectProbe[n](), name);

  const nonExtractable = await run("injectNonExtractable");
  check(
    "an injected non-extractable Ed25519 key signs, and the signature verifies under its public half",
    nonExtractable.isSigningKey === true && nonExtractable.verified === true,
    `isSigningKey=${nonExtractable.isSigningKey} verified=${nonExtractable.verified}`,
  );
  check(
    "its getters answer from the CryptoKey, with no package-side mint record",
    nonExtractable.extractable === false && nonExtractable.canSign === true &&
      nonExtractable.algorithm === "Ed25519" && nonExtractable.curve === null &&
      nonExtractable.hash === null && nonExtractable.length === null,
    `extractable=${nonExtractable.extractable} canSign=${nonExtractable.canSign} ` +
      `algorithm=${nonExtractable.algorithm} curve=${nonExtractable.curve} hash=${nonExtractable.hash}`,
  );

  const extractable = await run("injectExtractable");
  check(
    "an extractable key is accepted and reports extractable: policy is the embedder's, truth is the guest's",
    extractable.extractable === true && extractable.exportedBytes > 0 && extractable.verified === true,
    `extractable=${extractable.extractable} pkcs8Bytes=${extractable.exportedBytes}`,
  );

  const refusal = await run("injectedExportRefusal");
  check(
    "a non-extractable injected key refuses export through the ordinary not-extractable path, and still signs",
    refusal.payload?.kind === "not-extractable" && refusal.stillSigns === true,
    `payload=${JSON.stringify(refusal.payload)} stillSigns=${refusal.stillSigns}`,
  );

  const publicKey = await run("injectPublicKey");
  check(
    "a public key is refused at the wrap site",
    publicKey.message.includes("private"),
    JSON.stringify(publicKey.message),
  );

  const wrongSigning = await run("injectWrongSigningAlgorithm");
  check(
    "an ECDSA key is refused at the wrap site (its mint-bound digest is not on the CryptoKey)",
    wrongSigning.message.includes("Ed25519") && wrongSigning.message.includes("ECDSA"),
    JSON.stringify(wrongSigning.message),
  );

  const coexist = await run("coexistence");
  check(
    "injected and package-minted signing keys coexist in one invocation: same class, both sign",
    coexist.sameClass === true && coexist.distinct === true && coexist.mintedVerified === true &&
      coexist.injectedVerified === true && coexist.differentSignatures === true,
    `sameClass=${coexist.sameClass} minted=${coexist.mintedVerified} injected=${coexist.injectedVerified}`,
  );

  const hkdf = await run("injectHkdf");
  check(
    "an injected HKDF secret drives the package's derivation path to the platform's own answer",
    hkdf.isIkm === true && hkdf.matchesPlatform === true && hkdf.canDeriveBits === true &&
      hkdf.canDeriveKey === true,
    `isIkm=${hkdf.isIkm} matchesPlatform=${hkdf.matchesPlatform} ` +
      `canDeriveBits=${hkdf.canDeriveBits} canDeriveKey=${hkdf.canDeriveKey}`,
  );

  const bitsOnly = await run("injectHkdfBitsOnly");
  check(
    "the derive grants an injected base secret reports are the key's own usages",
    bitsOnly.canDeriveBits === true && bitsOnly.canDeriveKey === false,
    `canDeriveBits=${bitsOnly.canDeriveBits} canDeriveKey=${bitsOnly.canDeriveKey}`,
  );

  const pbkdf2 = await run("injectPbkdf2");
  check(
    "an injected PBKDF2 secret lands on the password resource and drives its path",
    pbkdf2.isPassword === true && pbkdf2.matchesPlatform === true && pbkdf2.canDeriveBits === true,
    `isPassword=${pbkdf2.isPassword} matchesPlatform=${pbkdf2.matchesPlatform}`,
  );

  const wrongDerivation = await run("injectWrongDerivationAlgorithm");
  check(
    "an AES-GCM key is refused as a derivation base secret",
    wrongDerivation.message.includes("HKDF") && wrongDerivation.message.includes("PBKDF2"),
    JSON.stringify(wrongDerivation.message),
  );

  const parity = await run("importsParity");
  check(
    "webcryptoHost().imports is exactly webcryptoImports()",
    parity.equal === true && parity.count > 0,
    `equal=${parity.equal} interfaces=${parity.count}`,
  );
} finally {
  await browser.close();
  server.close();
}

const failed = results.filter((r) => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
