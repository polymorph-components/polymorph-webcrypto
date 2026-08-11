// The deltic-browser shard worker's bundle entry: the deltic engine
// surface (../browser-bundle-entry.ts, resolved through this repo's
// exact-pinned JSR import map), the upstream
// worker message loop, and this repo's deltic host module, resolved
// through ONE import map so the emitted bundle carries exactly one
// embedder module instance — which is what keeps `instanceof WitError`
// true when the host module throws across the component boundary
// (workers resolve no import maps, so bundling is the only sound shape;
// see @polymorph/component-test-js's runner-deltic README).
//
// Built by `just conformance-ct::run-deltic-browser` with
// `deno bundle --platform browser` into target/deltic-browser/, and
// served to the page from there as runSuitesInPage's workerUrl. Both
// suites (shared + signing) run through this one worker; the host
// module reads no configuration, so `suiteImports` is the plain record.

import * as deltic from "../browser-bundle-entry.ts";
import { workerMain } from "@polymorph/component-test-js/deltic-worker-main";
import { setRsaPrivateKeyPolicy, webcryptoImports } from "../../../../js/deltic/src/mod.ts";

// The browser posture, matching the jco-browser rows: a browser is an
// attacker-observable timing domain, so the gated RSA private-key mints
// (`rsa-sign`, `rsa-oaep-decrypt`) fail closed — the targets declare the
// features missing and the suites' `!feature` decline probes assert the
// refusal.
setRsaPrivateKeyPolicy("decline");

workerMain({
  deltic,
  suiteImports: () => webcryptoImports(),
});
