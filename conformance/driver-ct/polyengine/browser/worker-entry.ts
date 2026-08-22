// The polyengine-browser shard worker's bundle entry: the polyengine engine
// surface (../browser-bundle-entry.ts, resolved through this repo's
// exact-pinned JSR import map), the upstream
// worker message loop, and this repo's polyengine host module, resolved
// through ONE import map so the emitted bundle carries exactly one
// embedder module instance — which is what keeps `instanceof ComponentException`
// true when the host module throws across the component boundary
// (workers resolve no import maps, so bundling is the only sound shape;
// see @jsr/polymorph__test's runner-polyengine README).
//
// Built by `just conformance-ct::_polyengine-browser-bundle` with
// `deno bundle --platform browser` into target/polyengine-browser/, and
// served to the page from there: as runSuitesInPage's workerUrl by the
// conformance leg, and as the staged results viewer's live-pane worker
// (locally and on the published Pages site). Both suites (shared +
// signing) run through this one worker; the host module reads no
// configuration, so `suiteImports` is the plain record.

import * as polyengine from "../browser-bundle-entry.ts";
import { workerMain } from "@polymorph/test/polyengine-worker-main";
import { setRsaPrivateKeyPolicy, webcryptoImports } from "../../../../js/polyengine/src/mod.ts";

// The browser posture, matching the jco-browser rows: a browser is an
// attacker-observable timing domain, so the gated RSA private-key mints
// (`rsa-sign`, `rsa-oaep-decrypt`) fail closed — the targets declare the
// features missing and the suites' `!feature` decline probes assert the
// refusal.
setRsaPrivateKeyPolicy("decline");

workerMain({
  polyengine,
  suiteImports: () => webcryptoImports(),
});
