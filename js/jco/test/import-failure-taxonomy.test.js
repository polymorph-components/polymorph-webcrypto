// The import-failure taxonomy: a platform `NotSupportedError` at
// `importKey` means "this implementation does not serve the request"
// (`unsupported`), not a judgment of the material (`invalid-key`) — the
// same taxonomy `platformCall` applies elsewhere. No conformance target
// can observe the distinction: every platform on the matrix serves the
// algorithms this host mints, so their `importKey` never reports
// NotSupportedError. Hence a direct host test with a stubbed platform
// import, the same host-direct reasoning as the admission suite.

import assert from "node:assert/strict";
import { test } from "node:test";

import { MacKeyOptions, hmacSha2 } from "../webcrypto.js";

const macOptions = () => {
  const o = new MacKeyOptions();
  o.canSign(true);
  return o;
};

/**
 * Run `fn` with the platform's `importKey` replaced by a rejection of
 * `err`. The host holds the `SubtleCrypto` instance, so an own property
 * shadows the prototype method for it too; deleting the shadow restores
 * the platform.
 */
async function withImportKeyRejecting(err, fn) {
  const subtle = globalThis.crypto.subtle;
  /** @type {any} */ (subtle).importKey = () => Promise.reject(err);
  try {
    return await fn();
  } finally {
    delete (/** @type {any} */ (subtle).importKey);
  }
}

test("a platform NotSupportedError at import maps to unsupported", async () => {
  await withImportKeyRejecting(new DOMException("HMAC not served", "NotSupportedError"), () =>
    assert.rejects(
      () => hmacSha2.importKeyRaw("sha256", new Uint8Array(32), macOptions()),
      (err) => err.tag === "unsupported",
    ),
  );
});

test("any other platform import failure maps to invalid-key", async () => {
  await withImportKeyRejecting(new DOMException("bad key data", "DataError"), () =>
    assert.rejects(
      () => hmacSha2.importKeyRaw("sha256", new Uint8Array(32), macOptions()),
      (err) => err.tag === "invalid-key",
    ),
  );
});
