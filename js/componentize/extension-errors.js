// @ts-check
// The `DOMException` names for the package's named extension conditions,
// by (`origin`, `name`) pair: the WebCrypto-vocabulary mirror of the
// package registry, `wit/extension-conditions.json`.
// `check-extension-conditions.mjs` (run by `just componentize::typecheck`)
// fails when the two drift. A pair not listed here is handled as an
// operational failure — the package's rule for unrecognized pairs (see
// `mapWitError` in webcrypto.js).

/** @type {Readonly<Record<string, Readonly<Record<string, string>> | undefined>>} */
export const EXTENSION_ERRORS = Object.freeze({
  "polymorph:webcrypto": Object.freeze({
    "collision-detected": "OperationError",
    "message-too-long": "OperationError",
  }),
});
