// Module-private construction token for the resource classes whose
// constructors are runtime-internal (polymorph-webcrypto#391).
//
// This module is deliberately NOT re-exported from mod.ts: `deno.json`'s
// single `exports` entry (`./src/mod.ts`) is what a consumer can reach, so
// keeping `MINT` out of mod.ts makes the token unforgeable from outside the
// package rather than merely undocumented.
//
// `Symbol()` and not `Symbol.for()`: a registry symbol is reachable by name
// from any realm-sharing code, which would hand the token to exactly the
// callers the constructor guard exists to refuse. Module-private IDENTITY is
// the whole mechanism.

/** The witness that a `signing-key`/`verifying-key` came out of a minting interface in this package. */
export const MINT: unique symbol = Symbol("polymorph:webcrypto mint");
