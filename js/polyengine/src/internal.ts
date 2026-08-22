// Package-private plumbing for the embedder key seams
// (polymorph-webcrypto#391): the construction token every CryptoKey-holding
// resource class is gated on, and the laundering step every `fromCryptoKey`
// runs before it looks at a caller-supplied key.
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

import { errInvalidKey, errNotPermitted, errOther, errUnsupported } from "./errors.ts";

/**
 * The witness that a key resource came out of a minting interface in this
 * package.
 *
 * Every class in this package that holds a `CryptoKey` behind a `#private`
 * field takes this as its first constructor argument and refuses anything
 * else: `signing-key`, `verifying-key`, `mac-key`, `aead-key`, `cipher-key`,
 * `kw-key`, `encryption-key`, `decryption-key`, and key-agreement's
 * `secret-key` / `public-key`. The classes whose state lives in a
 * module-private `WeakMap` instead (`ikm`, `password`) are already
 * unconstructible-in-effect — a bare instance carries no state and every
 * method refuses it — and keep their WeakMap provenance check.
 */
export const MINT: unique symbol = Symbol("polymorph:webcrypto mint");

/**
 * The refusal a token-gated constructor renders, phrased to match the
 * package's WeakMap provenance idiom ("… minted by another provider",
 * derivation.ts:23, aead.ts:31).
 */
export function requireMint(token: unknown, resource: string): void {
  if (token !== MINT) {
    // Deliberately `other`: this is not a bad key or a denied usage, it is a
    // resource that never came from a minting interface at all.
    errOther(`${resource} constructed outside its minting interfaces`);
  }
}

/**
 * Launder an embedder-supplied `CryptoKey` into a clone this package owns —
 * the first step of every `fromCryptoKey` (polymorph-webcrypto#391).
 *
 * `CryptoKey`'s internal slots are immutable, but its PROTOTYPE GETTERS are
 * shadowable: `Object.defineProperty(key, "usages", { value: [...] })` makes
 * `key.usages` say whatever the caller likes, and the same trick works on
 * `algorithm`, `type` and `extractable`. Structured clone serializes the
 * internal slots only and drops own properties, so the clone answers with
 * platform truth. Validating and storing the CLONE — never the argument — is
 * what makes every downstream policy mirror trustworthy, and it also denies
 * the caller a live handle to the key the resource operates with.
 *
 * The same call is the clone-OUT step of every `toCryptoKey`, for the mirror
 * reason: a fresh clone per call keeps the resource's own key unreachable, so
 * nothing a caller writes on a returned key is observable by the resource.
 */
export function launderCryptoKey(what: string, key: CryptoKey): CryptoKey {
  try {
    return structuredClone(key);
  } catch {
    // Not a taxonomy fudge: on a host whose structured-clone algorithm does
    // not serialize `CryptoKey`, injecting or extracting a host-held key is a
    // well-formed request this implementation cannot serve.
    errUnsupported(
      `${what}: this host does not serialize CryptoKey (structured clone), which key injection requires`,
    );
  }
}

/** The shape gate shared by every `fromCryptoKey`: a real platform key, not a duck-typed stand-in. */
export function requirePlatformKey(what: string, key: CryptoKey): void {
  if (!(key instanceof CryptoKey)) {
    errInvalidKey(`${what} takes a platform CryptoKey`);
  }
}

/** Shape-check and launder in one step — what every `fromCryptoKey` opens with. */
export function injectedKey(what: string, key: CryptoKey): CryptoKey {
  requirePlatformKey(what, key);
  return launderCryptoKey(what, key);
}

/** The `secret`/`private`/`public` half a `fromCryptoKey` requires, refused as `invalid-key` (a wrong half is a wrong key, not a denied usage). */
export function requireKeyType(what: string, key: CryptoKey, type: KeyType): void {
  if (key.type !== type) {
    errInvalidKey(`${what} takes a ${type} key, got a ${key.type} key`);
  }
}

/** The algorithm name a `fromCryptoKey` requires (checked on the laundered clone, so a shadowed `algorithm` cannot cross a family boundary). */
export function requireAlgorithmName(what: string, key: CryptoKey, name: string): void {
  if (key.algorithm.name !== name) {
    errInvalidKey(`${what} takes a ${name} key, got ${key.algorithm.name}`);
  }
}

/**
 * The at-least-one-usage rule for an injected key.
 *
 * This mirrors the package-wide mint rule that an options resource granting
 * nothing cannot mint (derivation.ts:50-52, errors.ts:139-141): a key that
 * permits none of the operations its resource exists to perform is a
 * degenerate injection, refused loudly at the seam rather than minted into a
 * resource that will only fail at first use.
 */
export function requireSomeUsage(granted: boolean, resource: string, operations: string): void {
  if (!granted) {
    errNotPermitted(`a ${resource} permitting neither ${operations} cannot be injected`);
  }
}
