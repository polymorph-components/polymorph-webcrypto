// Embedder-side key injection for the `polymorph:webcrypto` polyengine
// host module: turning a `CryptoKey` the EMBEDDER holds into the same
// typed key handle a guest receives from the package's own minting
// interfaces.
//
// Why this lives here rather than in WIT: the resource tables are
// package-internal, so an embedder implementing its own import (a
// consumer-owned `device-identity: func() -> option<signing-key>`, say)
// has no way to produce the value that import must return. That one
// piece — host object to guest-visible handle — is what this API
// supplies. Everything around it (where the key came from, how it was
// persisted, which key to hand over) is the embedder's, deliberately.
//
// The handle a guest gets from `inject.signingKey` is indistinguishable
// from one the package minted: same class, same table, same getters. It
// carries no package-side mint record, so every getter answers from the
// `CryptoKey` itself — the surface `signing-key.extractable` and the
// per-kind `can-*` getters were designed for.
//
// Policy is REPORTED, not enforced. An embedder may inject an
// extractable key, a key with no usages, a key it minted under any
// policy at all; it already holds the key, so refusing here would
// protect nothing. What the package owes the guest is a truthful
// answer — `extractable()` says true when the key is extractable, and a
// denied operation fails through the ordinary `not-permitted` path.
//
// The wrap site validates KIND, not policy: a `CryptoKey` whose
// algorithm the package's resource for that kind cannot represent is
// refused, because such a handle would have to invent the parameters
// its getters are contractually bound to report.

import { ED25519_ALGORITHM, SigningKey } from "./signature.ts";
import { Ikm, mintInjectedIkm } from "./hkdf.ts";
import { mintInjectedPassword, Password } from "./pbkdf2.ts";
import type { DerivePolicy } from "./derivation.ts";

/**
 * The package's derivation base secrets: HKDF input keying material
 * (`hkdf.ikm`) and a PBKDF2 password (`pbkdf2.password`). The
 * `derivation` kind has no single key resource — a base secret is typed
 * by the KDF that consumes it — so an injected derivation key lands on
 * whichever of the two its algorithm names.
 */
export type DerivationKey = Ikm | Password;

/** Embedder-held `CryptoKey`s as guest-visible key handles. */
export interface Inject {
  /**
   * An Ed25519 private key as a `signature.signing-key` handle.
   *
   * Only Ed25519 is served: it is the one signature algorithm whose
   * whole mint-bound record is recoverable from `[[algorithm]]`. ECDSA
   * binds a digest at mint and RSA-PSS a salt length, and WebCrypto
   * carries neither on the key (both are per-operation parameters
   * there), so a handle wrapped around one would have to invent the
   * value its `algorithm-hash` getter must report.
   */
  signingKey(key: CryptoKey): SigningKey;

  /**
   * An HKDF or PBKDF2 secret as the derivation base-secret handle its
   * algorithm names: `hkdf.ikm` for HKDF, `pbkdf2.password` for PBKDF2.
   *
   * The derive grants the handle reports come from the key's own
   * `[[usages]]`, which is where the package's own imports put them
   * too.
   */
  derivationKey(key: CryptoKey): DerivationKey;
}

function requireCryptoKey(key: CryptoKey, what: string): void {
  if (!(key instanceof CryptoKey)) {
    throw new TypeError(`inject.${what}: expected a CryptoKey, got ${key === null ? "null" : typeof key}`);
  }
}

/** The derive grants a base secret carries, read off the key rather than a mint record. */
function derivePolicyOfKey(key: CryptoKey): DerivePolicy {
  return {
    deriveBits: key.usages.includes("deriveBits"),
    deriveKey: key.usages.includes("deriveKey"),
  };
}

function injectSigningKey(key: CryptoKey): SigningKey {
  requireCryptoKey(key, "signingKey");
  if (key.type !== "private") {
    throw new TypeError(
      `inject.signingKey: a signing key is a private key; this CryptoKey is a ${key.type} key`,
    );
  }
  if (key.algorithm.name !== "Ed25519") {
    throw new TypeError(
      `inject.signingKey: this host injects Ed25519 signing keys; this CryptoKey is ${key.algorithm.name}. ` +
        "ECDSA and the RSA families bind a digest (and for RSA-PSS a salt length) at mint, and WebCrypto keeps " +
        "neither on the key, so their handles cannot be built from a CryptoKey alone.",
    );
  }
  return new SigningKey(key, ED25519_ALGORITHM);
}

function injectDerivationKey(key: CryptoKey): DerivationKey {
  requireCryptoKey(key, "derivationKey");
  if (key.type !== "secret") {
    throw new TypeError(
      `inject.derivationKey: a derivation base secret is a secret key; this CryptoKey is a ${key.type} key`,
    );
  }
  const policy = derivePolicyOfKey(key);
  switch (key.algorithm.name) {
    case "HKDF":
      return mintInjectedIkm(key, policy);
    case "PBKDF2":
      return mintInjectedPassword(key, policy);
    default:
      throw new TypeError(
        `inject.derivationKey: this host injects HKDF and PBKDF2 base secrets; this CryptoKey is ` +
          `${key.algorithm.name}. Other algorithms are keys of another kind, not derivation inputs.`,
      );
  }
}

/**
 * Build one invocation's injection functions.
 *
 * @internal — reached through `webcryptoHost()`, which pairs it with the
 * imports record it belongs to.
 */
export function createInject(): Inject {
  return { signingKey: injectSigningKey, derivationKey: injectDerivationKey };
}
