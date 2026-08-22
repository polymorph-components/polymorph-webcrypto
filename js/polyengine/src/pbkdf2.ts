// `polymorph:webcrypto/pbkdf2` plus `pbkdf2-sha1` / `pbkdf2-sha2` —
// wit/pbkdf2.wit.
//
// Behavioral reference: js/jco/webcrypto.js:1556-1665. Empty passwords are
// accepted (RFC 8018 admits an empty `P` and the platform serves it) —
// the documented asymmetry with `hkdf.import-ikm`. A zero iteration count
// fails at `prepare`, not at use, so a misparameterized input cannot mint.

import { errOther, platformCall } from "./errors.ts";
import {
  DeriveInput,
  type DeriveOptions,
  type DerivePolicy,
  deriveUsages,
  mintDeriveInput,
  readDerivePolicy,
} from "./derivation.ts";
import { asBufferSource } from "./util.ts";
import { redactingInvalidKey, served, SHA1_ENTRY, SHA2_VARIANTS } from "./platform.ts";
import { consumeUnwrapInput, type UnwrapInput } from "./wrapping.ts";
import {
  injectedKey,
  launderCryptoKey,
  requireAlgorithmName,
  requireKeyType,
  requireSomeUsage,
} from "./internal.ts";

const subtle = globalThis.crypto.subtle;

const passwordState = new WeakMap<Password, { key: CryptoKey; policy: DerivePolicy }>();

function passwordOf(p: Password): { key: CryptoKey; policy: DerivePolicy } {
  const state = passwordState.get(p);
  if (state === undefined) errOther("password minted by another provider");
  return state;
}

/**
 * `pbkdf2.password`: a password as a `PBKDF2`-bound platform key. The
 * platform forces non-extractability at import, and the WIT grants ride
 * the key's usages (reference: webcrypto.js:1570).
 *
 * The constructor is internal by construction — all state lives in the
 * module-private `passwordState` WeakMap, so a bare `new Password()` yields an
 * object every method refuses. The supported external construction path is
 * {@link Password.fromCryptoKey} (polymorph-webcrypto#391).
 */
export class Password {
  canDeriveBits(): boolean {
    return passwordOf(this).policy.deriveBits;
  }
  canDeriveKey(): boolean {
    return passwordOf(this).policy.deriveKey;
  }

  /**
   * Adopt an embedder-held PBKDF2 `CryptoKey` — the injection half of the
   * persistence seam (polymorph-webcrypto#391): an embedder that keeps a
   * password-derived key handle as a NON-EXTRACTABLE `CryptoKey` in IndexedDB
   * gets it back as a `password` here, instead of having to retain the
   * password bytes.
   *
   * `password` is a served ("tier A") kind: PBKDF2 keys take no parameters at
   * mint — salt, iteration count and digest are all bound later, at `prepare`
   * — and the WIT's `can-derive-bits`/`can-derive-key` grants are 1:1 with the
   * platform's `deriveBits`/`deriveKey` usages (pbkdf2.ts:46-54, via
   * derivation.ts:45-54). So the policy is READ OFF THE PLATFORM USAGES rather
   * than taken from a `derive-options`: for an injected key the slots ARE the
   * policy, loading being itself a minting path, and the platform refuses
   * anything the slots do not cover regardless of what this wrapper claimed.
   *
   * Synchronous, and validating: a platform `CryptoKey`, of type `secret`,
   * with `algorithm.name === "PBKDF2"`, permitting at least one derive
   * operation — a password permitting neither is a degenerate injection.
   *
   * Validation and storage both use a LAUNDERED clone: `usages` and
   * `algorithm` are shadowable own-property accessors on the caller's object,
   * and structured clone carries only the internal slots, so `canDeriveBits()`
   * answers platform truth and no caller retains a handle to the key this
   * `password` derives with.
   */
  static fromCryptoKey(key: CryptoKey): Password {
    const what = "password injection";
    const clone = injectedKey(what, key);
    requireKeyType(what, clone, "secret");
    requireAlgorithmName(what, clone, "PBKDF2");
    const policy: DerivePolicy = {
      deriveBits: clone.usages.includes("deriveBits"),
      deriveKey: clone.usages.includes("deriveKey"),
    };
    requireSomeUsage(policy.deriveBits || policy.deriveKey, "password", "derive-bits nor derive-key");
    return mintPassword(clone, policy);
  }

  /**
   * Hand back the platform key — the extraction half of the persistence seam
   * (polymorph-webcrypto#391). The returned `CryptoKey` structured-clones into
   * IndexedDB with its non-extractability intact (PBKDF2 keys are minted
   * non-extractable by the platform in any case, pbkdf2.ts:50).
   *
   * Security framing, as on `signing-key`: confidentiality of the material is
   * the `extractable` bit's job and stays platform-enforced — this hands back
   * a key, never the password bytes. What the wrapper scopes is the USE
   * capability in durable, parameter-free form: a raw PBKDF2 `CryptoKey`
   * derives under any salt, iteration count and digest its holder picks,
   * whereas a `password` is consumable only through `prepare` under the policy
   * above and under an iteration count `prepare` validates. A fresh clone per
   * call keeps the wrapper's own key unreachable.
   *
   * Inverse of {@link Password.fromCryptoKey}: the derive policy round-trips
   * through the platform usages.
   */
  toCryptoKey(): CryptoKey {
    return launderCryptoKey("password extraction", passwordOf(this).key);
  }
}

/** Bind a platform key and its policy to a fresh `password` — the one construction path for the WeakMap state. */
function mintPassword(key: CryptoKey, policy: DerivePolicy): Password {
  const password = new Password();
  passwordState.set(password, { key, policy: { ...policy } });
  return password;
}

async function importPassword(raw: Uint8Array, options: DeriveOptions): Promise<Password> {
  const policy = readDerivePolicy(options);
  const usages = deriveUsages(policy);
  const key = await platformCall("PBKDF2 password import", () =>
    subtle.importKey("raw", asBufferSource(raw), "PBKDF2", false, usages));
  return mintPassword(key, policy);
}

/** The `polymorph:webcrypto/pbkdf2@0.1.0` interface. */
export const pbkdf2 = {
  Password,
  importPassword,
  unwrapPassword: (input: UnwrapInput, options: DeriveOptions): Promise<Password> => {
    const { bytes } = consumeUnwrapInput(input);
    return redactingInvalidKey("unwrapped PBKDF2 password", () => importPassword(bytes, options));
  },
};

/** `prepare` (reference: webcrypto.js:1615): salt and work factor bound now, output length per use. */
function preparePbkdf2(hash: string, input: Password, salt: Uint8Array, iterations: number): DeriveInput {
  if (iterations === 0) {
    errOther("PBKDF2 requires a positive iteration count");
  }
  const { key, policy } = passwordOf(input);
  const params = { name: "PBKDF2", hash, salt: asBufferSource(salt.slice()), iterations };
  // PBKDF2 has no natural output length: every derivation is a caller
  // choice, so `derive-bits(none)` is refused by `DeriveInput` itself.
  return mintDeriveInput(key, params, policy, /* hasNaturalLength */ false);
}

/** The `polymorph:webcrypto/pbkdf2-sha2@0.1.0` interface. */
export const pbkdf2Sha2 = {
  prepare: (variant: string, input: Password, salt: Uint8Array, iterations: number): Promise<DeriveInput> =>
    Promise.resolve(preparePbkdf2(served(SHA2_VARIANTS, variant).hash, input, salt, iterations)),
};

/** The `polymorph:webcrypto/pbkdf2-sha1@0.1.0` interface. */
export const pbkdf2Sha1 = {
  prepare: (input: Password, salt: Uint8Array, iterations: number): Promise<DeriveInput> =>
    Promise.resolve(preparePbkdf2(SHA1_ENTRY.hash, input, salt, iterations)),
};
