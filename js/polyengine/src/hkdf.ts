// `polymorph:webcrypto/hkdf` + `hkdf-sha2` + `hkdf-sha1` — wit/hkdf.wit.

import { errInvalidKey, errNotPermitted, errOther, errUnsupported, notPermitted, platformCall } from "./errors.ts";
import {
  DeriveInput,
  type DerivePolicy,
  deriveUsages,
  inputStateOf,
  mintDeriveInput,
  readDerivePolicy,
} from "./derivation.ts";
import { consumeUnwrapInput, type UnwrapInput } from "./wrapping.ts";
import { asBufferSource } from "./util.ts";
import type { DeriveOptions } from "./derivation.ts";

const subtle = globalThis.crypto.subtle;

const ikmState = new WeakMap<Ikm, { key: CryptoKey; policy: DerivePolicy }>();

/**
 * `hkdf.ikm`: input keying material, consumable only by `prepare`.
 *
 * The constructor is effectively internal already — all state lives in the
 * module-private `ikmState` WeakMap, so a bare `new Ikm()` yields an object
 * every method refuses. The supported external construction path is
 * {@link Ikm.fromCryptoKey} (polymorph-webcrypto#391).
 */
export class Ikm {
  canDeriveBits(): boolean {
    return ikmState.get(this)!.policy.deriveBits;
  }
  canDeriveKey(): boolean {
    return ikmState.get(this)!.policy.deriveKey;
  }

  /**
   * Adopt an embedder-held HKDF `CryptoKey` — the injection half of the
   * persistence seam (polymorph-webcrypto#391): an embedder that keeps its
   * input keying material as a NON-EXTRACTABLE `CryptoKey` in IndexedDB gets
   * it back as an `ikm` here, instead of having to hold the raw bytes.
   *
   * Synchronous, and validating: a platform `CryptoKey`, of type `secret`,
   * with `algorithm.name === "HKDF"`.
   *
   * The derive policy is READ OFF THE PLATFORM USAGES rather than taken from a
   * `derive-options` — for an injected key the platform's `deriveBits` /
   * `deriveKey` slots ARE the policy, since loading is itself a minting path
   * and the platform will refuse anything the slots do not cover regardless of
   * what this wrapper claimed. A key with neither derive usage is a degenerate
   * injection and is refused (`not-permitted`), the same rule as an options
   * resource granting nothing (derivation.ts:50-52).
   *
   * Validation and storage both use a LAUNDERED clone (see
   * signature.ts's `launderCryptoKey` for the reasoning): `usages` and
   * `algorithm` are shadowable own-property accessors on the caller's object,
   * and structured clone carries only the internal slots, so `canDeriveBits()`
   * answers platform truth and no caller retains a handle to the key this
   * `ikm` derives with.
   */
  static fromCryptoKey(key: CryptoKey): Ikm {
    const what = "ikm injection";
    if (!(key instanceof CryptoKey)) errInvalidKey(`${what} takes a platform CryptoKey`);
    let clone: CryptoKey;
    try {
      clone = structuredClone(key);
    } catch {
      errUnsupported(
        `${what}: this host does not serialize CryptoKey (structured clone), which key injection requires`,
      );
    }
    if (clone.type !== "secret") {
      errInvalidKey(`${what} takes a secret key, got a ${clone.type} key`);
    }
    if (clone.algorithm.name !== "HKDF") {
      errInvalidKey(`${what} takes an HKDF key, got ${clone.algorithm.name}`);
    }
    const policy: DerivePolicy = {
      deriveBits: clone.usages.includes("deriveBits"),
      deriveKey: clone.usages.includes("deriveKey"),
    };
    if (!policy.deriveBits && !policy.deriveKey) {
      errNotPermitted("an ikm permitting neither derive-bits nor derive-key cannot be injected");
    }
    return mintIkm(clone, policy);
  }

  /**
   * Hand back the platform key — the extraction half of the persistence seam
   * (polymorph-webcrypto#391). The returned `CryptoKey` is structured-clonable
   * into IndexedDB with its non-extractability preserved, which is how keying
   * material is meant to outlive a session.
   *
   * Security framing, as on `signing-key`: material confidentiality belongs to
   * the `extractable` bit and stays platform-enforced in both directions —
   * `hkdf.import-ikm` mints non-extractable and this hands back a key, not
   * bytes. What the wrapper scopes is the USE capability in durable,
   * parameter-free form: a raw HKDF `CryptoKey` derives under any salt/info/
   * hash its holder picks, whereas an `ikm` is consumable only through
   * `prepare` under the policy above. Returning a FRESH CLONE per call keeps
   * the wrapper's own key unreachable, so that scoping is total.
   *
   * Inverse of {@link Ikm.fromCryptoKey}: the returned key satisfies that
   * validation by construction (the derive policy round-trips through the
   * platform usages).
   */
  toCryptoKey(): CryptoKey {
    const state = ikmState.get(this);
    if (state === undefined) errOther("ikm minted by another provider");
    return structuredClone(state.key);
  }
}

function mintIkm(key: CryptoKey, policy: DerivePolicy): Ikm {
  const ikm = new Ikm();
  ikmState.set(ikm, { key, policy: { ...policy } });
  return ikm;
}

async function importIkmKey(raw: Uint8Array, options: DeriveOptions): Promise<Ikm> {
  const policy = readPolicy(options);
  const usages = deriveUsages(policy);
  const key = await platformCall("HKDF import ikm", () =>
    subtle.importKey("raw", asBufferSource(raw), "HKDF", false, usages));
  return mintIkm(key, policy);
}

// `DeriveOptions` exposes only mint-time setters per the WIT; `hkdf`'s
// `import-ikm`/`unwrap-ikm` need the accumulated policy to mint an `ikm`,
// so `derivation.ts` exports a read accessor rather than this module
// re-deriving it by hand.
function readPolicy(options: DeriveOptions): DerivePolicy {
  return readDerivePolicy(options);
}

/** The `polymorph:webcrypto/hkdf@0.1.0` interface. */
export const hkdf = {
  Ikm,
  importIkm: (raw: Uint8Array, options: DeriveOptions): Promise<Ikm> => importIkmKey(raw, options),
  unwrapIkm: (input: UnwrapInput, options: DeriveOptions): Promise<Ikm> => {
    const { bytes } = consumeUnwrapInput(input);
    return importIkmKey(bytes, options);
  },
};

const SHA2_HASH: Readonly<Record<string, string | undefined>> = Object.freeze({
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
});

function sha2Hash(variant: string): string {
  const hash = SHA2_HASH[variant];
  if (hash === undefined) errUnsupported(`${variant} is not served by this implementation`);
  return hash;
}

async function prepare(hash: string, input: Ikm, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput> {
  const state = ikmState.get(input);
  if (state === undefined) {
    errOther("ikm minted by another provider");
  }
  const params = {
    name: "HKDF",
    hash,
    salt: asBufferSource(salt.slice()),
    info: asBufferSource(info.slice()),
  };
  return mintDeriveInput(state.key, params, state.policy, /* hasNaturalLength */ false);
}

async function prepareFrom(
  hash: string,
  input: DeriveInput,
  salt: Uint8Array,
  info: Uint8Array,
): Promise<DeriveInput> {
  const upstream = inputStateOf(input);
  if (!upstream.policy.deriveKey) notPermitted("derive-key");
  if (!upstream.hasNaturalLength) {
    errOther(
      "chaining from another KDF's input is not served: a KDF's output length is a caller choice, not natural",
    );
  }
  const secret = await subtle.deriveBits(upstream.params, upstream.key, null as unknown as number);
  const key = await subtle.importKey("raw", secret, "HKDF", false, deriveUsages(upstream.policy));
  const params = {
    name: "HKDF",
    hash,
    salt: asBufferSource(salt.slice()),
    info: asBufferSource(info.slice()),
  };
  return mintDeriveInput(key, params, upstream.policy, false);
}

/** The `polymorph:webcrypto/hkdf-sha2@0.1.0` interface. */
export const hkdfSha2 = {
  prepare: (variant: string, input: Ikm, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput> =>
    prepare(sha2Hash(variant), input, salt, info),
  prepareFrom: (variant: string, input: DeriveInput, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput> =>
    prepareFrom(sha2Hash(variant), input, salt, info),
};

/** The `polymorph:webcrypto/hkdf-sha1@0.1.0` interface. */
export const hkdfSha1 = {
  prepare: (input: Ikm, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput> =>
    prepare("SHA-1", input, salt, info),
  prepareFrom: (input: DeriveInput, salt: Uint8Array, info: Uint8Array): Promise<DeriveInput> =>
    prepareFrom("SHA-1", input, salt, info),
};
