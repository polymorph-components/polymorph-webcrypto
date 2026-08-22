// `polymorph:webcrypto/key-wrap` plus `aes-kw` — wit/wrapping.wit
// `interface key-wrap`, wit/aes.wit `interface aes-kw`.
//
// Behavioral reference: js/jco/webcrypto.js:3097-3440. The platform's
// AES-KW operations wrap and unwrap `CryptoKey`s, not bytes, so both
// directions route the serialized material through a throwaway
// HMAC-SHA-256 `CryptoKey` whose raw import/export accepts any non-empty
// length; the wire format is RFC 3394's either way.

import { errAuthenticationFailed, errInvalidKey, errOther, decryptFailure, notPermitted, platformCall } from "./errors.ts";
import { asBufferSource, unwrappedJwk } from "./util.ts";
import {
  AES_VARIANT_BYTES,
  aesVariantByteLength,
  exportJwkGated,
  exportRawGated,
  importPlatformKey,
  importPlatformKeyJwk,
  jwkKeyBytes,
  jwkMaterial,
  redactingInvalidKey,
  requireStrictBase64url,
} from "./platform.ts";
import { type DeriveInput, deriveKeyFrom } from "./derivation.ts";
import { consumeUnwrapInput, consumeWrapInput, UnwrapInput, WrapInput } from "./wrapping.ts";
import { grantedUsages, errUnsupported } from "./errors.ts";
import {
  injectedKey,
  launderCryptoKey,
  MINT,
  requireAlgorithmName,
  requireKeyType,
  requireMint,
  requireSomeUsage,
} from "./internal.ts";

const subtle = globalThis.crypto.subtle;

interface KwPolicy {
  wrap: boolean;
  unwrap: boolean;
  extractable: boolean;
}

const kwPolicies = new WeakMap<KwKeyOptions, KwPolicy>();

function kwPolicyOf(o: KwKeyOptions): KwPolicy {
  const p = kwPolicies.get(o);
  if (p === undefined) errOther("kw-key-options minted by another provider");
  return p;
}

/** `key-wrap.kw-key-options` (reference: webcrypto.js:3098). */
export class KwKeyOptions {
  constructor() {
    kwPolicies.set(this, { wrap: false, unwrap: false, extractable: false });
  }
  canWrap(allowed: boolean): void {
    kwPolicyOf(this).wrap = allowed;
  }
  canUnwrap(allowed: boolean): void {
    kwPolicyOf(this).unwrap = allowed;
  }
  extractable(allowed: boolean): void {
    kwPolicyOf(this).extractable = allowed;
  }
}

/** One-to-one with the platform's own AES-KW usages (reference: webcrypto.js:3125). */
function kwUsages(policy: KwPolicy): KeyUsage[] {
  return grantedUsages([
    ["wrapKey", policy.wrap],
    ["unwrapKey", policy.unwrap],
  ]);
}

function kwGrantedOps(policy: KwPolicy): string[] {
  const ops: string[] = [];
  if (policy.wrap) ops.push("wrapKey");
  if (policy.unwrap) ops.push("unwrapKey");
  return ops;
}

/** `key-wrap.kw-key` (reference: webcrypto.js:3166). */
export class KwKey {
  #key: CryptoKey;
  #lengthBits: number;
  #grants: KwPolicy;

  /**
   * Runtime-internal (polymorph-webcrypto#391): a `kw-key` exists only as
   * minted by the `aes-kw` interface below or by {@link KwKey.fromCryptoKey}.
   */
  constructor(token: typeof MINT, key: CryptoKey, lengthBits: number, grants: KwPolicy) {
    requireMint(token, "kw-key");
    this.#key = key;
    this.#lengthBits = lengthBits;
    this.#grants = { ...grants };
  }

  /**
   * Adopt an embedder-held AES-KW `CryptoKey` — the injection half of the
   * persistence seam (polymorph-webcrypto#391), so a key-wrapping key can be
   * kept across sessions as a NON-EXTRACTABLE `CryptoKey` in IndexedDB rather
   * than as material.
   *
   * `kw-key` is a served ("tier A") kind: AES-KW's only parameter is the key
   * length, which rides `AesKeyAlgorithm`, and the WIT's `can-wrap`/
   * `can-unwrap` grants are 1:1 with the platform's `wrapKey`/`unwrapKey`
   * usages (keyWrap.ts:59-65). So the slots determine both the record and the
   * policy, and no options parameter is needed — for an injected key the
   * platform slots ARE the policy.
   *
   * Synchronous, and validating: a platform `CryptoKey`, of type `secret`,
   * with `algorithm.name === "AES-KW"`, of a length the `aes-kw` mint serves
   * — 128 or 256 bits, the `aes-variant` table at platform.ts:28-31 (aes192 is
   * declined package-wide by the WIT's portability ruling, so an injected
   * 192-bit key is refused exactly as an imported one would be). At least one
   * of wrap/unwrap is required: a wrapping key that can do neither is a
   * degenerate injection.
   *
   * NOTE on `extractable()`: this class mirrors extractability from its GRANTS
   * record, not from the key (keyWrap.ts:151-153). For an injected key the
   * grant is taken from the platform's own `extractable` slot, which is the
   * truth the export paths are gated on anyway.
   */
  static fromCryptoKey(key: CryptoKey): KwKey {
    const what = "kw-key injection";
    const clone = injectedKey(what, key);
    requireKeyType(what, clone, "secret");
    requireAlgorithmName(what, clone, "AES-KW");
    const { length } = clone.algorithm as AesKeyAlgorithm;
    // The served `aes-variant` lengths, read off the mint's own table rather
    // than restated (platform.ts:28-31, via `aesVariantByteLength`).
    const served = Object.values(AES_VARIANT_BYTES).some((bytes) => bytes !== undefined && bytes * 8 === length);
    if (!served) {
      errUnsupported(
        `${what}: aes-kw serves 128- and 256-bit keys; this key is ${length} bits`,
      );
    }
    requireSomeUsage(
      clone.usages.includes("wrapKey") || clone.usages.includes("unwrapKey"),
      "kw-key",
      "wrap nor unwrap",
    );
    return new KwKey(MINT, clone, length, {
      wrap: clone.usages.includes("wrapKey"),
      unwrap: clone.usages.includes("unwrapKey"),
      extractable: clone.extractable,
    });
  }

  /**
   * Hand back the platform key — the extraction half of the persistence seam
   * (polymorph-webcrypto#391). The returned `CryptoKey` structured-clones into
   * IndexedDB with its non-extractability intact.
   *
   * Security framing, as on `signing-key`: confidentiality of the material is
   * the `extractable` bit's job and stays platform-enforced both ways — this
   * hands back a key, not bytes. What the wrapper scopes is the USE capability
   * in durable, parameter-free form: a raw AES-KW `CryptoKey` wraps and
   * unwraps at its holder's discretion, whereas a `kw-key` carries the grants
   * it was minted with. A fresh clone per call keeps `#key` unreachable.
   *
   * Inverse of {@link KwKey.fromCryptoKey}.
   */
  toCryptoKey(): CryptoKey {
    return launderCryptoKey("kw-key extraction", this.#key);
  }

  /**
   * Encrypt serialized key material (RFC 3394). JWK-format material is
   * first padded with ASCII spaces to a multiple of 8 bytes — the `aes-kw`
   * WIT contract, carried back by the JWK contract's trailing-space
   * tolerance. Material outside the algorithm's input domain fails
   * `invalid-key` with a fixed message: the material is not the caller's
   * to see (reference: webcrypto.js:3188).
   */
  async wrap(input: WrapInput): Promise<Uint8Array> {
    const state = consumeWrapInput(input);
    if (!this.canWrap()) notPermitted("wrap");
    let bytes = state.bytes;
    if (state.format === "jwk" && bytes.length % 8 !== 0) {
      const padded = new Uint8Array(bytes.length + 8 - (bytes.length % 8));
      padded.set(bytes);
      padded.fill(0x20, bytes.length);
      bytes = padded;
    }
    if (bytes.length % 8 !== 0 || bytes.length < 16) {
      errInvalidKey("AES-KW wraps key material of at least 16 bytes, a multiple of 8");
    }
    const trampoline = await platformCall("AES-KW wrap", () =>
      subtle.importKey("raw", asBufferSource(bytes), { name: "HMAC", hash: "SHA-256" }, true, ["sign"]));
    const wrapped = await platformCall("AES-KW wrap", () => subtle.wrapKey("raw", trampoline, this.#key, "AES-KW"));
    return new Uint8Array(wrapped);
  }

  /**
   * Decrypt and integrity-check wrapped material. Input that cannot carry
   * the RFC 3394 wire format reports the same detail-free
   * `authentication-failed` as an ICV failure, before the platform is
   * asked — the two verdicts are deliberately indistinguishable
   * (reference: webcrypto.js:3229).
   */
  async unwrap(wrapped: Uint8Array): Promise<UnwrapInput> {
    if (!this.canUnwrap()) notPermitted("unwrap");
    if (wrapped.length % 8 !== 0 || wrapped.length < 24) {
      errAuthenticationFailed();
    }
    let trampoline: CryptoKey;
    try {
      trampoline = await subtle.unwrapKey(
        "raw",
        asBufferSource(wrapped),
        this.#key,
        "AES-KW",
        { name: "HMAC", hash: "SHA-256" },
        true,
        ["sign"],
      );
    } catch (err) {
      decryptFailure(err, "unwrap");
    }
    const bytes = new Uint8Array(
      await platformCall("AES-KW unwrap", () => subtle.exportKey("raw", trampoline)),
    );
    return new UnwrapInput(bytes);
  }

  algorithmName(): string {
    return this.#key.algorithm.name;
  }
  algorithmLength(): number {
    return this.#lengthBits;
  }
  extractable(): boolean {
    return this.#grants.extractable;
  }
  canWrap(): boolean {
    return this.#grants.wrap;
  }
  canUnwrap(): boolean {
    return this.#grants.unwrap;
  }

  exportKeyRaw(): Promise<Uint8Array> {
    return exportRawGated(this.#key);
  }
  exportKeyJwk(): Promise<string> {
    return exportJwkGated(this.#key);
  }
  async toWrapInputRaw(): Promise<WrapInput> {
    return new WrapInput("raw", await exportRawGated(this.#key));
  }
  async toWrapInputJwk(): Promise<WrapInput> {
    return new WrapInput("jwk", new TextEncoder().encode(await exportJwkGated(this.#key)));
  }
}

/** The `polymorph:webcrypto/key-wrap@0.1.0` interface: its resource classes. */
export const keyWrap = { KwKey, KwKeyOptions };

/** The `aes-kw` minting interface's shape. */
interface AesKw {
  importKeyRaw(variant: string, raw: Uint8Array, options: KwKeyOptions): Promise<KwKey>;
  importKeyJwk(variant: string, jwk: string, options: KwKeyOptions): Promise<KwKey>;
  generateKey(variant: string, options: KwKeyOptions): Promise<KwKey>;
  deriveKey(variant: string, input: DeriveInput, options: KwKeyOptions): Promise<KwKey>;
  unwrapKeyRaw(variant: string, input: UnwrapInput, options: KwKeyOptions): Promise<KwKey>;
  unwrapKeyJwk(variant: string, input: UnwrapInput, options: KwKeyOptions): Promise<KwKey>;
}

/** The `polymorph:webcrypto/aes-kw@0.1.0` interface (reference: webcrypto.js:3317). */
export const aesKw: AesKw = {
  async importKeyRaw(variant: string, raw: Uint8Array, options: KwKeyOptions): Promise<KwKey> {
    const policy = kwPolicyOf(options);
    const usages = kwUsages(policy);
    const expected = aesVariantByteLength(variant);
    if (raw.length !== expected) {
      errInvalidKey(`${variant} requires ${expected} key bytes, got ${raw.length}`);
    }
    const key = await importPlatformKey(
      `${variant} key`,
      "raw",
      raw,
      { name: "AES-KW" },
      policy.extractable,
      usages,
    );
    return new KwKey(MINT, key, expected * 8, policy);
  },

  async importKeyJwk(variant: string, jwk: string, options: KwKeyOptions): Promise<KwKey> {
    const policy = kwPolicyOf(options);
    const usages = kwUsages(policy);
    const lengthBits = aesVariantByteLength(variant) * 8;
    const material = jwkMaterial(jwk);
    requireStrictBase64url(material.k);
    const key = await importPlatformKeyJwk(
      `${variant} JWK`,
      material,
      { name: "AES-KW" },
      policy.extractable,
      usages,
    );
    const gotBits = jwkKeyBytes(material.k) * 8;
    if (gotBits !== lengthBits) {
      errInvalidKey(`JWK carries a ${gotBits}-bit key; ${variant} requires ${lengthBits}`);
    }
    return new KwKey(MINT, key, lengthBits, policy);
  },

  async generateKey(variant: string, options: KwKeyOptions): Promise<KwKey> {
    const policy = kwPolicyOf(options);
    const usages = kwUsages(policy);
    const bits = aesVariantByteLength(variant) * 8;
    const key = await platformCall(`${variant} key generation`, () =>
      subtle.generateKey({ name: "AES-KW", length: bits }, policy.extractable, usages)) as CryptoKey;
    return new KwKey(MINT, key, bits, policy);
  },

  async deriveKey(variant: string, input: DeriveInput, options: KwKeyOptions): Promise<KwKey> {
    const policy = kwPolicyOf(options);
    const usages = kwUsages(policy);
    const bits = aesVariantByteLength(variant) * 8;
    const key = await deriveKeyFrom(input, { name: "AES-KW", length: bits }, policy.extractable, usages);
    return new KwKey(MINT, key, bits, policy);
  },

  unwrapKeyRaw(variant: string, input: UnwrapInput, options: KwKeyOptions): Promise<KwKey> {
    const { bytes } = consumeUnwrapInput(input);
    return redactingInvalidKey(
      `unwrapped ${variant} key material`,
      () => aesKw.importKeyRaw(variant, bytes, options),
    );
  },

  unwrapKeyJwk(variant: string, input: UnwrapInput, options: KwKeyOptions): Promise<KwKey> {
    const { bytes } = consumeUnwrapInput(input);
    const policy = kwPolicyOf(options);
    kwUsages(policy);
    const jwk = unwrappedJwk(bytes, "enc", kwGrantedOps(policy));
    return redactingInvalidKey(
      `unwrapped ${variant} JWK`,
      () => aesKw.importKeyJwk(variant, jwk, options),
    );
  },
};
