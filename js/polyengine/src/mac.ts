// `polymorph:webcrypto/mac` (algorithm-agnostic MAC key resource) plus
// `hmac-sha2` / `hmac-sha1` (the two minting interfaces) — wit/webcrypto.wit
// `interface mac`, wit/hmac.wit.

import {
  errAuthenticationFailed,
  errInvalidKey,
  errNotExtractable,
  errNotPermitted,
  errOther,
  errUnsupported,
  notPermitted,
  platformCall,
} from "./errors.ts";
import { importPlatformKeyJwk, jwkKeyBytes, jwkMaterial, requireStrictBase64url } from "./platform.ts";
import { asBufferSource, unwrappedJwk, utf8Encode } from "./util.ts";
import { deriveKeyFrom, type DeriveInput } from "./derivation.ts";
import { consumeUnwrapInput, type UnwrapInput, WrapInput } from "./wrapping.ts";
import type { Stream } from "@polyengine/runtime/embedder";
import { collectByteStream } from "./util.ts";
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

interface MacPolicy {
  sign: boolean;
  verify: boolean;
  extractable: boolean;
}

const macPolicies = new WeakMap<MacKeyOptions, MacPolicy>();

function policyOf(o: MacKeyOptions): MacPolicy {
  const p = macPolicies.get(o);
  if (p === undefined) {
    errOther("mac-key-options minted by another provider");
  }
  return p;
}

/** `mac.mac-key-options`: mint-time policy, granting nothing by default. */
export class MacKeyOptions {
  constructor() {
    macPolicies.set(this, { sign: false, verify: false, extractable: false });
  }
  canSign(allowed: boolean): void {
    policyOf(this).sign = allowed;
  }
  canVerify(allowed: boolean): void {
    policyOf(this).verify = allowed;
  }
  extractable(allowed: boolean): void {
    policyOf(this).extractable = allowed;
  }
}

function macUsages(policy: MacPolicy): KeyUsage[] {
  const usages: KeyUsage[] = [];
  if (policy.sign) usages.push("sign");
  if (policy.verify) usages.push("verify");
  if (usages.length === 0) {
    errNotPermitted("a key with no enabled usage cannot be minted");
  }
  return usages;
}

interface HashSpec {
  hash: string;
  blockBytes: number;
}

/** `mac.mac-key`: an HMAC key bound to a hash at mint. */
export class MacKey {
  #key: CryptoKey;
  #lengthBits: number;
  #hashName: string;

  /**
   * Runtime-internal (polymorph-webcrypto#391): a `mac-key` exists only as
   * minted by one of the HMAC interfaces in this module or by
   * {@link MacKey.fromCryptoKey}. `MINT` is package-private and unexported
   * from mod.ts, so no external caller can reach this signature.
   */
  constructor(token: typeof MINT, key: CryptoKey, lengthBits: number, hashName: string) {
    requireMint(token, "mac-key");
    this.#key = key;
    this.#lengthBits = lengthBits;
    this.#hashName = hashName;
  }

  /**
   * Adopt an embedder-held HMAC `CryptoKey` — the injection half of the
   * persistence seam (polymorph-webcrypto#391): a MAC key an embedder
   * structured-cloned into IndexedDB comes back as a `mac-key` here, so
   * keeping one across sessions does not require holding its material.
   *
   * `mac-key` is a served ("tier A") kind because the platform key's slots
   * determine everything the resource needs: `HmacKeyAlgorithm` carries the
   * mint-bound hash and length, and the WIT's `can-sign`/`can-verify` grants
   * are 1:1 with the platform's `sign`/`verify` usages (mac.ts:56-64), so the
   * usages ARE the policy for an injected key — loading is itself a minting
   * path, and the platform will refuse anything its slots do not cover
   * regardless of what this wrapper claimed.
   *
   * Synchronous, and validating: a platform `CryptoKey`, of type `secret`,
   * with `algorithm.name === "HMAC"`, bound to one of the digests the minting
   * interfaces serve — SHA-1 (`hmac-sha1`, mac.ts:233) and SHA-256/384/512
   * (`hmac-sha2`, mac.ts:235-239) — and of a length the mint admits (non-zero
   * and a whole number of bytes; mac.ts:170-173). At least one of
   * `sign`/`verify` is required: a MAC key that can do neither is a degenerate
   * injection.
   *
   * Validation reads the LAUNDERED clone, which is also what the wrapper
   * stores, so shadowed accessors on the argument cannot get a key admitted
   * and no caller retains a handle to the key this resource MACs with.
   */
  static fromCryptoKey(key: CryptoKey): MacKey {
    const what = "mac-key injection";
    const clone = injectedKey(what, key);
    requireKeyType(what, clone, "secret");
    requireAlgorithmName(what, clone, "HMAC");
    const { hash, length } = clone.algorithm as HmacKeyAlgorithm;
    if (servedHmacSpec(hash.name) === undefined) {
      errUnsupported(
        `${what}: the HMAC interfaces serve SHA-1 and SHA-256/384/512; this key is bound to ${hash.name}`,
      );
    }
    // The mint's own length rules, applied to the slot instead of to raw
    // material (mac.ts:157, 170-173): an empty key cannot be imported and a
    // sub-byte length is not served.
    if (length === 0) errInvalidKey(`${what}: empty key`);
    if (length % 8 !== 0) {
      errUnsupported(`HMAC key length ${length} is not a multiple of 8; sub-byte lengths are not served`);
    }
    requireSomeUsage(
      clone.usages.includes("sign") || clone.usages.includes("verify"),
      "mac-key",
      "sign nor verify",
    );
    return new MacKey(MINT, clone, length, hash.name);
  }

  /**
   * Hand back the platform key — the extraction half of the persistence seam
   * (polymorph-webcrypto#391). The returned `CryptoKey` structured-clones into
   * IndexedDB with its non-extractability intact, which is how a MAC key is
   * meant to outlive a session.
   *
   * Security framing, as on `signing-key`: material confidentiality is the
   * `extractable` bit's job and stays platform-enforced both ways — this hands
   * back a key, never bytes, and a non-extractable key stays non-extractable
   * in the caller's hands. What the wrapper scopes is the USE capability in
   * durable, parameter-free form: a raw HMAC `CryptoKey` MACs whatever its
   * holder asks, whereas a `mac-key` is bound to the hash and grants it was
   * minted with. A fresh clone per call keeps `#key` unreachable, so that
   * scoping is total.
   *
   * Inverse of {@link MacKey.fromCryptoKey}: the returned key satisfies that
   * validation by construction.
   */
  toCryptoKey(): CryptoKey {
    return launderCryptoKey("mac-key extraction", this.#key);
  }

  extractable(): boolean {
    return this.#key.extractable;
  }
  canSign(): boolean {
    return this.#key.usages.includes("sign");
  }
  canVerify(): boolean {
    return this.#key.usages.includes("verify");
  }
  algorithmName(): string {
    return this.#key.algorithm.name;
  }
  algorithmHash(): string | undefined {
    return this.#hashName;
  }
  algorithmLength(): number {
    return this.#lengthBits;
  }

  async sign(data: Stream<number>): Promise<Uint8Array> {
    const message = await collectByteStream(data);
    if (!this.canSign()) notPermitted("sign");
    const out = await platformCall("HMAC sign", () => subtle.sign("HMAC", this.#key, asBufferSource(message)));
    return new Uint8Array(out);
  }

  async verify(data: Stream<number>, tag: Uint8Array): Promise<void> {
    const message = await collectByteStream(data);
    if (!this.canVerify()) notPermitted("verify");
    const ok = await platformCall("HMAC verify", () =>
      subtle.verify("HMAC", this.#key, asBufferSource(tag), asBufferSource(message)));
    if (!ok) {
      errAuthenticationFailed();
    }
  }

  async exportKeyRaw(): Promise<Uint8Array> {
    return exportRawGated(this.#key);
  }
  async exportKeyJwk(): Promise<string> {
    return exportJwkGated(this.#key);
  }
  async toWrapInputRaw(): Promise<WrapInput> {
    return new WrapInput("raw", await exportRawGated(this.#key));
  }
  async toWrapInputJwk(): Promise<WrapInput> {
    const jwk = await exportJwkGated(this.#key);
    return new WrapInput("jwk", utf8Encode(jwk));
  }
}

/** The `error.not-extractable` gate shared by every export path (reference: js/jco/webcrypto.js `exportRawGated`-style helpers). */
async function exportRawGated(key: CryptoKey): Promise<Uint8Array> {
  if (!key.extractable) {
    errNotExtractable();
  }
  const raw = await platformCall("export raw", () => subtle.exportKey("raw", key));
  return new Uint8Array(raw);
}

async function exportJwkGated(key: CryptoKey): Promise<string> {
  if (!key.extractable) {
    errNotExtractable();
  }
  const jwk = await platformCall("export jwk", () => subtle.exportKey("jwk", key));
  return JSON.stringify(jwk);
}

/** The `polymorph:webcrypto/mac@0.1.0` interface: its resource classes. */
export const mac = { MacKey, MacKeyOptions };

async function importHmacKey(resolved: HashSpec, raw: Uint8Array, options: MacKeyOptions): Promise<MacKey> {
  const policy = policyOf(options);
  const usages = macUsages(policy);
  if (raw.length === 0) errInvalidKey("empty key");
  const key = await platformCall("HMAC import key", () =>
    subtle.importKey("raw", asBufferSource(raw), { name: "HMAC", hash: resolved.hash }, policy.extractable, usages));
  return new MacKey(MINT, key, raw.length * 8, resolved.hash);
}

async function generateHmacKey(
  resolved: HashSpec,
  length: number | undefined,
  options: MacKeyOptions,
): Promise<MacKey> {
  const policy = policyOf(options);
  const usages = macUsages(policy);
  if (length === 0) errInvalidKey("HMAC key length must be non-zero");
  if (length !== undefined && length % 8 !== 0) {
    errUnsupported(`HMAC key length ${length} is not a multiple of 8; sub-byte lengths are not served`);
  }
  const bits = length ?? resolved.blockBytes * 8;
  const key = await platformCall(`HMAC-${resolved.hash} key generation`, () =>
    subtle.generateKey({ name: "HMAC", hash: resolved.hash, length: bits }, policy.extractable, usages));
  return new MacKey(MINT, key as CryptoKey, bits, resolved.hash);
}

/**
 * Import an `oct` HMAC JWK (reference: js/jco/webcrypto.js:868-905). The
 * material members go through `jwkMaterial` — `use`/`key_ops` are consumer
 * policy and must NOT reach the platform, whose import would otherwise
 * enforce them against the usages this host passes — and every platform
 * refusal (a wrong `kty`, a mismatched `alg`, a malformed `k`) is
 * `error.invalid-key`, the verdict the WIT pins for a bad JWK.
 */
async function importHmacKeyJwk(resolved: HashSpec, jwk: string, options: MacKeyOptions): Promise<MacKey> {
  const policy = policyOf(options);
  const usages = macUsages(policy);
  const material = jwkMaterial(jwk);
  requireStrictBase64url(material.k);
  const key = await importPlatformKeyJwk(
    "HMAC JWK",
    material,
    { name: "HMAC", hash: resolved.hash },
    policy.extractable,
    usages,
  );
  const kLen = typeof material.k === "string" ? jwkKeyBytes(material.k) * 8 : 0;
  return new MacKey(MINT, key, kLen, resolved.hash);
}

async function deriveHmacKey(
  resolved: HashSpec,
  input: DeriveInput,
  length: number | undefined,
  options: MacKeyOptions,
): Promise<MacKey> {
  const policy = policyOf(options);
  const usages = macUsages(policy);
  if (length === 0) errInvalidKey("HMAC key length must be non-zero");
  if (length !== undefined && length % 8 !== 0) {
    errUnsupported(`HMAC key length ${length} is not a multiple of 8; sub-byte lengths are not served`);
  }
  const bits = length ?? resolved.blockBytes * 8;
  const key = await deriveKeyFrom(input, { name: "HMAC", hash: resolved.hash, length: bits }, policy.extractable, usages);
  return new MacKey(MINT, key, bits, resolved.hash);
}

function unwrapHmacKeyRaw(resolved: HashSpec, input: UnwrapInput, options: MacKeyOptions): Promise<MacKey> {
  const { bytes } = consumeUnwrapInput(input);
  return importHmacKey(resolved, bytes, options);
}

function unwrapHmacKeyJwk(resolved: HashSpec, input: UnwrapInput, options: MacKeyOptions): Promise<MacKey> {
  const { bytes } = consumeUnwrapInput(input);
  const policy = policyOf(options);
  const jwk = unwrappedJwk(bytes, "sig", macUsages(policy));
  return importHmacKeyJwk(resolved, jwk, options);
}

const SHA1_HMAC: HashSpec = { hash: "SHA-1", blockBytes: 64 };

const SHA2_HMAC: Readonly<Record<string, HashSpec | undefined>> = Object.freeze({
  sha256: { hash: "SHA-256", blockBytes: 64 },
  sha384: { hash: "SHA-384", blockBytes: 128 },
  sha512: { hash: "SHA-512", blockBytes: 128 },
});

function sha2Hmac(variant: string): HashSpec {
  const spec = SHA2_HMAC[variant];
  if (spec === undefined) errUnsupported(`${variant} is not served by this implementation`);
  return spec;
}

/**
 * The `HashSpec` for a WebCrypto digest NAME, or `undefined` if the HMAC
 * interfaces do not serve it — the served set read off the mint tables
 * themselves (`SHA1_HMAC` and `SHA2_HMAC` above) rather than restated, so
 * `mac-key` injection admits exactly the digests a mint does.
 */
function servedHmacSpec(hashName: string): HashSpec | undefined {
  if (hashName === SHA1_HMAC.hash) return SHA1_HMAC;
  return Object.values(SHA2_HMAC).find((spec) => spec !== undefined && spec.hash === hashName);
}

/** The `polymorph:webcrypto/hmac-sha1@0.1.0` interface. */
export const hmacSha1 = {
  importKeyRaw: (raw: Uint8Array, options: MacKeyOptions): Promise<MacKey> => importHmacKey(SHA1_HMAC, raw, options),
  importKeyJwk: (jwk: string, options: MacKeyOptions): Promise<MacKey> => importHmacKeyJwk(SHA1_HMAC, jwk, options),
  generateKey: (length: number | undefined, options: MacKeyOptions): Promise<MacKey> =>
    generateHmacKey(SHA1_HMAC, length, options),
  deriveKey: (input: DeriveInput, length: number | undefined, options: MacKeyOptions): Promise<MacKey> =>
    deriveHmacKey(SHA1_HMAC, input, length, options),
  unwrapKeyRaw: (input: UnwrapInput, options: MacKeyOptions): Promise<MacKey> =>
    unwrapHmacKeyRaw(SHA1_HMAC, input, options),
  unwrapKeyJwk: (input: UnwrapInput, options: MacKeyOptions): Promise<MacKey> =>
    unwrapHmacKeyJwk(SHA1_HMAC, input, options),
};

/** The `polymorph:webcrypto/hmac-sha2@0.1.0` interface. */
export const hmacSha2 = {
  importKeyRaw: (variant: string, raw: Uint8Array, options: MacKeyOptions): Promise<MacKey> =>
    importHmacKey(sha2Hmac(variant), raw, options),
  importKeyJwk: (variant: string, jwk: string, options: MacKeyOptions): Promise<MacKey> =>
    importHmacKeyJwk(sha2Hmac(variant), jwk, options),
  generateKey: (variant: string, length: number | undefined, options: MacKeyOptions): Promise<MacKey> =>
    generateHmacKey(sha2Hmac(variant), length, options),
  deriveKey: (
    variant: string,
    input: DeriveInput,
    length: number | undefined,
    options: MacKeyOptions,
  ): Promise<MacKey> => deriveHmacKey(sha2Hmac(variant), input, length, options),
  unwrapKeyRaw: (variant: string, input: UnwrapInput, options: MacKeyOptions): Promise<MacKey> =>
    unwrapHmacKeyRaw(sha2Hmac(variant), input, options),
  unwrapKeyJwk: (variant: string, input: UnwrapInput, options: MacKeyOptions): Promise<MacKey> =>
    unwrapHmacKeyJwk(sha2Hmac(variant), input, options),
};
