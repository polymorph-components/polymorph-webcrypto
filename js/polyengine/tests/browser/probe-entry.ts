// The injection probe's page body: `webcryptoHost().inject` exercised
// against a real browser's Web Crypto — the lane that can mint the
// non-extractable and hardware-shaped `CryptoKey`s an embedder actually
// holds, which is the whole subject of the API.
//
// SCOPE. These are host-module-level assertions: the checks call the
// injected handles' methods directly, exactly as the runtime's lift path
// calls them when a guest invokes a method on the handle, rather than
// driving a real component. Wrapping a guest around it would add a
// component build and an app-owned WIT world to observe the one thing
// this API does — hand back the host object the lift path expects — and
// the conformance suites already gate the resource-class surface under
// real instantiation. What is NOT covered here, and is named in the
// report: the table crossing itself.
//
// Every value crossing `page.evaluate` is JSON-safe, and no key material
// crosses. The message and the IKM are labeled synthetic constants
// (byte i = i, and an all-zero secret): the subject is which key answers,
// never the data.

/// <reference lib="dom" />

import { arrayStream } from "../testStream.ts";
import { DeriveInput, Ikm, Password, SigningKey, webcryptoHost } from "../../src/mod.ts";

/** A labeled synthetic message: byte i = i. Nothing about it is secret or meaningful. */
const MESSAGE = Uint8Array.from({ length: 32 }, (_, i) => i);
/** A labeled synthetic KDF secret: 32 zero bytes. Not a key anyone should use. */
const ZERO_IKM = new Uint8Array(32);
const SALT = Uint8Array.from({ length: 16 }, (_, i) => i);
const INFO = new TextEncoder().encode("polymorph:webcrypto inject probe");

const ED25519_SIGN = "polymorph:webcrypto/ed25519-sign@0.1.0";
const HKDF_SHA2 = "polymorph:webcrypto/hkdf-sha2@0.1.0";
const PBKDF2_SHA2 = "polymorph:webcrypto/pbkdf2-sha2@0.1.0";
const SIGNATURE = "polymorph:webcrypto/signature@0.1.0";

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** The message the wrap site refused with, or a failure if it did not refuse. */
function expectRejection(what: string, run: () => unknown): string {
  try {
    run();
  } catch (e) {
    return (e as Error)?.message ?? String(e);
  }
  throw new Error(`${what}: expected a rejection at the wrap site, got a handle`);
}

async function verifyWith(publicKey: CryptoKey, signature: Uint8Array): Promise<boolean> {
  return await crypto.subtle.verify(
    "Ed25519",
    publicKey,
    signature as BufferSource,
    MESSAGE as BufferSource,
  );
}

const probe = {
  /**
   * The first consumer's shape: a non-extractable Ed25519 private key the
   * embedder holds becomes a handle that signs, and whose getters
   * describe the key rather than a mint that never happened.
   */
  async injectNonExtractable() {
    const { inject } = webcryptoHost();
    const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]) as CryptoKeyPair;
    const handle = inject.signingKey(pair.privateKey);
    const signature = await handle.sign(arrayStream(MESSAGE));
    return {
      isSigningKey: handle instanceof SigningKey,
      verified: await verifyWith(pair.publicKey, signature),
      extractable: handle.extractable(),
      canSign: handle.canSign(),
      algorithm: handle.algorithmName(),
      curve: handle.algorithmCurve() ?? null,
      hash: handle.algorithmHash() ?? null,
      length: handle.algorithmLength() ?? null,
    };
  },

  /**
   * An extractable key is accepted — the embedder holds it either way —
   * and the `extractable` getter says so, which is what the guest needs
   * in order to know what it was handed. Export follows the getter.
   */
  async injectExtractable() {
    const { inject } = webcryptoHost();
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    const handle = inject.signingKey(pair.privateKey);
    const pkcs8 = await handle.exportKeyPkcs8();
    return {
      extractable: handle.extractable(),
      exportedBytes: pkcs8.length,
      verified: await verifyWith(pair.publicKey, await handle.sign(arrayStream(MESSAGE))),
    };
  },

  /** The non-extractable handle refuses export through the ordinary path, and still signs. */
  async injectedExportRefusal() {
    const { inject } = webcryptoHost();
    const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]) as CryptoKeyPair;
    const handle = inject.signingKey(pair.privateKey);
    let payload: unknown = null;
    try {
      await handle.exportKeyPkcs8();
    } catch (e) {
      payload = (e as { payload?: unknown }).payload ?? null;
    }
    return {
      payload,
      stillSigns: await verifyWith(pair.publicKey, await handle.sign(arrayStream(MESSAGE))),
    };
  },

  /** A public key is not a signing key: refused at the wrap site. */
  async injectPublicKey() {
    const { inject } = webcryptoHost();
    const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]) as CryptoKeyPair;
    return { message: expectRejection("a public key", () => inject.signingKey(pair.publicKey)) };
  },

  /** An algorithm whose mint-bound record a CryptoKey cannot carry is refused. */
  async injectWrongSigningAlgorithm() {
    const { inject } = webcryptoHost();
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    ) as CryptoKeyPair;
    return { message: expectRejection("an ECDSA key", () => inject.signingKey(pair.privateKey)) };
  },

  /**
   * Injected and package-minted keys are the same kind of thing in one
   * invocation: same class, both usable, distinct objects.
   */
  async coexistence() {
    const { imports, inject } = webcryptoHost();
    // deno-lint-ignore no-explicit-any
    const ed25519Sign = imports[ED25519_SIGN] as any;
    // deno-lint-ignore no-explicit-any
    const SigningKeyOptions = (imports[SIGNATURE] as any).SigningKeyOptions;

    const options = new SigningKeyOptions();
    options.canSign(true);
    const [minted, mintedPublic] = await ed25519Sign.generateKey(options);

    const pair = await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"]) as CryptoKeyPair;
    const injected = inject.signingKey(pair.privateKey);

    const mintedSig = await minted.sign(arrayStream(MESSAGE));
    const injectedSig = await injected.sign(arrayStream(MESSAGE));
    const mintedPublicKey = await crypto.subtle.importKey(
      "raw",
      (await mintedPublic.exportKeyRaw()) as BufferSource,
      "Ed25519",
      true,
      ["verify"],
    );
    return {
      sameClass: minted instanceof SigningKey && injected instanceof SigningKey,
      distinct: minted !== injected,
      mintedVerified: await verifyWith(mintedPublicKey, mintedSig),
      injectedVerified: await verifyWith(pair.publicKey, injectedSig),
      differentSignatures: hex(mintedSig) !== hex(injectedSig),
    };
  },

  /**
   * The passkey-PRF shape: an embedder-held HKDF secret becomes `ikm`,
   * drives the package's own derivation path, and yields exactly what
   * the platform yields for the same parameters.
   */
  async injectHkdf() {
    const { imports, inject } = webcryptoHost();
    // deno-lint-ignore no-explicit-any
    const hkdfSha2 = imports[HKDF_SHA2] as any;
    const key = await crypto.subtle.importKey("raw", ZERO_IKM as BufferSource, "HKDF", false, [
      "deriveBits",
      "deriveKey",
    ]);
    const handle = inject.derivationKey(key);
    const input: DeriveInput = await hkdfSha2.prepare("sha256", handle, SALT, INFO);
    const derived = await input.deriveBits(256);
    const expected = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: SALT as BufferSource, info: INFO as BufferSource },
        key,
        256,
      ),
    );
    return {
      isIkm: handle instanceof Ikm,
      canDeriveBits: handle.canDeriveBits(),
      canDeriveKey: handle.canDeriveKey(),
      matchesPlatform: hex(derived) === hex(expected),
    };
  },

  /** The grants an injected base secret reports are the key's own usages. */
  async injectHkdfBitsOnly() {
    const { inject } = webcryptoHost();
    const key = await crypto.subtle.importKey("raw", ZERO_IKM as BufferSource, "HKDF", false, ["deriveBits"]);
    const handle = inject.derivationKey(key);
    return { canDeriveBits: handle.canDeriveBits(), canDeriveKey: handle.canDeriveKey() };
  },

  /** A PBKDF2 secret lands on the other derivation resource and drives its path. */
  async injectPbkdf2() {
    const { imports, inject } = webcryptoHost();
    // deno-lint-ignore no-explicit-any
    const pbkdf2Sha2 = imports[PBKDF2_SHA2] as any;
    const key = await crypto.subtle.importKey("raw", ZERO_IKM as BufferSource, "PBKDF2", false, ["deriveBits"]);
    const handle = inject.derivationKey(key);
    const input: DeriveInput = await pbkdf2Sha2.prepare("sha256", handle, SALT, 1000);
    const derived = await input.deriveBits(256);
    const expected = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "PBKDF2", hash: "SHA-256", salt: SALT as BufferSource, iterations: 1000 },
        key,
        256,
      ),
    );
    return {
      isPassword: handle instanceof Password,
      canDeriveBits: handle.canDeriveBits(),
      matchesPlatform: hex(derived) === hex(expected),
    };
  },

  /** A key of another kind is not a derivation base secret. */
  async injectWrongDerivationAlgorithm() {
    const { inject } = webcryptoHost();
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    return { message: expectRejection("an AES-GCM key", () => inject.derivationKey(key as CryptoKey)) };
  },

  /** `webcryptoImports()` and `webcryptoHost().imports` serve the same interface set. */
  async importsParity() {
    const { webcryptoImports } = await import("../../src/mod.ts");
    const plain = Object.keys(webcryptoImports()).sort();
    const paired = Object.keys(webcryptoHost().imports).sort();
    return { equal: JSON.stringify(plain) === JSON.stringify(paired), count: paired.length };
  },
};

(globalThis as unknown as { injectProbe: typeof probe }).injectProbe = probe;
