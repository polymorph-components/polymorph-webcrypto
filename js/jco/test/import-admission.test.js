// Tests for the host-side import admission guards — the shallow
// fail-closed checks that pin rejection of key material the WIT's import
// contracts refuse but some platform engines admit (Gecko admits all three
// classes below). The conformance suite observes the same rejections on
// every target; these run the host directly, so the guards keep their
// coverage on the engine the unit suite runs on, where the platform would
// reject anyway and cannot distinguish a guard regression from a platform
// rejection. Each case verifies the host rejects, with `invalid-key`.

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  AgreementKeyOptions,
  MacKeyOptions,
  SigningKeyOptions,
  ecdh,
  ecdsaSign,
  ed25519Sign,
  ed25519Verify,
  hmacSha2,
  x25519,
} from "../webcrypto.js";

const subtle = globalThis.crypto.subtle;

const agreementOptions = () => {
  const o = new AgreementKeyOptions();
  o.canDeriveBits(true);
  return o;
};

const signingOptions = () => {
  const o = new SigningKeyOptions();
  o.canSign(true);
  return o;
};

const macOptions = () => {
  const o = new MacKeyOptions();
  o.canSign(true);
  return o;
};

const isInvalidKey = (err) => err !== null && typeof err === "object" && err.tag === "invalid-key";

/** A PKCS#8 PrivateKeyInfo for a freshly generated key on `namedCurve`. */
async function pkcs8On(algorithmName, namedCurve, usages) {
  const pair = await subtle.generateKey({ name: algorithmName, namedCurve }, true, usages);
  return new Uint8Array(await subtle.exportKey("pkcs8", pair.privateKey));
}

/** A JWK (as WIT-level text) for a freshly generated OKP key. */
async function okpJwk(algorithmName, which, usages) {
  const pair = await subtle.generateKey(algorithmName, true, usages);
  const key = which === "private" ? pair.privateKey : pair.publicKey;
  return JSON.stringify(await subtle.exportKey("jwk", key));
}

test("ECDH rejects a P-256 PKCS#8 imported under the P-384 variant", async () => {
  const pkcs8 = await pkcs8On("ECDH", "P-256", ["deriveBits"]);
  await assert.rejects(() => ecdh.importSecretKeyPkcs8("p384", pkcs8, agreementOptions()), isInvalidKey);
  // The same material under its own variant is admitted: the guard rejects
  // the curve mismatch, not the encoding.
  await ecdh.importSecretKeyPkcs8("p256", pkcs8, agreementOptions());
});

test("ECDSA rejects a P-256 PKCS#8 imported under a P-384 variant", async () => {
  const pkcs8 = await pkcs8On("ECDSA", "P-256", ["sign", "verify"]);
  await assert.rejects(
    () => ecdsaSign.importSigningKeyPkcs8("p384-sha384", pkcs8, signingOptions()),
    isInvalidKey,
  );
  await ecdsaSign.importSigningKeyPkcs8("p256-sha256", pkcs8, signingOptions());
});

test("EC PKCS#8 admission rejects truncated and non-PrivateKeyInfo input", async () => {
  const pkcs8 = await pkcs8On("ECDH", "P-256", ["deriveBits"]);
  for (const bytes of [new Uint8Array(0), new Uint8Array(3), pkcs8.slice(0, 8)]) {
    await assert.rejects(
      () => ecdh.importSecretKeyPkcs8("p256", bytes, agreementOptions()),
      isInvalidKey,
    );
  }
});

test("Ed25519 rejects an X25519 JWK", async () => {
  const publicJwk = await okpJwk("X25519", "public", ["deriveBits"]);
  await assert.rejects(() => ed25519Verify.importVerifyingKeyJwk(publicJwk), isInvalidKey);
  const privateJwk = await okpJwk("X25519", "private", ["deriveBits"]);
  await assert.rejects(
    () => ed25519Sign.importSigningKeyJwk(privateJwk, signingOptions()),
    isInvalidKey,
  );
});

test("X25519 rejects an Ed25519 JWK", async () => {
  const publicJwk = await okpJwk("Ed25519", "public", ["sign", "verify"]);
  await assert.rejects(() => x25519.importPublicKeyJwk(publicJwk), isInvalidKey);
  const privateJwk = await okpJwk("Ed25519", "private", ["sign", "verify"]);
  await assert.rejects(
    () => x25519.importSecretKeyJwk(privateJwk, agreementOptions()),
    isInvalidKey,
  );
});

test("an OKP import rejects a JWK whose kty is not OKP", async () => {
  const jwk = JSON.stringify({ kty: "EC", crv: "Ed25519", x: "AAAA" });
  await assert.rejects(() => ed25519Verify.importVerifyingKeyJwk(jwk), isInvalidKey);
});

test("HMAC rejects a JWK whose kty is not oct", async () => {
  // A synthetic all-zero key: what is under test is the `kty` member.
  const k = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  await assert.rejects(
    () => hmacSha2.importKeyJwk("sha256", JSON.stringify({ kty: "OKP", k }), macOptions()),
    isInvalidKey,
  );
  await hmacSha2.importKeyJwk("sha256", JSON.stringify({ kty: "oct", k }), macOptions());
});
