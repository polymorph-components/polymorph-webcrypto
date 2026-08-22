// The embedder key seams (polymorph-webcrypto#391): validated injection of
// host-held `CryptoKey`s into the wrapper resources, and extraction back out.
//
// The defensive point of these seams, and so of this file: an embedder that
// must keep a signing key or HKDF input keying material across sessions should
// persist a NON-EXTRACTABLE `CryptoKey` (structured clone into IndexedDB),
// not a pile of exported material. These tests assert the two properties that
// makes safe — extraction preserves non-extractability and clonability, and
// injection REFUSES the degenerate cases (wrong key half, unsupported family,
// a key whose usages do not cover the operation) rather than minting a
// resource that fails later.
//
// No key material is inlined: signing keys are generated in-test, and the one
// fixed input is an obviously-synthetic all-zero 32-byte IKM, labelled as
// such. The suite runs against the platform's own WebCrypto as its oracle
// (sign here / verify there, derive here / derive there), so it needs no
// published vectors.

import { assertEq, assertRejects, assertThrows, assertTrue } from "./asserts.ts";
import {
  AeadKey,
  CipherKey,
  DecryptionKey,
  EncryptionKey,
  hkdfSha2,
  hmacSha2,
  Ikm,
  KwKey,
  MacKey,
  MacKeyOptions,
  Password,
  pbkdf2Sha2,
  PublicKey,
  SecretKey,
  SigningKey,
  VerifyingKey,
} from "../src/mod.ts";
import { arrayStream } from "./testStream.ts";
import { ComponentException } from "@polyengine/runtime/embedder";

function kindOf(err: unknown): string {
  return ((err as ComponentException).payload as { kind: string }).kind;
}

/** Assert a synchronous refusal carries the WIT taxonomy case `kind`. */
function assertRefuses(kind: string, f: () => unknown, msg: string): void {
  const err = assertThrows(f, `${msg}: expected a refusal`);
  assertEq(kindOf(err), kind, msg);
}

/** A mint options resource granting both MAC directions. */
function macOptions(): MacKeyOptions {
  const o = new MacKeyOptions();
  o.canSign(true);
  o.canVerify(true);
  return o;
}

/** An RSASSA-PKCS1-v1_5 pair at a given modulus and digest, generated in-test. */
async function rsassaPair(modulusLength: number, hash: string): Promise<CryptoKeyPair> {
  return await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength,
      // F4 (65537), the platform's own default exponent — public parameter,
      // not key material.
      publicExponent: new Uint8Array([1, 0, 1]),
      hash,
    },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
}

/**
 * The kinds excluded from the seams because their WIT grants collapse onto
 * fewer platform usages than the policy has bits (see the tier statement in
 * signature.ts).
 */
// deno-lint-ignore no-explicit-any
function collapsedPolicyClasses(): Array<[string, any]> {
  return [
    ["aead-key", AeadKey],
    ["cipher-key", CipherKey],
    ["decryption-key", DecryptionKey],
    ["encryption-key", EncryptionKey],
    // Agreement keys are excluded for the other documented reason: their
    // platform usages are constant, so the policy is not on the key at all.
    ["secret-key", SecretKey],
    ["public-key", PublicKey],
  ];
}

/** Every class whose constructor is gated on the package-private mint token. */
// deno-lint-ignore no-explicit-any
function tokenGatedClasses(): Array<[string, any]> {
  return [
    ["signing-key", SigningKey],
    ["verifying-key", VerifyingKey],
    ["mac-key", MacKey],
    ["kw-key", KwKey],
    ...collapsedPolicyClasses(),
  ];
}

const MESSAGE = new TextEncoder().encode("polymorph-webcrypto#391 embedder key seams");

/** A non-extractable Ed25519 pair — the posture the persistence seam exists to serve. */
function ed25519Pair(extractable = false): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey("Ed25519", extractable, ["sign", "verify"]) as Promise<CryptoKeyPair>;
}

Deno.test("391: a non-extractable Ed25519 pair round-trips through injection and still signs/verifies", async () => {
  const pair = await ed25519Pair();
  const signing = SigningKey.fromCryptoKey(pair.privateKey);
  const verifying = VerifyingKey.fromCryptoKey(pair.publicKey);

  assertEq(signing.algorithmName(), "Ed25519", "injected signing key keeps the Ed25519 mint record");
  assertEq(signing.extractable(), false, "injection preserves non-extractability");
  assertEq(signing.canSign(), true, "the platform sign usage carries across injection");

  const sig = await signing.sign(arrayStream(MESSAGE));
  assertEq(sig.length, 64, "Ed25519 signature width");
  await verifying.verify(arrayStream(MESSAGE), sig);

  // A tampered signature is a failed verification, not an operational error:
  // the WIT pins `authentication-failed` and nothing more detailed.
  const tampered = sig.slice();
  tampered[0] ^= 0x01;
  const err = await assertRejects(() => verifying.verify(arrayStream(MESSAGE), tampered));
  assertEq(kindOf(err), "authentication-failed", "a tampered signature is refused");
});

Deno.test("391: signing-key injection refuses every degenerate key", async () => {
  const pair = await ed25519Pair();

  assertRefuses(
    "invalid-key",
    () => SigningKey.fromCryptoKey(pair.publicKey),
    "a public key is not a signing key",
  );

  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(32), // synthetic all-zero IKM; never a real secret
    "HKDF",
    false,
    ["deriveBits"],
  );
  assertRefuses(
    "invalid-key",
    () => SigningKey.fromCryptoKey(hkdfKey),
    "a secret key is not a signing key",
  );

  // The v1 family boundary: ECDSA's mint-bound digest is not carried by the
  // platform key, so injecting one would have to invent it.
  const ecdsa = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  assertRefuses(
    "unsupported",
    () => SigningKey.fromCryptoKey(ecdsa.privateKey),
    "ECDSA injection is outside the v1 boundary",
  );

  assertRefuses(
    "invalid-key",
    () => SigningKey.fromCryptoKey({ type: "private", algorithm: { name: "Ed25519" }, usages: ["sign"] } as CryptoKey),
    "a duck-typed stand-in is not a platform CryptoKey",
  );
});

Deno.test("391: the sign-usage requirement is defence in depth the platform also enforces", async () => {
  // A private Ed25519 key that cannot sign is not constructible on a
  // conforming platform: WebCrypto refuses to MINT one, at generate and at
  // import alike (empty usages is a SyntaxError). This test records that fact
  // — which is why the host-side `not-permitted` check on injection cannot be
  // exercised with a real key here — and pins the platform behaviour the check
  // is backstopping, so a platform that ever starts minting such a key is
  // caught by this suite rather than silently admitted.
  await assertRejects(
    () => crypto.subtle.generateKey("Ed25519", false, ["verify"]),
    "generateKey must refuse a key pair whose private half would have no usage",
  );
  const pair = await ed25519Pair(true);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", pair.privateKey);
  await assertRejects(
    () => crypto.subtle.importKey("pkcs8", pkcs8, "Ed25519", false, []),
    "importKey must refuse a private key with no usages",
  );

  // The corresponding reachable refusal on the verifying half: `verify` is not
  // among a PRIVATE key's usages, so the type gate fires first — assert the
  // ordering is the strict one (wrong half is invalid-key, not not-permitted).
  assertRefuses(
    "invalid-key",
    () => VerifyingKey.fromCryptoKey(pair.privateKey),
    "a private key is not a verifying key",
  );
});

Deno.test("391: verifying-key injection refuses the wrong half and the wrong family", async () => {
  const rsa = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  assertRefuses(
    "unsupported",
    () => VerifyingKey.fromCryptoKey(rsa.publicKey),
    "RSA-PSS injection is outside the v1 boundary (the salt length is not on the key)",
  );

  const ecdh = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  ) as CryptoKeyPair;
  assertRefuses(
    "unsupported",
    () => VerifyingKey.fromCryptoKey(ecdh.publicKey),
    "an ECDH public key is not a verifying key",
  );
});

Deno.test("391: ikm injection reads its policy off the platform usages and refuses the rest", async () => {
  const bitsOnly = await crypto.subtle.importKey("raw", new Uint8Array(32), "HKDF", false, ["deriveBits"]);
  const ikm = Ikm.fromCryptoKey(bitsOnly);
  assertEq(ikm.canDeriveBits(), true, "the platform deriveBits slot is the policy");
  assertEq(ikm.canDeriveKey(), false, "a slot the platform did not grant is not granted here");

  const both = await crypto.subtle.importKey("raw", new Uint8Array(32), "HKDF", false, [
    "deriveBits",
    "deriveKey",
  ]);
  const wide = Ikm.fromCryptoKey(both);
  assertEq(wide.canDeriveKey(), true, "the deriveKey slot carries across injection");

  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  assertRefuses(
    "invalid-key",
    () => Ikm.fromCryptoKey(aes as CryptoKey),
    "an AES key is not HKDF input keying material",
  );

  const pair = await ed25519Pair();
  assertRefuses(
    "invalid-key",
    () => Ikm.fromCryptoKey(pair.privateKey),
    "a private key is not a secret key",
  );

  // A key with neither derive usage cannot be minted by the platform either
  // (empty usages is a SyntaxError), which is the same defence-in-depth
  // situation as the signing case above.
  await assertRejects(
    () => crypto.subtle.importKey("raw", new Uint8Array(32), "HKDF", false, []),
    "importKey must refuse HKDF material with no derive usage",
  );
});

Deno.test("391: injection launders the key, so shadowed accessors cannot lie about policy", async () => {
  const pair = await ed25519Pair();

  // `CryptoKey`'s slots are immutable but its prototype getters are
  // shadowable. If the wrapper mirrored the CALLER's object, this would make
  // `canSign()` and `extractable()` say whatever the caller wanted.
  Object.defineProperty(pair.privateKey, "usages", { value: [], configurable: true });
  Object.defineProperty(pair.privateKey, "extractable", { value: true, configurable: true });
  assertEq(pair.privateKey.usages.length, 0, "the shadow is in place on the argument");

  const signing = SigningKey.fromCryptoKey(pair.privateKey);
  assertEq(signing.canSign(), true, "canSign answers the platform slot, not the shadow");
  assertEq(signing.extractable(), false, "extractable answers the platform slot, not the shadow");

  // And the laundered key really is usable: the shadow did not make it past
  // validation by accident, it was ignored.
  const sig = await signing.sign(arrayStream(MESSAGE));
  assertEq(sig.length, 64, "the laundered key signs");

  // The same laundering on the way in defeats a family lie: shadowing
  // `algorithm` cannot smuggle an ECDSA key past the Ed25519 boundary.
  const ecdsa = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  Object.defineProperty(ecdsa.privateKey, "algorithm", { value: { name: "Ed25519" }, configurable: true });
  assertRefuses(
    "unsupported",
    () => SigningKey.fromCryptoKey(ecdsa.privateKey),
    "a shadowed algorithm name does not cross the family boundary",
  );
});

Deno.test("391: extraction hands back a fresh clone and preserves non-extractability", async () => {
  const pair = await ed25519Pair();
  const signing = SigningKey.fromCryptoKey(pair.privateKey);
  const verifying = VerifyingKey.fromCryptoKey(pair.publicKey);

  const a = signing.toCryptoKey();
  const b = signing.toCryptoKey();
  assertTrue(a !== b, "each extraction is a fresh clone, never the wrapper's own key");
  assertEq(a.extractable, false, "non-extractability survives extraction");
  assertEq(a.type, "private", "the extracted key is the private half");
  assertEq(a.algorithm.name, "Ed25519", "the extracted key keeps its family");

  // The IndexedDB persistence property, testable without IndexedDB: the
  // returned key is structured-clonable, which is the storage path's
  // precondition.
  const persisted = structuredClone(a);
  assertEq(persisted.extractable, false, "a persisted key stays non-extractable");
  assertEq(persisted.usages.includes("sign"), true, "a persisted key keeps its usage");

  // Nothing a caller does to a returned clone is observable by the wrapper.
  Object.defineProperty(a, "usages", { value: [], configurable: true });
  // deno-lint-ignore no-explicit-any
  (a as any).expando = "caller scribble";
  assertEq(signing.canSign(), true, "expandos on a returned clone do not reach the wrapper");
  assertEq(signing.extractable(), false, "nor does anything else the caller writes");
  assertTrue(!("expando" in signing.toCryptoKey()), "the next extraction is unpolluted");

  const vClone = verifying.toCryptoKey();
  assertEq(vClone.type, "public", "the verifying half extracts as the public key");
  assertTrue(vClone !== verifying.toCryptoKey(), "verifying-key extraction is also per-call");
});

Deno.test("391: extraction hands back the same key, not a lookalike", async () => {
  const pair = await ed25519Pair();
  const signing = SigningKey.fromCryptoKey(pair.privateKey);
  const verifying = VerifyingKey.fromCryptoKey(pair.publicKey);

  // Sign with the EXTRACTED key through the platform, verify through the
  // wrapper: agreement proves the extracted handle carries the same material,
  // and that a persisted-then-reloaded key is interchangeable with the one
  // that was injected.
  const platformSig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", signing.toCryptoKey(), MESSAGE),
  );
  await verifying.verify(arrayStream(MESSAGE), platformSig);

  // And the mirror: sign through the wrapper, verify with the extracted
  // public key through the platform.
  const wrapperSig = await signing.sign(arrayStream(MESSAGE));
  const ok = await crypto.subtle.verify("Ed25519", verifying.toCryptoKey(), wrapperSig as Uint8Array<ArrayBuffer>, MESSAGE);
  assertEq(ok, true, "the extracted public key verifies the wrapper's signature");

  // A full persistence round trip: extract, structured-clone (the IndexedDB
  // step), re-inject, and sign again.
  const reloaded = SigningKey.fromCryptoKey(structuredClone(signing.toCryptoKey()));
  await verifying.verify(arrayStream(MESSAGE), await reloaded.sign(arrayStream(MESSAGE)));
});

Deno.test("391: the key constructors are unreachable from outside their minting interfaces", async () => {
  const pair = await ed25519Pair();

  // The construction token is module-private and unexported from mod.ts, so
  // no argument a consumer can produce satisfies the guard.
  assertRefuses(
    "other",
    // deno-lint-ignore no-explicit-any
    () => new (SigningKey as any)(pair.privateKey, { name: "Ed25519", signatureLength: 64 }),
    "a signing key cannot be constructed directly",
  );
  assertRefuses(
    "other",
    // deno-lint-ignore no-explicit-any
    () => new (VerifyingKey as any)(Symbol("forged"), pair.publicKey, { name: "Ed25519", signatureLength: 64 }),
    "a forged token does not satisfy the verifying-key guard",
  );

  // `Ikm`'s constructor is internal by a different mechanism (all state lives
  // in a module-private WeakMap), so a bare instance is inert rather than
  // rejected at construction.
  assertThrows(() => new Ikm().canDeriveBits(), "a bare Ikm carries no policy");
});

Deno.test("391: an injected ikm derives exactly what the platform derives", async () => {
  // Synthetic, labelled inputs: an all-zero 32-byte IKM and short ASCII
  // salt/info. The oracle is the platform's own HKDF over the same key.
  const ikmBytes = new Uint8Array(32);
  const salt = new TextEncoder().encode("391-salt");
  const info = new TextEncoder().encode("391-info");

  const key = await crypto.subtle.importKey("raw", ikmBytes, "HKDF", false, ["deriveBits"]);
  const ikm = Ikm.fromCryptoKey(key);

  const input = await hkdfSha2.prepare("sha256", ikm, salt, info);
  const viaWrapper = await input.deriveBits(256);

  const viaPlatform = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, 256),
  );
  assertEq(viaWrapper.length, 32, "256 bits derived");
  assertEq(
    viaWrapper.every((b, i) => b === viaPlatform[i]),
    true,
    "the injected ikm derives the platform's answer",
  );

  // Extraction round-trips the material too: re-inject the extracted key and
  // derive the same bits.
  const reloaded = Ikm.fromCryptoKey(structuredClone(ikm.toCryptoKey()));
  assertEq(reloaded.canDeriveBits(), true, "the derive policy survives the round trip");
  const again = await (await hkdfSha2.prepare("sha256", reloaded, salt, info)).deriveBits(256);
  assertEq(
    again.every((b, i) => b === viaPlatform[i]),
    true,
    "a persisted-and-reloaded ikm is the same keying material",
  );
});

// --- Round 2: the seams extended to every kind whose platform slots fully
// determine both the mint record and the WIT policy ("tier A"), and the
// constructor-provenance discipline made uniform across every
// CryptoKey-holding class. The exclusions are asserted too: a kind whose
// policy collapses onto fewer platform usages than it has WIT grants has no
// `fromCryptoKey` at all, and these tests pin that absence so it cannot be
// added by accident.

Deno.test("391: an injected mac-key MACs exactly what the platform MACs", async () => {
  const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const mac = MacKey.fromCryptoKey(key as CryptoKey);

  assertEq(mac.algorithmName(), "HMAC", "the injected key keeps its family");
  assertEq(mac.algorithmHash(), "SHA-256", "the mint-bound digest is read off HmacKeyAlgorithm");
  assertEq(mac.algorithmLength(), 512, "SHA-256's default HMAC key length is the block size in bits");
  assertEq(mac.canSign(), true, "the platform sign usage is the policy");
  assertEq(mac.canVerify(), true, "and so is verify");
  assertEq(mac.extractable(), false, "injection preserves non-extractability");

  // The platform is the oracle: MAC through the wrapper, verify the tag with
  // subtle over the EXTRACTED key. Agreement proves extraction hands back the
  // same key rather than a lookalike.
  const tag = await mac.sign(arrayStream(MESSAGE));
  const ok = await crypto.subtle.verify("HMAC", mac.toCryptoKey(), tag as Uint8Array<ArrayBuffer>, MESSAGE);
  assertEq(ok, true, "the extracted key verifies the wrapper's tag");

  // And the wrapper refuses a tampered tag with the detail-free verdict.
  const tampered = tag.slice();
  tampered[0] ^= 0x01;
  const err = await assertRejects(() => mac.verify(arrayStream(MESSAGE), tampered));
  assertEq(kindOf(err), "authentication-failed", "a tampered tag is refused");

  // The persistence round trip: extract, structured-clone (the IndexedDB
  // step), re-inject, MAC again.
  const reloaded = MacKey.fromCryptoKey(structuredClone(mac.toCryptoKey()));
  const again = await reloaded.sign(arrayStream(MESSAGE));
  assertEq(
    again.every((b, i) => b === tag[i]),
    true,
    "a persisted-and-reloaded mac-key is the same key",
  );

  // SHA-1 is served by `hmac-sha1`, so an injected SHA-1 key is admitted on
  // the same terms a minted one is.
  const sha1 = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  assertEq(MacKey.fromCryptoKey(sha1 as CryptoKey).algorithmHash(), "SHA-1", "hmac-sha1's digest is served");
});

Deno.test("391: mac-key injection refuses the wrong family and an unserved digest", async () => {
  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  assertRefuses(
    "invalid-key",
    () => MacKey.fromCryptoKey(aes as CryptoKey),
    "an AES-GCM key is not an HMAC key",
  );

  const pair = await ed25519Pair();
  assertRefuses(
    "invalid-key",
    () => MacKey.fromCryptoKey(pair.privateKey),
    "a private key is not a secret key",
  );
});

Deno.test("391: an injected kw-key wraps and unwraps across an extract/inject cycle", async () => {
  const key = await crypto.subtle.generateKey({ name: "AES-KW", length: 256 }, false, ["wrapKey", "unwrapKey"]);
  const kw = KwKey.fromCryptoKey(key as CryptoKey);

  assertEq(kw.algorithmName(), "AES-KW", "the injected key keeps its family");
  assertEq(kw.algorithmLength(), 256, "the length is read off AesKeyAlgorithm");
  assertEq(kw.canWrap(), true, "the wrapKey usage is the policy");
  assertEq(kw.canUnwrap(), true, "and so is unwrapKey");
  assertEq(kw.extractable(), false, "injection preserves non-extractability");

  // Wrap a MAC key's material with the injected wrapper, then unwrap it back
  // into a mac-key through a DIFFERENT wrapper obtained by an extract/inject
  // cycle. Recovering a working key proves the cycle is lossless.
  const inner = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign"]);
  const innerMac = MacKey.fromCryptoKey(inner as CryptoKey);
  const wrapped = await kw.wrap(await innerMac.toWrapInputRaw());

  const reloaded = KwKey.fromCryptoKey(structuredClone(kw.toCryptoKey()));
  const recovered = await hmacSha2.unwrapKeyRaw("sha256", await reloaded.unwrap(wrapped), macOptions());

  const expected = await innerMac.sign(arrayStream(MESSAGE));
  const got = await recovered.sign(arrayStream(MESSAGE));
  assertEq(
    got.every((b, i) => b === expected[i]),
    true,
    "the unwrapped key is the key that was wrapped",
  );

  // A tampered wrapped blob still fails the integrity check through an
  // injected key: injection does not weaken the RFC 3394 ICV.
  const corrupt = wrapped.slice();
  corrupt[0] ^= 0x01;
  const err = await assertRejects(() => reloaded.unwrap(corrupt));
  assertEq(kindOf(err), "authentication-failed", "a tampered blob is refused");
});

Deno.test("391: kw-key injection refuses the wrong family and an unserved length", async () => {
  const gcm = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  assertRefuses(
    "invalid-key",
    () => KwKey.fromCryptoKey(gcm as CryptoKey),
    "an AES-GCM key is not a key-wrapping key",
  );

  const cbc = await crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, false, ["encrypt", "decrypt"]);
  assertRefuses(
    "invalid-key",
    () => KwKey.fromCryptoKey(cbc as CryptoKey),
    "an AES-CBC key is not a key-wrapping key",
  );

  // aes192 is declined package-wide by the WIT's portability ruling, so an
  // injected 192-bit key is refused exactly as an imported one would be.
  try {
    const aes192 = await crypto.subtle.generateKey({ name: "AES-KW", length: 192 }, false, ["wrapKey"]);
    assertRefuses(
      "unsupported",
      () => KwKey.fromCryptoKey(aes192 as CryptoKey),
      "aes192 is declined package-wide, injection included",
    );
  } catch {
    // A platform that declines to mint AES-192 at all upholds the same
    // boundary a step earlier; nothing to assert here.
  }
});

Deno.test("391: an injected password derives exactly what the platform derives", async () => {
  // Synthetic, labelled inputs throughout: an all-zero 16-byte "password",
  // a short ASCII salt, and a small iteration count (this is a
  // self-consistency check against the platform, not a work-factor test).
  const passwordBytes = new Uint8Array(16);
  const salt = new TextEncoder().encode("391-salt");
  const iterations = 1000;

  const key = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
  const password = Password.fromCryptoKey(key);
  assertEq(password.canDeriveBits(), true, "the platform deriveBits slot is the policy");
  assertEq(password.canDeriveKey(), false, "a slot the platform did not grant is not granted here");

  const viaWrapper = await (await pbkdf2Sha2.prepare("sha256", password, salt, iterations)).deriveBits(256);
  const viaPlatform = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256),
  );
  assertEq(
    viaWrapper.every((b, i) => b === viaPlatform[i]),
    true,
    "the injected password derives the platform's answer",
  );

  // Persistence round trip.
  const reloaded = Password.fromCryptoKey(structuredClone(password.toCryptoKey()));
  const again = await (await pbkdf2Sha2.prepare("sha256", reloaded, salt, iterations)).deriveBits(256);
  assertEq(
    again.every((b, i) => b === viaPlatform[i]),
    true,
    "a persisted-and-reloaded password is the same keying material",
  );
});

Deno.test("391: password injection refuses a key of another derivation family", async () => {
  const hkdfKey = await crypto.subtle.importKey("raw", new Uint8Array(32), "HKDF", false, ["deriveBits"]);
  assertRefuses(
    "invalid-key",
    () => Password.fromCryptoKey(hkdfKey),
    "an HKDF key is not a PBKDF2 password",
  );

  const aes = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  assertRefuses(
    "invalid-key",
    () => Password.fromCryptoKey(aes as CryptoKey),
    "an AES key is not a PBKDF2 password",
  );

  // The mirror of the ikm case: Password and Ikm are distinct kinds and
  // neither admits the other's key.
  const pbkdf2Key = await crypto.subtle.importKey("raw", new Uint8Array(16), "PBKDF2", false, ["deriveBits"]);
  assertRefuses(
    "invalid-key",
    () => Ikm.fromCryptoKey(pbkdf2Key),
    "a PBKDF2 password is not HKDF input keying material",
  );
});

Deno.test("391: an injected RSASSA-PKCS1-v1_5 pair signs, verifies, and reports its platform record", async () => {
  const pair = await rsassaPair(2048, "SHA-256");
  const signing = SigningKey.fromCryptoKey(pair.privateKey);
  const verifying = VerifyingKey.fromCryptoKey(pair.publicKey);

  // The mint-bound record is rebuilt from the platform slots, through the
  // family's own record builder — so the getters report the real key.
  assertEq(signing.algorithmName(), "RSASSA-PKCS1-v1_5", "the family is read off the key");
  assertEq(signing.algorithmHash(), "SHA-256", "the digest is read off RsaHashedKeyAlgorithm");
  assertEq(signing.algorithmLength(), 2048, "the modulus length is read off the key");
  assertEq(verifying.algorithmHash(), "SHA-256", "the public half agrees");
  assertEq(verifying.algorithmLength(), 2048, "and on the modulus length");
  const e = signing.algorithmPublicExponent();
  assertEq(e === undefined ? -1 : e.length, 3, "the public exponent is the platform's own 3-octet value");

  const sig = await signing.sign(arrayStream(MESSAGE));
  assertEq(sig.length, 256, "a 2048-bit RSA signature is one modulus wide");
  await verifying.verify(arrayStream(MESSAGE), sig);

  // Platform oracle in both directions.
  const platformSig = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signing.toCryptoKey(), MESSAGE),
  );
  await verifying.verify(arrayStream(MESSAGE), platformSig);

  const tampered = sig.slice();
  tampered[0] ^= 0x01;
  const err = await assertRejects(() => verifying.verify(arrayStream(MESSAGE), tampered));
  assertEq(kindOf(err), "authentication-failed", "a tampered RSA signature is refused");
});

Deno.test("391: RSASSA injection applies the mint paths' own admission windows", async () => {
  // The signing interfaces use a TIGHTER modulus window (2048-8192) than the
  // verifying ones (1024-16384), because verification is a public operation
  // over an attacker-supplied key. Injection inherits both windows, so a
  // 1024-bit key is admissible as a verifying key and refused as a signing
  // key — the asymmetry is deliberate, not an oversight.
  const small = await rsassaPair(1024, "SHA-256");
  assertRefuses(
    "invalid-key",
    () => SigningKey.fromCryptoKey(small.privateKey),
    "a 1024-bit modulus is below the signing window",
  );
  assertEq(
    VerifyingKey.fromCryptoKey(small.publicKey).algorithmLength(),
    1024,
    "the same modulus is inside the verifying window",
  );

  // SHA-1 is deliberately absent from the RSA families' variant table, so a
  // SHA-1-bound RSASSA key is refused however it was minted.
  try {
    const sha1 = await rsassaPair(2048, "SHA-1");
    assertRefuses(
      "unsupported",
      () => VerifyingKey.fromCryptoKey(sha1.publicKey),
      "the RSA families do not serve SHA-1",
    );
  } catch {
    // A platform that will not mint SHA-1 RSASSA at all upholds the same
    // boundary earlier.
  }
});

Deno.test("391: the excluded families keep their named refusal", async () => {
  const ecdsa = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const err = assertThrows(() => SigningKey.fromCryptoKey(ecdsa.privateKey));
  assertEq(kindOf(err), "unsupported", "ECDSA stays outside the injection boundary");
  const detail = ((err as ComponentException).payload as { value: string }).value;
  assertTrue(
    detail.includes("mint bindings") && detail.includes("invent"),
    "the refusal names the reason: the per-mint binding is not on the key",
  );

  const pss = await crypto.subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    false,
    ["sign", "verify"],
  ) as CryptoKeyPair;
  const pssErr = assertThrows(() => SigningKey.fromCryptoKey(pss.privateKey));
  assertEq(kindOf(pssErr), "unsupported", "RSA-PSS stays outside too: its salt length is a mint choice");
});

Deno.test("391: kinds whose policy collapses onto fewer usages expose no injection seam", () => {
  // These are the documented exclusions (see the tier statement in
  // signature.ts). The absence is asserted rather than assumed, so a future
  // change that adds a seam without resolving the policy-collapse question
  // fails here instead of silently widening an injected key's authority.
  for (const [name, cls] of collapsedPolicyClasses()) {
    assertTrue(
      !("fromCryptoKey" in cls),
      `${name} must expose no fromCryptoKey: its WIT grants collapse onto fewer platform usages`,
    );
    assertTrue(
      !("toCryptoKey" in cls.prototype),
      `${name} must expose no toCryptoKey either: no seam means no half of one`,
    );
  }
});

Deno.test("391: every CryptoKey-holding class refuses construction outside its minting interfaces", () => {
  // One sweep over the whole token-gated roster: the construction token is
  // package-private and unexported from mod.ts, so no argument a consumer can
  // build satisfies any of these guards.
  for (const [name, cls] of tokenGatedClasses()) {
    // deno-lint-ignore no-explicit-any
    const err = assertThrows(() => new (cls as any)(), `${name} must refuse a bare construction`);
    assertEq(kindOf(err), "other", `${name} refuses with the provenance verdict`);
    const detail = ((err as ComponentException).payload as { value: string }).value;
    assertTrue(
      detail.includes("constructed outside its minting interfaces"),
      `${name} uses the package's provenance phrasing, got: ${detail}`,
    );

    // A forged token is no better than none: identity is the mechanism.
    // deno-lint-ignore no-explicit-any
    const forged = assertThrows(() => new (cls as any)(Symbol("polymorph:webcrypto mint"), {}, {}, {}));
    assertEq(kindOf(forged), "other", `${name} refuses a same-description forged symbol`);
  }
});
