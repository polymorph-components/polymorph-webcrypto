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
import { hkdfSha2, Ikm, SigningKey, VerifyingKey } from "../src/mod.ts";
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
