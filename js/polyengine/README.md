# `js/polyengine` — the polyengine-native `polymorph:webcrypto` host module

`src/mod.ts` is the [polyengine](https://github.com/polymorph-components/polyengine)-native port of
[`js/jco/webcrypto.js`](../jco/webcrypto.js): the same behavioral reference
host — one platform-WebCrypto-backed implementation of every
`polymorph:webcrypto@0.1.0` interface — rewritten over polyengine's embedder
API (typed `Stream<T>` rather than jco's bare-payload `Stream`, and
`ComponentException` throws rather than `throw { tag, val }`). It was developed as
polyengine's own `ports/webcrypto` reference-host port and is upstreamed here
per [polymorph-components/polyengine#40](https://github.com/polymorph-components/polyengine/pull/40); the WIT
contract is [`wit/`](../../wit), and every doc comment quoting a contract
quotes that package. Doc comments citing `contracts/embedder-api.md` cite
the *polyengine* repository's embedder contract, the port's other authority.

`webcryptoImports()` is the whole entry point: it returns the imports
record — one entry per WIT interface, keyed by the fully qualified id with
version — that polyengine's `instantiate` takes.

## Standing declines

Both are the WIT's own rulings rather than Deno gaps, and both are
fail-closed refusals, not silent weakenings:

- **`sha1-checked`** is provided but refuses with `error.unsupported`: its
  postures need sha1dc collision detection, which no platform WebCrypto
  carries (`src/sha1Checked.ts`). Conformance targets declare it in
  `missing-features` (`conformance/driver-ct/targets.toml`), and the
  suite's `!sha1-checked` decline case still runs, verifying that the
  refusal actually happens.
- **`aes192`, `p521`/`p521-sha512`, and the truncated SHA-2 variants** are
  declined package-wide with `error.unsupported` (see the WIT docs).

The RSA private-key posture (`rsa-pss-sign`, `rsassa-pkcs1-v15-sign`,
`rsa-oaep-decrypt`) defaults to **served** here, matching the reference
host's Node posture — Deno's `crypto.subtle` mints those keys. A
browser-hosted embedding should call `setRsaPrivateKeyPolicy("decline")`
(`src/rsaSignature.ts`), the posture `jco-browser` runs under.

## Injecting embedder-held keys

`webcryptoHost()` returns the imports record **paired with** injection
functions, for embedders that hand the guest a key they hold themselves:

```ts
const { imports, inject } = webcryptoHost();
const identity = inject.signingKey(await loadDeviceKey());
await instantiate(artifacts, {
  ...wasi(),
  ...imports,
  "app:device/identity": { deviceIdentity: () => identity },
});
```

The returned handle is what the package's own minting interfaces return:
same resource class, same table, same getters. Only this module can
produce one — the resource tables are package-internal — which is the
whole reason the API exists. The guest-visible function that hands the
key over is the consumer's own WIT, not this package's (see
[#391](https://github.com/polymorph-components/polymorph-webcrypto/issues/391),
and #389 for why the alternative — a keystore in WIT — was rejected).

`webcryptoImports()` is unchanged and remains the simple form for
embedders that inject nothing; it is exactly `webcryptoHost().imports`.

**`inject` belongs to the `imports` record it came with.** Take the pair
and use the pair: injecting through one invocation and instantiating from
another invocation's record is outside the contract.

v1 serves two kinds:

| function | accepts | returns |
| --- | --- | --- |
| `inject.signingKey` | a **private** `Ed25519` key | `SigningKey` |
| `inject.derivationKey` | a **secret** `HKDF` or `PBKDF2` key | `Ikm` / `Password` |

Ed25519 is the only signature algorithm served because it is the only one
whose entire mint-bound record is recoverable from `[[algorithm]]`: ECDSA
binds a digest at mint and RSA-PSS a salt length, and WebCrypto carries
neither on the key. Wrong kind, wrong key type, or an algorithm outside
those sets throws a `TypeError` — this is an embedder API, so its
failures are programming errors, not WIT `error`s.

Policy is reported, never enforced. An embedder may inject an extractable
key or one with no usages; `extractable()` and the per-kind `can-*`
getters answer from the key's own `[[extractable]]`/`[[usages]]`, and
operations the key does not permit fail through the usual
`not-permitted`/`not-extractable` paths. Injection is not a place to
defend against the party that already holds the key.

The gate is `just polyengine-inject-probe` (`tests/browser/`): a
Playwright-driven Chromium page, because non-extractable platform keys
are the subject and Deno's suite cannot mint the shapes that matter.

## Module identity

`deno.json`'s `@polyengine/runtime/embedder` import maps to the exact same
pinned JSR version as
[`conformance/driver-ct/polyengine/deno.json`](../../conformance/driver-ct/polyengine/deno.json).
polyengine's `wasi-shims` module imports that specifier by bare name
internally; if the two configs ever disagreed, the embedder module would
load twice and `instanceof ComponentException` would stop holding across the
boundary. Keep both import maps' version identical for that one entry —
`just conformance-ct::polyengine-pin-check` gates that.

## Unit tests

`tests/families_test.ts` is a focused known-answer suite, one case per
family, reading this repository's own `conformance/vectors` tree by
RELATIVE path. Each case either agrees with a published vector or verifies
that the implementation rejects a tampered / upstream-invalid input with
the WIT taxonomy's verdict for that condition; vectors are named by file +
tcId, never inlined.

```sh
cd js/polyengine
deno task check
deno task test
```

Both run against the pinned JSR release with `deno.lock` frozen (`just
polyengine-module-check` runs the pair as CI does). The exhaustive behavioral
surface is the real conformance suite, which lives at
[`conformance/driver-ct/polyengine/`](../../conformance/driver-ct/polyengine).

## The pin

See [`conformance/driver-ct/polyengine/README.md`](../../conformance/driver-ct/polyengine/README.md)
— it owns the bump procedure for both pin sites (this `deno.json`
included).
