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

## The keystore module

`src/keystore.ts` (`@polymorph/webcrypto/keystore`) serves a *different*
WIT package: [`polymorph:webcrypto-keystore`](../../wit-keystore), which
keeps a signing key across instantiations by a name the guest chooses.
`keystoreImports({ namespace })` is its entry point, and `namespace` is
the IndexedDB database the embedder assigns — persistence is a capability
the embedder grants, so `keystoreImports()` with no argument returns
functions that refuse.

```ts
instantiate(artifacts, {
  ...wasi(),
  ...webcryptoImports(),
  ...keystoreImports({ namespace: "pm-device-7" }),
});
```

No key material crosses the interface in either direction: what IndexedDB
holds is the `CryptoKey` handle, structured-cloned, so a non-extractable
key survives a reload with its material still unreadable. The module
refuses to store an extractable key, and re-validates every entry on the
way back out (algorithm, key type, usages, `extractable`), because
IndexedDB is writable by anything else in the origin.

Its gate is `just polyengine-keystore-probe` — a Playwright-driven
Chromium page (`tests/browser/`) covering the store/reload/load/sign round
trip, the extractability refusals on both edges, the missing-name and
no-keystore answers, and namespace isolation. It is a separate lane
because Deno has no IndexedDB, so `deno task test` cannot observe any of
it.

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
