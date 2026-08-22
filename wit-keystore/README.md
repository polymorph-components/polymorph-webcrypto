# `wit-keystore` — the `polymorph:webcrypto-keystore` package

A **sibling** package to [`polymorph:webcrypto`](../wit): keeping a
signing key across instantiations, by name, without the key's material
ever crossing an interface.

It lives beside that package rather than inside it because
`polymorph:webcrypto` tracks the Web Cryptography API and takes no
extensions to it (`AGENTS.md`, "What this repository is"). Storing a key
by a name of the guest's choosing is not a SubtleCrypto operation: what
WebCrypto supplies is the enabling machinery — §13's structured-clone
steps for `CryptoKey`, which exist so IndexedDB can hold one. The ruling
and the inherited design record are
[issue #389](https://github.com/polymorph-components/polymorph-webcrypto/issues/389)
(successor to #97).

The package pulls `polymorph:webcrypto` in through the
`deps/polymorph-webcrypto` **symlink** back to the root `wit/`, the same
way every component in this repository does. Do not replace it with a
copy.

## The shape

One interface, `signing-keystore`, with two functions: store a
`polymorph:webcrypto/signature.signing-key` under an identifier, and load
it back. `none` from a load means "nothing usable under that name" — the
ordinary first-run answer, and also what an entry that fails validation
reports, because such an entry is removed rather than returned.

Two properties do the real work, and both are stated in the WIT:

- **Placement is the host's, naming is the guest's.** The host is
  configured with one storage root before the guest runs; guest
  identifiers are scoped inside it. A guest cannot reach another's keys
  and cannot choose where its own live.
- **A loaded key is untrusted input.** An implementation validates a
  stored entry — algorithm, key type, usages, `extractable` — against the
  resource type being loaded, and returns nothing that fails. The store
  is typically writable by anything else in the same protection domain.

## Errors

`result<_, string>`: the string describes a condition (no keystore
configured, the store is unavailable, the name is empty, the key is
extractable), not a code to branch on. The package deliberately does not
reuse `polymorph:webcrypto/types.error` — that variant's cases are the
crypto-operation conditions its contracts named, and it is frozen against
growth (`AGENTS.md`, "WIT is organized by ownership"), so borrowing it
here would either misreport storage conditions as `other` or push a
foreign package's needs onto a closed variant.

## Implementations

`js/polyengine/src/keystore.ts` (`@polymorph/webcrypto/keystore`) serves it
over IndexedDB, one database per namespace. Its browser lane is `just
polyengine-keystore-probe`. A native analogue (preopen-backed key files) is
open design, and the interface does not preclude one; see #389's open
questions, which also carry the two other undecided points — kind
coverage beyond `signing-key`, and whether a guest may enumerate its
namespace.
