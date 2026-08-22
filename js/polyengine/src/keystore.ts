// The `polymorph:webcrypto-keystore@0.1.0` host module for
// [polyengine](https://github.com/polymorph-components/polyengine): `keystoreImports()`
// returns
// the imports-record fragment serving `signing-keystore` over IndexedDB.
//
// The WIT contract is [`wit-keystore/`](../../../wit-keystore) — a
// SIBLING package to `polymorph:webcrypto`, which tracks the WebCrypto
// standard and takes no extensions to it (AGENTS.md, "What this
// repository is"; the ruling and its design record are issue #389).
// The keystore imports the `signing-key` resource from that package and
// adds no cryptography of its own.
//
// What makes this possible without any key material moving: the Web
// Cryptography API gives `CryptoKey` structured-clone steps (§13), so a
// browser can put a key in IndexedDB and take it out again with
// `[[extractable]]` and the underlying handle intact. A non-extractable
// key therefore survives a page reload while its material stays
// unreadable — the property this module exists to carry across
// instantiations, and the reason the alternative (export material,
// re-import next time) is a downgrade rather than an equivalent.
//
// Storage layout: one IndexedDB database per namespace — the embedder's
// storage root, fixed before the guest runs — holding a single object
// store of key handles keyed by the guest's identifiers.
//
// Two edges enforce non-extractability, because they fail differently.
// `persist-signing-key` refuses an extractable key: today the
// `polymorph:webcrypto` port mints signing keys non-extractable unless
// the caller asked otherwise (signature.ts `SigningKeyOptions`,
// defaulting `extractable: false`, threaded through
// `ed25519Sign.generateKey`), so the refusal is a check on the caller's
// mint, not on this port's default. `loadSigningKey` re-validates every
// stored entry — algorithm, key type, usages, and `extractable === false`
// — because IndexedDB is writable by anything else in the same origin,
// so an entry is untrusted input on the way back in (the shape is wosh's
// validated `usable()` predicate, site/identity-store.ts:67-76).

import { ComponentException } from "@polyengine/runtime/embedder";
import { ED25519_ALGORITHM, SigningKey } from "./signature.ts";

/** Where a keystore keeps its entries. The embedder chooses it; the guest never names it. */
export interface KeystoreOptions {
  /**
   * The storage root: the IndexedDB database name. Every identifier the
   * guest uses is scoped inside it, so two namespaces cannot see each
   * other's keys.
   */
  namespace: string;
}

/** The object store inside a namespace database. */
const STORE = "signing-keys";

/** The database version this module creates and expects. */
const DB_VERSION = 1;

// The slice of IndexedDB this module uses, typed structurally rather
// than through the DOM lib. A published module cannot pull the DOM
// globals into its consumers' type environment (JSR bans the triple
// slash directive that would), and nothing here declares a global, so
// the module type-checks the same whether or not the consumer has the
// DOM lib loaded.

interface IdbRequestLike<T> {
  readonly result: T;
  readonly error: unknown;
  onsuccess: (() => void) | null;
  onerror: (() => void) | null;
}

interface IdbOpenRequestLike extends IdbRequestLike<IdbDatabaseLike> {
  onupgradeneeded: (() => void) | null;
  onblocked: (() => void) | null;
}

interface IdbObjectStoreLike {
  get(key: string): IdbRequestLike<unknown>;
  put(value: unknown, key: string): unknown;
  delete(key: string): unknown;
}

interface IdbTransactionLike {
  readonly error: unknown;
  objectStore(name: string): IdbObjectStoreLike;
  oncomplete: (() => void) | null;
  onabort: (() => void) | null;
  onerror: (() => void) | null;
}

interface IdbDatabaseLike {
  readonly objectStoreNames: { contains(name: string): boolean };
  createObjectStore(name: string): unknown;
  transaction(store: string, mode?: "readonly" | "readwrite"): IdbTransactionLike;
  close(): void;
}

interface IdbFactoryLike {
  open(name: string, version?: number): IdbOpenRequestLike;
}

/** This platform's IndexedDB, or `undefined` where there is none (Deno, some private-browsing modes). */
function indexedDbFactory(): IdbFactoryLike | undefined {
  return (globalThis as { indexedDB?: IdbFactoryLike }).indexedDB;
}

/** Throw the WIT `result<_, string>` err arm. */
function keystoreError(detail: string): never {
  throw new ComponentException(detail);
}

const req = <T>(r: IdbRequestLike<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

const committed = (tx: IdbTransactionLike): Promise<void> =>
  new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(tx.error);
  });

function openDb(namespace: string): Promise<IdbDatabaseLike> {
  return new Promise((resolve, reject) => {
    const factory = indexedDbFactory();
    if (factory === undefined) {
      reject(new Error("this platform has no IndexedDB"));
      return;
    }
    const open = factory.open(namespace, DB_VERSION);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains(STORE)) db.createObjectStore(STORE);
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
    // Another connection is holding an older version open. Rejecting
    // beats waiting: `blocked` has no timeout of its own, and the guest
    // can retry.
    open.onblocked = () => reject(new Error("IndexedDB open blocked by another connection"));
  });
}

/**
 * Run `body` against the namespace database, mapping a storage refusal
 * onto the WIT err arm.
 *
 * Some private-browsing modes offer no IndexedDB at all, which is a
 * condition rather than a fault: the guest is told the keystore is
 * unavailable, and decides for itself whether to run without persistence
 * (the degradation the first consumer performs) or to stop.
 */
async function withDb<T>(namespace: string, body: (db: IdbDatabaseLike) => Promise<T>): Promise<T> {
  let db: IdbDatabaseLike;
  try {
    db = await openDb(namespace);
  } catch (e) {
    keystoreError(`keystore unavailable: ${(e as Error)?.message ?? e}`);
  }
  try {
    return await body(db);
  } catch (e) {
    if (e instanceof ComponentException) throw e;
    keystoreError(`keystore unavailable: ${(e as Error)?.message ?? e}`);
  } finally {
    db.close();
  }
}

/**
 * Whether a stored value is a key this module is willing to hand back:
 * exactly what a conforming `persist-signing-key` accepted, re-checked
 * rather than assumed.
 *
 * `extractable === false` is the load-side half of the promise the
 * interface makes about stored keys. The algorithm check is what keeps
 * the mint-bound algorithm record honest: the record is reconstructed
 * from a constant here, never read from storage, so a rewritten entry
 * cannot switch a per-operation binding.
 */
function usableSigningKey(value: unknown): value is CryptoKey {
  return (
    value instanceof CryptoKey &&
    value.type === "private" &&
    value.algorithm.name === "Ed25519" &&
    value.extractable === false &&
    value.usages.includes("sign")
  );
}

/** Remove an entry that failed validation, so the caller's mint-and-store path is not a loop. */
async function discard(db: IdbDatabaseLike, id: string): Promise<void> {
  const tx = db.transaction(STORE, "readwrite");
  tx.objectStore(STORE).delete(id);
  await committed(tx);
}

function requireId(id: string): void {
  if (id === "") keystoreError("a keystore identifier must not be empty");
}

function servedKeystore(options: KeystoreOptions) {
  const { namespace } = options;
  return {
    /**
     * `signing-keystore.persist-signing-key`: store the key's handle
     * under `id`, replacing any entry already there (the interface's
     * idempotence under `id`).
     */
    persistSigningKey: async (key: SigningKey, id: string): Promise<void> => {
      requireId(id);
      if (key.extractable()) {
        keystoreError(
          "an extractable signing key cannot be stored: a stored key promises material that was never readable",
        );
      }
      if (key.algorithmName() !== "Ed25519") {
        keystoreError(
          `this keystore stores Ed25519 signing keys; this key is ${key.algorithmName()}`,
        );
      }
      await withDb(namespace, async (db) => {
        const tx = db.transaction(STORE, "readwrite");
        tx.objectStore(STORE).put(key.cryptoKey, id);
        await committed(tx);
      });
    },

    /**
     * `signing-keystore.load-signing-key`: the key stored under `id`, or
     * `undefined` (the WIT `none`) when this namespace holds no usable
     * key by that name.
     */
    loadSigningKey: async (id: string): Promise<SigningKey | undefined> => {
      requireId(id);
      return await withDb(namespace, async (db) => {
        const stored = await req(db.transaction(STORE).objectStore(STORE).get(id));
        if (stored === undefined) return undefined;
        if (!usableSigningKey(stored)) {
          console.warn(
            `keystore: the entry ${JSON.stringify(id)} in ${JSON.stringify(namespace)} is not a usable ` +
              "non-extractable Ed25519 signing key; discarding it",
          );
          await discard(db, id);
          return undefined;
        }
        return new SigningKey(stored, ED25519_ALGORITHM);
      });
    },
  };
}

/**
 * The fragment served when the embedder granted no keystore. Persistence
 * is a capability the embedder hands over by naming a namespace, so its
 * absence is a refusal the guest can observe and report, never a silent
 * no-op that loses keys.
 */
const unavailableKeystore = {
  persistSigningKey: (_key: SigningKey, _id: string): Promise<void> =>
    keystoreError("this embedding grants no keystore"),
  loadSigningKey: (_id: string): Promise<SigningKey | undefined> =>
    keystoreError("this embedding grants no keystore"),
};

/**
 * Build the `polymorph:webcrypto-keystore@0.1.0` imports fragment for
 * `instantiate`.
 *
 * Usage:
 * `instantiate(artifacts, { ...wasi(), ...webcryptoImports(), ...keystoreImports({ namespace: "pm-device-7" }) })`.
 *
 * Called without options, the two functions refuse: a guest can ask, and
 * learns that this embedding keeps nothing.
 *
 * Concurrency: two instances sharing a namespace do not corrupt each
 * other — every write is one IndexedDB readwrite transaction, which the
 * store serializes — and the outcome for an identifier both instances
 * store is the later write. Callers that need one winner for a first
 * mint settle it above this interface (load, mint on `none`, store), and
 * a lost race costs the loser its unstored key, not the store's
 * consistency.
 */
export function keystoreImports(options?: KeystoreOptions): Record<string, unknown> {
  if (options !== undefined && options.namespace === "") {
    throw new TypeError("keystoreImports: namespace must not be empty");
  }
  return {
    "polymorph:webcrypto-keystore/signing-keystore@0.1.0": options === undefined
      ? unavailableKeystore
      : servedKeystore(options),
  };
}
