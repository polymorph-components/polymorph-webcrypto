// The keystore browser probe's page body: the checks that need a real
// browser — IndexedDB, `CryptoKey` structured clone, and a page reload —
// which the Deno unit suite cannot run (Deno has no IndexedDB).
//
// The steps run through `globalThis.keystoreProbe`, called by
// ../run.mjs's driver from Playwright: it evaluates the pre-reload steps,
// RELOADS the page (a fresh JS realm, fresh module state, one surviving
// IndexedDB origin), and evaluates the post-reload steps. That reload is
// the whole point of the lane — the port's promise is about instances
// that do not share memory.
//
// Every value crossing `page.evaluate` is JSON-safe; key material never
// does. The one public value that crosses is the verification key, hex
// encoded, which is what the driver checks the post-reload signature
// against.
//
// The message signed throughout is a labeled synthetic constant (bytes
// 0,1,2,…), not a captured or realistic-looking value: the checks are
// about key identity, so the message content carries no meaning.

/// <reference lib="dom" />

import { ed25519Sign, ed25519Verify, SigningKey, SigningKeyOptions } from "../../src/mod.ts";
import { keystoreImports } from "../../src/keystore.ts";
import { arrayStream } from "../testStream.ts";

/** A labeled synthetic message: byte i = i. Nothing about it is secret or meaningful. */
const MESSAGE = Uint8Array.from({ length: 32 }, (_, i) => i);

const KEYSTORE_ID = "polymorph:webcrypto-keystore/signing-keystore@0.1.0";

interface Keystore {
  persistSigningKey(key: SigningKey, id: string): Promise<void>;
  loadSigningKey(id: string): Promise<SigningKey | undefined>;
}

function keystore(namespace?: string): Keystore {
  const fragment = keystoreImports(namespace === undefined ? undefined : { namespace });
  return fragment[KEYSTORE_ID] as Keystore;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function mintSigningKey(extractable: boolean): Promise<[SigningKey, string]> {
  const options = new SigningKeyOptions();
  options.canSign(true);
  options.extractable(extractable);
  const [signingKey, verifyingKey] = await ed25519Sign.generateKey(options);
  return [signingKey, hex(await verifyingKey.exportKeyRaw())];
}

/** The `ComponentException` payload of a refusal, as a string for the driver. */
function refusal(e: unknown): string {
  const payload = (e as { payload?: unknown })?.payload;
  return typeof payload === "string" ? payload : String((e as Error)?.message ?? e);
}

async function expectRefusal(what: string, run: () => Promise<unknown>): Promise<string> {
  try {
    await run();
  } catch (e) {
    return refusal(e);
  }
  throw new Error(`${what}: expected a refusal, got success`);
}

/** Write a value straight into a namespace's object store, bypassing the port. */
function plant(namespace: string, id: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(namespace, 1);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("signing-keys")) db.createObjectStore("signing-keys");
    };
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction("signing-keys", "readwrite");
      tx.objectStore("signing-keys").put(value, id);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onabort = tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    };
  });
}

function rawEntry(namespace: string, id: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(namespace, 1);
    open.onupgradeneeded = () => {
      const db = open.result;
      if (!db.objectStoreNames.contains("signing-keys")) db.createObjectStore("signing-keys");
    };
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const get = db.transaction("signing-keys").objectStore("signing-keys").get(id);
      get.onsuccess = () => {
        db.close();
        resolve(get.result);
      };
      get.onerror = () => {
        db.close();
        reject(get.error);
      };
    };
  });
}

const probe = {
  /** Mint a non-extractable signing key, store it, and report its public half. */
  async mintAndPersist(namespace: string, id: string) {
    const [key, publicKeyHex] = await mintSigningKey(false);
    await keystore(namespace).persistSigningKey(key, id);
    return { publicKeyHex, signatureHex: hex(await key.sign(arrayStream(MESSAGE))) };
  },

  /**
   * Load the key stored under `id` and sign the probe message with it —
   * the post-reload half of the round trip. The signature is verified
   * against `publicKeyHex`, the public half of the key minted BEFORE the
   * reload: a different key cannot produce a signature that verifies.
   */
  async loadAndSign(namespace: string, id: string, publicKeyHex: string) {
    const key = await keystore(namespace).loadSigningKey(id);
    if (key === undefined) return { loaded: false };
    const signatureHex = hex(await key.sign(arrayStream(MESSAGE)));
    const verifying = await ed25519Verify.importVerifyingKeyRaw(
      Uint8Array.from(publicKeyHex.match(/../g) ?? [], (b) => parseInt(b, 16)),
    );
    let verified = true;
    try {
      await verifying.verify(arrayStream(MESSAGE), Uint8Array.from(signatureHex.match(/../g) ?? [], (b) => parseInt(b, 16)));
    } catch {
      verified = false;
    }
    return {
      loaded: true,
      verified,
      signatureHex,
      extractable: key.extractable(),
      canSign: key.canSign(),
      algorithm: key.algorithmName(),
    };
  },

  /** An extractable key must be refused at the store edge, and nothing may land. */
  async persistExtractable(namespace: string, id: string) {
    const [key] = await mintSigningKey(true);
    const message = await expectRefusal(
      "persisting an extractable key",
      () => keystore(namespace).persistSigningKey(key, id),
    );
    return { message, stored: (await rawEntry(namespace, id)) !== undefined };
  },

  /** A name nothing was stored under is `none`, not an error. */
  async loadMissing(namespace: string, id: string) {
    return { loaded: (await keystore(namespace).loadSigningKey(id)) !== undefined };
  },

  /** Without the embedder's namespace, both functions refuse. */
  async withoutKeystore() {
    const [signingKey] = await mintSigningKey(false);
    return {
      persist: await expectRefusal("persist without a keystore", () => keystore().persistSigningKey(signingKey, "id")),
      load: await expectRefusal("load without a keystore", () => keystore().loadSigningKey("id")),
    };
  },

  /**
   * An entry that fails the load-side validation is discarded and
   * reported as `none`. The planted entry is an EXTRACTABLE key — the
   * exact thing the store edge refuses — standing in for any entry
   * written by something other than this port, since IndexedDB is
   * writable by anything else in the origin.
   */
  async plantedExtractable(namespace: string, id: string) {
    const pair = await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]) as CryptoKeyPair;
    await plant(namespace, id, pair.privateKey);
    const loaded = await keystore(namespace).loadSigningKey(id);
    return { loaded: loaded !== undefined, remaining: (await rawEntry(namespace, id)) !== undefined };
  },

  /** A non-key entry is discarded the same way. */
  async plantedGarbage(namespace: string, id: string) {
    await plant(namespace, id, { note: "not a CryptoKey" });
    const loaded = await keystore(namespace).loadSigningKey(id);
    return { loaded: loaded !== undefined, remaining: (await rawEntry(namespace, id)) !== undefined };
  },

  /** Two namespaces are two stores: the same identifier does not collide. */
  async namespaceIsolation(namespaceA: string, namespaceB: string, id: string) {
    const [key] = await mintSigningKey(false);
    await keystore(namespaceA).persistSigningKey(key, id);
    return {
      inA: (await keystore(namespaceA).loadSigningKey(id)) !== undefined,
      inB: (await keystore(namespaceB).loadSigningKey(id)) !== undefined,
    };
  },

  /** An empty identifier is refused on both functions. */
  async emptyId(namespace: string) {
    const [key] = await mintSigningKey(false);
    return {
      persist: await expectRefusal("persist with an empty id", () => keystore(namespace).persistSigningKey(key, "")),
      load: await expectRefusal("load with an empty id", () => keystore(namespace).loadSigningKey("")),
    };
  },

  /** Storing twice under one name converges on the later key (documented last-write-wins). */
  async restoreOverwrites(namespace: string, id: string) {
    const [first] = await mintSigningKey(false);
    const [second, secondPublicHex] = await mintSigningKey(false);
    const store = keystore(namespace);
    await store.persistSigningKey(first, id);
    await store.persistSigningKey(second, id);
    const loaded = await store.loadSigningKey(id);
    if (loaded === undefined) return { loaded: false };
    const signatureHex = hex(await loaded.sign(arrayStream(MESSAGE)));
    const verifying = await ed25519Verify.importVerifyingKeyRaw(
      Uint8Array.from(secondPublicHex.match(/../g) ?? [], (b) => parseInt(b, 16)),
    );
    let isSecond = true;
    try {
      await verifying.verify(arrayStream(MESSAGE), Uint8Array.from(signatureHex.match(/../g) ?? [], (b) => parseInt(b, 16)));
    } catch {
      isSecond = false;
    }
    return { loaded: true, isSecond };
  },
};

(globalThis as unknown as { keystoreProbe: typeof probe }).keystoreProbe = probe;
