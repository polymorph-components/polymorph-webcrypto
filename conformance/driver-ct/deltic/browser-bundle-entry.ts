// Local replacement for the retired `@deltic/release-bundle-entry` raw-URL
// import: upstream's `tools/release-bundle/entry.ts` re-export surface,
// reproduced here so the worker bundle (browser/worker-entry.ts) resolves
// the deltic engine through this repo's own pinned JSR import map instead
// of a second, separately-pinned copy of the same modules — the
// module-identity constraint (see deno.json's "//" comment) wants exactly
// one embedder module instance.
//
// See the migration contract's "Browser-leg assets" section for the
// upstream entry file this mirrors.

export * from "@deltic/runtime/embedder";
export { Translator } from "@deltic/runtime/shim";
export * from "@deltic/ct-runner";
export { wasiShims } from "@deltic/wasi-shims";
export type { WasiShims, WasiShimsOptions } from "@deltic/wasi-shims";
