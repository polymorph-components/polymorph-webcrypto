// Local replacement for the retired `@polyengine/release-bundle-entry` raw-URL
// import: upstream's `tools/release-bundle/entry.ts` re-export surface,
// reproduced here so the worker bundle (browser/worker-entry.ts) resolves
// the polyengine engine through this repo's own pinned JSR import map instead
// of a second, separately-pinned copy of the same modules — the
// module-identity constraint (see deno.json's "//" comment) wants exactly
// one embedder module instance.
//
// See the migration contract's "Browser-leg assets" section for the
// upstream entry file this mirrors.

export * from "@polyengine/runtime/embedder";
export { Translator } from "@polyengine/runtime/shim";
export * from "@polyengine/ct-runner";
export { wasi } from "@polyengine/wasi";
export type { WasiImports, WasiOptions } from "@polyengine/wasi";
