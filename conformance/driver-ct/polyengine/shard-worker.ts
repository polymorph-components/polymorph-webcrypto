/// <reference lib="deno.worker" />

// Deno module worker running one shard of a suite: loads the suite
// artifacts, wires the host imports, and runs `runSuite` over its stripe
// (see run.ts's SHARDING section for the parent-side merge contract).

import { Translator } from "@polyengine/runtime/shim";
import type { ComponentArtifacts } from "@polyengine/runtime/embedder";
import { runSuite, type RunCounts } from "@polyengine/ct-runner";
import { wasi } from "@polyengine/wasi";
import { defaultTranslator } from "@polyengine/translator";
import { webcryptoImports } from "../../../js/polyengine/src/mod.ts";

/** Posted once by the parent to start this shard's run. */
export interface ShardRequest {
  wasmPath: string;
  translatorPath?: string;
  target: string;
  suiteName: string;
  only?: string;
  missing: string[];
  caseTimeoutMs: number;
  jspi: boolean;
  freshCases: boolean;
  shard?: { index: number; count: number };
}

/** This shard's complete result, ready for the parent to merge. */
export interface ShardDone {
  kind: "done";
  envelope: string;
  terminator: string;
  rows: [number, string][];
  counts: RunCounts;
}

export interface ShardError {
  kind: "error";
  error: string;
}

export type ShardReply = ShardDone | ShardError;

async function loadArtifacts(
  translatorPath: string | undefined,
  wasmPath: string,
): Promise<ComponentArtifacts> {
  const translator = translatorPath
    ? await Translator.create(await Deno.readFile(translatorPath))
    : await defaultTranslator();
  const componentBytes = await Deno.readFile(wasmPath);
  const { plan, adapters } = translator.translate(componentBytes);
  return { plan, componentBytes, adapters };
}

self.onmessage = async (event: MessageEvent<ShardRequest>) => {
  try {
    const req = event.data;
    const artifacts = await loadArtifacts(req.translatorPath, req.wasmPath);
    // The whole import surface: WASI (no ambient environment) plus every
    // `polymorph:webcrypto/*` interface from the host module under test.
    // ct-runner adds `polymorph:test/test-context` itself.
    const imports = {
      ...wasi({ cli: { env: {}, passthrough: false } }),
      ...webcryptoImports(),
    };

    let envelope: string | undefined;
    let terminator: string | undefined;
    const rows: [number, string][] = [];

    const counts = await runSuite(artifacts, {
      imports,
      target: req.target,
      suiteName: req.suiteName,
      only: req.only,
      missing: req.missing,
      caseTimeoutMs: req.caseTimeoutMs,
      jspi: req.jspi,
      freshCases: req.freshCases,
      shard: req.shard,
      emit: (line, caseIndex) => {
        if (caseIndex !== undefined) {
          rows.push([caseIndex, line]);
          return;
        }
        if (envelope === undefined) {
          envelope = line;
        } else if (terminator === undefined) {
          terminator = line;
        } else {
          throw new Error(
            `unexpected third no-index emit line (unknown wire shape): ${line}`,
          );
        }
      },
    });

    if (envelope === undefined || terminator === undefined) {
      throw new Error(
        "runSuite completed without emitting both an envelope and a terminator line",
      );
    }

    const reply: ShardDone = { kind: "done", envelope, terminator, rows, counts };
    self.postMessage(reply);
  } catch (e) {
    const reply: ShardError = {
      kind: "error",
      error: String(e instanceof Error ? e.stack ?? e.message : e),
    };
    self.postMessage(reply);
  }
};

self.onunhandledrejection = (event: PromiseRejectionEvent) => {
  event.preventDefault();
  const reply: ShardError = {
    kind: "error",
    error: String(
      event.reason instanceof Error
        ? event.reason.stack ?? event.reason.message
        : event.reason,
    ),
  };
  self.postMessage(reply);
};
