#!/usr/bin/env python3
"""Extract the deltic translator-shim wasm from a `deno info --json` module
graph, i.e. from the deno.lock-pinned JSR module cache — no network, no
sha256 bookkeeping (JSR package integrity already lives in the lock).

WARNING (learned the hard way): Deno's on-disk remote-cache file is the
module bytes PLUS a trailing "\n// denoCacheMetadata={...}" line. Copying
the whole file yields a CORRUPT wasm (WebAssembly.compile fails with an
"unexpected section <Code>"-style error; wasm-tools reports a section out
of order near EOF). Truncate to the exact byte size `deno info` reports for
the module, then sanity-check the WASM magic before writing the output.

Usage: extract-translator-wasm.py <deno-info.json> <out.wasm> <expected-pin>
"""
import json
import sys


def main() -> None:
    info_path, out_path, expected_pin = sys.argv[1], sys.argv[2], sys.argv[3]
    graph = json.load(open(info_path))
    mods = [m for m in graph["modules"] if "/@deltic/" in m.get("specifier", "")]
    if not mods:
        sys.exit("no @deltic modules found in module graph")

    bad = {m["specifier"] for m in mods if expected_pin not in m["specifier"]}
    if bad:
        sys.exit(f"pin drift in translator graph (expected {expected_pin}): {bad}")

    candidates = [m for m in mods if m["specifier"].endswith("/translator_shim.wasm")]
    if not candidates:
        sys.exit("translator_shim.wasm not found in @deltic module graph")
    asset = candidates[0]

    data = open(asset["local"], "rb").read()
    body, rest = data[: asset["size"]], data[asset["size"] :]
    if body[:4] != b"\0asm":
        sys.exit("extracted bytes do not start with the WASM magic after truncation")
    if rest and not rest.startswith(b"\n// denoCacheMetadata="):
        sys.exit(
            "unexpected cache-file layout after the reported module size; "
            "refusing to copy (see this script's module docstring)"
        )

    open(out_path, "wb").write(body)
    print(f"wrote {out_path} ({len(body)} bytes)")


if __name__ == "__main__":
    main()
