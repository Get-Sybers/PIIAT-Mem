"""piiat-mem — point at a memory image, get a timeline.

    piiat-mem -f memory.raw -o out/                 # container backend, JSONL timeline
    piiat-mem -f memory.raw -o out/ --format csv
    piiat-mem -f memory.raw -o out/ --native        # use an installed volatility3
    piiat-mem -f memory.raw -o out/ --symbols-online  # allow ISF symbol download

Writes:
    out/plugins/<plugin>.jsonl   raw per-plugin Volatility output
    out/timeline.<json|csv>      the merged, time-sorted timeline
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import __version__, runner, timeline


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="piiat-mem",
                                 description="Put a memory image In A Timeline (Volatility 3 + DFIR plugins).")
    ap.add_argument("-f", "--memory", help="memory image (raw/lime/dmp/vmem/...).")
    ap.add_argument("-o", "--out", help="output directory.")
    ap.add_argument("--format", choices=["json", "csv"], default="json", help="timeline format (default: json/JSONL).")
    ap.add_argument("--image", default=runner.DEFAULT_IMAGE, help="hardened Volatility image (container backend).")
    ap.add_argument("--symbols", default=None, help="ISF symbol cache dir (default: a temp dir).")
    ap.add_argument("--symbols-online", action="store_true", help="allow the container to fetch ISF symbols (network).")
    ap.add_argument("--native", action="store_true", help="run an installed volatility3 instead of the container.")
    ap.add_argument("--plugins", default=None, help="comma-separated plugin override (else the default set).")
    ap.add_argument("--no-timeline", action="store_true",
                    help="write only the raw per-plugin JSONL under <out>/plugins/; skip the merged timeline.")
    ap.add_argument("--list-plugins", action="store_true",
                    help="print the default plugin set as a JSON list and exit.")
    ap.add_argument("--version", action="version", version=f"piiat-mem {__version__}")
    args = ap.parse_args(argv)

    if args.list_plugins:
        json.dump(runner.ALL_PLUGINS, sys.stdout)
        sys.stdout.write("\n")
        return 0
    if not args.memory or not args.out:
        ap.error("-f/--memory and -o/--out are required")
    if not os.path.isfile(args.memory):
        sys.stderr.write(f"memory image not found: {args.memory}\n")
        return 2
    os.makedirs(args.out, exist_ok=True)
    symbols = args.symbols or tempfile.mkdtemp(prefix="piiat-symbols-")
    os.makedirs(symbols, exist_ok=True)
    plugins = args.plugins.split(",") if args.plugins else None

    sys.stderr.write(f"piiat-mem {__version__}: {args.memory} -> {args.out} ({args.format})\n")
    # symbols-online lifts the container's network isolation for the ISF fetch.
    results = runner.run_all(args.memory, args.out, plugins=plugins,
                             symbols_dir=symbols, image=args.image, native=args.native,
                             symbols_online=args.symbols_online)
    ok = sum(1 for r in results if r["ok"])
    for r in results:
        mark = "ok " if r["ok"] else "ERR"
        sys.stderr.write(f"  [{mark}] {r['plugin']}: {r['rows']} rows"
                         + (f"  ({r['error']})" if not r["ok"] else "") + "\n")

    if args.no_timeline:
        sys.stderr.write(f"\nraw per-plugin JSONL from {ok}/{len(results)} plugins -> {os.path.join(args.out, 'plugins')}\n")
    else:
        plugin_paths = [r["output"] for r in results]
        events = timeline.build(plugin_paths)
        ext = "csv" if args.format == "csv" else "json"
        tl_path = os.path.join(args.out, f"timeline.{ext}")
        (timeline.write_csv if args.format == "csv" else timeline.write_json)(events, tl_path)
        sys.stderr.write(f"\n{len(events)} timeline events from {ok}/{len(results)} plugins -> {tl_path}\n")
    if ok == 0:
        sys.stderr.write("no plugin produced output — is the image built (or --native volatility3 installed)?\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
