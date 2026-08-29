"""piiat-mem — point at a memory image, get a MITRE CAR timeline.

    piiat-mem -f memory.raw -o out/                 # container backend, CAR JSONL timeline
    piiat-mem -f memory.raw -o out/ --format csv    # per-CAR-object CSVs instead
    piiat-mem -f memory.raw -o out/ --native        # use an installed volatility3
    piiat-mem -f memory.raw -o out/ --symbols-online  # allow ISF symbol download

Pipeline (Plaso-shaped): extract -> normalize -> store -> output.

Writes:
    out/plugins/<plugin>.jsonl   raw per-plugin Volatility output (traceability)
    out/car.db                   the CAR-event store (SQLite) — the primary artifact
    out/timeline.json            wide CAR timeline: timestamp, car_object,
                                 car_action, every CAR property (null or not)
    out/car/<object>.csv         (--format csv) one CSV per CAR object instead
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile

from . import __version__, enrich, mappings, normalize, runner, store, timeline


def _load_records(path: str) -> list[dict]:
    out = []
    if not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def build_store(out_dir: str, source_image: str) -> "store.CarStore":
    """Normalize + enrich EVERY raw per-plugin JSONL under <out>/plugins/ into a
    fresh <out>/car.db. Scanning the disk (not one invocation's plugin list)
    makes the store safe under subset/incremental runs — earlier plugins' raw
    output is re-normalized, never destroyed. Plugins with no CAR map (banners,
    windows.info, windows.pslist, ...) land in the image_context side table.
    Stale rendered views (timeline.json, car/*.csv) are removed so they can
    never disagree with the store they derive from."""
    plug_dir = os.path.join(out_dir, "plugins")
    events, context = [], []
    if os.path.isdir(plug_dir):
        present = {n[:-len(".jsonl")] for n in os.listdir(plug_dir) if n.endswith(".jsonl")}
        # a superseded built-in's JSONL is skipped when its piiat.* successor's
        # output is present — see mappings.SUPERSEDES (prevents e.g. every logon
        # double-counting under the old and new user_session identity schemes)
        superseded = {old for new, old in mappings.SUPERSEDES.items()
                      if new in present}
        for name in sorted(os.listdir(plug_dir)):
            if not name.endswith(".jsonl"):
                continue
            plugin = name[:-len(".jsonl")]
            if plugin in superseded:
                continue
            records = _load_records(os.path.join(plug_dir, name))
            if not records:
                continue
            evs = [normalize.normalize(plugin, rec) for rec in records]
            evs = [e for e in evs if e is not None]
            if evs:
                for ev in evs:
                    ev["source_image"] = source_image
                events.extend(evs)
            else:
                context.append((plugin, records))
    events = enrich.enrich(events)

    db_path = os.path.join(out_dir, "car.db")
    if os.path.exists(db_path):
        os.remove(db_path)  # the store is rebuilt from the raw JSONL each run
    for stale in (os.path.join(out_dir, "timeline.json"),):
        if os.path.exists(stale):
            os.remove(stale)
    csv_dir = os.path.join(out_dir, "car")
    if os.path.isdir(csv_dir):
        for name in os.listdir(csv_dir):
            if name.endswith(".csv"):
                os.remove(os.path.join(csv_dir, name))
    st = store.CarStore(db_path)
    st.insert_events(events)
    for plugin, records in context:
        st.insert_context(source_image, plugin, records)
    return st


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="piiat-mem",
                                 description="Put a memory image In A Timeline (Volatility 3 -> MITRE CAR).")
    ap.add_argument("-f", "--memory", help="memory image (raw/lime/dmp/vmem/...).")
    ap.add_argument("-o", "--out", help="output directory.")
    ap.add_argument("--format", choices=["json", "csv"], default="json",
                    help="output: json = wide CAR timeline (JSONL); csv = one CSV per CAR object.")
    ap.add_argument("--image", default=runner.DEFAULT_IMAGE, help="hardened Volatility image (container backend).")
    ap.add_argument("--symbols", default=None, help="ISF symbol cache dir (default: a temp dir).")
    ap.add_argument("--symbols-online", action="store_true", help="allow the container to fetch ISF symbols (network).")
    ap.add_argument("--native", action="store_true", help="run an installed volatility3 instead of the container.")
    ap.add_argument("--plugins", default=None, help="comma-separated plugin override (else the default set).")
    ap.add_argument("--no-timeline", action="store_true",
                    help="skip the rendered outputs (timeline/CSVs); still writes the raw "
                         "per-plugin JSONL and the car.db store.")
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

    # normalize -> enrich -> store (the CAR product; always built, from ALL raw
    # JSONL on disk — not just this invocation's plugins)
    st = build_store(args.out, os.path.basename(args.memory))
    counts = st.counts()
    sys.stderr.write("\nCAR store -> " + os.path.join(args.out, "car.db")
                     + "  (" + ", ".join(f"{o}:{n}" for o, n in sorted(counts.items())) + ")\n")

    if args.no_timeline:
        sys.stderr.write(f"raw per-plugin JSONL from {ok}/{len(results)} plugins -> {os.path.join(args.out, 'plugins')}\n")
    elif args.format == "csv":
        written = timeline.write_object_csvs(st, os.path.join(args.out, "car"))
        sys.stderr.write("per-object CSVs -> " + os.path.join(args.out, "car")
                         + "  (" + ", ".join(f"{o}.csv:{n}" for o, n in sorted(written.items())) + ")\n")
    else:
        tl_path = os.path.join(args.out, "timeline.json")
        n = timeline.write_timeline_json(st, tl_path)
        sys.stderr.write(f"{n} CAR timeline events -> {tl_path}\n")
    st.close()

    if ok == 0:
        sys.stderr.write("no plugin produced output — is the image built (or --native volatility3 installed)?\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
