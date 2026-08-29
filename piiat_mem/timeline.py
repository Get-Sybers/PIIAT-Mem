"""Output stage — derive the deliverables from the CAR-event store (epic #1, phase 3).

The store (car.db) is the primary artifact; this module is the psort-analogue
that renders it:

- **wide JSONL timeline** (`timeline.json`) — one line per TIMESTAMPED CAR event:
  `timestamp`, `car_object`, `car_action`, the link columns
  (`guid`, `owning_guid`, `parent_guid`, `link_confidence`), provenance
  (`source_plugin`, `source_image`), and **every CAR property across every
  object** (the model superset), null where the object doesn't carry it.
- **per-object CSVs** (`car/<object>.csv`) — one file per CAR object that has
  rows: the event header plus that object's own canonical properties.

Store-only events (no timestamp — file/service/driver from memory) appear in the
CSVs but not the timeline, exactly as designed (docs/design/car-store.md §6).
"""
from __future__ import annotations

import csv
import json
import os

from . import carmodel

_META = ["timestamp", "car_object", "car_action", "guid", "owning_guid",
         "parent_guid", "link_confidence", "source_plugin", "source_image"]

# malfind is a TRIGGER, not a stored record (see cli.build_store): its regions
# are joined against the already-stored processes here, at output time.
MALFIND_PLUGINS = ("windows.malfind", "windows.malware.malfind")


def _load_jsonl(path):
    if not os.path.isfile(path):
        return []
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def malfind_overlay(store, out_dir: str) -> list[dict]:
    """A malfind region is a TRIGGER. We do NOT store it; instead we RETRIEVE the
    process we already extracted (by PID) and populate a CAR `module` timeline
    entry from THAT stored record — its guid/identity/host/user/image — plus the
    region detail malfind uniquely provides (address, protection, tag). One entry
    per region, timelined at the stored process's create time; unbacked
    (module_path null — the injection tell). Nothing is written to the store."""
    # index the stored processes by pid — the data we retrieve to populate from
    procs = {int(p["pid"]): p for p in store.iter_object("process")
             if p.get("car_action") == "create" and p.get("pid") is not None}

    plug_dir = os.path.join(out_dir, "plugins")
    regions = []
    for name in MALFIND_PLUGINS:
        regions += _load_jsonl(os.path.join(plug_dir, name + ".jsonl"))

    entries = []
    for r in regions:
        pid = r.get("PID")
        proc = procs.get(int(pid)) if pid is not None else None
        if proc is None:
            continue  # malfind flagged a process we have no record of — skip
        image = proc.get("source_image")
        start = r.get("Start VPN")
        entry = {
            "timestamp": proc.get("timestamp"),          # the stored process's create time
            "car_object": "module", "car_action": "load",
            "guid": f"module-{pid}-{start}",
            "owning_guid": proc.get("guid"),
            "link_confidence": "heuristic",              # joined by PID
            "source_plugin": "windows.malfind", "source_image": image,
            # retrieved from the stored process — NOT re-derived from malfind
            "pid": pid, "exe": proc.get("exe"), "image_path": proc.get("image_path"),
            "hostname": proc.get("hostname"), "fqdn": proc.get("fqdn"),
            # the region detail malfind uniquely supplies
            "base_address": start,
            "_native": {"malfind": True, "Protection": r.get("Protection"),
                        "Tag": r.get("Tag"), "StartVPN": start, "EndVPN": r.get("End VPN"),
                        "CommitCharge": r.get("CommitCharge"),
                        "PrivateMemory": r.get("PrivateMemory"),
                        "Disasm": r.get("Disasm"), "Hexdump": r.get("Hexdump")},
        }
        entries.append(entry)
    return entries


def write_timeline_json(store, path: str, out_dir: str | None = None) -> int:
    """The wide CAR timeline: every property of every object, null or not, plus
    the malfind overlay (retrieved from stored processes) when out_dir is given."""
    superset = carmodel.all_fields()
    cols = _META + [f for f in superset if f not in _META]
    rows = list(store.iter_timeline())
    if out_dir:
        rows += [e for e in malfind_overlay(store, out_dir) if e.get("timestamp")]
    rows.sort(key=lambda d: d["timestamp"])
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for ev in rows:
            row = {c: ev.get(c) for c in cols}
            fh.write(json.dumps(row, sort_keys=False, default=str))
            fh.write("\n")
            n += 1
    return n


def write_object_csvs(store, out_dir: str) -> dict[str, int]:
    """One CSV per CAR object that has rows: header + the object's properties."""
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for obj, count in store.counts().items():
        cols = [c for c in _META if c != "car_object"] \
            + [f for f in carmodel.fields(obj) if f not in _META]
        path = os.path.join(out_dir, f"{obj}.csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for ev in store.iter_object(obj):
                w.writerow({c: ev.get(c) for c in cols})
        written[obj] = count
    return written
