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


def write_timeline_json(store, path: str) -> int:
    """The wide CAR timeline: every property of every object, null or not."""
    superset = carmodel.all_fields()
    cols = _META + [f for f in superset if f not in _META]
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for ev in store.iter_timeline():
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
