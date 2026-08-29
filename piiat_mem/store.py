"""The CAR-event store — SQLite, the `.plaso` analogue (epic #1, phase 2).

One table per CAR object (all 13 from the vendored model, empty where memory has
nothing), each with a common event header plus that object's canonical
properties as nullable columns:

    event_id · timestamp · car_action · guid · owning_pid · owning_guid ·
    parent_pid · parent_guid · link_confidence · source_plugin · source_image ·
    native (JSON: non-CAR fields kept — never faked into CAR columns)

`guid` is the object's reuse-proof identity (docs/design/car-store.md §3);
`owning_guid`/`parent_guid` are the resolved process-context links. A side table
`image_context` holds the raw output of every plugin with no CAR map —
banners.Banners and windows.info (image metadata), and e.g. windows.pslist
(the active-list contrast evidence behind the Hidden flag).

The store is the run's primary artifact; the timeline and the per-object CSVs
are derived views of it (timeline.py).
"""
from __future__ import annotations

import json
import sqlite3

from . import carmodel

HEADER = ["timestamp", "car_action", "guid", "owning_pid", "owning_guid",
          "parent_pid", "parent_guid", "link_confidence",
          "source_plugin", "source_image", "native"]


def _q(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class CarStore:
    """Create/open a car.db and read/write CAR events."""

    def __init__(self, path: str):
        self.path = path
        self.model = carmodel.load()
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._create()

    # -- schema ---------------------------------------------------------------

    def _cols(self, obj: str) -> list[str]:
        # header first, then the object's CAR properties (minus header collisions)
        return HEADER + [f for f in self.model[obj]["fields"] if f not in HEADER]

    def _create(self):
        cur = self.conn.cursor()
        for obj in self.model:
            cols = ", ".join(f"{_q(c)}" for c in self._cols(obj))
            cur.execute(f"CREATE TABLE IF NOT EXISTS {_q(obj)} "
                        f"(event_id INTEGER PRIMARY KEY, {cols})")
            cur.execute(f"CREATE INDEX IF NOT EXISTS {_q('ix_' + obj + '_guid')} "
                        f"ON {_q(obj)} (guid)")
            cur.execute(f"CREATE INDEX IF NOT EXISTS {_q('ix_' + obj + '_ts')} "
                        f"ON {_q(obj)} (timestamp)")
        cur.execute("CREATE TABLE IF NOT EXISTS image_context "
                    "(source_image TEXT, source_plugin TEXT, record TEXT)")
        self.conn.commit()

    # -- write ----------------------------------------------------------------

    def insert_events(self, events: list[dict]) -> int:
        n = 0
        cur = self.conn.cursor()
        for ev in events:
            obj = ev["car_object"]
            cols = self._cols(obj)
            row = []
            for c in cols:
                if c == "native":
                    row.append(json.dumps(ev.get("_native") or {}, default=str))
                elif c == "car_action":
                    row.append(ev.get("car_action"))
                else:
                    v = ev.get(c)
                    row.append(json.dumps(v, default=str) if isinstance(v, (list, dict)) else v)
            ph = ", ".join("?" for _ in cols)
            names = ", ".join(_q(c) for c in cols)
            cur.execute(f"INSERT INTO {_q(obj)} ({names}) VALUES ({ph})", row)
            n += 1
        self.conn.commit()
        return n

    def insert_context(self, source_image: str, plugin: str, records: list[dict]):
        cur = self.conn.cursor()
        cur.executemany(
            "INSERT INTO image_context (source_image, source_plugin, record) VALUES (?,?,?)",
            [(source_image, plugin, json.dumps(r, default=str)) for r in records])
        self.conn.commit()

    # -- read -----------------------------------------------------------------

    def iter_object(self, obj: str):
        """Every event row of one object, as dicts (native JSON decoded)."""
        for row in self.conn.execute(f"SELECT * FROM {_q(obj)} ORDER BY event_id"):
            d = dict(row)
            d["car_object"] = obj
            try:
                d["native"] = json.loads(d.get("native") or "{}")
            except (TypeError, ValueError):
                pass
            yield d

    def iter_timeline(self):
        """Every TIMESTAMPED event across all objects, ascending — the timeline."""
        rows = []
        for obj in self.model:
            rows.extend(d for d in self.iter_object(obj) if d.get("timestamp"))
        rows.sort(key=lambda d: d["timestamp"])
        return iter(rows)

    def counts(self) -> dict[str, int]:
        out = {}
        for obj in self.model:
            (n,) = self.conn.execute(f"SELECT COUNT(*) FROM {_q(obj)}").fetchone()
            if n:
                out[obj] = n
        return out

    def close(self):
        self.conn.close()
