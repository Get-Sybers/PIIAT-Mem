"""Normalize a raw Volatility record into a MITRE CAR event (epic #1, phase 2).

`normalize(plugin, record)` applies the plugin's map from `mappings.py` and returns
one CAR event dict: `car_object`, `car_action`, `timestamp`, the synthesized `guid`
(the object's reuse-proof identity), `owning_pid` / `parent_pid` (resolved to
`owning_guid` / `parent_guid` during enrichment, with `link_confidence`), the
canonical CAR **properties**, and `_native` (kept fields with no CAR home). See
docs/design/car-store.md.
"""
from __future__ import annotations

import ntpath
import re

from . import mappings

_HIVE_USER = re.compile(r"(?i)(?:Documents and Settings|Users)\\([^\\]+)\\")


def _blank(v) -> bool:
    return v is None or v == "" or v == "-"


def _resolve(src, rec):
    """Resolve a property-source marker (or a plain field name) against a record."""
    if isinstance(src, str):
        return rec.get(src)
    kind = src[0]
    if kind == "first":
        for f in src[1]:
            v = rec.get(f)
            if not _blank(v):
                return v
        return None
    if kind == "basename":
        v = rec.get(src[1])
        return ntpath.basename(v) if v else None
    if kind == "user_from_hive":
        v = rec.get(src[1]) or ""
        m = _HIVE_USER.search(str(v))
        return m.group(1) if m else None
    raise ValueError(f"unknown source marker: {src!r}")


def _guid(spec, obj, rec):
    """Synthesize the object's CAR guid: a field the plugin already carries, or
    `<object>-<identity fields>` from its memory identity (offset / natural key)."""
    if "field" in spec:
        return rec.get(spec["field"])
    parts = [str(rec.get(f)) for f in spec["fields"]]
    if any(p in ("None", "") for p in parts):
        return None
    return f"{obj}-" + "-".join(parts)


def normalize(plugin: str, rec: dict) -> dict | None:
    """One raw record → one CAR event, or None if the plugin has no CAR map."""
    m = mappings.MAPPINGS.get(plugin)
    if m is None:
        return None
    obj = m["object"]
    props = {car: _resolve(src, rec) for car, src in m["props"].items()}
    event = {
        "car_object": obj,
        "car_action": m["action"],
        "timestamp": None if m["ts"] is None else rec.get(m["ts"]),
        "guid": _guid(m["guid"], obj, rec),
        "owning_pid": rec.get(m["owning_pid"]) if m.get("owning_pid") else None,
        "parent_pid": rec.get(m["parent_pid"]) if m.get("parent_pid") else None,
        "owning_guid": None,        # set in enrichment (offset/create-time ordered)
        "parent_guid": None,        # set in enrichment
        "link_confidence": None,    # set in enrichment
        "source_plugin": plugin,
        "_native": {k: rec.get(k) for k in m.get("keep", []) if k in rec},
    }
    event.update(props)
    return event
