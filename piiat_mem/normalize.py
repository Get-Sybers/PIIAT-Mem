"""Normalize a raw Volatility record into a MITRE CAR event (epic #1, phase 2).

`normalize(plugin, record)` applies the plugin's map from `mappings.py` (picking
the matching variant where the plugin splits across objects) and returns one CAR
event dict: `car_object`, `car_action`, `timestamp`, the synthesized `guid` (the
object's reuse-proof identity), `owning_pid` / `parent_pid` (resolved to
`owning_guid` / `parent_guid` during enrichment, with `link_confidence`), the
canonical CAR **properties**, and `_native` (kept fields with no CAR home). See
docs/design/car-store.md.
"""
from __future__ import annotations

import ntpath
import re

from . import mappings

# The profile owner from a user-hive FILE path. Covers real renderings:
# \??\C:\Users\<name>\NTUSER.DAT, \Device\HarddiskVolumeN\Users\<name>\...,
# Documents and Settings\<name>\ (XP), and Windows service profiles
# (\Windows\ServiceProfiles\<name>\NTUSER.DAT — the account IS <name>).
# SID-form hive paths (\REGISTRY\USER\S-1-5-21-...) carry no name here; they are
# resolved in enrichment against the image's own ProfileList mapping.
_HIVE_USER = re.compile(r"(?i)(?:Documents and Settings|Users|ServiceProfiles)\\([^\\]+)\\")
# Volatility's "no time" sentinels (epoch zero renderings) — treated as no timestamp.
_EPOCH_ZERO = re.compile(r"^(1601-01-01|1970-01-01|0001-01-01|1600-12-)")
_PROTO = re.compile(r"(?i)^([a-z]+?)(v(4|6))?$")


def _clean_ts(v):
    """A usable timestamp string, or None (blank / epoch-zero sentinel)."""
    if _blank(v):
        return None
    s = str(v)
    return None if _EPOCH_ZERO.match(s) else s


def _blank(v) -> bool:
    return v is None or v == "" or v == "-"


def _resolve(src, rec):
    """Resolve a property source against a record: a plain field name, or a
    marker from mappings.py — markers nest (e.g. basename(first(...)))."""
    if isinstance(src, str):
        return rec.get(src)
    kind = src[0]
    if kind == "first":
        for f in src[1]:
            v = _resolve(f, rec)
            if not _blank(v):
                return v
        return None
    if kind == "basename":
        v = _resolve(src[1], rec)
        return ntpath.basename(str(v)) if not _blank(v) else None
    if kind == "user_from_hive":
        v = _resolve(src[1], rec) or ""
        m = _HIVE_USER.search(str(v))
        return m.group(1) if m else None
    if kind == "transport":
        v = _resolve(src[1], rec)
        m = _PROTO.match(str(v)) if not _blank(v) else None
        return m.group(1).upper() if m else None
    if kind == "family":
        v = _resolve(src[1], rec)
        m = _PROTO.match(str(v)) if not _blank(v) else None
        return ("ipv" + m.group(3)) if m and m.group(3) else None
    if kind == "const":
        return src[1]
    if kind == "ext":
        v = _resolve(src[1], rec)
        if _blank(v):
            return None
        e = ntpath.splitext(ntpath.basename(str(v)))[1].lstrip(".").lower()
        return e or None
    if kind == "proc_guid":
        v = _resolve(src[1], rec)
        try:
            return f"proc-{int(v):x}" if v is not None else None
        except (TypeError, ValueError):
            return None
    if kind == "exe_path":
        v = _resolve(src[1], rec)
        if _blank(v):
            return None
        s = str(v).strip()
        if s.startswith('"'):
            end = s.find('"', 1)
            return s[1:end] if end > 0 else s.strip('"')
        i = s.lower().find(".exe")
        if i >= 0:
            return s[:i + 4]
        return s.split(" ")[0]
    raise ValueError(f"unknown source marker: {src!r}")


def _guid(spec, obj, rec):
    """Synthesize the object's CAR guid: a field the plugin already carries, a
    resolved marker (e.g. proc_guid of an offset), `<object>-<identity fields>`
    from its natural identity, or None-for-now ({"none": True} — assigned by a
    later merge stage). Only a MISSING (None) component voids a fields-guid —
    "" is a legitimate identity value (e.g. a registry key's default value has
    ValueName "")."""
    if spec.get("none"):
        return None
    if "marker" in spec:
        return _resolve(spec["marker"], rec)
    if "field" in spec:
        return rec.get(spec["field"])
    parts = [rec.get(f) for f in spec["fields"]]
    if any(p is None for p in parts):
        return None
    return f"{obj}-" + "-".join(str(p) for p in parts)


def _select_map(m, rec):
    """The plugin's map for this record: the first matching variant, else the
    default (a plugin without variants IS its own map)."""
    if "variants" not in m:
        return m
    for pred_name, sub in m["variants"]:
        if mappings.PREDICATES[pred_name](rec):
            return sub
    return m["default"]


def normalize(plugin: str, rec: dict) -> dict | None:
    """One raw record → one CAR event, or None if the plugin has no CAR map."""
    entry = mappings.MAPPINGS.get(plugin)
    if entry is None:
        return None
    m = _select_map(entry, rec)
    obj = m["object"]
    props = {car: _resolve(src, rec) for car, src in m["props"].items()}
    event = {
        "car_object": obj,
        "car_action": m["action"],
        "timestamp": None if m["ts"] is None else _clean_ts(rec.get(m["ts"])),
        "guid": _guid(m["guid"], obj, rec),
        "owning_pid": rec.get(m["owning_pid"]) if m.get("owning_pid") else None,
        "owning_offset": rec.get(m["owning_offset"]) if m.get("owning_offset") else None,
        "parent_pid": rec.get(m["parent_pid"]) if m.get("parent_pid") else None,
        "owning_guid": None,        # set in enrichment (create-time-window PID join)
        "parent_guid": None,        # set in enrichment
        "link_confidence": None,    # set in enrichment
        # a timeless event (e.g. malfind region) that should be timelined at its
        # owning process's create time — enrichment stamps it after the link.
        "_ts_from_owner": bool(m.get("ts_from_owner")),
        "source_plugin": plugin,
        "_native": {k: rec.get(k) for k in m.get("keep", []) if k in rec},
    }
    event.update(props)
    return event
