"""The MITRE CAR data model (vendored car_data_model.json) — epic #1.

The single source of truth for which objects exist and which actions/properties
each object has. Regenerated from MITRE's own mitre-attack/car repo
(docs/data_model/*.md) — 13 objects. The store's table schemas and the wide
timeline's property superset both derive from here, so a model refresh is a data
change, not a code change.
"""
from __future__ import annotations

import json
import os

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "car_data_model.json")

_cache: dict | None = None


def load() -> dict[str, dict]:
    """{object_name: {"fields": [...], "actions": [...]}} from the vendored model."""
    global _cache
    if _cache is None:
        with open(MODEL_PATH, encoding="utf-8") as fh:
            doc = json.load(fh)
        objs = {}
        for o in doc["objects"]:
            name = o["name"][0] if isinstance(o["name"], list) else o["name"]
            objs[name] = {"fields": list(o["fields"]), "actions": list(o["actions"])}
        _cache = objs
    return _cache


def fields(obj: str) -> list[str]:
    """The canonical property names of one CAR object."""
    return load()[obj]["fields"]


def actions(obj: str) -> list[str]:
    """The canonical actions of one CAR object."""
    return load()[obj]["actions"]


def all_fields() -> list[str]:
    """The sorted union of every object's properties — the wide timeline's columns."""
    out: set[str] = set()
    for spec in load().values():
        out.update(spec["fields"])
    return sorted(out)
