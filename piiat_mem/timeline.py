"""Turn per-plugin JSONL into a single time-ordered timeline.

Each Volatility record that carries a timestamp becomes one timeline event
``{timestamp, plugin, artifact, description, pid, process, detail}``; events are
sorted ascending by time. Records with no usable timestamp are dropped from the
timeline (they remain in the raw ``plugins/<plugin>.jsonl``).
"""
from __future__ import annotations

import csv
import json
import os
import re

# Candidate timestamp fields across the timeline plugins, best-first.
_TS_FIELDS = ["CreateTime", "LoadTime", "Created", "LastWrite", "Create Time",
              "CreatedTime", "GenerationTime", "Time"]
_EPOCH_ZERO = re.compile(r"^(1601-01-01|1970-01-01|0001-01-01)")

# plugin -> (artifact label, how to describe a record)
_ARTIFACT = {
    "windows.piiat.processes": "process",
    "windows.pslist": "process",
    "windows.pstree": "process",
    "windows.dlllist": "module",
    "windows.modules": "driver",
    "windows.thrdscan": "thread",
    "windows.netscan": "network",
    "windows.netstat": "network",
    "windows.sessions": "session",
    "windows.piiat.registry": "registry",
    "windows.svcscan": "service",
    "windows.filescan": "file",
}


def _plugin_of(path: str) -> str:
    return os.path.basename(path).rsplit(".jsonl", 1)[0]


def _timestamp(rec: dict):
    for f in _TS_FIELDS:
        v = rec.get(f)
        if v in (None, "", "-"):
            continue
        s = str(v)
        if _EPOCH_ZERO.match(s):        # Volatility's "no time" sentinel
            continue
        return s
    return None


def _describe(plugin: str, rec: dict) -> tuple[str, str, str]:
    """Return (artifact, description, process) for a record."""
    art = _ARTIFACT.get(plugin, plugin.split(".")[0])
    pid = rec.get("PID") or rec.get("Pid") or ""
    proc = rec.get("Process") or rec.get("ImageFileName") or rec.get("Owner") or ""
    if art == "process":
        desc = rec.get("Path") or rec.get("ImageFileName") or rec.get("CommandLine") or ""
    elif art == "module":
        desc = rec.get("Path") or rec.get("Name") or ""
    elif art == "driver":
        desc = rec.get("Path") or rec.get("Name") or ""
    elif art == "thread":
        desc = f"tid={rec.get('TID','')} start={rec.get('Win32StartPath') or rec.get('Win32StartAddress','')}"
    elif art == "network":
        desc = (f"{rec.get('Proto','')} {rec.get('LocalAddr','')}:{rec.get('LocalPort','')}"
                f" -> {rec.get('ForeignAddr','')}:{rec.get('ForeignPort','')} {rec.get('State','')}").strip()
    elif art == "session":
        desc = f"session {rec.get('Session ID','')} {rec.get('User Name','') or rec.get('Process','')}"
    elif art == "registry":
        desc = f"{rec.get('Key','')}\\{rec.get('ValueName','')}".rstrip("\\")
    else:
        desc = rec.get("Name") or rec.get("Path") or ""
    return art, str(desc), str(proc)


def build(plugin_paths: list[str]) -> list[dict]:
    """Read the given per-plugin JSONL files -> a time-sorted list of events."""
    events: list[dict] = []
    for path in plugin_paths:
        if not os.path.isfile(path):
            continue
        plugin = _plugin_of(path)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ts = _timestamp(rec)
                if not ts:
                    continue
                art, desc, proc = _describe(plugin, rec)
                events.append({
                    "timestamp": ts,
                    "plugin": plugin,
                    "artifact": art,
                    "pid": rec.get("PID") or rec.get("Pid") or "",
                    "process": proc,
                    "description": desc,
                    "detail": json.dumps(rec, sort_keys=True, default=str),
                })
    events.sort(key=lambda e: e["timestamp"])
    return events


_COLUMNS = ["timestamp", "plugin", "artifact", "pid", "process", "description", "detail"]


def write_csv(events: list[dict], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(events)


def write_json(events: list[dict], path: str) -> None:
    """One JSON event per line (JSONL) — stream-friendly and ingest-ready."""
    with open(path, "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, sort_keys=True, default=str))
            fh.write("\n")
