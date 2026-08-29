"""Enrichment — resolve process-context links and inherit properties (epic #1).

Implements docs/design/car-store.md §3 over the normalized events of ONE run:

- **process → parent**: candidates are processes whose `pid` == the child's
  `ppid` and whose create time is <= the child's; the latest such wins. PID is
  reused by the OS, so this is a **heuristic** link (a definitive link needs the
  parent `_EPROCESS` pointer, which the plugin does not walk yet).
- **spoke → owning process** (thread/module/flow/service/user_session rows that
  carry an owning PID): same candidate rule against the spoke's timestamp. All
  current spokes carry only a PID, so these links are **heuristic** too.
- **inheritance**: a linked event inherits its process context — but only
  properties the object HAS in the CAR model, and only where its own value is
  null. A natively-supplied value is never overwritten.
- **link_confidence**: "definitive" when the join key was an object identity
  (reserved for future offset-carrying spokes), "heuristic" for PID-window
  joins, null where no link was made.

Also dedupes events that describe the same object instance:
- `user_session` — windows.sessions emits one row per process in a session; the
  session logs in once. Rows collapse to one event per session guid (earliest
  create time), and the collapsed rows first feed a pid→user index used to fill
  `process.user`.
- exact (object, guid, action) duplicates across plugins — the row with the most
  populated properties wins. Flow/socket guids are the protocol+endpoint tuple
  (not the scan offset, which differs between netscan's physical and netstat's
  virtual view and is shared by dual-stack twins), so the same socket seen by
  both plugins genuinely collapses and v4/v6 twins genuinely don't.

Everything is grouped by `source_image`: joins never cross images.
"""
from __future__ import annotations

from collections import defaultdict

from . import carmodel

# Process-context properties a spoke may inherit (filtered per object by the
# CAR model, filled only where null).
_INHERIT = ["exe", "image_path", "command_line", "user", "sid", "fqdn", "hostname"]


def _populated(ev: dict) -> int:
    return sum(1 for k, v in ev.items() if not k.startswith("_") and v not in (None, ""))


def _dedupe(events: list[dict]) -> list[dict]:
    """Collapse exact (image, object, guid, action) duplicates — most-populated wins."""
    best: dict[tuple, dict] = {}
    order: list[tuple] = []
    for ev in events:
        k = (ev.get("source_image"), ev["car_object"], ev.get("guid"), ev.get("car_action"))
        if ev.get("guid") is None:
            k = k + (id(ev),)  # no identity -> never collapse
        if k not in best:
            best[k] = ev
            order.append(k)
        elif _populated(ev) > _populated(best[k]):
            best[k] = ev
    return [best[k] for k in order]


def _collapse_sessions(events: list[dict]) -> tuple[list[dict], dict]:
    """windows.sessions: one row per process -> one user_session event per session
    (earliest timestamp = the login) + a (image, pid) -> user index for
    process.user inheritance."""
    keep, sessions, user_by_pid = [], {}, {}
    for ev in events:
        if ev["car_object"] != "user_session":
            keep.append(ev)
            continue
        if ev.get("owning_pid") is not None and ev.get("user"):
            user_by_pid.setdefault((ev.get("source_image"), int(ev["owning_pid"])), ev["user"])
        if ev.get("guid") is None:
            keep.append(ev)  # no identity -> never collapse (same rule as _dedupe)
            continue
        k = (ev.get("source_image"), ev.get("guid"))
        cur = sessions.get(k)
        if cur is None or ((ev.get("timestamp") or "~") < (cur.get("timestamp") or "~")):
            sessions[k] = ev
    return keep + list(sessions.values()), user_by_pid


def _process_index(events: list[dict]) -> dict:
    """(image, pid) -> [process events sorted by create time ascending]."""
    idx = defaultdict(list)
    for ev in events:
        if ev["car_object"] == "process" and ev.get("pid") is not None:
            idx[(ev.get("source_image"), int(ev["pid"]))].append(ev)
    for lst in idx.values():
        lst.sort(key=lambda e: e.get("timestamp") or "")
    return idx


def _match(candidates: list[dict], ts):
    """The process instance a PID refers to at time `ts`: the latest create
    <= ts. When the event HAS a timestamp the window is authoritative — if it
    disqualifies every candidate (all created after ts), there is NO match; a
    process created later cannot own an earlier event. Only a timestamp-less
    event falls back to an unambiguous single candidate."""
    if not candidates:
        return None
    if ts:
        eligible = [c for c in candidates if (c.get("timestamp") or "") <= ts]
        return eligible[-1] if eligible else None
    return candidates[0] if len(candidates) == 1 else None


def _inherit(ev: dict, proc: dict, obj_fields: set):
    for f in _INHERIT:
        if f in obj_fields and ev.get(f) in (None, "") and proc.get(f) not in (None, ""):
            ev[f] = proc[f]


def enrich(events: list[dict]) -> list[dict]:
    """Dedupe, link, inherit. Returns the final event list for the store."""
    model = carmodel.load()
    events, user_by_pid = _collapse_sessions(events)
    events = _dedupe(events)
    procs = _process_index(events)

    for ev in events:
        image = ev.get("source_image")
        obj_fields = set(model[ev["car_object"]]["fields"])

        if ev["car_object"] == "process":
            # user from the session table (per-pid, heuristic)
            if ev.get("user") in (None, "") and ev.get("pid") is not None:
                u = user_by_pid.get((image, int(ev["pid"])))
                if u:
                    ev["user"] = u
            # parent link by (ppid, create-time window) — heuristic (PID reuse)
            if ev.get("parent_pid") is not None:
                parent = _match(procs.get((image, int(ev["parent_pid"])), []),
                                ev.get("timestamp"))
                if parent is not None and parent is not ev:
                    ev["parent_guid"] = parent.get("guid")
                    ev["link_confidence"] = "heuristic"
                    for src, dst in (("exe", "parent_exe"),
                                     ("image_path", "parent_image_path"),
                                     ("command_line", "parent_command_line")):
                        if dst in obj_fields and ev.get(dst) in (None, "") \
                                and parent.get(src) not in (None, ""):
                            ev[dst] = parent[src]
            continue

        # spoke -> owning process by (pid, create-time window) — heuristic
        if ev.get("owning_pid") is not None:
            owner = _match(procs.get((image, int(ev["owning_pid"])), []),
                           ev.get("timestamp"))
            if owner is not None:
                ev["owning_guid"] = owner.get("guid")
                ev["link_confidence"] = "heuristic"
                _inherit(ev, owner, obj_fields)
    return events
