"""Per-plugin → MITRE CAR object maps (epic #1, phase 2).

One entry per Volatility plugin: the CAR **object** it yields, the **action**, the
**timestamp** field, the **identity** that becomes the CAR `guid`, the owning
process link (an owning-PID field, resolved to `owning_guid` during enrichment),
and how each raw field maps to a canonical CAR **property**. Native fields with no
CAR home are listed in `keep` (retained in `_native`, never faked into a CAR
column) — and a canonical column is left NULL rather than filled with a
near-miss (e.g. module.image_path is the owning PROCESS's image per CAR, so the
module map leaves it null for enrichment to fill; it never puts the DLL's own
path there).

A plugin whose records split across objects declares `variants`: an ordered list
of (predicate-name, map) pairs — the first predicate that matches the record
picks the map (used by netscan/netstat: bound/listening sockets are CAR
**socket** events; actual connections are CAR **flow** events, so no direction is
ever faked onto a listener).

Identity is a **memory object offset or natural key** — never the reused PID.
Flows/sockets key on the protocol + endpoint tuple (scan offsets are not
comparable between netscan's physical and netstat's virtual view, and dual-stack
twins share one offset — the tuple is the real identity). See
docs/design/car-store.md.
"""
from __future__ import annotations

# --- property-source markers (resolved by normalize.py; markers nest) --------


def first(*fields):
    """Use the first of `fields` (field names or markers) that is non-empty."""
    return ("first", fields)


def basename(field):
    """Windows basename of a path field."""
    return ("basename", field)


def user_from_hive(field="Hive"):
    """Extract the profile user from an NTUSER.DAT / UsrClass.dat hive path."""
    return ("user_from_hive", field)


def transport(field):
    """Layer-4 protocol from Volatility's Proto ('TCPv4' -> 'TCP')."""
    return ("transport", field)


def family(field):
    """Address family from Volatility's Proto ('TCPv4' -> 'ipv4')."""
    return ("family", field)


# --- variant predicates (referenced by name from `variants`) -----------------

def is_bound_socket(rec) -> bool:
    """A netscan/netstat row that is a bound/listening socket, not a connection:
    LISTENING state, or no real foreign endpoint (UDP '*', 0.0.0.0, ::)."""
    if (rec.get("State") or "") == "LISTENING":
        return True
    fa = rec.get("ForeignAddr")
    return fa in (None, "", "*", "0.0.0.0", "::")


PREDICATES = {"is_bound_socket": is_bound_socket}


# --- the maps ---------------------------------------------------------------
# guid: {"field": X}  -> the record already carries the guid in field X
#       {"fields":[…]} -> synthesize `<object>-<v1>-<v2>…` (the object's identity;
#                         a None component voids the guid, but "" is legitimate —
#                         e.g. a registry key's default value has ValueName "")

_SOCKET_MAP = {
    # bound/listening socket — no connection, so no src/dest is asserted at all
    "object": "socket", "action": "listen", "ts": "Created",
    "guid": {"fields": ["Proto", "LocalAddr", "LocalPort", "PID"]},
    "owning_pid": "PID",
    "props": {
        "local_address": "LocalAddr", "local_port": "LocalPort",
        "protocol": transport("Proto"), "family": family("Proto"),
        "pid": "PID",
    },
    "keep": ["State", "Offset", "Owner", "ForeignAddr", "ForeignPort"],
}
_FLOW_MAP = {
    # an actual connection. Direction is NOT knowable from a socket snapshot:
    # by convention src_* = the LOCAL endpoint and dest_* = the FOREIGN one, and
    # network_direction stays null — consumers must not infer the originator.
    "object": "flow", "action": "start", "ts": "Created",
    "guid": {"fields": ["Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort"]},
    "owning_pid": "PID",
    "props": {
        "src_ip": "LocalAddr", "src_port": "LocalPort",
        "dest_ip": "ForeignAddr", "dest_port": "ForeignPort",
        "transport_protocol": transport("Proto"),
        "start_time": "Created", "pid": "PID", "exe": "Owner",
    },
    "keep": ["State", "Offset", "Proto"],
}

MAPPINGS = {
    # ---- process — the hub; identity already synthesized by the plugin -------
    "windows.piiat.processes": {
        "object": "process", "action": "create", "ts": "CreateTime",
        "guid": {"field": "Guid"}, "owning_pid": None, "parent_pid": "PPID",
        "props": {
            "pid": "PID", "ppid": "PPID",
            # CAR: `exe` is the BASENAME of image_path; ImageFileName (a 15-char
            # EPROCESS name) is a valid exe fallback but NOT a path — image_path
            # stays null when the PEB path is unavailable.
            "exe": first(basename("Path"), "ImageFileName"),
            "image_path": "Path",
            "command_line": "CommandLine",
            "parent_exe": basename("ParentPath"), "parent_image_path": "ParentPath",
        },
        "keep": ["Offset", "ImageFileName", "LoadedDlls", "DllCount", "Hidden"],
    },
    # ---- thread — _ETHREAD offset is identity; owns via PID -----------------
    "windows.thrdscan": {
        "object": "thread", "action": "create", "ts": "CreateTime",
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "tgt_pid": "PID", "tgt_tid": "TID",
            "start_address": first("Win32StartAddress", "StartAddress"),
            "start_module": first("Win32StartPath", "StartPath"),
            "start_module_name": basename(first("Win32StartPath", "StartPath")),
        },
        "keep": ["ExitTime"],
    },
    # ---- module — identity is (owning pid, base). CAR module.image_path is the
    # OWNING PROCESS's image (enrichment fills it); module_path is the DLL's own.
    "windows.dlllist": {
        "object": "module", "action": "load", "ts": "LoadTime",
        "guid": {"fields": ["PID", "Base"]}, "owning_pid": "PID",
        "props": {
            "module_path": "Path",
            "module_name": "Name", "base_address": "Base", "pid": "PID",
        },
        "keep": ["Size", "LoadCount", "Process"],
    },
    # ---- driver — kernel-global; modules offset is identity, no owner. For a
    # driver, image_path IS the driver's own path (there is no owning process).
    "windows.modules": {
        "object": "driver", "action": "load", "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": None,
        "props": {
            "image_path": "Path", "module_name": "Name", "base_address": "Base",
        },
        "keep": ["Size"],
    },
    # ---- netscan/netstat — socket (bound/listening) or flow (connection) ----
    "windows.netscan": {"variants": [("is_bound_socket", _SOCKET_MAP)],
                        "default": _FLOW_MAP},
    "windows.netstat": {"variants": [("is_bound_socket", _SOCKET_MAP)],
                        "default": _FLOW_MAP},
    # ---- file — FILE_OBJECT offset is identity; no owner from filescan ------
    "windows.filescan": {
        "object": "file", "action": None, "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": None,
        "props": {"file_path": "Name", "file_name": basename("Name")},
        "keep": [],
    },
    # ---- registry — identity is (hive,key,value); user from the hive path ---
    "windows.piiat.registry": {
        # one row per registry VALUE → CAR `value_edit` (CAR split `edit` into
        # key_edit / value_edit). ValueName "" (the default value) is a
        # legitimate identity component.
        "object": "registry", "action": "value_edit", "ts": "LastWrite",
        "guid": {"fields": ["Hive", "Key", "ValueName"]}, "owning_pid": None,
        "props": {
            "key": "Key", "value": "ValueName", "data": "ValueData",
            "type": "ValueType", "hive": "Hive", "user": user_from_hive("Hive"),
        },
        "keep": [],
    },
    # ---- service — service record offset is identity; host process via PID.
    # 'Binary (Registry)' is the registry ImagePath incl. arguments — exactly
    # CAR service.command_line.
    "windows.svcscan": {
        "object": "service", "action": None, "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "name": "Name", "image_path": "Binary", "exe": basename("Binary"),
            "command_line": "Binary (Registry)", "pid": "PID",
        },
        "keep": ["Order", "Start", "State", "Type", "Display", "Dll"],
    },
    # ---- user_session — identity is (Session ID, User Name): distinct users'
    # logons must not merge under one TS session number. Owning process via PID.
    "windows.sessions": {
        "object": "user_session", "action": "login", "ts": "Create Time",
        "guid": {"fields": ["Session ID", "User Name"]}, "owning_pid": "Process ID",
        "props": {"user": "User Name", "login_id": "Session ID"},
        "keep": ["Session Type", "Process"],
    },
}
