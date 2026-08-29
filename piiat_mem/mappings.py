"""Per-plugin → MITRE CAR object maps (epic #1, phase 2).

One entry per Volatility plugin: the CAR **object** it yields, the **action**, the
**timestamp** field, the **identity** that becomes the CAR `guid`, the owning
process link (an owning-PID field, resolved to `owning_guid` during enrichment),
and how each raw field maps to a canonical CAR **property**. Native fields with no
CAR home are listed in `keep` (retained, never faked into a CAR column).

Grounded in the real TreeGrid columns of each plugin. Identity is a **memory
object offset** wherever the plugin exposes one (reuse-proof) — never the PID. See
docs/design/car-store.md.
"""
from __future__ import annotations

# --- property-source markers (resolved by normalize.py) ---------------------


def first(*fields):
    """Use the first of `fields` that is non-empty."""
    return ("first", fields)


def basename(field):
    """Windows basename of a path field."""
    return ("basename", field)


def user_from_hive(field="Hive"):
    """Extract the profile user from an NTUSER.DAT / UsrClass.dat hive path."""
    return ("user_from_hive", field)


# --- the maps ---------------------------------------------------------------
# guid: {"field": X}  -> the record already carries the guid in field X
#       {"fields":[…]} -> synthesize `<object>-<v1>-<v2>…` (the object's identity)

MAPPINGS = {
    # ---- process — the hub; identity already synthesized by the plugin -------
    "windows.piiat.processes": {
        "object": "process", "action": "create", "ts": "CreateTime",
        "guid": {"field": "Guid"}, "owning_pid": None, "parent_pid": "PPID",
        "props": {
            "pid": "PID", "ppid": "PPID",
            "exe": first("Path", "ImageFileName"),
            "image_path": first("Path", "ImageFileName"),
            "command_line": "CommandLine",
            "parent_exe": "ParentPath", "parent_image_path": "ParentPath",
        },
        "keep": ["Offset", "LoadedDlls", "DllCount", "Hidden"],
    },
    # ---- thread — _ETHREAD offset is identity; owns via PID -----------------
    "windows.thrdscan": {
        "object": "thread", "action": "create", "ts": "CreateTime",
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "tgt_pid": "PID", "tgt_tid": "TID",
            "start_address": first("Win32StartAddress", "StartAddress"),
            "start_module": first("Win32StartPath", "StartPath"),
        },
        "keep": ["ExitTime"],
    },
    # ---- module — no pool offset; identity is (owning pid, base) ------------
    "windows.dlllist": {
        "object": "module", "action": "load", "ts": "LoadTime",
        "guid": {"fields": ["PID", "Base"]}, "owning_pid": "PID",
        "props": {
            "module_path": "Path", "image_path": "Path",
            "module_name": "Name", "base_address": "Base", "pid": "PID",
        },
        "keep": ["Size", "LoadCount", "Process"],
    },
    # ---- driver — kernel-global; modules offset is identity, no owner -------
    "windows.modules": {
        "object": "driver", "action": "load", "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": None,
        "props": {
            "image_path": "Path", "module_name": "Name", "base_address": "Base",
        },
        "keep": ["Size"],
    },
    # ---- flow — socket object offset is identity; owns via PID --------------
    "windows.netscan": {
        "object": "flow", "action": "start", "ts": "Created",
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "src_ip": "LocalAddr", "src_port": "LocalPort",
            "dest_ip": "ForeignAddr", "dest_port": "ForeignPort",
            "transport_protocol": "Proto", "pid": "PID", "exe": "Owner",
        },
        "keep": ["State"],
    },
    "windows.netstat": {
        "object": "flow", "action": "start", "ts": "Created",
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "src_ip": "LocalAddr", "src_port": "LocalPort",
            "dest_ip": "ForeignAddr", "dest_port": "ForeignPort",
            "transport_protocol": "Proto", "pid": "PID", "exe": "Owner",
        },
        "keep": ["State"],
    },
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
        # key_edit / value_edit).
        "object": "registry", "action": "value_edit", "ts": "LastWrite",
        "guid": {"fields": ["Hive", "Key", "ValueName"]}, "owning_pid": None,
        "props": {
            "key": "Key", "value": "ValueName", "data": "ValueData",
            "type": "ValueType", "hive": "Hive", "user": user_from_hive("Hive"),
        },
        "keep": [],
    },
    # ---- service — service record offset is identity; host process via PID --
    "windows.svcscan": {
        "object": "service", "action": None, "ts": None,
        "guid": {"fields": ["Offset"]}, "owning_pid": "PID",
        "props": {
            "name": "Name", "image_path": "Binary", "exe": "Binary", "pid": "PID",
        },
        "keep": ["Order", "Start", "State", "Type", "Display", "Dll"],
    },
    # ---- user_session — Session ID is identity; owning process via PID ------
    "windows.sessions": {
        "object": "user_session", "action": "login", "ts": "Create Time",
        "guid": {"fields": ["Session ID"]}, "owning_pid": "Process ID",
        "props": {"user": "User Name", "login_id": "Session ID"},
        "keep": ["Session Type", "Process"],
    },
}
