"""Volatility 3 plugin: DFIR process records for the CAR data model.

`windows.piiat.processes` — one row per process, enumerated with psscan
(pool-tag scanning) so UNLINKED / terminated processes a rootkit hid from the
active list are still found. Each row carries what CarProcess wants and no single
built-in plugin gives together:

  Offset          the _EPROCESS pool-scan offset — the process's unique kernel-
                  object identity (reuse-proof, unlike PID)
  Guid            CAR `guid` synthesized from Offset (memory has no Sysmon guid);
                  the definitive join key for a process instance
  PID, PPID
  ImageFileName   the EPROCESS short name (<= 15 chars)
  Path            the FULL image path from the PEB (ProcessParameters.ImagePathName)
  CommandLine     from the PEB
  ParentPath      the parent's full image path, resolved by PID
  CreateTime      process creation time
  DllCount        number of loaded modules
  LoadedDlls      the loaded modules' full paths (PEB load-order list)
  Hidden          true if psscan found it but the active list (pslist) did not
                  — i.e. an unlinked process, the reason to use psscan
  Sid             the process token's USER SID (UserAndGroups[0]) — CAR `sid`
  User            the SID resolved to a name: real accounts via the SOFTWARE
                  hive's ProfileList, well-known/service SIDs via volatility's
                  own tables (the getsids lookup)
  LogonId         the token AuthenticationId LUID as a hex string — joins the
                  process to its `user_session` (CAR `login_id`)

A psscan process is found in the PHYSICAL layer, so `EPROCESS.get_peb()` /
`load_order_modules()` (which build the process layer off `self.vol.layer_name`)
raise "not a translation layer". An unlinked process is still RUNNING, so its PEB
is in memory: this plugin rebuilds the process address space from the DTB using
the KERNEL's Intel layer as the template, so the PEB, command line and loaded
DLLs resolve for unlinked processes too. Truly dead processes (invalid DTB) get
empty fields but are still listed and flagged.

Token identity works the same way: a psscan process object is built on the
physical layer with the kernel layer as its native layer, so `proc.Token`
(an _EX_FAST_REF) dereferences through kernel virtual space; a terminated /
smeared process whose token pages are gone gets NotAvailableValue — never a
guessed identity.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.processes") -> CarProcess reads Record.Path/ParentPath/etc.
"""
import datetime
import json
import ntpath
import os
import re

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel
from volatility3.framework.objects import utility
from volatility3.plugins.windows import pslist, psscan
from volatility3.plugins.windows.registry import hivelist


class Processes(interfaces.plugins.PluginInterface):
    """Process records (psscan) with full image path, parent path and loaded DLLs."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _process_layer(self, proc, kernel_layer):
        """Build the process's virtual address space from its DTB, using the
        kernel Intel layer as the template — so a psscan (physical) process's PEB
        is reachable. Returns the new layer name, or None if the DTB is unusable.
        """
        try:
            dtb = proc.Pcb.DirectoryTableBase
            if hasattr(dtb, "cast"):
                dtb = dtb.cast("unsigned long long")
            dtb = int(dtb) & ((1 << kernel_layer.bits_per_register) - 1)
            if not dtb:
                return None
            config = kernel_layer.build_configuration()
            # build_configuration() omits the base-layer reference; the Intel
            # layer __init__ requires it, so copy it from the kernel layer (this
            # is what EPROCESS._add_process_layer does), then point at the DTB.
            config["memory_layer"] = kernel_layer.config["memory_layer"]
            config["page_map_offset"] = dtb
            name = self.context.layers.free_layer_name(prefix="dfir_proc")
            path = interfaces.configuration.path_join("temporary", name)
            self.context.config.splice(path, config)
            self.context.layers.add_layer(
                kernel_layer.__class__(self.context, config_path=path, name=name))
            return name
        except Exception:  # pylint: disable=broad-except
            return None

    def _enrich(self, proc, kernel_layer):
        """(full image path, command line, [loaded dll paths]) via the rebuilt
        process layer; empty where a field / the whole PEB is unreachable."""
        image_path = command_line = ""
        dlls = []
        layer_name = self._process_layer(proc, kernel_layer)
        if layer_name is None:
            return image_path, command_line, dlls
        try:
            sym_table = proc.get_symbol_table_name()
            peb = self.context.object(
                sym_table + constants.BANG + "_PEB",
                layer_name=layer_name, offset=proc.Peb)
            params = peb.ProcessParameters
            try:
                image_path = params.ImagePathName.get_string()
            except Exception:  # pylint: disable=broad-except
                pass
            try:
                command_line = params.CommandLine.get_string()
            except Exception:  # pylint: disable=broad-except
                pass
            try:
                for entry in peb.Ldr.InLoadOrderModuleList.to_list(
                        sym_table + constants.BANG + "_LDR_DATA_TABLE_ENTRY",
                        "InLoadOrderLinks"):
                    try:
                        name = entry.FullDllName.get_string()
                        if name:
                            dlls.append(name)
                    except Exception:  # pylint: disable=broad-except
                        continue
            except Exception:  # pylint: disable=broad-except
                pass
        except Exception:  # pylint: disable=broad-except
            pass
        return image_path, command_line, dlls

    def _token_identity(self, proc):
        """(user SID string, AuthenticationId LUID as int) from the process
        token — (None, None) / partial where the token is unreadable (a
        terminated psscan process whose token pages are gone)."""
        try:
            token = proc.Token.dereference().cast("_TOKEN")
        except Exception:  # pylint: disable=broad-except
            return None, None
        sid = None
        try:
            # UserAndGroups[0] is the token's USER SID (the rest are groups).
            for sid_string in token.get_sids():
                sid = sid_string
                break
        except Exception:  # pylint: disable=broad-except
            pass
        logon_id = None
        try:
            luid = token.AuthenticationId
            logon_id = (int(luid.HighPart) << 32) | int(luid.LowPart)
        except Exception:  # pylint: disable=broad-except
            pass
        return sid, logon_id

    def _sid_names(self):
        """({sid: name}, [(compiled_re, name)]) for resolving SIDs to account
        names — real local accounts from the SOFTWARE hive's ProfileList
        (ProfileImagePath basename), well-known / service SIDs and the regex
        fallbacks from volatility's own sids_and_privileges.json (the same
        tables windows.getsids uses). Empty where unreadable."""
        names = {}
        sid_res = []
        try:
            for plugin_dir in constants.PLUGINS_PATH:
                path = os.path.join(plugin_dir, "windows", "sids_and_privileges.json")
                if not os.path.exists(path):
                    continue
                with open(path) as file_handle:
                    data = json.load(file_handle)
                names.update(data.get("well known", {}))
                names.update(data.get("service sids", {}))
                sid_res = [(re.compile(item[0]), item[1])
                           for item in data.get("sids re", [])]
                break
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            for hive in hivelist.HiveList.list_hives(
                    self.context, self.config_path, self.config["kernel"],
                    filter_string="config\\software"):
                try:
                    profile_list = hive.get_key(
                        "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
                    for subkey in profile_list.get_subkeys():
                        try:
                            sid = str(subkey.get_name())
                            for node in subkey.get_values():
                                if node.get_name() != "ProfileImagePath":
                                    continue
                                data = node.decode_data()
                                if not isinstance(data, bytes):
                                    continue
                                profile_path = data.decode(
                                    "utf-16-le", "replace").rstrip("\x00")
                                user = ntpath.basename(profile_path)
                                if user:
                                    # Well-known names win (S-1-5-18 is "Local
                                    # System", not its "systemprofile" dir).
                                    names.setdefault(sid, user)
                        except Exception:  # pylint: disable=broad-except
                            continue
                except Exception:  # pylint: disable=broad-except
                    continue
        except Exception:  # pylint: disable=broad-except
            pass
        return names, sid_res

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]
        if not isinstance(kernel_layer, intel.Intel):
            return

        # Active (linked) PIDs, so psscan-only processes can be flagged Hidden.
        linked = set()
        try:
            for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
                try:
                    linked.add(int(proc.UniqueProcessId))
                except exceptions.InvalidAddressException:
                    continue
        except Exception:  # pylint: disable=broad-except
            pass

        # Pass one: pool-scan every process, enrich, record path by pid.
        records = []
        path_by_pid = {}
        for proc in psscan.PsScan.scan_processes(self.context, self.config["kernel"]):
            try:
                pid = int(proc.UniqueProcessId)
                ppid = int(proc.InheritedFromUniqueProcessId)
                name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue
            # The _EPROCESS pool-scan offset is the process's unique kernel-object
            # identity — reuse-proof, unlike the PID. It is the memory-native basis
            # for CAR `guid` (a memory image has no Sysmon ProcessGuid). See
            # docs/design/car-store.md §3.
            offset = int(proc.vol.offset)
            image_path, command_line, dlls = self._enrich(proc, kernel_layer)
            try:
                create_time = proc.get_create_time()
            except Exception:  # pylint: disable=broad-except
                create_time = None
            sid, logon_id = self._token_identity(proc)
            if image_path:
                path_by_pid[pid] = image_path
            records.append((offset, pid, ppid, name, image_path, command_line,
                            create_time, dlls, sid, logon_id))

        # SID -> account-name tables (ProfileList + well-known), built once.
        sid_names, sid_res = self._sid_names()

        # Pass two: synthesize the guid, fill ParentPath from the pid->path map, emit.
        for (offset, pid, ppid, name, image_path, command_line, create_time,
             dlls, sid, logon_id) in records:
            na = renderers.NotAvailableValue
            # Synthesize CAR `guid` from the offset (per-image unique; the store
            # namespaces it by source image). ParentPath by pid stays a HEURISTIC
            # until the store resolves parent_guid by offset (create-time ordered).
            guid = f"proc-{offset:x}"
            user = sid_names.get(sid) if sid else None
            if user is None and sid:
                for regex, resolved in sid_res:
                    if regex.search(sid):
                        user = resolved
                        break
            yield (0, (
                offset, guid,
                pid, ppid, name,
                image_path or na(),
                command_line or na(),
                path_by_pid.get(ppid) or na(),
                create_time if create_time is not None else na(),
                len(dlls),
                ", ".join(dlls) if dlls else na(),
                pid not in linked,
                sid or na(),
                user or na(),
                f"0x{logon_id:x}" if logon_id is not None else na(),
            ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", int),
                ("Guid", str),
                ("PID", int),
                ("PPID", int),
                ("ImageFileName", str),
                ("Path", str),
                ("CommandLine", str),
                ("ParentPath", str),
                ("CreateTime", datetime.datetime),
                ("DllCount", int),
                ("LoadedDlls", str),
                ("Hidden", bool),
                ("Sid", str),
                ("User", str),
                ("LogonId", str),
            ],
            self._generator(),
        )
