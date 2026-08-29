"""Volatility 3 plugin: DFIR module (DLL load) records for the CAR data model.

`windows.piiat.modules` — one row per loaded module, from each active process's
PEB load-order list (the same walk as windows.dlllist). Its reason to exist is
the DEFINITIVE module -> process link demanded by docs/design/car-store.md §3:
the row is *produced from* a specific _EPROCESS whose PEB is being walked, so
the owning process's kernel-object identity is known at extraction — no reused
PID guessing. Each row carries:

  OwnerOffset   the owning _EPROCESS offset, normalized to the SAME convention
                psscan uses so it equals the Offset (and thus the synthesized
                Guid "proc-<offset:x>") emitted by windows.piiat.processes —
                the definitive join key that upgrades module->process
                enrichment from heuristic (PID) to definitive. On Windows 10
                poolscanner scans the kernel VIRTUAL layer, so psscan offsets
                are mask-normalized kernel virtual addresses and this plugin
                emits the pslist proc's virtual offset & address_mask; on older
                Windows poolscanner scans the physical layer, so this plugin
                translates the virtual offset to physical — mirroring
                poolscanner.generate_pool_scan_extended's own branch
  PID           the owner's PID — kept as a plain attribute / fallback heuristic
  ProcessName   the owner's EPROCESS short name (<= 15 chars)
  Base          the module's base virtual address in the owner's address space
  Size          SizeOfImage
  Name          BaseDllName
  Path          FullDllName — the module identity CAR `module.module_path` wants
  LoadTime      _LDR_DATA_TABLE_ENTRY.LoadTime (Win >= 6.1 only; the loader
                zeroes it for the EXE itself and some early modules)
  LoadCount     LoadCount / ObsoleteLoadCount where the OS version exposes one

This replaces windows.dlllist in the pipeline. The simple pslist walk is
correct here (unlike the psscan + DTB-rebuild in windows.piiat.processes):
a hidden process's modules already surface via that plugin's LoadedDlls, while
this plugin's job is per-module rows with an exact owner for linked processes.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.modules") -> CarModule reads Record.OwnerOffset/Base/Path/…
"""
import datetime

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import conversion
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import info, pslist, psscan


class Modules(interfaces.plugins.PluginInterface):
    """Loaded-module records with the owning _EPROCESS offset (definitive link)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _owner_offset(self, proc, kernel, psscan_is_virtual):
        """The owning _EPROCESS offset in the SAME convention psscan emits it
        (see the module docstring), so it joins windows.piiat.processes.Offset
        bit-for-bit. Falls back to the raw virtual offset — still exact, but
        layer-local — if translation fails."""
        try:
            if psscan_is_virtual:
                mask = self.context.layers[kernel.layer_name].address_mask
                return int(proc.vol.offset) & mask
            return int(psscan.PsScan.physical_offset_from_virtual(
                self.context, kernel.layer_name, proc))
        except Exception:  # pylint: disable=broad-except
            return int(proc.vol.offset)

    def _generator(self):
        kernel = self.context.modules[self.config["kernel"]]

        # poolscanner scans the virtual kernel layer on Win10, the physical
        # layer before that — psscan offsets follow, and OwnerOffset must too.
        try:
            psscan_is_virtual = versions.is_windows_10(
                self.context, kernel.symbol_table_name)
        except Exception:  # pylint: disable=broad-except
            psscan_is_virtual = True

        # LoadTime exists in _LDR_DATA_TABLE_ENTRY only from Windows 6.1 on
        # (same gate windows.dlllist applies).
        has_load_time = False
        try:
            kuser = info.Info.get_kuser_structure(self.context, self.config["kernel"])
            major, minor = int(kuser.NtMajorVersion), int(kuser.NtMinorVersion)
            has_load_time = (major > 6) or (major == 6 and minor >= 1)
        except Exception:  # pylint: disable=broad-except
            pass

        na = renderers.NotAvailableValue
        for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
            try:
                pid = int(proc.UniqueProcessId)
                proc_name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue
            # The owning _EPROCESS in psscan's own offset convention — the §3
            # definitive module->process link; PID stays a plain attribute.
            owner_offset = self._owner_offset(proc, kernel, psscan_is_virtual)
            try:
                proc.add_process_layer()
                entries = proc.load_order_modules()
            except Exception:  # pylint: disable=broad-except
                continue
            for entry in entries:
                try:
                    base = int(entry.DllBase)
                except exceptions.InvalidAddressException:
                    base = None
                try:
                    size = int(entry.SizeOfImage)
                except exceptions.InvalidAddressException:
                    size = None
                base_name = full_name = ""
                try:
                    base_name = entry.BaseDllName.get_string()
                    full_name = entry.FullDllName.get_string()
                except Exception:  # pylint: disable=broad-except
                    pass
                load_time = None
                if has_load_time:
                    try:
                        load_time = conversion.wintime_to_datetime(
                            entry.LoadTime.QuadPart)
                    except Exception:  # pylint: disable=broad-except
                        load_time = None
                    if not isinstance(load_time, datetime.datetime):
                        load_time = None  # zero / unconvertible -> unavailable
                try:
                    load_count = entry.get_load_count()
                    if load_count is not None:
                        load_count = int(load_count)
                except Exception:  # pylint: disable=broad-except
                    load_count = None
                yield (0, (
                    owner_offset,
                    pid,
                    proc_name,
                    base if base is not None else na(),
                    size if size is not None else na(),
                    base_name or na(),
                    full_name or na(),
                    load_time if load_time is not None else na(),
                    load_count if load_count is not None else na(),
                ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("OwnerOffset", int),
                ("PID", int),
                ("ProcessName", str),
                ("Base", int),
                ("Size", int),
                ("Name", str),
                ("Path", str),
                ("LoadTime", datetime.datetime),
                ("LoadCount", int),
            ],
            self._generator(),
        )
