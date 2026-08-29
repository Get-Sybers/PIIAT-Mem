"""Volatility 3 plugin: OWNED file records for the CAR data model.

`windows.piiat.files` — one row per open FILE-type handle, enumerated by
walking every process's handle table. This closes the capability gap that
filescan leaves: filescan finds _FILE_OBJECTs by pool-scanning but can never
say WHOSE they are; a handle-table walk starts at the owning _EPROCESS, so
every row is born with a definitive process link (docs/design/car-store.md §3
— the owning-_EPROCESS OFFSET is the definitive link; a reused PID is only a
heuristic). Each row carries:

  OwnerOffset       the owning _EPROCESS offset — the definitive process
                    identity this file record joins to (reuse-proof, unlike
                    PID); matches windows.piiat.processes Offset / Guid
  PID, ProcessName  the owner, for human reading / heuristic fallback
  HandleValue       the handle number inside that process's table
  FileObjectOffset  the _FILE_OBJECT address — the file's kernel-object
                    identity, the join key against filescan-style records
  Path              the file's full name (\\Device\\...\\path), resolved via the
                    FILE_OBJECT's DeviceObject + FileName the way
                    windows.handles does
  GrantedAccess     the access mask granted on the handle

Handle enumeration reuses windows.handles.Handles' public classmethod helpers
(get_type_map / find_cookie / handles) rather than re-implementing the
multi-level _HANDLE_TABLE walk. Rows whose name resolution fails still emit
(Path = NotAvailableValue) — FileObjectOffset alone still joins.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.files") -> CarFile reads Record.OwnerOffset/FileObjectOffset/Path.
"""
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import handles, pslist, psscan


class Files(interfaces.plugins.PluginInterface):
    """File records with definitive owners: one row per FILE-type handle."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
            requirements.VersionRequirement(
                name="handles", component=handles.Handles, version=(4, 0, 0)),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(3, 0, 0)),
        ]

    def _owner_offset(self, proc, kernel, psscan_is_virtual):
        """The owning _EPROCESS offset in the SAME convention psscan emits it —
        mask-normalized virtual on Win10, physical before that — so it joins
        windows.piiat.processes.Offset bit-for-bit on every Windows version
        (mirrors windows.piiat.modules)."""
        try:
            if psscan_is_virtual:
                mask = self.context.layers[kernel.layer_name].address_mask
                return int(proc.vol.offset) & mask
            return int(psscan.PsScan.physical_offset_from_virtual(
                self.context, kernel.layer_name, proc))
        except Exception:  # pylint: disable=broad-except
            return int(proc.vol.offset)

    def _generator(self):
        kernel_name = self.config["kernel"]
        kernel = self.context.modules[kernel_name]
        type_map = handles.Handles.get_type_map(
            context=self.context, kernel_module_name=kernel_name)
        cookie = handles.Handles.find_cookie(
            context=self.context, kernel_module_name=kernel_name)
        na = renderers.NotAvailableValue
        # psscan's offset convention: virtual on Win10, physical before that.
        try:
            psscan_is_virtual = versions.is_windows_10(
                self.context, kernel.symbol_table_name)
        except Exception:  # pylint: disable=broad-except
            psscan_is_virtual = True

        for proc in pslist.PsList.list_processes(self.context, kernel_name):
            try:
                # The _EPROCESS offset IS the definitive owner identity (CAR
                # car-store.md §3); it matches piiat.processes' Offset/Guid.
                owner_offset = self._owner_offset(proc, kernel, psscan_is_virtual)
                pid = int(proc.UniqueProcessId)
                object_table = proc.ObjectTable
            except exceptions.InvalidAddressException:
                continue
            try:
                process_name = utility.array_to_string(proc.ImageFileName)
            except Exception:  # pylint: disable=broad-except
                process_name = ""

            try:
                entries = handles.Handles.handles(
                    self.context, kernel_name, object_table)
                for entry in entries:
                    try:
                        obj_type = entry.get_object_type(type_map, cookie)
                        if obj_type != "File":
                            continue
                        file_object = entry.Body.cast("_FILE_OBJECT")
                        file_offset = int(file_object.vol.offset)
                        handle_value = int(entry.HandleValue)
                        granted = int(entry.GrantedAccess)
                    except (exceptions.InvalidAddressException, AttributeError,
                            TypeError, ValueError):
                        continue
                    try:
                        path = file_object.file_name_with_device()
                        # file_name_with_device may return an absent-value
                        # sentinel (UnreadableValue) instead of raising.
                        if not isinstance(path, str):
                            path = ""
                    except Exception:  # pylint: disable=broad-except
                        path = ""
                    # A nameless handle still joins by FileObjectOffset.
                    yield (0, (
                        owner_offset,
                        pid,
                        process_name or na(),
                        handle_value,
                        file_offset,
                        path or na(),
                        granted,
                    ))
            except Exception:  # pylint: disable=broad-except
                # One corrupt handle table must never kill the run.
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("OwnerOffset", int),
                ("PID", int),
                ("ProcessName", str),
                ("HandleValue", int),
                ("FileObjectOffset", int),
                ("Path", str),
                ("GrantedAccess", int),
            ],
            self._generator(),
        )
