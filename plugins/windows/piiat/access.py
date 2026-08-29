"""Volatility 3 plugin: process ACCESS records for the CAR data model.

`windows.piiat.access` — one row per open PROCESS-type handle, enumerated by
walking every process's handle table. An open Process-type handle is an
observed "process A holds access to process B" fact: memory supplies exactly
the CAR process:access fields — the access mask (access_level), the target's
PID/name, and (via the dereferenced target _EPROCESS offset) the target's
reuse-proof identity (target_guid). Each row carries:

  OwnerOffset       the HOLDER's _EPROCESS offset — the definitive process
                    identity this access record joins to (reuse-proof, unlike
                    PID); matches windows.piiat.processes Offset / Guid
                    (docs/design/car-store.md §3)
  PID, ProcessName  the holder, for human reading / heuristic fallback
  HandleValue       the handle number inside the holder's table
  GrantedAccess     the access mask granted on the handle — CAR access_level
  TargetOffset      the TARGET's _EPROCESS offset, normalized the same way as
                    OwnerOffset so it too joins piiat.processes bit-for-bit;
                    NotAvailableValue if the object body is unreadable
  TargetPid         the target's UniqueProcessId
  TargetName        the target's ImageFileName

The target _EPROCESS is dereferenced from the handle's object body exactly the
way windows.handles does for Process-type objects (entry.Body.cast
("_EPROCESS")). Every Process-type handle emits — including a process's own
pseudo self-handles; filtering is a downstream choice. Handle enumeration
reuses windows.handles.Handles' public classmethod helpers (get_type_map /
find_cookie / handles) rather than re-implementing the multi-level
_HANDLE_TABLE walk.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.access") -> CAR process:access reads Record.GrantedAccess /
TargetPid / TargetName / TargetOffset.
"""
from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import handles, pslist, psscan


class Access(interfaces.plugins.PluginInterface):
    """Process access records: one row per PROCESS-type handle."""

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
                # The _EPROCESS offset IS the definitive holder identity (CAR
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
                        if obj_type != "Process":
                            continue
                        handle_value = int(entry.HandleValue)
                        granted = int(entry.GrantedAccess)
                    except (exceptions.InvalidAddressException, AttributeError,
                            TypeError, ValueError):
                        continue
                    # Dereference the target _EPROCESS the way windows.handles
                    # does for Process-type objects, and normalize its offset
                    # with the SAME convention as OwnerOffset so both join
                    # piiat.processes bit-for-bit.
                    try:
                        target = entry.Body.cast("_EPROCESS")
                        target_offset = self._owner_offset(
                            target, kernel, psscan_is_virtual)
                        target_pid = int(target.UniqueProcessId)
                    except Exception:  # pylint: disable=broad-except
                        target_offset = None
                        target_pid = None
                    try:
                        target_name = utility.array_to_string(
                            target.ImageFileName)
                    except Exception:  # pylint: disable=broad-except
                        target_name = ""
                    # An unreadable target body still emits — the holder-side
                    # fact (a Process handle exists with this mask) stands.
                    yield (0, (
                        owner_offset,
                        pid,
                        process_name or na(),
                        handle_value,
                        granted,
                        target_offset if target_offset is not None else na(),
                        target_pid if target_pid is not None else na(),
                        target_name or na(),
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
                ("GrantedAccess", int),
                ("TargetOffset", int),
                ("TargetPid", int),
                ("TargetName", str),
            ],
            self._generator(),
        )
