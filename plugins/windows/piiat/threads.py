"""Volatility 3 plugin: DFIR thread records for the CAR data model.

`windows.piiat.threads` — one row per thread, enumerated with the same pool-tag
scan the built-in `windows.thrdscan` uses (so UNLINKED / terminated threads a
rootkit hid from a process's thread list are still found). Each row carries what
CarThread wants and thrdscan does not give together:

  Offset             the _ETHREAD scan offset — the thread's unique kernel-object
                     identity (reuse-proof, unlike TID)
  OwnerOffset        the owning _EPROCESS address (_ETHREAD.Tcb.Process, or
                     ThreadsProcess on XP) — the DEFINITIVE process link per
                     docs/design/car-store.md §3: PIDs are reused, so the store
                     joins thread → process on this offset (= the process Guid
                     basis in windows.piiat.processes); the PID column is only
                     the heuristic fallback
  PID, TID           from _ETHREAD.Cid (surface identity, reusable)
  CreateTime
  ExitTime           only for TERMINATED threads (Win10 unions ExitTime with
                     KeyedWaitChain, so a running thread's field is pointer
                     garbage — gated on the Terminated cross-thread flag)
  StartAddress       kernel-recorded thread entry point
  StartPath          the mapped module (VAD file path) holding StartAddress
  Win32StartAddress  the user-mode entry point
  Win32StartPath     the mapped module holding Win32StartAddress — an injected
                     thread shows an unbacked / wrong-module start here
  StackBase,  StackLimit       the KERNEL stack bounds (from the KTHREAD/Tcb)
  UserStackBase, UserStackLimit  the USER stack bounds (TEB.NtTib), read through
                     the owning process's address space

The scanned _ETHREAD's pointers (Tcb.Process, Tcb.Teb) dereference through the
kernel layer (poolscanner passes native_layer_name=kernel.layer_name), but the
TEB itself is USER-MODE memory: it is only mapped in the owning process's
address space. So this plugin rebuilds each owner's process layer from its DTB
(the same trick windows.piiat.processes uses for the PEB) and reads
TEB.NtTib.StackBase/StackLimit through it; threads whose TEB is paged out or
whose process is dead get NotAvailableValue there but are still listed.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.threads") -> CarThread reads Record.OwnerOffset/TID/…
"""
import datetime

from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.constants import windows as windows_constants
from volatility3.framework.layers import intel
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import pe_symbols, psscan, thrdscan


class Threads(interfaces.plugins.PluginInterface):
    """Thread records (pool scan) with the owning-_EPROCESS offset and kernel/user stack bounds."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _process_layer(self, proc, kernel_layer):
        """Build the process's virtual address space from its DTB, using the
        kernel Intel layer as the template — so the thread's user-mode TEB is
        reachable. Returns the new layer name, or None if the DTB is unusable.
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
            name = self.context.layers.free_layer_name(prefix="dfir_thrd")
            path = interfaces.configuration.path_join("temporary", name)
            self.context.config.splice(path, config)
            self.context.layers.add_layer(
                kernel_layer.__class__(self.context, config_path=path, name=name))
            return name
        except Exception:  # pylint: disable=broad-except
            return None

    def _user_stack(self, ethread, owner, kernel, kernel_layer, layer_cache):
        """(UserStackBase, UserStackLimit) from the thread's TEB, read through
        the owning process's rebuilt address space; (None, None) where the TEB
        pointer is null or the memory is unreachable (dead process, paged TEB).
        """
        try:
            teb_ptr = int(ethread.Tcb.Teb)
            if not teb_ptr:
                return None, None
            owner_offset = int(owner.vol.offset)
            if owner_offset not in layer_cache:
                layer_cache[owner_offset] = self._process_layer(owner, kernel_layer)
            layer_name = layer_cache[owner_offset]
            if layer_name is None:
                return None, None
            teb = self.context.object(
                kernel.symbol_table_name + constants.BANG + "_TEB",
                layer_name=layer_name, offset=teb_ptr)
            return int(teb.NtTib.StackBase), int(teb.NtTib.StackLimit)
        except Exception:  # pylint: disable=broad-except
            return None, None

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
        kernel = self.context.modules[self.config["kernel"]]
        kernel_layer = self.context.layers[kernel.layer_name]
        # poolscanner scans the virtual kernel layer on Win10, the physical
        # layer before that — psscan offsets follow, and OwnerOffset must too.
        try:
            psscan_is_virtual = versions.is_windows_10(
                self.context, kernel.symbol_table_name)
        except Exception:  # pylint: disable=broad-except
            psscan_is_virtual = True
        if not isinstance(kernel_layer, intel.Intel):
            return

        na = renderers.NotAvailableValue
        vads_cache = {}    # owner _EPROCESS offset -> VAD ranges (start-path lookup)
        layer_cache = {}   # owner _EPROCESS offset -> rebuilt process layer name

        for ethread in thrdscan.ThrdScan.scan_threads(self.context, self.config["kernel"]):
            try:
                offset = int(ethread.vol.offset)
                pid = int(ethread.Cid.UniqueProcess)
                tid = int(ethread.Cid.UniqueThread)
            except Exception:  # pylint: disable=broad-except
                continue
            # Same junk filter as thrdscan: NT pids/tids are non-zero multiples of 4.
            if pid == 0 or pid % 4 != 0 or pid > windows_constants.MAX_PID:
                continue
            if tid == 0 or tid % 4 != 0 or tid > windows_constants.MAX_PID:
                continue

            # The DEFINITIVE owner link (car-store.md §3): the owning _EPROCESS
            # address, matching the Offset that windows.piiat.processes emits.
            owner = None
            owner_offset = None
            try:
                owner = ethread.owning_process()
                if owner is not None and owner.is_valid():
                    owner_offset = self._owner_offset(owner, kernel, psscan_is_virtual)
                else:
                    owner = None
            except Exception:  # pylint: disable=broad-except
                owner = None

            try:
                create_time = ethread.get_create_time()
            except Exception:  # pylint: disable=broad-except
                create_time = na()
            # On Win10 _ETHREAD.ExitTime is UNIONED with KeyedWaitChain: for a
            # RUNNING thread the field holds kernel list pointers, which decode
            # to garbage year-1600 dates. Only a TERMINATED thread (cross-thread
            # flag bit 0) has a real ExitTime; everyone else gets N/A.
            exit_time = na()
            try:
                if int(ethread.CrossThreadFlags) & 1:  # PS_CROSS_THREAD_FLAGS_TERMINATED
                    exit_time = ethread.get_exit_time()
            except Exception:  # pylint: disable=broad-except
                pass
            if isinstance(exit_time, datetime.datetime) and exit_time.year < 1990:
                exit_time = na()

            try:
                start_addr = int(ethread.StartAddress)
            except Exception:  # pylint: disable=broad-except
                start_addr = None
            try:
                win32_start_addr = int(ethread.Win32StartAddress)
            except Exception:  # pylint: disable=broad-except
                win32_start_addr = None

            # Resolve the start addresses to the mapped module (VAD file path),
            # exactly as thrdscan does; PID 4 (System) has no user VADs.
            start_path = win32_start_path = None
            if owner is not None and pid != 4:
                try:
                    vads = pe_symbols.PESymbols.get_vads_for_process_cache(
                        vads_cache, owner)
                    if vads:
                        if start_addr is not None:
                            start_path = pe_symbols.PESymbols.filepath_for_address(
                                vads, start_addr)
                        if win32_start_addr is not None:
                            win32_start_path = pe_symbols.PESymbols.filepath_for_address(
                                vads, win32_start_addr)
                except Exception:  # pylint: disable=broad-except
                    pass

            # Kernel stack bounds live in the KTHREAD itself.
            try:
                stack_base = int(ethread.Tcb.StackBase)
            except Exception:  # pylint: disable=broad-except
                stack_base = None
            try:
                stack_limit = int(ethread.Tcb.StackLimit)
            except Exception:  # pylint: disable=broad-except
                stack_limit = None

            # User stack bounds live in the TEB — user-mode memory, so read them
            # through the owning process's rebuilt address space.
            user_stack_base = user_stack_limit = None
            if owner is not None:
                user_stack_base, user_stack_limit = self._user_stack(
                    ethread, owner, kernel, kernel_layer, layer_cache)

            yield (0, (
                offset,
                owner_offset if owner_offset is not None else na(),
                pid, tid,
                create_time,
                exit_time,
                start_addr if start_addr is not None else na(),
                start_path or na(),
                win32_start_addr if win32_start_addr is not None else na(),
                win32_start_path or na(),
                stack_base if stack_base is not None else na(),
                stack_limit if stack_limit is not None else na(),
                user_stack_base if user_stack_base is not None else na(),
                user_stack_limit if user_stack_limit is not None else na(),
            ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", int),
                ("OwnerOffset", int),
                ("PID", int),
                ("TID", int),
                ("CreateTime", datetime.datetime),
                ("ExitTime", datetime.datetime),
                ("StartAddress", int),
                ("StartPath", str),
                ("Win32StartAddress", int),
                ("Win32StartPath", str),
                ("StackBase", int),
                ("StackLimit", int),
                ("UserStackBase", int),
                ("UserStackLimit", int),
            ],
            self._generator(),
        )
