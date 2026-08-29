"""Volatility 3 plugin: network endpoint records for the CAR data model.

`windows.piiat.network` — netscan (pool-tag scanning for TcpL/TcpE/UdpA) with a
DEFINITIVE owner link. The built-in netscan resolves each structure's Owner
pointer only far enough to print the PID and process name; this plugin follows
the SAME pointer but also emits its target address, because per
docs/design/car-store.md §3 the owning-_EPROCESS OFFSET is the definitive
process link while a (reusable) PID is only a heuristic. One row per socket /
connection binding:

  Offset       the _TCP_ENDPOINT / _TCP_LISTENER / _UDP_ENDPOINT structure
               address (pool-scan identity of the artifact)
  OwnerOffset  the owner _EPROCESS address the structure's Owner pointer holds
               — joins DEFINITIVELY against windows.piiat.processes Offset
               (NotAvailable where the pointer is unreadable/null)
  PID          the owner's UniqueProcessId (heuristic link; kept for humans)
  Owner        the owner's ImageFileName
  Proto        TCPv4 / TCPv6 / UDPv4 / UDPv6
  LocalAddr, LocalPort
  ForeignAddr, ForeignPort   ("*" / 0 for listeners and UDP, as in netscan)
  State        TCP state; LISTENING for listeners; NotAvailable for UDP
  Created      endpoint creation time

Column names match the built-in netscan where they overlap so the normalize
maps can be reused. A dual-stack listener/UDP socket yields one row per
address-family binding (same Offset), exactly as netscan does.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.network") -> CarNetwork reads Record.OwnerOffset/LocalAddr/…
"""
import datetime

from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.windows import versions
from volatility3.framework.symbols.windows.extensions import network
from volatility3.plugins.windows import netscan, psscan


class Network(interfaces.plugins.PluginInterface):
    """Network endpoints (netscan) with the owning _EPROCESS address for a
    definitive process link."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _normalize_owner_ptr(self, ptr, kernel, psscan_is_virtual):
        """The Owner pointer (a VIRTUAL _EPROCESS address) in the SAME
        convention psscan emits process offsets — mask-normalized virtual on
        Win10, PHYSICAL before that — so it joins windows.piiat.processes.Offset
        bit-for-bit on every Windows version (mirrors windows.piiat.modules).
        Falls back to the raw pointer if translation fails (e.g. the owner's
        page tables for that address are gone)."""
        try:
            if psscan_is_virtual:
                return ptr & self.context.layers[kernel.layer_name].address_mask
            proc = self.context.object(
                kernel.symbol_table_name + constants.BANG + "_EPROCESS",
                layer_name=kernel.layer_name, offset=ptr)
            return int(psscan.PsScan.physical_offset_from_virtual(
                self.context, kernel.layer_name, proc))
        except Exception:  # pylint: disable=broad-except
            return ptr

    def _owner_fields(self, netw_obj, kernel, psscan_is_virtual):
        """(OwnerOffset, PID, Owner-name) for a pooled network object.

        OwnerOffset is taken from the Owner POINTER value — not the
        dereferenced object — so it survives even when the pointed-at process
        page is unreadable; it is then normalized to psscan's offset
        convention (see _normalize_owner_ptr).
        """
        na = renderers.NotAvailableValue
        owner_offset = na()
        pid = na()
        owner_name = na()
        try:
            ptr = int(netw_obj.member("Owner"))
            if ptr:
                owner_offset = self._normalize_owner_ptr(ptr, kernel, psscan_is_virtual)
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            value = netw_obj.get_owner_pid()
            if value is not None:
                pid = int(value)
        except Exception:  # pylint: disable=broad-except
            pass
        try:
            value = netw_obj.get_owner_procname()
            if value:
                owner_name = str(value)
        except Exception:  # pylint: disable=broad-except
            pass
        return owner_offset, pid, owner_name

    @staticmethod
    def _created(netw_obj):
        try:
            value = netw_obj.get_create_time()
            if isinstance(value, datetime.datetime):
                return value
        except Exception:  # pylint: disable=broad-except
            pass
        return renderers.NotAvailableValue()

    def _generator(self):
        na = renderers.NotAvailableValue
        symbol_table = netscan.NetScan.create_netscan_symbol_table(
            self.context, self.config["kernel"], self.config_path)
        kernel = self.context.modules[self.config["kernel"]]
        # psscan's offset convention: virtual on Win10, physical before that.
        try:
            psscan_is_virtual = versions.is_windows_10(
                self.context, kernel.symbol_table_name)
        except Exception:  # pylint: disable=broad-except
            psscan_is_virtual = True

        for netw_obj in netscan.NetScan.scan(
                self.context, self.config["kernel"], symbol_table):
            try:
                if not netw_obj.is_valid():
                    continue
                offset = int(netw_obj.vol.offset)
                owner_offset, pid, owner_name = self._owner_fields(
                    netw_obj, kernel, psscan_is_virtual)
                created = self._created(netw_obj)

                if isinstance(netw_obj, network._UDP_ENDPOINT):
                    # UDP: no state, remote end is asterisks (as in netscan).
                    try:
                        local_port = int(netw_obj.Port)
                    except Exception:  # pylint: disable=broad-except
                        local_port = na()
                    for ver, laddr, _ in netw_obj.dual_stack_sockets():
                        yield (0, (
                            offset, owner_offset, pid, owner_name,
                            "UDP" + ver,
                            laddr or na(), local_port,
                            "*", 0,
                            na(),
                            created,
                        ))

                elif isinstance(netw_obj, network._TCP_ENDPOINT):
                    if netw_obj.get_address_family() == network.AF_INET:
                        proto = "TCPv4"
                    elif netw_obj.get_address_family() == network.AF_INET6:
                        proto = "TCPv6"
                    else:
                        proto = "TCPv?"
                    try:
                        state = netw_obj.State.description
                    except Exception:  # pylint: disable=broad-except
                        state = na()
                    try:
                        local_port = int(netw_obj.LocalPort)
                    except Exception:  # pylint: disable=broad-except
                        local_port = na()
                    try:
                        remote_port = int(netw_obj.RemotePort)
                    except Exception:  # pylint: disable=broad-except
                        remote_port = na()
                    yield (0, (
                        offset, owner_offset, pid, owner_name,
                        proto,
                        netw_obj.get_local_address() or na(), local_port,
                        netw_obj.get_remote_address() or na(), remote_port,
                        state,
                        created,
                    ))

                # listener last: the other pooled types inherit from it
                elif isinstance(netw_obj, network._TCP_LISTENER):
                    try:
                        local_port = int(netw_obj.Port)
                    except Exception:  # pylint: disable=broad-except
                        local_port = na()
                    for ver, laddr, raddr in netw_obj.dual_stack_sockets():
                        yield (0, (
                            offset, owner_offset, pid, owner_name,
                            "TCP" + ver,
                            laddr or na(), local_port,
                            raddr or na(), 0,
                            "LISTENING",
                            created,
                        ))
            except Exception:  # pylint: disable=broad-except
                # one corrupt pooled object must never kill the run
                continue

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", int),
                ("OwnerOffset", int),
                ("PID", int),
                ("Owner", str),
                ("Proto", str),
                ("LocalAddr", str),
                ("LocalPort", int),
                ("ForeignAddr", str),
                ("ForeignPort", int),
                ("State", str),
                ("Created", datetime.datetime),
            ],
            self._generator(),
        )
