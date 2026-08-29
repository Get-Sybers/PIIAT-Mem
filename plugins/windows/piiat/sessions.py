"""Volatility 3 plugin: logon-session records for the CAR data model.

`windows.piiat.sessions` — one row per process, carrying the process's REAL
logon session identity. The built-in windows.sessions only surfaces the
terminal-services Session ID (an int like 0/1); the CAR `login_id` is the logon
session LUID that the security subsystem stamps into every access token —
_TOKEN.AuthenticationId — the same value the 4624/4672 event logs call
TargetLogonId. Each row emits:

  OwnerOffset   the owning _EPROCESS virtual address — per car-store.md §3 the
                DEFINITIVE process link (the reused PID is only a heuristic);
                enrichment joins this against windows.piiat.processes offsets
                to upgrade the process<->session link from heuristic to definitive
  PID, ProcessName
  SessionId     the terminal-services session int (from the _MM_SESSION_SPACE)
  LogonId       _TOKEN.AuthenticationId rendered as hex ("0x3e7") — CAR login_id,
                joinable against event-log TargetLogonId downstream
  Sid           the token's user SID (first _SID_AND_ATTRIBUTES entry)
  User          account name resolved from the SOFTWARE hive ProfileList
                (SID -> ProfileImagePath basename); NotAvailable when the SID
                has no profile (service SIDs, well-known SIDs)
  CreateTime    process creation time — the session's earliest process create
                approximates the logon time downstream

One row PER PROCESS is intentional: enrichment collapses rows into sessions
(group by LogonId) AND harvests the per-process user/sid from the same rows.

Rendered by the jsonl_dfir renderer -> memory.VolatilityJson (Plugin =
"windows.piiat.sessions") -> CarUserSession reads Record.LogonId/Sid/…
"""
import datetime
import ntpath

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.registry import RegistryException
from volatility3.framework.objects import utility
from volatility3.framework.symbols.windows import versions
from volatility3.plugins.windows import pslist, psscan
from volatility3.plugins.windows.registry import hivelist


class Sessions(interfaces.plugins.PluginInterface):
    """Per-process logon session identity: token AuthenticationId (login_id), user SID and name."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Windows kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _sid_to_user(self):
        """{sid: account name} from the SOFTWARE hive's ProfileList (the
        getsids lookup_user_sids approach): each profiled SID's
        ProfileImagePath basename is the account name. Empty map if the
        SOFTWARE hive / key is not resident."""
        sids = {}
        try:
            for hive in hivelist.HiveList.list_hives(
                    self.context, self.config_path, self.config["kernel"],
                    filter_string="config\\software"):
                try:
                    key = hive.get_key(
                        "Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
                    for subkey in key.get_subkeys():
                        try:
                            sid = str(subkey.get_name())
                            for node in subkey.get_values():
                                if node.get_name() != "ProfileImagePath":
                                    continue
                                data = node.decode_data()
                                if isinstance(data, bytes):
                                    path = data.decode(
                                        "utf-16-le", "replace").rstrip("\x00")
                                    user = ntpath.basename(path)
                                    if user:
                                        sids[sid] = user
                        except Exception:  # pylint: disable=broad-except
                            continue
                except (KeyError, RegistryException,
                        exceptions.InvalidAddressException):
                    continue
        except Exception:  # pylint: disable=broad-except
            pass
        return sids

    @staticmethod
    def _token(proc):
        """The process's _TOKEN, or None if the fast-ref is unreadable."""
        try:
            token = proc.Token.dereference().cast("_TOKEN")
            if isinstance(token, interfaces.objects.ObjectInterface):
                return token
        except exceptions.InvalidAddressException:
            pass
        return None

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
        na = renderers.NotAvailableValue
        sid_to_user = self._sid_to_user()
        kernel = self.context.modules[self.config["kernel"]]
        # psscan's offset convention: virtual on Win10, physical before that.
        try:
            psscan_is_virtual = versions.is_windows_10(
                self.context, kernel.symbol_table_name)
        except Exception:  # pylint: disable=broad-except
            psscan_is_virtual = True

        for proc in pslist.PsList.list_processes(self.context, self.config["kernel"]):
            try:
                owner_offset = self._owner_offset(proc, kernel, psscan_is_virtual)
                pid = int(proc.UniqueProcessId)
                name = utility.array_to_string(proc.ImageFileName)
            except exceptions.InvalidAddressException:
                continue

            try:
                session_id = proc.get_session_id()
                session_id = int(session_id)
            except Exception:  # pylint: disable=broad-except
                # Session == 0 (NotApplicable: System/idle) or unreadable.
                session_id = None

            try:
                create_time = proc.get_create_time()
            except Exception:  # pylint: disable=broad-except
                create_time = None

            logon_id = sid = None
            token = self._token(proc)
            if token is not None:
                try:
                    # The LUID the security subsystem assigned to this logon
                    # session — CAR login_id; event logs show it as hex
                    # TargetLogonId, so render it the same way for the join.
                    auth = token.AuthenticationId
                    logon_id = "0x%x" % (
                        (int(auth.HighPart) << 32) | int(auth.LowPart))
                except Exception:  # pylint: disable=broad-except
                    pass
                try:
                    # First UserAndGroups entry is the token's USER sid.
                    sid = next(iter(token.get_sids()), None)
                except Exception:  # pylint: disable=broad-except
                    pass

            yield (0, (
                owner_offset,
                pid,
                name,
                session_id if session_id is not None else na(),
                logon_id if logon_id is not None else na(),
                sid if sid is not None else na(),
                sid_to_user.get(sid) or na(),
                create_time if create_time is not None else na(),
            ))

    def run(self):
        return renderers.TreeGrid(
            [
                ("OwnerOffset", int),
                ("PID", int),
                ("ProcessName", str),
                ("SessionId", int),
                ("LogonId", str),
                ("Sid", str),
                ("User", str),
                ("CreateTime", datetime.datetime),
            ],
            self._generator(),
        )
