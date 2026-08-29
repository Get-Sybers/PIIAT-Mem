"""Unit tests for the CAR pipeline: normalize -> enrich -> store -> output.

Synthetic records shaped exactly like the real plugins' JSONL (no docker needed).
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from piiat_mem import carmodel, enrich, normalize, store, timeline  # noqa: E402


def _proc(pid, ppid, offset, name, path, ts, cmdline="c"):
    return normalize.normalize("windows.piiat.processes", {
        "Offset": offset, "Guid": f"proc-{offset:x}", "PID": pid, "PPID": ppid,
        "ImageFileName": name, "Path": path, "CommandLine": cmdline,
        "ParentPath": None, "CreateTime": ts, "DllCount": 0,
        "LoadedDlls": None, "Hidden": False})


def _tag(ev, image="img.mem"):
    ev["source_image"] = image
    return ev


# ---- model -----------------------------------------------------------------

def test_model_is_authoritative_13_objects():
    m = carmodel.load()
    assert len(m) == 13
    assert {"authentication", "email", "http", "socket"} <= set(m)
    assert {"guid", "parent_guid", "target_guid"} <= set(m["process"]["fields"])
    assert set(carmodel.all_fields()) >= set(m["flow"]["fields"])


# ---- normalize -------------------------------------------------------------

def test_normalize_process_exe_is_basename():
    ev = _proc(10, 4, 0xabc, "x.exe", r"C:\dir\x.exe", "2020-01-01T00:00:10+00:00")
    assert ev["car_object"] == "process" and ev["car_action"] == "create"
    assert ev["guid"] == "proc-abc"
    assert ev["exe"] == "x.exe" and ev["image_path"] == r"C:\dir\x.exe"


def test_normalize_epoch_sentinel_timestamp_dropped():
    ev = normalize.normalize("windows.thrdscan", {
        "Offset": 1, "PID": 4, "TID": 8, "CreateTime": "1601-01-01T00:00:00+00:00"})
    assert ev["timestamp"] is None
    assert ev["guid"] == "thread-1" and ev["owning_pid"] == 4


def test_normalize_registry_user_from_hive_and_action():
    ev = normalize.normalize("windows.piiat.registry", {
        "Hive": r"\??\C:\Users\jake\NTUSER.DAT", "Key": "Software\\Run",
        "ValueName": "x", "ValueData": "y", "ValueType": "REG_SZ",
        "LastWrite": "2020-01-02"})
    assert ev["car_action"] == "value_edit" and ev["user"] == "jake"


def test_normalize_unmapped_plugin_returns_none():
    assert normalize.normalize("windows.info", {"Variable": "Is64Bit"}) is None


# ---- enrich ----------------------------------------------------------------

def test_spoke_inherits_owner_and_is_marked_heuristic():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    t = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 99, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
    out = enrich.enrich([p, t])
    th = [e for e in out if e["car_object"] == "thread"][0]
    assert th["owning_guid"] == "proc-a"
    assert th["link_confidence"] == "heuristic"
    # thread has user/hostname in CAR but NOT image_path — nothing to inherit there
    assert "image_path" not in carmodel.fields("thread")


def test_pid_reuse_disambiguated_by_create_time_window():
    old = _tag(_proc(10, 4, 0xa, "old.exe", r"C:\old.exe", "2020-01-01T00:00:10+00:00"))
    new = _tag(_proc(10, 4, 0xb, "new.exe", r"C:\new.exe", "2020-01-01T09:00:00+00:00"))
    early = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 1, "PID": 10, "TID": 1, "CreateTime": "2020-01-01T00:30:00+00:00"}))
    late = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 2, "PID": 10, "TID": 2, "CreateTime": "2020-01-01T10:00:00+00:00"}))
    out = enrich.enrich([old, new, early, late])
    th = {e["tgt_tid"]: e for e in out if e["car_object"] == "thread"}
    assert th[1]["owning_guid"] == "proc-a"   # created before new.exe existed
    assert th[2]["owning_guid"] == "proc-b"   # latest create <= its time


def test_parent_link_and_parent_fields_fill_only_null():
    parent = _tag(_proc(4, 0, 0x1, "par.exe", r"C:\par.exe", "2020-01-01T00:00:01+00:00"))
    child = _tag(_proc(10, 4, 0x2, "kid.exe", r"C:\kid.exe", "2020-01-01T00:00:05+00:00"))
    out = enrich.enrich([parent, child])
    kid = [e for e in out if e.get("pid") == 10][0]
    assert kid["parent_guid"] == "proc-1"
    assert kid["parent_image_path"] == r"C:\par.exe"
    assert kid["parent_exe"] == "par.exe"
    assert kid["link_confidence"] == "heuristic"


def test_session_rows_collapse_and_feed_process_user():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    s1 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\jake", "Create Time": "2020-01-01T00:00:02+00:00",
        "Process ID": 10, "Process": "x.exe"}))
    s2 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\jake", "Create Time": "2020-01-01T00:00:09+00:00",
        "Process ID": 11, "Process": "y.exe"}))
    out = enrich.enrich([p, s1, s2])
    sessions = [e for e in out if e["car_object"] == "user_session"]
    assert len(sessions) == 1                       # collapsed to one login event
    assert sessions[0]["timestamp"] == "2020-01-01T00:00:02+00:00"
    proc = [e for e in out if e["car_object"] == "process"][0]
    assert proc["user"] == "HOST\\jake"             # filled from the session table


def test_native_value_never_overwritten():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    svc = _tag(normalize.normalize("windows.svcscan", {
        "Offset": 5, "Name": "svc", "Binary": r"C:\svc.exe", "PID": 10}))
    out = enrich.enrich([p, svc])
    s = [e for e in out if e["car_object"] == "service"][0]
    assert s["image_path"] == r"C:\svc.exe"         # native value kept
    assert s["exe"] == "svc.exe"
    assert s["owning_guid"] == "proc-a"


def test_netscan_listener_is_socket_connection_is_flow():
    listener = normalize.normalize("windows.netscan", {
        "Offset": 7, "Proto": "TCPv4", "LocalAddr": "0.0.0.0", "LocalPort": 3389,
        "ForeignAddr": "0.0.0.0", "ForeignPort": 0, "State": "LISTENING",
        "PID": 10, "Owner": "svchost.exe", "Created": "2020-01-01T00:01:00+00:00"})
    conn = normalize.normalize("windows.netscan", {
        "Offset": 8, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 5000,
        "ForeignAddr": "2001:db8::5", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:01+00:00"})
    assert listener["car_object"] == "socket" and listener["car_action"] == "listen"
    assert listener["local_port"] == 3389 and listener["protocol"] == "TCP"
    assert listener["family"] == "ipv4"
    assert conn["car_object"] == "flow" and conn["transport_protocol"] == "TCP"
    assert conn["start_time"] == "2020-01-01T00:01:01+00:00"


def test_dedupe_same_socket_across_plugins_and_dualstack_twins_survive():
    # same connection seen by netscan (physical offset) and netstat (virtual
    # offset) -> ONE flow, most-populated wins; guid is the protocol+5-tuple
    a = _tag(normalize.normalize("windows.netscan", {
        "Offset": 7, "Proto": "TCPv4", "LocalAddr": "1.1.1.1", "LocalPort": 1,
        "ForeignAddr": "2.2.2.2", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": None, "Created": "2020-01-01T00:01:00+00:00"}))
    b = _tag(normalize.normalize("windows.netstat", {
        "Offset": 0xFFFF7000, "Proto": "TCPv4", "LocalAddr": "1.1.1.1", "LocalPort": 1,
        "ForeignAddr": "2.2.2.2", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": "x.exe", "Created": "2020-01-01T00:01:00+00:00"}))
    # dual-stack twins share ONE offset but differ by protocol family -> distinct
    c = _tag(normalize.normalize("windows.netscan", {
        "Offset": 7, "Proto": "TCPv6", "LocalAddr": "::1", "LocalPort": 1,
        "ForeignAddr": "2001:db8::5", "ForeignPort": 443, "State": "ESTABLISHED",
        "PID": 10, "Owner": None, "Created": "2020-01-01T00:01:00+00:00"}))
    out = enrich.enrich([a, b, c])
    flows = [e for e in out if e["car_object"] == "flow"]
    assert len(flows) == 2
    v4 = [f for f in flows if f["src_ip"] == "1.1.1.1"][0]
    assert v4["exe"] == "x.exe"          # most-populated (netstat) row won


def test_module_image_path_left_null_then_inherited_from_owner():
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\dir\x.exe", "2020-01-01T00:00:10+00:00"))
    m = _tag(normalize.normalize("windows.dlllist", {
        "PID": 10, "Process": "x.exe", "Base": 0x7ff0, "Name": "ntdll.dll",
        "Path": r"C:\Windows\SYSTEM32\ntdll.dll", "LoadTime": "2020-01-01T00:00:11+00:00"}))
    assert m.get("image_path") is None                # never the DLL's own path
    assert m["module_path"] == r"C:\Windows\SYSTEM32\ntdll.dll"
    out = enrich.enrich([p, m])
    mod = [e for e in out if e["car_object"] == "module"][0]
    assert mod["image_path"] == r"C:\dir\x.exe"       # inherited: the LOADER's image
    assert mod["owning_guid"] == "proc-a"


def test_registry_default_value_keeps_its_guid():
    ev = normalize.normalize("windows.piiat.registry", {
        "Hive": "SOFTWARE", "Key": "Microsoft\\Windows\\Run", "ValueName": "",
        "ValueData": "x", "ValueType": "REG_SZ", "LastWrite": "2020-01-02"})
    assert ev["guid"] == "registry-SOFTWARE-Microsoft\\Windows\\Run-"


def test_match_never_links_to_a_later_created_process():
    late = _tag(_proc(10, 4, 0xb, "late.exe", r"C:\late.exe", "2020-01-01T09:00:00+00:00"))
    early_thread = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 1, "PID": 10, "TID": 1, "CreateTime": "2020-01-01T00:30:00+00:00"}))
    out = enrich.enrich([late, early_thread])
    th = [e for e in out if e["car_object"] == "thread"][0]
    assert th["owning_guid"] is None                  # sole candidate created AFTER
    assert th["link_confidence"] is None


def test_distinct_users_same_session_id_do_not_merge():
    s1 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\alice", "Create Time": "2020-01-01T00:00:02+00:00",
        "Process ID": 10, "Process": "x.exe"}))
    s2 = _tag(normalize.normalize("windows.sessions", {
        "Session ID": 1, "User Name": "HOST\\bob", "Create Time": "2020-01-01T00:00:05+00:00",
        "Process ID": 11, "Process": "y.exe"}))
    out = enrich.enrich([s1, s2])
    assert len([e for e in out if e["car_object"] == "user_session"]) == 2


def test_process_image_path_never_a_bare_name():
    ev = _proc(10, 4, 0xa, "truncatedname14", None, "2020-01-01T00:00:10+00:00")
    assert ev["image_path"] is None                   # no faked path from EPROCESS name
    assert ev["exe"] == "truncatedname14"             # exe fallback is fine


# ---- store + output --------------------------------------------------------

def test_store_and_outputs(tmp_path):
    p = _tag(_proc(10, 4, 0xa, "x.exe", r"C:\x.exe", "2020-01-01T00:00:10+00:00"))
    f = _tag(normalize.normalize("windows.filescan", {"Offset": 3, "Name": r"\x\y.txt"}))
    t = _tag(normalize.normalize("windows.thrdscan", {
        "Offset": 9, "PID": 10, "TID": 7, "CreateTime": "2020-01-01T00:00:20+00:00"}))
    events = enrich.enrich([p, f, t])

    st = store.CarStore(str(tmp_path / "car.db"))
    assert st.insert_events(events) == 3
    st.insert_context("img.mem", "windows.info", [{"Variable": "Is64Bit", "Value": "True"}])

    assert st.counts() == {"process": 1, "file": 1, "thread": 1}
    # file has no timestamp -> store-only, not timelined
    tl = list(st.iter_timeline())
    assert [e["car_object"] for e in tl] == ["process", "thread"]

    # wide JSONL: every CAR property present on every row, null or not
    tl_path = str(tmp_path / "timeline.json")
    n = timeline.write_timeline_json(st, tl_path)
    assert n == 2
    rows = [json.loads(l) for l in open(tl_path)]
    superset = set(carmodel.all_fields())
    for row in rows:
        assert {"timestamp", "car_object", "car_action", "guid"} <= set(row)
        assert superset <= set(row)                 # every property, null or not
    assert rows[0]["car_object"] == "process" and rows[1]["car_object"] == "thread"
    assert rows[1]["owning_guid"] == "proc-a"

    # per-object CSVs: one per populated object, with that object's properties
    written = timeline.write_object_csvs(st, str(tmp_path / "car"))
    assert set(written) == {"process", "file", "thread"}
    head = open(tmp_path / "car" / "process.csv").readline().strip().split(",")
    assert "command_line" in head and "guid" in head and "car_object" not in head
    st.close()
