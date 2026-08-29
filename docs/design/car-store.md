# CAR-event store — relational model (Phase 1)

Tracks epic #1. This is the **relational design** the store is built on: the CAR
objects, what makes each event unique, how the objects relate, and the identity
key each object needs to **inherit** properties from a related entry. Source of
truth for objects / actions / properties: `car_data_model.json` (repo root,
MITRE's own file).

Scope: the **PIIAT-Mem processor** only. CAR-at-query-time still applies to the
artefacts we don't own; PIIAT-Mem is ours, so it emits finished CAR.

## 1. The objects — identity, action, timestamp (from memory)

Each CAR object is sourced from one Volatility plugin. "Timelineable" = memory
gives it a timestamp (so it appears on the timeline); the rest are stored and
join-able but carry no time.

| CAR object | memory plugin | unique identity | action | timestamp (source) | timelineable |
|---|---|---|---|---|---|
| process | `windows.piiat.processes` | `pid` | create | CreateTime | yes |
| thread | `windows.thrdscan` | `tgt_pid` + `tgt_tid` | create | create time | yes |
| module | `windows.dlllist` | `pid` + `module_path` (`base_address`) | load | LoadTime | yes |
| flow | `windows.netscan` / `netstat` | `pid` + 5-tuple | start / end | Created | yes |
| user_session | `windows.sessions` | `logon_id` (+ `user`) | login | create time | yes |
| registry | `windows.piiat.registry` | `hive`+`key`+`value` | edit | LastWrite | yes |
| driver | `windows.modules` | `image_path` + `base_address` | load | — | no (store-only) |
| file | `windows.filescan` | `file_path` | — | — | no (store-only) |
| service | `windows.svcscan` | `name` (+ `pid`) | — | — | no (store-only) |

`banners` / `windows.info` are not CAR objects — they are **image-context
metadata** (kept in a side table, not `car_events`).

## 2. Relationships — `process` is the hub

Almost every object references the process it belongs to via **`pid`**. `process`
references its parent via `ppid`. `driver` is kernel-global (no process).

```
                                 ┌── ppid ──┐  (parent process)
                                 ▼          │
   thread ──tgt_pid─▶┐        ┌─────────────┴──┐
   thread ──src_pid─▶│        │   process(pid) │◀── pid ── module
   flow   ──pid─────▶├───────▶│                │◀── pid ── service (+ppid)
   file   ──pid─────▶│        └────────────────┘◀── pid ── registry
   user_session ─user/logon_id┘
   driver ── (standalone, kernel — hostname/fqdn only)
```

Foreign keys:

- `process.ppid  → process.pid`   (parent process; self-referential)
- `thread.tgt_pid → process.pid`  (thread runs in process) · `thread.src_pid → process.pid` (creator, for `remote_create`)
- `module.pid   → process.pid`    · `flow.pid → process.pid` · `file.pid → process.pid` · `registry.pid → process.pid`
- `service.pid  → process.pid`    · `service.ppid → process.pid`
- `user_session.user → process.user` (weak; or `logon_id` where present)

The PIDs above are the *surface* the plugins expose. Because PIDs are **reused**,
the real join is on process **`guid` (= `_EPROCESS` offset)**, with PID only as a
fallback — see §3.

## 3. Inheritance — when can a property *definitively* be said to belong?

The logical test: **object A's property may be attributed to object B only if A
and B share a key that identifies the *same entity instance* beyond doubt.** A
non-unique key is a guess, not a proof.

**`pid` is not that key.** The OS **reuses** PIDs — after a process exits, its PID
is handed to a new, unrelated process. So a `pid` match in a memory image can join
across two *different* process instances. Attribution on bare `pid` is a
**heuristic**, never definitive.

**MITRE CAR already says so.** The authoritative CAR `process` object identifies a
process by **`guid`** ("global unique identifier for the initiating process"),
with **`parent_guid`** / **`target_guid`** for the parent and access-target links —
reuse-immune identities, distinct from `pid`/`ppid`. (The local
`car_data_model.json` is a 9-object subset that omits `guid` — see §7.)

**Memory has no Sysmon `guid`** (it is not stored in `_EPROCESS`). The
memory-native unique identity is the **`_EPROCESS` offset** — every process object
has a unique address in the image, and the kernel itself links threads, modules
and handles to a process **by pointer to that object**, not by PID. So:

> PIIAT-Mem **synthesizes CAR `guid` = the `_EPROCESS` offset** (the process's
> kernel-object identity). That becomes the definitive join key; `pid` is demoted
> to a plain attribute.

**Definitive vs heuristic, per link** — a spoke inherits process context
(`exe, image_path, command_line, user, sid, parent_*, fqdn, hostname`) via a
LEFT JOIN that fills a property **only where the spoke's own value is null**:

| link | what memory actually gives | verdict |
|---|---|---|
| module → process | `dlllist` walks **each process's** PEB — the row is *produced from* that `_EPROCESS`, so its offset is known at extraction | **definitive** (carry the owning offset) |
| thread → process | `thrdscan` gives the thread offset + `pid`; the owning `_EPROCESS` pointer is reachable but not currently emitted | **definitive if** we emit the owning-`_EPROCESS` offset; else `pid` = heuristic |
| flow → process | `netscan` gives owner `pid` only | **heuristic** (pid) |
| service → process | `svcscan` gives `pid` only | **heuristic** (pid) |
| process → parent | `ppid` is a *recorded* PID; the real parent may be dead/reused | **heuristic**; `parent_guid` from the parent `_EPROCESS` pointer (create-time ordered) is definitive |
| file → process | `filescan` finds global FILE_OBJECTs with **no owner** | **none** — needs handle enumeration; stays null |
| registry → user | the hive's **file path** (`…\<user>\NTUSER.DAT`) *is* that user's | **definitive by path** (not a join) |
| user_session → process | shares only `user` (+ time) | **heuristic** |

**Rule for the store:** key `process` on **`guid` (= `_EPROCESS` offset)**; carry
`pid`/`ppid` as attributes only. Populate a spoke's inherited properties by joining
on `guid` and mark those rows **definitive**; where only `pid` is available, join
on `pid` disambiguated by a create-time window and record
**`link_confidence = "heuristic"`** — never assert a reused-PID match as fact. Our
current process plugin resolves `ParentPath` by a bare PID→path map (§ processes.py);
that is a heuristic and Phase 2 replaces it with the offset/`parent_guid` link.

**Consequence for extraction (Phase 2):** the process plugin must emit the
`_EPROCESS` **`Offset`** (it does not today) so `guid` can be synthesized; a
*definitive* thread/module link needs the owning-`_EPROCESS` offset emitted too
(custom plugins that follow the pointer) — otherwise those links are honestly
marked heuristic.

## 4. What makes an event unique (distinct entry AND join target)

Composite identity per object = `(car_object, <identity>, timestamp, action)`.
Where the object's identity IS a memory object, the offset is the identity — not
the reused PID:

- **process `(guid = _EPROCESS offset)`** — `pid`+`create_time` only as a fallback
- thread `(_ETHREAD offset, tgt_tid)` · module `(owning guid, base_address|module_path)`
- flow `(socket offset; else pid + 5-tuple)` · driver `(image_path|module_name, base_address)`
- registry `(hive, key, value, last_write)` · user_session `(logon_id|user, time)`
- file `(file_path)` · service `(name)`

## 5. Store schema (SQLite, relational)

One **table per object** — its CAR properties (all nullable) — plus a common
event header on every table:

```
event_id (pk) · timestamp · car_object · car_action · guid · pid · owning_guid · link_confidence · source_plugin · source_image · _native (json: non-CAR fields kept, never faked into CAR columns)
```

`guid` (= `_EPROCESS` offset) is the process's identity and the shared join
column; `owning_guid` on a spoke is the FK to its process; `pid` is a plain
attribute. `link_confidence ∈ {definitive, heuristic}` records how an inherited
property was attributed (§3). Objects with no timestamp still populate their
table (join targets) but never reach the timeline.

## 6. Output (derived from the store)

- **per-object CSV** — `SELECT * FROM <object>` per table (that object's properties).
- **wide JSONL timeline** — `UNION ALL` across every object, projected onto the
  full property superset (absent properties → null), each row tagged
  `car_object` / `car_action` (and `link_confidence`), `ORDER BY timestamp`. Only
  timestamped rows appear; file / service / driver without a time remain
  store-only (still enrichment join targets).

## 7. Note — car_data_model.json vs. the authoritative CAR model

The repo's `car_data_model.json` is a **9-object subset** and, on `process`, omits
the identity fields the live CAR model defines — **`guid`, `parent_guid`,
`target_guid`** (and the `access` action). Those fields are exactly the
reuse-immune identity §3 relies on. Two options, for the owner to decide:
refresh `car_data_model.json` to the full MITRE model (car.mitre.org — 15 objects:
adds authentication, email, http, socket, …), or keep the subset and have
PIIAT-Mem add the synthesized `guid`/`parent_guid` columns regardless. Either way
the store carries `guid`; this doc treats CAR's real identity model as the target.

---

**Next:** Phase 2 (extract → normalize → store) implements §5 tables + the
per-plugin → CAR maps + the §3 enrichment; Phase 3 (output) implements §6.
