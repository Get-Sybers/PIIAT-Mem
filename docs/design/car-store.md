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

## 3. Inheritance — the key each object needs to inherit related properties

A spoke event inherits its **process context** — `exe, image_path, command_line,
user, sid, signer, parent_exe, parent_image_path, fqdn, hostname` — by joining
`pid → process.pid`. `process` inherits parent paths via `ppid`. Inheritance is a
LEFT JOIN that fills a property **only where the object's own value is null** —
never overwriting a natively-supplied value.

| object | key it must carry | inherits (from) | does memory supply the key? |
|---|---|---|---|
| process | `ppid` | parent_exe / parent_image_path (parent process) | yes (PPID); our plugin also resolves ParentPath natively |
| thread | `tgt_pid` (+ `tgt_tid`) | exe, image_path, user, command_line (process) | yes (PID / TID) |
| module | `pid` | exe, image_path, user (process) | yes (PID) |
| flow | `pid` | exe, image_path, user (process) | yes (PID / Owner) |
| service | `pid` | exe, image_path, user (process) | yes (PID) |
| file | `pid` | exe, user (process) | **no** — `filescan` carries no pid → stays null (honest gap) |
| registry | — | user | via **hive path** (`NTUSER.DAT` → user), not a join |
| user_session | `user` / `logon_id` | *is* the user context process rows join to | user yes; logon_id sometimes |
| driver | — | — | kernel-global; hostname/fqdn only |

**The only inheritance join key memory reliably provides is `pid`** (plus `ppid`
for the process self-join and `user` for sessions). So `pid` is the store's
central foreign key, and `process` is the parent every timelineable object
enriches from.

## 4. What makes an event unique (distinct entry AND join target)

Composite identity per object = `(car_object, <identity>, timestamp, action)`:

- process `(pid, create_time)` · thread `(tgt_pid, tgt_tid, create_time)`
- module `(pid, base_address|module_path, load_time)` · flow `(pid, proto, src_ip, src_port, dest_ip, dest_port, time)`
- registry `(hive, key, value, last_write)` · user_session `(logon_id|user, time)`
- driver `(image_path|module_name, base_address)` · file `(file_path)` · service `(name)`

## 5. Store schema (SQLite, relational)

One **table per object** — its CAR properties (all nullable) — plus a common
event header on every table:

```
event_id (pk) · timestamp · car_object · car_action · source_plugin · source_image · _native (json: non-CAR fields kept, never faked into CAR columns)
```

`process.pid` is the shared join column; the §2 FK columns drive the §3
enrichment. Objects with no timestamp still populate their table (join targets)
but never reach the timeline.

## 6. Output (derived from the store)

- **per-object CSV** — `SELECT * FROM <object>` per table (that object's properties).
- **wide JSONL timeline** — `UNION ALL` across every object, projected onto the
  full property superset (absent properties → null), each row tagged
  `car_object` / `car_action`, `ORDER BY timestamp`. Only timestamped rows appear;
  file / service / driver without a time remain store-only (still enrichment
  join targets).

---

**Next:** Phase 2 (extract → normalize → store) implements §5 tables + the
per-plugin → CAR maps + the §3 enrichment; Phase 3 (output) implements §6.
