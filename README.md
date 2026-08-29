# PIIAT-Mem — Put It In A Timeline (Memory)

Point it at a memory image; get a time-ordered **timeline** (CSV or JSON) built
from [Volatility 3](https://github.com/volatilityfoundation/volatility3),
including two custom DFIR plugins and a flat JSONL renderer. The analysis runs
inside a **minimal hardened container** by default (no shell, no package
manager, uid 0 renamed and locked, `--cap-drop ALL --read-only --network none`),
or natively against an installed Volatility 3.

```
piiat-mem -f memory.raw -o out/                 # JSONL timeline (container backend)
piiat-mem -f memory.raw -o out/ --format csv    # CSV timeline
piiat-mem -f memory.raw -o out/ --native        # use an installed volatility3
piiat-mem -f memory.raw -o out/ --symbols-online  # allow ISF symbol download (network)
```

Output:

```
out/plugins/<plugin>.jsonl   raw per-plugin Volatility output (one record per line)
out/timeline.json            merged, time-sorted events (JSONL) — or timeline.csv
```

Each timeline event is `{timestamp, plugin, artifact, pid, process, description, detail}`,
sorted ascending. Records with no usable timestamp stay in the raw per-plugin
JSONL but are not timelined.

## What it runs

Timestamped plugins feed the timeline:

| Plugin | Artifact | Time |
|---|---|---|
| `windows.PIIAT_processes` | process | process create time (psscan — finds unlinked/terminated too) |
| `windows.pslist` | process | process create time (active list) |
| `windows.dlllist` | module | module load time |
| `windows.thrdscan` | thread | thread create time |
| `windows.netscan` | network | socket created time |
| `windows.sessions` | session | session create time |
| `windows.PIIAT_registry` | registry | key last-write time |

`windows.info`, `windows.svcscan`, `windows.filescan` and `windows.modules` are
also dumped (no per-record time, so not timelined).

### Custom plugins
- **`windows.PIIAT_processes`** — one row per process via `psscan`
  (pool-tag scanning, so rootkit-unlinked processes are still found), each
  carrying PID/PPID, the full image path and command line from the PEB, the
  parent's full path, loaded DLLs, and a `Hidden` flag for processes the active
  list missed. It rebuilds the process address space from the DTB so the PEB
  resolves even for unlinked processes.
- **`windows.PIIAT_registry`** — reads a RECmd-batch-style list of
  high-value keys out of the hives resident in memory and emits one row per
  value (Hive, Key, ValueName, ValueType, ValueData, LastWrite). Override with
  `--plugins` or the plugin's `--targets`.

## Backends

- **Container (default)** — the hardened `dfir/volatility:latest` image. Build it:
  ```
  docker build -t dfir/volatility:latest -f docker/Dockerfile docker
  ```
  The plugins and the `jsonl_dfir` renderer are bind-mounted read-only; the ISF
  symbol cache is the one writable mount. No network unless `--symbols-online`.
- **Native (`--native`)** — an installed `volatility3` (`pip install
  piiat-mem[native]`). The renderer is imported so Volatility discovers
  `-r jsonl_dfir`, then the CLI runs in-process.

## Install

```
pip install .            # the piiat-mem CLI (container backend)
pip install .[native]    # also pull in volatility3 for --native
```

## As a submodule

PIIAT-Mem is designed to drop into a larger pipeline as a git submodule: the
parent repo builds the image from `docker/Dockerfile` and points its own runner
at `plugins/` and `jsonl_dfir_renderer.py`. It is the memory-forensics engine
behind the DX_DFIR volatility lane.

## License

MIT — see [LICENSE](LICENSE).
