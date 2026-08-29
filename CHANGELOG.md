# Changelog

All notable changes are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-29

### Changed
- **Breaking:** the two custom plugins now live in the `windows` category to
  match the built-in Volatility naming, and are referenced by the shorthand the
  rest of the pipeline uses:
  - `dfir_processes.DfirProcesses` → `windows.PIIAT_processes` (class
    `PIIATProcesses`, now at `plugins/windows/PIIAT_processes.py`)
  - `dfir_registry.DfirRegistry` → `windows.PIIAT_registry` (class
    `PIIATRegistry`, now at `plugins/windows/PIIAT_registry.py`)
  Anything selecting the old `dfir_processes.DfirProcesses` /
  `dfir_registry.DfirRegistry` identifiers must switch to the new names.

## [0.1.0] - 2026-08-28

### Added
- Initial release. `piiat-mem -f <image> -o <out>` runs Volatility 3 over a
  memory image and writes a time-ordered timeline (`timeline.json` JSONL or
  `--format csv`) alongside the raw per-plugin JSONL.
- Custom Volatility 3 plugins: `dfir_processes.DfirProcesses` (psscan-based
  process records with full image path, parent path and loaded DLLs, unlinked
  processes flagged) and `dfir_registry.DfirRegistry` (RECmd-style target keys
  read from in-memory hives).
- Flat `jsonl_dfir` renderer — one JSON object per TreeGrid node.
- Minimal hardened Volatility 3 container (uid 0 renamed and locked, no shell,
  no package manager, runs as uid 2000); every run is `--cap-drop ALL
  --security-opt no-new-privileges --read-only --network none` (network only
  with `--symbols-online`). `--native` runs an installed Volatility 3 instead.
