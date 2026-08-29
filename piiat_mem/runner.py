"""Run Volatility 3 plugins over one memory image, capturing flat JSONL.

Two backends:
  container (default) — the hardened dfir/volatility image; the plugins dir and
    the jsonl_dfir renderer are bind-mounted read-only, the ISF symbol cache
    read-write, the image read-only. The image ENTRYPOINT is the baked wrapper
    (``python3 /opt/dfir/vol_wrapper.py``); it imports the mounted renderer so
    Volatility discovers ``-r jsonl_dfir``, then runs the CLI.
  native — an installed ``volatility3``: import the renderer, then drive the CLI
    in-process. Handy for a host that already has Volatility.

The plugin's stdout is the JSONL (one record per TreeGrid node); it is captured
to ``<out>/plugins/<plugin>.jsonl``. ``symbols_online`` lifts the container's
network isolation for the ISF symbol fetch.
"""
from __future__ import annotations

import os
import subprocess
import sys

from . import container

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RENDERER = os.path.join(REPO, "jsonl_dfir_renderer.py")
PLUGINS_DIR = os.path.join(REPO, "plugins")

DEFAULT_IMAGE = "dfir/volatility:latest"

# Plugins whose records carry a timestamp — the ones the timeline is built from.
# (Order preserved; the two windows.piiat.* plugins are the custom ones in ./plugins/windows/piiat.)
TIMELINE_PLUGINS = [
    "windows.piiat.processes",        # process create times (psscan; unlinked too)
    "windows.pslist",                 # process create times (active list)
    "windows.dlllist",                # module load times
    "windows.thrdscan",               # thread create times
    "windows.netscan",                # socket created times
    "windows.sessions",               # session create times
    "windows.piiat.registry",         # registry key last-write times
]
# Plugins with no per-record time — still dumped for completeness (not timelined).
CONTEXT_PLUGINS = ["windows.info", "windows.svcscan", "windows.filescan", "windows.modules"]
# The full set this tool runs by default; exported (and surfaced by
# ``piiat-mem --list-plugins``) so a consumer can name the plugins it wants.
ALL_PLUGINS = TIMELINE_PLUGINS + CONTEXT_PLUGINS


def _container_argv(image, mem, plugin, symbols_dir, *, symbols_online=False):
    mem = os.path.realpath(mem)
    return container.run(
        image,
        ["/opt/renderer.py",
         "-q", "-p", "/plugins", "-s", "/symbols", "-r", "jsonl_dfir",
         "-f", f"/mem/{os.path.basename(mem)}", plugin],
        mounts=[f"{os.path.dirname(mem)}:/mem:ro",
                f"{os.path.realpath(symbols_dir)}:/symbols",
                f"{RENDERER}:/opt/renderer.py:ro",
                f"{PLUGINS_DIR}:/plugins:ro"],
        network=symbols_online,
    )


def _native_argv(mem, plugin, symbols_dir):
    boot = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('jsonl_dfir_renderer', {RENDERER!r})\n"
        "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)\n"
        "from volatility3.cli import CommandLine\n"
        f"sys.argv = ['vol','-q','-p',{PLUGINS_DIR!r},'-s',{os.path.realpath(symbols_dir)!r},"
        f"'-r','jsonl_dfir','-f',{os.path.realpath(mem)!r},{plugin!r}]\n"
        "CommandLine().run()\n"
    )
    return [sys.executable, "-c", boot]


def run_plugin(mem, plugin, out_dir, symbols_dir, *, image=DEFAULT_IMAGE,
               native=False, symbols_online=False) -> dict:
    """Run one plugin; write its JSONL to <out_dir>/plugins/<plugin>.jsonl."""
    plug_dir = os.path.join(out_dir, "plugins")
    os.makedirs(plug_dir, exist_ok=True)
    try:
        os.chmod(os.path.realpath(symbols_dir), 0o777)  # ISF cache written by uid 2000
    except OSError:
        pass
    out_path = os.path.join(plug_dir, f"{plugin}.jsonl")
    argv = (_native_argv(mem, plugin, symbols_dir) if native
            else _container_argv(image, mem, plugin, symbols_dir, symbols_online=symbols_online))
    with open(out_path, "w", encoding="utf-8") as fh:
        proc = subprocess.run(argv, stdout=fh, stderr=subprocess.PIPE, text=True, check=False)
    lines = 0
    if os.path.isfile(out_path):
        with open(out_path, encoding="utf-8", errors="replace") as fh:
            lines = sum(1 for ln in fh if ln.strip())
    return {"plugin": plugin, "output": out_path, "rows": lines,
            "ok": proc.returncode == 0,
            "error": (proc.stderr or "").strip()[:300] if proc.returncode else ""}


def run_all(mem, out_dir, *, plugins=None, symbols_dir, image=DEFAULT_IMAGE,
            native=False, symbols_online=False) -> list[dict]:
    """Run the timeline + context plugins over one image. Returns per-plugin results."""
    plugins = plugins if plugins is not None else ALL_PLUGINS
    return [run_plugin(mem, p, out_dir, symbols_dir, image=image, native=native,
                       symbols_online=symbols_online) for p in plugins]
