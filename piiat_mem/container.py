"""Hardened ``docker run`` construction for the PIIAT-Mem Volatility image.

The image is stripped to Volatility 3 + the baked wrapper (uid 0 renamed and
locked, no shell, no package manager, runs as uid 2000). Every run is confined:
no capabilities, no new privileges, a read-only root filesystem, a pids limit,
and no network unless ISF symbol download is explicitly requested. Pure list
builders so the argv stays testable.
"""
from __future__ import annotations

HARDENING_FLAGS = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--pids-limit", "512",
    "--read-only",
]
_BASE_TMPFS = ["--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=1g"]


def run_flags(network: bool = False) -> list[str]:
    flags = list(HARDENING_FLAGS) + list(_BASE_TMPFS)
    if not network:
        flags += ["--network", "none"]
    return flags


def run(image: str, after_image=(), *, mounts=(), network: bool = False) -> list[str]:
    """``docker run`` argv. ``after_image`` is appended after the image name (the
    image's ENTRYPOINT is ``python3 /opt/dfir/vol_wrapper.py``, so these are the
    wrapper's arguments: the renderer path, then the Volatility CLI args)."""
    argv = ["docker", "run", "--rm", *run_flags(network)]
    for mount in mounts:
        argv += ["-v", mount]
    argv += [image, *after_image]
    return argv
