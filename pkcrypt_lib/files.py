"""File I/O helpers for the PKCrypt CLI."""

from __future__ import annotations

from pathlib import Path


def read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def write_bytes(path: str | Path, data: bytes) -> None:
    Path(path).write_bytes(data)


def encrypted_output_path(input_path: str) -> str:
    """Default output path when encrypting: ``<input>.pkcrypt``."""
    return input_path + ".pkcrypt"


def decrypted_output_path(input_path: str) -> str:
    """Default output path when decrypting: strip ``.pkcrypt`` or append
    ``.decrypted``, refusing to overwrite an existing file."""
    p = Path(input_path)
    if p.name.endswith(".pkcrypt"):
        cand = Path(str(p)[: -len(".pkcrypt")])
        if cand.name and not cand.exists():
            return str(cand)
    base = input_path + ".decrypted"
    cand = Path(base)
    i = 1
    while cand.exists():
        cand = Path(f"{base}.{i}")
        i += 1
    return str(cand)
