from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

log = get_logger(__name__)


def ensure_dir(path: str | Path) -> Path:
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def read_bytes(path: str | Path) -> bytes:
    return Path(path).read_bytes()


def write_text(path: str | Path, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def sha256sum(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def is_readable_file(path: str | Path) -> bool:
    file_path = Path(path)
    if not file_path.is_file():
        log.error("Path is not a file: %s", file_path)
        return False
    if not os.access(file_path, os.R_OK):
        log.error("File is not readable: %s", file_path)
        return False
    return True


def save_output(output_dir: str | Path, name: str, content: str, suffix: str = "txt") -> Path:
    ensure_dir(output_dir)
    path = Path(output_dir) / f"{name}.{suffix}"
    write_text(path, content)
    return path
