from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import magic  # type: ignore

from utils.file_utils import sha256sum
from utils.logger import get_logger

log = get_logger(__name__)


def analyze_file(path: str | Path) -> Dict[str, Any]:
    target = Path(path)
    info: Dict[str, Any] = {
        "path": str(target),
        "size": target.stat().st_size,
        "sha256": sha256sum(target),
    }
    try:
        info["mime"] = magic.from_file(str(target), mime=True)
        info["description"] = magic.from_file(str(target))
    except Exception as exc:  # noqa: BLE001
        log.warning("magic failed: %s", exc)
    return info


def analyze_file_json(path: str | Path) -> str:
    return json.dumps(analyze_file(path), indent=2)
