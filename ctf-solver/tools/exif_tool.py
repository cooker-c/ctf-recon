from __future__ import annotations

from pathlib import Path
from typing import Optional

from tools.runner import ToolRunner, ToolResult
from utils.logger import get_logger

log = get_logger(__name__)


class ExifTool:
    def __init__(self, runner: ToolRunner) -> None:
        self.runner = runner

    def run(self, path: str | Path) -> Optional[ToolResult]:
        if not self.runner.is_available("exiftool"):
            log.info("exiftool not available; skipping")
            return None
        result = self.runner.run(["exiftool", str(path)])
        if not result.ok:
            log.warning("exiftool exited with %s", result.exit_code)
        return result
