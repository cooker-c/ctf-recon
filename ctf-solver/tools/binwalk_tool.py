from __future__ import annotations

from pathlib import Path
from typing import Optional

from tools.runner import ToolRunner, ToolResult
from utils.logger import get_logger

log = get_logger(__name__)


class BinwalkTool:
    def __init__(self, runner: ToolRunner) -> None:
        self.runner = runner

    def run_scan(self, path: str | Path) -> Optional[ToolResult]:
        if not self.runner.is_available("binwalk"):
            log.info("binwalk not available; skipping")
            return None
        result = self.runner.run(["binwalk", str(path)])
        if not result.ok:
            log.warning("binwalk exited with %s", result.exit_code)
        return result

    def run_extract(self, path: str | Path, output_dir: str | Path) -> Optional[ToolResult]:
        if not self.runner.is_available("binwalk"):
            return None
        result = self.runner.run(["binwalk", "-e", str(path), "-C", str(output_dir)])
        return result
