from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Iterable, List

from tools.runner import ToolRunner
from utils.logger import get_logger

log = get_logger(__name__)


class StringsTool:
    def __init__(self, runner: ToolRunner, min_length: int = 4) -> None:
        self.runner = runner
        self.min_length = min_length

    def _python_strings(self, data: bytes) -> List[str]:
        pattern = re.compile(rb"[\x20-\x7e]{%d,}" % self.min_length)
        return [match.decode(errors="ignore") for match in pattern.findall(data)]

    def run(self, path: str, data: bytes | None = None) -> List[str]:
        if self.runner.is_available("strings"):
            result = self.runner.run(["strings", "-n", str(self.min_length), path])
            if result.ok:
                return result.stdout.splitlines()
            log.warning("strings returned non-zero exit code: %s", result.exit_code)
        if data is None:
            data = Path(path).read_bytes()
        return self._python_strings(data)
