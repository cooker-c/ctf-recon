from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass
from shutil import which
from typing import List, Sequence

from utils.logger import get_logger

log = get_logger(__name__)


@dataclass
class ToolResult:
    command: str
    stdout: str
    stderr: str
    exit_code: int

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


class ToolRunner:
    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    def is_available(self, name: str) -> bool:
        return which(name) is not None

    def run(self, command: Sequence[str], cwd: str | None = None) -> ToolResult:
        cmd_display = " ".join(shlex.quote(part) for part in command)
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                cwd=cwd,
                timeout=self.timeout,
                check=False,
            )
            return ToolResult(cmd_display, proc.stdout, proc.stderr, proc.returncode)
        except subprocess.TimeoutExpired as exc:
            log.error("Command timed out: %s", cmd_display)
            return ToolResult(cmd_display, exc.stdout or "", exc.stderr or "", -1)
        except FileNotFoundError:
            log.error("Command not found: %s", command[0])
            return ToolResult(cmd_display, "", "command not found", -1)
