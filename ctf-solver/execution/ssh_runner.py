from __future__ import annotations

import shlex
from typing import List, Sequence

from tools.runner import ToolResult, ToolRunner
from utils.logger import get_logger

log = get_logger(__name__)


class SSHRunner:
    def __init__(self, host: str, user: str, key_path: str | None = None, timeout: int = 60) -> None:
        self.host = host
        self.user = user
        self.key_path = key_path
        self.runner = ToolRunner(timeout=timeout)

    def _build_cmd(self, remote_cmd: Sequence[str]) -> List[str]:
        cmd: List[str] = ["ssh"]
        if self.key_path:
            cmd.extend(["-i", self.key_path])
        cmd.append(f"{self.user}@{self.host}")
        cmd.append(" ".join(shlex.quote(part) for part in remote_cmd))
        return cmd

    def run(self, remote_cmd: Sequence[str], cwd: str | None = None) -> ToolResult:
        full_cmd = self._build_cmd(remote_cmd)
        result = self.runner.run(full_cmd, cwd=cwd)
        if not result.ok:
            log.warning("SSH command failed (%s): %s", result.exit_code, result.command)
        return result
